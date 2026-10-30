"""Tests for the live-feature detection pipeline: shared feature definitions,
recording validation, feature-log labeling, train/evaluate separation, and the
defense engine's logging and mitigation maths.

No Docker, Prometheus or real recordings are needed: everything is synthetic.
"""
import asyncio
import importlib.util
import json
import random
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense" / "classifier"))

import dataset  # noqa: E402
import evaluate  # noqa: E402
import live_features  # noqa: E402
import train  # noqa: E402
from features import FEATURE_NAMES  # noqa: E402
from live_features import LIVE_FEATURE_NAMES  # noqa: E402
import scoring  # noqa: E402
from scoring import attack_confidence  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402

BASE = 1_000_000.0


# ---------------------------------------------------------------- feature definitions

def test_live_feature_names_extend_the_correlation_engines_five():
    # threat-intel's correlation engine reads these five by name and expects them first.
    assert LIVE_FEATURE_NAMES[: len(FEATURE_NAMES)] == FEATURE_NAMES
    assert LIVE_FEATURE_NAMES[-1] == "established_connections"
    vector = live_features.LiveFeatures(1, 2, 3, 4, 5, 6).as_vector()
    assert vector == [1, 2, 3, 4, 5, 6] and len(vector) == len(LIVE_FEATURE_NAMES)


PROMQL_VALUES = {
    "sum(rate(target_http_requests_total[15s]))": "100",
    "sum(rate(target_tcp_connections_total[15s]))": "5",
    "sum(rate(target_udp_packets_total[15s]))": "10",
    "sum(target_active_connections)": "4",
    "sum(target_tcp_active_connections)": "200",
    "sum(target_udp_inflight_datagrams)": "1",
    "sum(rate(target_http_errors_total[15s]))": "10",
    "histogram_quantile(0.95, sum(rate(target_http_request_duration_seconds_bucket[1m])) by (le))": "0.25",
    "sum(target_http_established_sockets)": "103",
}


def prometheus_client(values: dict[str, str | None], fail: set[str] = frozenset()) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params["query"]
        if query in fail:
            return httpx.Response(500)
        value = values.get(query)
        result = [] if value is None else [{"value": [0, value]}]
        return httpx.Response(200, json={"data": {"result": result}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_gather_features_combines_http_tcp_and_udp_and_adds_established_sockets():
    async def run():
        async with prometheus_client(PROMQL_VALUES) as client:
            return await live_features.gather_features(client, "http://prom")

    f = asyncio.run(run())
    assert f.request_rate == 115  # http + tcp + udp
    assert f.active_connections == 205  # http in-flight + tcp active + udp in-flight
    assert f.error_rate == pytest.approx(0.1)  # 5xx / HTTP requests only
    assert f.avg_connection_duration == 0.25
    assert f.inter_arrival_std == pytest.approx(1 / 115)
    assert f.established_connections == 103


def test_gather_features_with_no_traffic_is_all_zero_not_an_error():
    async def run():
        async with prometheus_client({}) as client:  # every metric has no series yet
            return await live_features.gather_features(client, "http://prom")

    assert asyncio.run(run()).as_vector() == [0.0] * len(LIVE_FEATURE_NAMES)


def test_gather_features_treats_nan_latency_as_zero():
    async def run():
        async with prometheus_client({**PROMQL_VALUES, list(PROMQL_VALUES)[7]: "NaN"}) as client:
            return await live_features.gather_features(client, "http://prom")

    assert asyncio.run(run()).avg_connection_duration == 0.0


def test_prometheus_failure_is_none_not_zeros():
    async def run():
        async with prometheus_client(PROMQL_VALUES, fail={"sum(target_http_established_sockets)"}) as client:
            return await live_features.gather_features(client, "http://prom")

    assert asyncio.run(run()) is None


def load_web_target():
    spec = importlib.util.spec_from_file_location("web_target_app", ROOT / "targets" / "web" / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_web_target_counts_only_established_sockets_on_its_port():
    web = load_web_target()
    lines = [
        "   0: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1",  # LISTEN :8000
        "   1: 0100007F:1F40 0100007F:D2C2 01 00000000:00000000 00:00000000 00000000     0        0 2 1",  # ESTABLISHED :8000
        "   2: 0100007F:1F40 0100007F:D2C3 01 00000000:00000000 00:00000000 00000000     0        0 3 1",  # ESTABLISHED :8000
        "   3: 0100007F:1F40 0100007F:D2C4 06 00000000:00000000 00:00000000 00000000     0        0 4 1",  # TIME_WAIT :8000
        "   4: 0100007F:2382 0100007F:D2C5 01 00000000:00000000 00:00000000 00000000     0        0 5 1",  # ESTABLISHED :9090
    ]
    assert web.count_established(lines, 8000) == 2
    assert web.count_established([], 8000) == 0


# ---------------------------------------------------------------- metrics

def test_compute_metrics_known_confusion_matrix():
    # 4 attack samples (3 caught) and 6 normal samples (1 false alarm).
    labels = [True, True, True, True, False, False, False, False, False, False]
    confidences = [0.9, 0.8, 0.7, 0.2, 0.6, 0.1, 0.1, 0.2, 0.3, 0.4]
    m = evaluate.compute_metrics(labels, confidences, threshold=0.5)
    assert (m.true_positives, m.false_negatives, m.false_positives, m.true_negatives) == (3, 1, 1, 5)
    assert m.precision == pytest.approx(3 / 4)
    assert m.recall == pytest.approx(3 / 4)
    assert m.false_positive_rate == pytest.approx(1 / 6)
    assert m.f1 == pytest.approx(0.75)
    assert m.accuracy == pytest.approx(8 / 10)


def test_compute_metrics_threshold_is_inclusive():
    assert evaluate.compute_metrics([True], [0.5], threshold=0.5).true_positives == 1


def test_compute_metrics_handles_empty_denominators():
    m = evaluate.compute_metrics([False, False], [0.1, 0.2])
    assert (m.precision, m.recall, m.f1, m.false_positive_rate) == (0.0, 0.0, 0.0, 0.0)
    assert m.accuracy == 1.0
    assert evaluate.compute_metrics([], []).accuracy == 0.0


def test_compute_metrics_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        evaluate.compute_metrics([True, False], [0.9])


def test_attack_confidence_is_bounded_and_ranks_attacks_higher():
    rng = random.Random(0)
    legit = [[rng.uniform(1, 3), rng.uniform(0.03, 0.08), rng.uniform(0.2, 0.6), 0.0, rng.uniform(5, 15)] for _ in range(200)]
    model = IsolationForest(n_estimators=100, random_state=42).fit(legit)
    normal = attack_confidence(model, legit[0])
    attack = attack_confidence(model, [100.0, 0.8, 0.01, 0.3, 500.0])
    assert 0.0 <= normal <= 1.0 and 0.0 <= attack <= 1.0
    assert attack > 0.5 > normal


def test_range_guard_catches_values_beyond_training_that_the_forest_alone_cannot():
    rng = random.Random(1)
    # Training shaped like the lab's legitimate traffic: active_connections is constant (3), rate is 3-17/s.
    legit = [[rng.uniform(3, 17), 0.006, rng.uniform(0.06, 0.3), 0.0, 3.0, rng.choice([3.0, 4.0])] for _ in range(80)]
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42).fit(legit)
    ranges = scoring.feature_ranges(legit, LIVE_FEATURE_NAMES)
    assert ranges["active_connections"] == [3.0, 3.0] and ranges["request_rate"][1] <= 17

    tcp_exhaustion = [0.6, 0.01, 1.67, 0.0, 203.0, 3.0]  # only active_connections is abnormal
    slowloris = [0.6, 0.005, 1.67, 0.0, 3.0, 103.0]  # only established_connections is abnormal
    flood = [105.0, 0.005, 0.0095, 0.0, 3.0, 3.0]  # 6x the training maximum rate
    for attack in (tcp_exhaustion, slowloris, flood):
        assert attack_confidence(model, attack, LIVE_FEATURE_NAMES, ranges) > 0.85
    # The forest on its own cannot split a constant feature and does not extrapolate past the training range.
    assert attack_confidence(model, tcp_exhaustion) < 0.6
    assert attack_confidence(model, flood) < 0.7

    # Samples inside the training range are scored exactly as before.
    for sample in legit[:20]:
        assert attack_confidence(model, sample, LIVE_FEATURE_NAMES, ranges) == attack_confidence(model, sample)


def test_range_excess_ignores_decreases_and_in_range_values():
    ranges = {"request_rate": [3.0, 17.0], "inter_arrival_std": [0.06, 0.3], "active_connections": [3.0, 3.0]}
    names = ["request_rate", "inter_arrival_std", "active_connections"]
    assert scoring.range_excess([10.0, 0.01, 3.0], names, ranges) == 0.0  # lower inter-arrival time alone is not excess
    assert scoring.range_excess([31.0, 0.1, 3.0], names, ranges) == pytest.approx(1.0)  # one training range above max
    assert scoring.range_excess([5.0, 0.1, 4.0], names, ranges) == pytest.approx(1.0)  # constant feature: one-unit floor


# ---------------------------------------------------------------- synthetic lab data

def write_run(directory: Path, name: str, attack_type: str, start: float, end: float, status: int | None = 200,
              events: int = 20, blocked_fraction: float = 0.0, meta: bool = True, extra_lines: list[str] | None = None):
    lines = []
    for i in range(events):
        blocked = status is not None and i < events * blocked_fraction
        lines.append(json.dumps({
            "ts": start + (end - start) * i / max(events - 1, 1), "attack_type": attack_type, "target": "t",
            "status": 429 if blocked else status, "latency_ms": None if status is None else 20.0,
        }))
    (directory / f"{name}.jsonl").write_text("\n".join(lines + (extra_lines or [])), encoding="utf-8")
    if meta:
        (directory / f"{name}.meta.json").write_text(
            json.dumps({"run": name, "attack_type": attack_type, "start_ts": start, "end_ts": end}), encoding="utf-8")


def vector(kind: str, rng: random.Random) -> dict:
    """Synthetic live feature vectors shaped like what the lab produced."""
    if kind == "legit":
        rate = rng.uniform(2.5, 6.0)
        return {"request_rate": rate, "avg_connection_duration": 0.005 + rng.uniform(0, 0.003), "inter_arrival_std": 1 / rate,
                "error_rate": 0.0, "active_connections": rng.choice([3, 3, 4, 5]), "established_connections": rng.choice([1, 2, 3, 4, 5])}
    if kind == "idle":
        return {"request_rate": 0.6, "avg_connection_duration": 0.005, "inter_arrival_std": 1.67, "error_rate": 0.0,
                "active_connections": 3, "established_connections": rng.choice([1, 2, 3])}
    if kind == "http_flood":
        return {"request_rate": rng.uniform(100, 110), "avg_connection_duration": 0.005, "inter_arrival_std": 0.0095,
                "error_rate": 0.0, "active_connections": rng.choice([3, 4, 5]), "established_connections": rng.uniform(8, 12)}
    if kind == "udp_flood":
        return {"request_rate": rng.uniform(900, 930), "avg_connection_duration": 0.005, "inter_arrival_std": 0.0011,
                "error_rate": 0.0, "active_connections": rng.choice([3, 4]), "established_connections": 3}
    if kind == "tcp_exhaustion":
        return {"request_rate": 0.6, "avg_connection_duration": 0.005, "inter_arrival_std": 1.67, "error_rate": 0.0,
                "active_connections": 203, "established_connections": 3}
    if kind == "slowloris":  # identical to idle except for the TCP-level socket count
        return {**vector("idle", rng), "established_connections": rng.uniform(95, 110)}
    raise ValueError(kind)


def write_samples(path: Path, spans: list[tuple[str, float, float]], rng: random.Random, mitigation=False,
                  model=False, confidence=0.0, threshold=500.0):
    """Appends one feature-log entry every 5s for each (kind, start, end) span."""
    with open(path, "a", encoding="utf-8") as fh:
        for kind, start, end in spans:
            t = start
            while t <= end:
                fh.write(json.dumps({
                    "ts": t, "features": vector(kind, rng), "confidence": confidence, "threshold": threshold,
                    "model": model, "mitigation": mitigation,
                }) + "\n")
                t += 5.0


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Recordings and a feature log for every traffic type, plus a model trained on two legit runs."""
    rec = tmp_path / "rec"
    rec.mkdir()
    log = tmp_path / "feature_log.jsonl"
    rng = random.Random(7)
    monkeypatch.setattr(train, "RECORDINGS_DIR", rec)
    monkeypatch.setattr(train, "FEATURE_LOG", log)
    monkeypatch.setattr(train, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(evaluate, "MODEL_PATH", tmp_path / "model.joblib")

    # (run name, traffic kind, attack_type, start, end, status)
    runs = [
        ("legit_a", "legit", "legitimate_load", BASE + 0, BASE + 300, 200),
        ("legit_b", "legit", "legitimate_load", BASE + 400, BASE + 700, 200),
        ("legit_holdout", "legit", "legitimate_load", BASE + 800, BASE + 1100, 200),
        ("flood", "http_flood", "http_flood", BASE + 1200, BASE + 1400, 200),
        ("udp", "udp_flood", "udp_flood", BASE + 1500, BASE + 1700, None),
        ("tcp", "tcp_exhaustion", "tcp_exhaustion", BASE + 1800, BASE + 2000, None),
        ("slowloris", "slowloris", "slowloris", BASE + 2100, BASE + 2300, None),
    ]
    for name, kind, attack_type, start, end, status in runs:
        write_run(rec, name, attack_type, start, end, status=status)
        write_samples(log, [(kind, start, end)], rng)
    write_samples(log, [("idle", BASE + 710, BASE + 790)], rng)  # between runs: idle
    # A run recorded before the engine's feature log existed: no samples fall inside it.
    write_run(rec, "old_flood", "http_flood", BASE - 9000, BASE - 8900)

    monkeypatch.setattr(sys, "argv", ["train.py", "--legit-runs", "legit_a", "legit_b"])
    train.main()
    return tmp_path, rec, log, rng


def run_evaluate(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["evaluate.py", *args])
    evaluate.main()


# ---------------------------------------------------------------- recordings

def test_label_comes_from_events_not_file_name(tmp_path):
    write_run(tmp_path, "legit_looking_name", "http_flood", BASE, BASE + 10)
    info = dataset.inspect_recording(tmp_path / "legit_looking_name.jsonl")
    assert (info.label, info.attack_type, info.usable) == ("attack", "http_flood", True)


def test_unreachable_http_run_is_excluded_with_reason(tmp_path):
    write_run(tmp_path, "http_flood_run", "http_flood", BASE, BASE + 40, status=None, events=500)
    info = dataset.inspect_recording(tmp_path / "http_flood_run.jsonl")
    assert not info.usable and "target never responded" in info.reason
    assert info.events == 500  # still reported, never dropped silently


def test_statusless_attack_types_are_not_treated_as_unreachable(tmp_path):
    for attack_type in ("slowloris", "udp_flood", "tcp_exhaustion"):
        write_run(tmp_path, attack_type, attack_type, BASE, BASE + 30, status=None)
        assert dataset.inspect_recording(tmp_path / f"{attack_type}.jsonl").usable


def test_mixed_labels_and_empty_runs_are_excluded(tmp_path):
    write_run(tmp_path, "mixed", "http_flood", BASE, BASE + 10)
    with open(tmp_path / "mixed.jsonl", "a", encoding="utf-8") as fh:
        fh.write("\n" + json.dumps({"ts": 1.0, "attack_type": "legitimate_load", "status": 200}))
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")
    assert "mixed labels" in dataset.inspect_recording(tmp_path / "mixed.jsonl").reason
    assert dataset.inspect_recording(tmp_path / "empty.jsonl").reason == "no valid events"


def test_truncated_last_line_is_a_warning_not_an_exclusion(tmp_path):
    write_run(tmp_path, "cut", "legitimate_load", BASE, BASE + 30, events=500, extra_lines=['{"ts": 12'])
    info = dataset.inspect_recording(tmp_path / "cut.jsonl")
    assert info.usable and info.parse_errors == 1 and any("unparseable" in w for w in info.warnings)


def test_meta_json_gives_the_runs_real_span_and_blocked_requests_are_counted(tmp_path):
    # tcp_exhaustion logs every event in the first instant; the .meta.json has the real span.
    (tmp_path / "burst.jsonl").write_text(
        "\n".join(json.dumps({"ts": BASE, "attack_type": "tcp_exhaustion", "status": None}) for _ in range(5)), encoding="utf-8")
    (tmp_path / "burst.meta.json").write_text(json.dumps({"start_ts": BASE - 1, "end_ts": BASE + 30}), encoding="utf-8")
    info = dataset.inspect_recording(tmp_path / "burst.jsonl")
    assert (info.start_ts, info.end_ts, info.span_seconds) == (BASE - 1, BASE + 30, 31) and info.warnings == []

    write_run(tmp_path, "mitigated", "http_flood", BASE, BASE + 10, events=10, blocked_fraction=0.4, meta=False)
    assert dataset.inspect_recording(tmp_path / "mitigated.jsonl").blocked_events == 4


def test_discover_lists_every_file_and_errors_clearly_when_missing(tmp_path):
    write_run(tmp_path, "a", "legitimate_load", BASE + 100, BASE + 130)
    write_run(tmp_path, "b", "http_flood", BASE, BASE + 30)
    discovered = dataset.discover_recordings(tmp_path)
    assert [i.run for i in discovered] == ["b", "a"]  # oldest first; .meta.json files are not recordings
    with pytest.raises(SystemExit, match="Recordings directory not found"):
        dataset.discover_recordings(tmp_path / "missing")


# ---------------------------------------------------------------- labeling the feature log

def entry(ts: float) -> dict:
    return {"ts": ts, "features": {n: 1.0 for n in LIVE_FEATURE_NAMES}, "confidence": 0.3, "threshold": 500.0}


def test_samples_are_labeled_by_run_span_with_margins_and_idle(tmp_path):
    write_run(tmp_path, "flood", "http_flood", BASE, BASE + 100)
    info = dataset.inspect_recording(tmp_path / "flood.jsonl")
    entries = [entry(BASE - 500), entry(BASE + 5), entry(BASE + 50), entry(BASE + 105), entry(BASE + 130)]
    labeled, excluded = dataset.label_samples(entries, [info], LIVE_FEATURE_NAMES)
    # BASE+5 is inside the 15s warm-up and BASE+105 inside the 20s cool-down: both unlabeled.
    assert [(s.ts, s.attack_type, s.label, s.run) for s in labeled] == [
        (BASE - 500, "idle", "normal", None),
        (BASE + 50, "http_flood", "attack", "flood"),
        (BASE + 130, "idle", "normal", None),
    ]
    assert excluded == {"warm-up/cool-down margin": 2}


def test_labeling_excludes_overlapping_and_unusable_runs(tmp_path):
    write_run(tmp_path, "a", "http_flood", BASE, BASE + 200)
    write_run(tmp_path, "b", "udp_flood", BASE + 50, BASE + 150, status=None)
    write_run(tmp_path, "dead", "http_flood", BASE + 1000, BASE + 1100, status=None)
    infos = dataset.discover_recordings(tmp_path)
    labeled, excluded = dataset.label_samples([entry(BASE + 100), entry(BASE + 1050), entry(BASE + 180)], infos, LIVE_FEATURE_NAMES)
    assert excluded["overlapping runs"] == 1 and excluded["inside an unusable recording"] == 1
    assert [s.run for s in labeled] == ["a"]


# ---------------------------------------------------------------- train / evaluate

def test_train_refuses_non_legit_unreachable_and_unknown_runs(lab, monkeypatch):
    _, rec, _, _ = lab
    write_run(rec, "dead_legit", "legitimate_load", BASE + 5000, BASE + 5100, status=None)
    for run, message in (("flood", "not legitimate traffic"), ("dead_legit", "target never responded"),
                         ("nope", "no recording with that name")):
        monkeypatch.setattr(sys, "argv", ["train.py", "--legit-runs", run])
        with pytest.raises(SystemExit, match=message):
            train.main()


def test_train_needs_enough_logged_samples(lab, monkeypatch):
    _, rec, _, _ = lab
    write_run(rec, "no_samples_legit", "legitimate_load", BASE + 9000, BASE + 9100)  # engine was not running
    monkeypatch.setattr(sys, "argv", ["train.py", "--legit-runs", "no_samples_legit"])
    with pytest.raises(SystemExit, match="live feature samples"):
        train.main()


def test_offline_evaluation_separates_training_data_and_reports_every_recording(lab, monkeypatch):
    tmp_path, rec, _, _ = lab
    out = tmp_path / "evaluation.json"
    run_evaluate(monkeypatch, "--output", str(out))
    report = json.loads(out.read_text(encoding="utf-8"))

    assert report["trained_on"] == ["legit_a", "legit_b"] and report["feature_names"] == LIVE_FEATURE_NAMES
    scored = {r["run"] for r in report["runs"]}
    assert scored == {"legit_holdout", "flood", "udp", "tcp", "slowloris"}
    excluded = {e["run"]: e["reason"] for e in report["excluded"]}
    assert set(excluded) == {"legit_a", "legit_b", "old_flood"}
    assert excluded["legit_a"] == "used for training"
    assert "no usable feature-log samples" in excluded["old_flood"]
    assert scored.isdisjoint(excluded)
    assert len(scored) + len(excluded) == len(list(rec.glob("*.jsonl")))  # nothing silently dropped
    assert "live" not in report  # no mitigation-active samples were logged

    assert report["normal"]["samples"] > 0 and report["idle"]["samples"] > 0
    assert report["normal"]["false_positives"] / report["normal"]["samples"] < 0.25
    assert report["metrics"]["recall"] == 1.0
    assert report["unlabeled_samples"]["warm-up/cool-down margin"] > 0


def test_slowloris_is_caught_by_the_tcp_socket_feature_alone(lab, monkeypatch):
    # In the synthetic data Slowloris is identical to idle except for established_connections.
    tmp_path, _, _, _ = lab
    out = tmp_path / "evaluation.json"
    run_evaluate(monkeypatch, "--output", str(out))
    by_type = {t["attack_type"]: t for t in json.loads(out.read_text(encoding="utf-8"))["by_type"]}
    assert set(by_type) == {"http_flood", "udp_flood", "tcp_exhaustion", "slowloris"}
    assert by_type["slowloris"]["metrics"]["recall"] == 1.0
    for t in by_type.values():
        assert t["samples"] >= 30 and t["low_sample"] is False


def test_live_section_uses_engine_confidence_and_measures_mitigation(lab, monkeypatch):
    tmp_path, rec, log, rng = lab
    # An end-to-end HTTP flood and a legitimate run with mitigation active: engine confidence and rate limit are logged.
    write_run(rec, "flood_live", "http_flood", BASE + 3000, BASE + 3200, events=100, blocked_fraction=0.6)
    write_samples(log, [("http_flood", BASE + 3000, BASE + 3200)], rng, mitigation=True, model=True, confidence=0.9, threshold=40.0)
    write_run(rec, "legit_live", "legitimate_load", BASE + 3300, BASE + 3500, events=100)
    write_samples(log, [("legit", BASE + 3300, BASE + 3500)], rng, mitigation=True, model=True, confidence=0.2, threshold=400.0)
    out = tmp_path / "evaluation.json"
    run_evaluate(monkeypatch, "--output", str(out))
    live = json.loads(out.read_text(encoding="utf-8"))["live"]

    flood = next(t for t in live["by_type"] if t["attack_type"] == "http_flood")
    assert flood["flagged"] == flood["samples"] and flood["metrics"]["recall"] == 1.0
    assert flood["mitigation"]["min_threshold_rps"] == 40.0
    assert flood["mitigation"]["blocked"] == 60 and flood["mitigation"]["blocked_fraction"] == pytest.approx(0.6)
    assert live["normal"]["false_positives"] == 0
    assert live["normal"]["mitigation"]["blocked"] == 0 and live["normal"]["mitigation"]["min_threshold_rps"] == 400.0
    # Mitigation-active samples are not mixed into the offline numbers.
    assert {r["run"] for r in json.loads(out.read_text(encoding="utf-8"))["runs"]}.isdisjoint({"flood_live", "legit_live"})


def test_evaluation_refuses_training_runs_unknown_runs_and_stale_models(lab, monkeypatch):
    tmp_path, _, _, _ = lab
    with pytest.raises(SystemExit, match="training data"):
        run_evaluate(monkeypatch, "--runs", "legit_a", "flood")
    with pytest.raises(SystemExit, match="Unknown run"):
        run_evaluate(monkeypatch, "--runs", "nope")

    import joblib
    stale = joblib.load(tmp_path / "model.joblib")
    stale["feature_names"] = FEATURE_NAMES  # an older model trained on the five recording-derived features
    joblib.dump(stale, tmp_path / "model.joblib")
    with pytest.raises(SystemExit, match="Retrain"):
        run_evaluate(monkeypatch)


def test_evaluation_needs_normal_and_attack_samples(lab, monkeypatch):
    with pytest.raises(SystemExit, match="legitimate-run samples"):
        run_evaluate(monkeypatch, "--runs", "flood")
    with pytest.raises(SystemExit, match="attack-run samples"):
        run_evaluate(monkeypatch, "--runs", "legit_holdout")


# ---------------------------------------------------------------- defense engine

@pytest.fixture
def engine():
    sys.path.insert(0, str(ROOT / "defense"))
    import engine as module
    return module


def test_engine_serves_evaluation_report(engine, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    client = TestClient(engine.app)  # no `with`: skips the detection-loop startup hook
    monkeypatch.setattr(engine, "EVALUATION_PATH", tmp_path / "evaluation.json")
    assert client.get("/evaluation").json() == {"available": False}

    report = {"generated_at": "2026-01-01T00:00:00+00:00", "metrics": {"precision": 0.9}, "runs": []}
    (tmp_path / "evaluation.json").write_text(json.dumps(report), encoding="utf-8")
    assert client.get("/evaluation").json() == {"available": True, **report}

    (tmp_path / "evaluation.json").write_text("not json", encoding="utf-8")
    assert client.get("/evaluation").json() == {"available": False}


def test_engine_ignores_a_model_trained_on_other_features(engine, tmp_path, monkeypatch):
    import joblib

    path = tmp_path / "model.joblib"
    monkeypatch.setattr(engine, "MODEL_PATH", path)
    model = IsolationForest(random_state=0).fit([[1.0] * 5, [2.0] * 5, [3.0] * 5])
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, path)
    assert engine._load_model() is None  # stale 5-feature model: pass-through instead of crashing on the first score
    joblib.dump({"model": model, "feature_names": LIVE_FEATURE_NAMES}, path)
    assert isinstance(engine._load_model(), IsolationForest)


def test_engine_logs_every_scored_vector(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "FEATURE_LOG_PATH", tmp_path / "feature_log.jsonl")
    features = live_features.LiveFeatures(1, 2, 3, 4, 5, 103)
    engine.log_features(features, confidence=0.7, threshold=120.0)
    logged = json.loads((tmp_path / "feature_log.jsonl").read_text(encoding="utf-8"))
    assert logged["features"] == dict(zip(LIVE_FEATURE_NAMES, [1, 2, 3, 4, 5, 103]))
    assert (logged["confidence"], logged["threshold"]) == (0.7, 120.0)
    assert logged["mitigation"] is (engine.MIN_THRESHOLD < engine.BASELINE_THRESHOLD)
    entries, bad = dataset.load_feature_log(tmp_path / "feature_log.jsonl", LIVE_FEATURE_NAMES)
    assert len(entries) == 1 and bad == 0  # what the engine writes is what training/evaluation read


def test_adaptive_threshold_is_monotonic_and_bounded(engine, monkeypatch):
    def settled(confidence: float) -> float:
        monkeypatch.setitem(engine._state, "threshold", engine.BASELINE_THRESHOLD)
        for _ in range(60):
            engine._state["threshold"] = engine.adapt_threshold(confidence)
        return engine._state["threshold"]

    low, mid, high = settled(0.0), settled(0.5), settled(1.0)
    assert low == pytest.approx(engine.BASELINE_THRESHOLD)  # no attack: relaxes to baseline
    assert low > mid > high  # more confident -> stricter limit
    assert high == pytest.approx(engine.MIN_THRESHOLD, abs=0.5)
    assert engine.MIN_THRESHOLD <= high <= mid <= low <= engine.MAX_THRESHOLD


# ---------------------------------------------------------------- feature parity, concurrent runs, collateral

def test_engine_training_and_evaluation_share_one_feature_definition(engine):
    import audit

    # (The engine imports it as classifier.live_features, the scripts as live_features: two module
    # objects, one source file -- there is no second implementation of the features.)
    assert engine.gather_features.__code__.co_filename == live_features.gather_features.__code__.co_filename
    assert Path(live_features.__file__).name == "live_features.py"
    for module in (engine, train, evaluate, audit):
        assert module.LIVE_FEATURE_NAMES == live_features.LIVE_FEATURE_NAMES


def test_concurrent_runs_of_the_same_type_are_labeled_but_different_types_are_not(tmp_path):
    write_run(tmp_path, "bot_a", "http_flood", BASE, BASE + 100)
    write_run(tmp_path, "bot_b", "http_flood", BASE + 5, BASE + 100)  # a second source in the same distributed flood
    write_run(tmp_path, "legit", "legitimate_load", BASE + 30, BASE + 90)
    infos = dataset.discover_recordings(tmp_path)
    flood_only = dataset.label_samples([entry(BASE + 20)], infos, LIVE_FEATURE_NAMES)
    assert [(s.attack_type, s.run) for s in flood_only[0]] == [("http_flood", "bot_a")]  # both flood runs, counted once
    mixed = dataset.label_samples([entry(BASE + 50)], infos, LIVE_FEATURE_NAMES)
    assert mixed[0] == [] and mixed[1] == {"overlapping runs": 1}  # flood and legit at once: ambiguous


def test_collateral_counts_legitimate_requests_blocked_during_an_attack(tmp_path):
    write_run(tmp_path, "flood", "http_flood", BASE, BASE + 100, events=200)
    write_run(tmp_path, "legit_during", "legitimate_load", BASE + 20, BASE + 80, events=100, blocked_fraction=0.25)
    write_run(tmp_path, "legit_later", "legitimate_load", BASE + 500, BASE + 560, events=50)  # no attack at that time
    rows = evaluate.collateral(dataset.discover_recordings(tmp_path))
    assert [(r["legit_run"], r["attack_type"]) for r in rows] == [("legit_during", "http_flood")]
    assert rows[0]["requests"] == 100 and rows[0]["blocked"] == 25 and rows[0]["blocked_fraction"] == 0.25
    assert rows[0]["overlap_seconds"] == 60.0


def test_legit_load_path_mix_is_weighted_and_stays_on_the_target():
    sys.path.insert(0, str(ROOT / "attackers"))
    from common.paths import parse_paths, pick_url

    paths, weights = parse_paths("/:6,/work:3,/health")
    assert (paths, weights) == (["/", "/work", "/health"], [6.0, 3.0, 1.0])
    random.seed(0)
    urls = [pick_url("http://rate-limiter:8080/", paths, weights) for _ in range(2000)]
    assert {u.split("8080")[0] for u in urls} == {"http://rate-limiter:"}  # same host and port every time
    share = {p: sum(u.endswith(p) for u in urls) / 2000 for p in ("/work", "/health")}
    assert share["/work"] == pytest.approx(0.3, abs=0.05) and share["/health"] == pytest.approx(0.1, abs=0.04)


def test_idle_windows_are_trained_on_recorded_in_the_model_and_not_evaluated(lab, monkeypatch):
    import joblib

    tmp_path, _, _, _ = lab
    out = tmp_path / "before.json"
    run_evaluate(monkeypatch, "--output", str(out))
    idle_before = json.loads(out.read_text(encoding="utf-8"))["idle"]["samples"]
    assert idle_before > 0

    window = f"{BASE + 710}:{BASE + 790}"
    monkeypatch.setattr(sys, "argv", ["train.py", "--legit-runs", "legit_a", "legit_b", "--idle-windows", window,
                                      "--contamination", "0.01"])
    train.main()
    blob = joblib.load(tmp_path / "model.joblib")
    assert blob["idle_windows"] == [(BASE + 710, BASE + 790)] and blob["contamination"] == 0.01
    assert blob["samples"] > 0 and blob["samples"] == len(train.training_vectors(["legit_a", "legit_b"], [(BASE + 710, BASE + 790)]))

    out = tmp_path / "after.json"
    run_evaluate(monkeypatch, "--output", str(out))
    idle_after = json.loads(out.read_text(encoding="utf-8"))["idle"]["samples"]
    assert idle_after < idle_before  # the trained-on idle window is no longer scored
    assert train.training_vectors(["legit_a", "legit_b"]) != train.training_vectors(["legit_a", "legit_b"], [(BASE + 710, BASE + 790)])


def test_collateral_only_counts_attack_runs_that_overlapped_the_legitimate_run(tmp_path):
    # Two floods far apart; the legitimate run overlaps only the second. The first must not stretch the window.
    write_run(tmp_path, "early_flood", "http_flood", BASE, BASE + 100, events=100)
    write_run(tmp_path, "late_flood", "http_flood", BASE + 1000, BASE + 1100, events=100)
    write_run(tmp_path, "legit", "legitimate_load", BASE + 1020, BASE + 1080, events=60, blocked_fraction=0.5)
    write_run(tmp_path, "legit_alone", "legitimate_load", BASE + 500, BASE + 560, events=60)
    rows = evaluate.collateral(dataset.discover_recordings(tmp_path))
    assert [(r["legit_run"], r["attack_runs"], r["overlap_seconds"]) for r in rows] == [("legit", 1, 60.0)]
    assert rows[0]["blocked"] == 30 and rows[0]["requests"] == 60
