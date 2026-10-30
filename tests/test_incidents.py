"""Unified incidents: grouping, agreement between Suricata and the Isolation Forest, metric evidence, missing signals.
Synthetic data only, no Docker."""
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense"))

import incidents  # noqa: E402

T0 = 1_800_000_000.0
KW = {"baseline_cap": 500.0, "policy": "guarded", "current_cap": 500.0, "suricata_available": True}


def alert(offset, sid=1000001, src="172.18.0.3", hops=0, sensor="ingress"):
    return {"ts": T0 + offset, "signature_id": sid, "signature": f"sig {sid}", "src_ip": src, "sensor": sensor,
            "interfaces": ["eth0"] + (["eth1"] if hops else []), "hop_alerts": hops}


def history(spec, step=5.0, start=-60.0):
    """spec(t) -> (confidence, request_rate, state, threshold); one poll every `step` seconds from `start`."""
    out, t = [], start
    while t <= 200:
        conf, rate, state, cap_now = spec(t)
        out.append({"ts": T0 + t, "confidence": conf, "threshold": cap_now, "request_rate": rate, "state": state,
                    "features": {"request_rate": rate, "established_connections": 0.0}, "blocked_rps": 0.0})
        t += step
    return out


def calm(t):
    return 0.2, 9.0, "normal", 500.0


def attack(t, begin=0.0, end=60.0, conf=0.8):
    return (conf, 120.0, "mitigating", 60.0) if begin <= t <= end else calm(t)


def series(base, peak, begin=0.0, end=60.0):
    return [(T0 + t, peak if begin <= t <= end else base) for t in range(-150, 200, 5)]


def build(alerts, hist, ser=None, **kw):
    groups, lone = incidents.plan(alerts, hist)
    return [incidents.assemble(g, None, hist, ser, T0 + 300, **{**KW, **kw}) for g in groups], lone


# ------------------------------------------------------------------ grouping and duplicates
def test_alerts_of_one_type_form_bursts_and_types_stay_apart():
    alerts = [alert(10), alert(20), alert(30), alert(200), alert(25, sid=1000003)]
    groups = incidents.group_alerts(alerts)
    assert sorted((g["attack_type"], len(g["alerts"])) for g in groups) == [("http_flood", 1), ("http_flood", 3), ("udp_flood", 1)]


def test_merged_sightings_are_counted_once_as_alerts_but_kept_as_evidence():
    (inc,), _ = build([alert(10, hops=1), alert(20)], history(lambda t: attack(t, 0, 40)))
    suricata = inc["detectors"]["suricata"]
    assert suricata["alerts"] == 2 and suricata["sightings"] == 3 and suricata["interfaces"] == ["eth0", "eth1"]


def test_every_source_address_is_listed_with_its_alert_count():
    (inc,), _ = build([alert(10, src="10.0.0.1"), alert(20, src="10.0.0.2"), alert(30, src="10.0.0.1")], history(calm))
    assert inc["detectors"]["suricata"]["sources"] == [{"ip": "10.0.0.1", "alerts": 2}, {"ip": "10.0.0.2", "alerts": 1}]


# ------------------------------------------------------------------ agreement
def test_both_detectors_flagging_the_period_is_corroborated_and_high():
    (inc,), lone = build([alert(12), alert(22), alert(32)], history(attack), series(9, 115))
    assert inc["assessment"] == "corroborated" and inc["severity"] == "high" and lone == []
    assert inc["detectors"]["ml"]["state"] == "flagged" and inc["detectors"]["ml"]["longest_run"] >= 3
    assert inc["metrics"]["state"] == "elevated" and inc["mitigation"]["cap_lowered"] is True
    assert any("Suricata" in line for line in inc["evidence"]) and any("Isolation Forest" in line for line in inc["evidence"])


def test_ml_calm_while_suricata_alerts_is_a_disagreement_not_a_confirmation():
    (inc,), _ = build([alert(12), alert(22)], history(calm), series(9, 9))
    assert inc["assessment"] == "suricata_only" and inc["detectors"]["ml"]["state"] == "not_flagged"
    assert inc["severity"] == "low" and inc["metrics"]["state"] == "not_elevated"


def test_one_flagged_poll_is_chance_not_agreement():
    def blip(t):
        return (0.9, 9.0, "normal", 500.0) if t == 10 else calm(t)

    (inc,), _ = build([alert(12)], history(blip))
    assert inc["detectors"]["ml"]["state"] == "not_flagged" and inc["detectors"]["ml"]["flagged_polls"] == 1


def test_busy_legitimate_traffic_that_trips_suricata_is_medium_with_a_caveat_not_high():
    (inc,), _ = build([alert(12), alert(22)], history(calm), series(9, 90))
    assert inc["assessment"] == "suricata_only" and inc["metrics"]["state"] == "elevated" and inc["severity"] == "medium"
    assert any("request rate" in c for c in inc["caveats"])  # rate-based signals are not independent
    assert any("not proof" in c for c in inc["caveats"])


def test_the_ml_cannot_confirm_the_attack_type_and_the_record_says_so():
    (inc,), _ = build([alert(12, sid=1000003)], history(attack), series(100, 4000))
    assert inc["attack_type"] == "udp_flood" and any("not attack type" in c for c in inc["caveats"])


# ------------------------------------------------------------------ missing signals
def test_missing_ml_history_is_no_data_not_calm():
    (inc,), _ = build([alert(12)], [])
    assert inc["detectors"]["ml"]["state"] == "no_data" and inc["assessment"] == "suricata_ml_unavailable"
    assert inc["metrics"]["state"] == "no_data" and inc["mitigation"]["samples"] == 0 and inc["mitigation"]["cap_lowered"] is None


def test_a_missing_model_scores_zero_everywhere_and_must_not_read_as_calm():
    groups, _ = incidents.plan([alert(12)], history(calm))
    inc = incidents.assemble(groups[0], None, history(calm), None, T0 + 300, ml_available=False, **KW)
    assert inc["detectors"]["ml"]["state"] == "no_data"


def test_prometheus_down_or_no_earlier_samples_is_stated_not_guessed():
    assert incidents.metric_view("http_flood", None, T0, T0 + 10)["state"] == "no_data"
    later = [(T0 + t, 50.0) for t in range(0, 40, 5)]
    view = incidents.metric_view("http_flood", later, T0 + 5, T0 + 30)
    assert view["state"] == "no_baseline" and view["peak"] == 50.0 and view["ratio"] is None
    assert incidents.metric_view("unknown_type", later, T0, T0 + 10)["state"] == "not_applicable"


def test_without_suricata_files_an_ml_episode_says_suricata_has_no_data():
    hist = history(attack)
    _, lone = incidents.plan([], hist)
    inc = incidents.assemble(None, lone[0], hist, None, T0 + 300, **{**KW, "suricata_available": False})
    assert inc["detectors"]["suricata"]["state"] == "no_data" and inc["assessment"] == "ml_only_suricata_unavailable"


# ------------------------------------------------------------------ ML-only incidents
def test_an_ml_episode_without_alerts_is_a_low_unclassified_incident_with_a_load_caveat():
    hist = history(attack)
    groups, lone = incidents.plan([], hist)
    assert groups == [] and len(lone) == 1
    inc = incidents.assemble(None, lone[0], hist, None, T0 + 300, **KW)
    assert inc["attack_type"] is None and inc["assessment"] == "ml_only" and inc["severity"] == "low"
    assert inc["detectors"]["suricata"]["state"] == "not_flagged" and inc["mitigation"]["applicable"] is None
    assert any("legitimate high load" in c for c in inc["caveats"])


def test_an_ml_episode_already_explained_by_suricata_is_not_a_second_incident():
    _, lone = incidents.plan([alert(12), alert(30)], history(attack))
    assert lone == []


def test_short_ml_blips_make_no_incident():
    def blips(t):
        return (0.9, 9.0, "normal", 500.0) if t in (10, 20, 40) else calm(t)

    assert incidents.ml_episodes(history(blips)) == []


# ------------------------------------------------------------------ mitigation status
def test_mitigation_is_reported_per_attack_type_without_overstating_it():
    http = incidents.mitigation_view("http_flood", history(attack), T0, T0 + 60, 500.0, "guarded", 60.0)
    assert http["applicable"] is True and http["cap_lowered"] is True and http["min_cap_rps"] == 60.0
    assert http["states_seen"] == ["mitigating", "normal"] and "note" not in http
    udp = incidents.mitigation_view("udp_flood", history(attack), T0, T0 + 60, 500.0, "guarded", 60.0)
    assert udp["applicable"] is False and "not mitigated" in udp["note"]
    unknown = incidents.mitigation_view(None, history(attack), T0, T0 + 60, 500.0, "guarded", 60.0)
    assert unknown["applicable"] is None


def test_a_cap_left_low_by_an_earlier_incident_is_not_credited_to_this_one():
    def after_a_flood(t):
        return (0.2, 9.0, "mitigating", 55.0) if t < 100 else calm(t)

    view = incidents.mitigation_view("slowloris", history(after_a_flood), T0 + 30, T0 + 80, 500.0, "guarded", 55.0)
    assert view["cap_lowered"] is True and view["lowered_before_start"] is True
    fresh = incidents.mitigation_view("http_flood", history(attack), T0 + 5, T0 + 60, 500.0, "guarded", 60.0)
    assert fresh["lowered_before_start"] is False
    assert incidents.mitigation_view("http_flood", [], T0, T0 + 5, 500.0, "guarded", 500.0)["lowered_before_start"] is None


def test_signature_types_match_the_rule_files():
    ids = set()
    for rules in (ROOT / "defense" / "suricata").glob("*.rules"):
        if rules.name != "calibrate.rules":
            ids |= {int(m) for m in re.findall(r"sid:(\d+);", rules.read_text(encoding="utf-8"))}
    assert ids == set(incidents.SIGNATURE_TYPES)


# ------------------------------------------------------------------ the engine endpoint
def test_engine_serves_incidents_and_never_touches_the_rate_limit(monkeypatch, tmp_path):
    import engine
    from fastapi.testclient import TestClient
    from suricata_alerts import AlertStore

    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(now - 20))
    eve = tmp_path / "eve.json"
    eve.write_text(json.dumps({
        "timestamp": stamp, "event_type": "alert", "in_iface": "eth1", "src_ip": "172.19.0.3", "src_port": 1,
        "dest_ip": "172.19.0.2", "dest_port": 8080, "proto": "TCP",
        "alert": {"signature_id": 1000001, "signature": "SENTINEL LAB: possible HTTP flood", "severity": 2, "action": "allowed"},
    }) + "\n", encoding="utf-8")
    store = AlertStore(eve)
    store.poll()
    polls = [{"ts": now - 40 + i * 5, "confidence": 0.8, "threshold": 60.0, "request_rate": 100.0, "state": "mitigating",
              "features": {"request_rate": 100.0}, "blocked_rps": 5.0} for i in range(10)]
    monkeypatch.setattr(engine, "suricata_store", store)
    monkeypatch.setattr(engine, "_eve_files", lambda: [eve])
    monkeypatch.setattr(engine, "_ml_history", type(engine._ml_history)(polls, maxlen=720))
    monkeypatch.setattr(engine, "_model", object())

    async def fake_series(kind, start, end):
        return [(start + d, 10.0 if d < 0 else 120.0) for d in range(-150, 60, 5)]

    monkeypatch.setattr(engine, "_metric_series", fake_series)
    before = dict(engine._state)
    body = TestClient(engine.app).get("/incidents").json()
    (inc,) = body["incidents"]
    assert inc["attack_type"] == "http_flood" and inc["assessment"] == "corroborated" and inc["severity"] == "high"
    assert inc["detectors"]["suricata"]["sources"][0]["ip"] == "172.19.0.3" and inc["metrics"]["state"] == "elevated"
    assert inc["mitigation"]["cap_lowered"] is True and body["inputs"]["ml_model_loaded"] is True
    assert engine._state == before  # advisory: the limit never moved
