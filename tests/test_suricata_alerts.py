"""Suricata EVE ingestion: parsing, incremental tailing, restart safety, deduplication, correlation and the
engine endpoints. All synthetic, no Docker."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense"))

import suricata_alerts  # noqa: E402
from suricata_alerts import AlertStore, correlate, normalize_alert, parse_timestamp, sensor_name  # noqa: E402

T0 = parse_timestamp("2026-10-30T11:10:59.000000+0000")
NOW = lambda: T0 + 30  # noqa: E731 -- a fixed "current time" so history pruning never depends on when the test runs
LIMITER = "172.18.0.12"  # the rate-limiter's target-side address: the source of proxied (hop) traffic

EVE_ALERT = {
    "timestamp": "2026-10-30T11:10:59.123456+0000",
    "flow_id": 1,
    "in_iface": "eth1",
    "event_type": "alert",
    "src_ip": "172.19.0.3",
    "src_port": 43262,
    "dest_ip": "172.19.0.2",
    "dest_port": 8080,
    "proto": "TCP",
    "app_proto": "http",
    "alert": {"action": "allowed", "gid": 1, "signature_id": 1000001, "rev": 1,
              "signature": "SENTINEL LAB: possible HTTP flood", "category": "Attempted Denial of Service", "severity": 2},
}


def line(offset: float = 0.0, **overrides) -> str:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(T0 + offset)) + ".000000+0000"
    return json.dumps({**EVE_ALERT, "timestamp": stamp, **overrides})


def hop(offset: float = 0.0, **overrides) -> str:
    """The same flood as the rate-limiter forwards it to the load balancer (target-facing leg)."""
    return line(offset, in_iface="eth0", src_ip=LIMITER, dest_ip="172.18.0.9", dest_port=8000, **overrides)


def store(path, **kwargs) -> AlertStore:
    kwargs.setdefault("clock", NOW)
    return AlertStore(path, **kwargs)


def append(path: Path, *lines: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("".join(entry + "\n" for entry in lines))


# ---------------------------------------------------------------- normalization
def test_alert_is_normalized_with_every_required_field():
    alert = normalize_alert(line())
    assert alert["signature"] == "SENTINEL LAB: possible HTTP flood" and alert["signature_id"] == 1000001
    assert alert["severity"] == 2 and alert["severity_label"] == "medium"
    assert (alert["src_ip"], alert["dest_ip"], alert["dest_port"]) == ("172.19.0.3", "172.19.0.2", 8080)
    assert alert["protocol"] == "TCP" and alert["in_iface"] == "eth1" and alert["interfaces"] == ["eth1"]
    assert alert["ts"] == parse_timestamp("2026-10-30T11:10:59.000000+0000") > 1.7e9


def test_non_alert_and_malformed_events_are_ignored():
    assert normalize_alert(line(event_type="flow")) is None
    assert normalize_alert("not json") is None
    assert normalize_alert("[]") is None
    assert normalize_alert(line(timestamp="yesterday")) is None
    assert normalize_alert(line(src_ip="")) is None
    assert normalize_alert(json.dumps({k: v for k, v in EVE_ALERT.items() if k != "alert"})) is None


def test_severity_levels_map_to_labels():
    for level, label in [(1, "high"), (2, "medium"), (3, "low")]:
        alert = json.loads(line())
        alert["alert"]["severity"] = level
        assert normalize_alert(json.dumps(alert))["severity_label"] == label


def test_sensor_names_come_from_the_file_name():
    assert sensor_name(Path("/x/eve.json")) == "ingress"
    assert sensor_name(Path("/x/eve-udp.json")) == "udp"


# ---------------------------------------------------------------- incremental ingestion
def test_store_tails_appended_lines_and_keeps_partial_lines_for_later(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve)
    assert s.poll() == []  # no file yet
    append(eve, line(), json.dumps({"event_type": "flow"}))
    assert [a["signature_id"] for a in s.poll()] == [1000001]
    half = line(1, src_ip="10.0.0.9")
    with open(eve, "a", encoding="utf-8") as fh:
        fh.write(half[:40])
    assert s.poll() == []  # incomplete line is not parsed (or lost)
    with open(eve, "a", encoding="utf-8") as fh:
        fh.write(half[40:] + "\n")
    assert [a["src_ip"] for a in s.poll()] == ["10.0.0.9"]
    assert s.total == 2 and s.skipped_lines == 0


def test_flow_records_are_skipped_without_parsing_and_bad_alert_lines_are_counted(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve)
    s.poll()
    append(eve, *[json.dumps({"event_type": "flow", "n": i}) for i in range(50)])
    append(eve, '{"event_type":"alert", broken')
    assert s.poll() == [] and s.skipped_lines == 1


def test_a_poll_reads_at_most_its_budget_and_catches_up_on_the_next(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata_alerts, "POLL_BUDGET_BYTES", 600)
    monkeypatch.setattr(suricata_alerts, "READ_CHUNK_BYTES", 300)
    eve = tmp_path / "eve.json"
    s = store(eve)
    s.poll()
    append(eve, *[line(i, src_ip=f"10.0.0.{i}") for i in range(12)])
    first = s.poll()
    assert s.behind and 0 < len(first) < 12
    seen = list(first)
    while s.behind:
        seen += s.poll()
    seen += s.poll()
    assert sorted(a["src_ip"] for a in seen) == sorted(f"10.0.0.{i}" for i in range(12))  # nothing lost or doubled


def test_rotation_restarts_from_the_top_and_runaway_lines_are_bounded(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve)
    s.poll()
    append(eve, line(), line(1))
    s.poll()
    eve.write_text(line(2, src_ip="10.1.1.1") + "\n", encoding="utf-8")  # smaller than before: rotated
    assert [a["src_ip"] for a in s.poll()] == ["10.1.1.1"]
    with open(eve, "a", encoding="utf-8") as fh:
        fh.write("x" * (3 * suricata_alerts.MAX_LINE_BYTES))  # no newline, ever
    s.poll()
    assert all(len(t.buffer) <= 2 * suricata_alerts.MAX_LINE_BYTES for t in s._tails.values())


def test_history_is_bounded_by_count_and_by_age(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve, max_alerts=5)
    s.poll()
    append(eve, *[line(i * 0.01, src_ip=f"10.0.0.{i}") for i in range(20)])
    s.poll()
    assert len(s.alerts) == 5 and s.total == 20
    aged = store(tmp_path / "eve2.json", clock=lambda: T0 + suricata_alerts.MAX_ALERT_AGE_S + 3600)
    aged.poll()
    append(tmp_path / "eve2.json", line())
    aged.poll()
    assert len(aged.alerts) == 0  # older than the age bound: pruned


def test_signature_counters_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(suricata_alerts, "MAX_SIGNATURES", 3)
    eve = tmp_path / "eve.json"
    s = store(eve)
    s.poll()
    for sid in range(10):
        alert = json.loads(line(sid * 0.01))
        alert["alert"]["signature_id"] = sid
        append(eve, json.dumps(alert))
    s.poll()
    assert len(s.by_signature) <= 4 and sum(s.by_signature.values()) == 10


# ---------------------------------------------------------------- restart safety
def test_existing_history_is_not_news_on_the_first_start(tmp_path):
    eve = tmp_path / "eve.json"
    append(eve, line(), line(1))
    s = store(eve, state_path=tmp_path / "state.json")
    assert s.poll() == []  # the pre-existing alerts fill the history but are not returned as new
    assert len(s.recent()) == 2
    append(eve, line(2, src_ip="10.9.9.9"))
    assert [a["src_ip"] for a in s.poll()] == ["10.9.9.9"]


def test_a_restart_never_counts_replayed_events_but_counts_those_written_while_down(tmp_path):
    eve, state = tmp_path / "eve.json", tmp_path / "state.json"
    first = store(eve, state_path=state)
    first.poll()
    append(eve, line(0), line(1))
    assert len(first.poll()) == 2  # counted once
    append(eve, line(2, src_ip="10.2.2.2"))  # written while the engine is down
    restarted = store(eve, state_path=state)
    news = restarted.poll()
    assert [a["src_ip"] for a in news] == ["10.2.2.2"]  # only the one it never saw
    assert len(restarted.recent()) == 3  # the history is complete again
    assert restarted.poll() == []
    assert store(eve, state_path=state).poll() == []  # and a second restart replays nothing


def test_a_missing_or_corrupt_state_file_falls_back_to_history_only(tmp_path):
    eve, state = tmp_path / "eve.json", tmp_path / "state.json"
    append(eve, line())
    state.write_text("{not json", encoding="utf-8")
    assert store(eve, state_path=state).poll() == []


def test_a_file_that_appears_after_start_is_all_news(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(lambda: [eve] if eve.exists() else [])
    assert s.poll() == []
    append(eve, line(), line(1))
    assert len(s.poll()) == 2


def test_the_counter_only_sees_news(tmp_path):
    """What engine.py does: increment a counter per returned alert."""
    eve, state = tmp_path / "eve.json", tmp_path / "state.json"
    counted = 0
    for _ in range(3):  # three engine lifetimes over the same growing file
        s = store(eve, state_path=state)
        counted += len(s.poll())
        append(eve, line(counted, src_ip=f"10.0.0.{counted}"))
        counted += len(s.poll())
    assert counted == 3


# ---------------------------------------------------------------- rotation
def rotate(eve: Path, stamp: str = "20261030120000") -> Path:
    """What rotate-eve.sh does: rename the file (same inode), then Suricata creates a fresh one."""
    rotated = eve.with_name(eve.name + "." + stamp)
    eve.rename(rotated)
    return rotated


def test_rotation_loses_nothing_written_between_the_last_read_and_the_rename(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve)
    s.poll()
    append(eve, line(0, src_ip="10.0.0.1"))
    assert [a["src_ip"] for a in s.poll()] == ["10.0.0.1"]
    append(eve, line(1, src_ip="10.0.0.2"))  # written, not yet read...
    rotate(eve)  # ...and then the file is rotated
    append(eve, line(2, src_ip="10.0.0.3"))  # the fresh file
    assert [a["src_ip"] for a in s.poll()] == ["10.0.0.2", "10.0.0.3"]
    assert s.poll() == [] and s.total == 3  # and nothing twice


def test_rotation_while_the_engine_was_down_resumes_the_old_file_then_the_new_one(tmp_path):
    eve, state = tmp_path / "eve.json", tmp_path / "state.json"
    first = store(eve, state_path=state)
    first.poll()
    append(eve, line(0, src_ip="10.0.0.1"))
    assert len(first.poll()) == 1
    append(eve, line(1, src_ip="10.0.0.2"))  # engine is down from here on
    rotate(eve)
    append(eve, line(2, src_ip="10.0.0.3"), line(3, src_ip="10.0.0.4"))
    restarted = store(eve, state_path=state)
    assert [a["src_ip"] for a in restarted.poll()] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]  # never 10.0.0.1 again
    assert store(eve, state_path=state).poll() == []


def test_a_restart_after_a_rotation_still_shows_the_recent_history_without_counting_it(tmp_path):
    eve, state = tmp_path / "eve.json", tmp_path / "state.json"
    first = store(eve, state_path=state)
    first.poll()
    append(eve, line(0, src_ip="10.0.0.1"), line(1, src_ip="10.0.0.2"))
    assert len(first.poll()) == 2
    rotate(eve)  # engine still running, then restarted after the rotation
    append(eve, line(2, src_ip="10.0.0.3"))
    assert [a["src_ip"] for a in first.poll()] == ["10.0.0.3"]
    restarted = store(eve, state_path=state)
    assert restarted.poll() == []  # nothing new, nothing replayed
    assert sorted(a["src_ip"] for a in restarted.recent()) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # history is whole
    nostate = store(eve)  # even with no saved position: history only, no counting
    assert nostate.poll() == [] and len(nostate.recent()) == 3


def test_rotated_while_down_counts_only_what_was_never_seen_but_keeps_older_history(tmp_path):
    eve, state = tmp_path / "eve.json", tmp_path / "state.json"
    first = store(eve, state_path=state)
    first.poll()
    append(eve, line(0, src_ip="10.0.0.1"))
    first.poll()
    rotate(eve, "20261030110000")  # an earlier rotation, long since counted
    append(eve, line(1, src_ip="10.0.0.2"))
    assert len(first.poll()) == 1
    append(eve, line(2, src_ip="10.0.0.3"))  # unseen, then the engine goes down and the file rotates
    rotate(eve, "20261030120000")
    append(eve, line(3, src_ip="10.0.0.4"))
    restarted = store(eve, state_path=state)
    assert [a["src_ip"] for a in restarted.poll()] == ["10.0.0.3", "10.0.0.4"]
    assert sorted(a["src_ip"] for a in restarted.recent()) == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_rotated_files_are_not_mistaken_for_sensors_and_a_missing_old_file_is_survived(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(lambda: sorted(tmp_path.glob("eve*.json")))
    s.poll()
    append(eve, line(0, src_ip="10.0.0.1"))
    s.poll()
    rotated = rotate(eve)
    assert sorted(tmp_path.glob("eve*.json")) == []  # the active-file glob does not match eve.json.<timestamp>
    rotated.unlink()  # retention removed it before we looked
    append(eve, line(1, src_ip="10.0.0.2"))
    assert [a["src_ip"] for a in s.poll()] == ["10.0.0.2"]


def test_repeated_rotations_keep_every_alert_exactly_once(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve)
    s.poll()
    append(eve, line(-1, src_ip="10.0.1.99"))
    seen = s.poll()  # the file is known before it is first rotated
    for n in range(5):
        append(eve, line(n, src_ip=f"10.0.1.{n}"))
        if n % 2:
            seen += s.poll()
        rotate(eve, f"2026103012000{n}")
    append(eve, line(9, src_ip="10.0.1.9"))
    seen += s.poll()
    assert sorted(a["src_ip"] for a in seen) == sorted([f"10.0.1.{n}" for n in range(5)] + ["10.0.1.9", "10.0.1.99"])


# ---------------------------------------------------------------- deduplication across interfaces
def test_a_hop_sighting_is_merged_into_the_attacker_facing_alert_in_either_order(tmp_path):
    for first, second in [(line(), hop(0.5)), (hop(0.5), line())]:
        eve = tmp_path / f"eve-{first[:0]}{id(first)}.json"
        s = store(eve, proxy_addresses=lambda: {LIMITER})
        s.poll()
        append(eve, first, second)
        news = s.poll()
        assert len(news) == 1 and s.total == 1  # one logical alert, counted once
        (alert,) = s.recent()
        assert alert["src_ip"] == "172.19.0.3" and alert["in_iface"] == "eth1"  # the real client is the primary
        assert alert["interfaces"] == ["eth1", "eth0"] and alert["hop_alerts"] == 1
        assert alert["observations"][0]["src_ip"] == LIMITER and alert["observations"][0]["in_iface"] == "eth0"
        assert s.merged_hops == 1


def test_different_signatures_or_distant_times_are_not_merged(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve, proxy_addresses=lambda: {LIMITER})
    s.poll()
    other = json.loads(hop(0.5))
    other["alert"]["signature_id"] = 1000002
    append(eve, line(), json.dumps(other), hop(suricata_alerts.DEDUP_WINDOW_S + 5))
    s.poll()
    assert s.merged_hops == 0
    s2 = store(tmp_path / "late.json", proxy_addresses=lambda: {LIMITER}, clock=lambda: T0 + 1000)
    s2.poll()
    append(tmp_path / "late.json", hop(0))
    promoted = s2.poll()
    assert len(promoted) == 1 and promoted[0]["src_ip"] == LIMITER  # no twin ever came: it is a real alert


def test_an_unmatched_hop_waits_for_its_twin_before_being_promoted(tmp_path):
    eve = tmp_path / "eve.json"
    clock = {"now": T0}
    s = store(eve, proxy_addresses=lambda: {LIMITER}, clock=lambda: clock["now"])
    s.poll()
    append(eve, hop(0))
    assert s.poll() == [] and s.total == 0  # held back
    clock["now"] = T0 + suricata_alerts.DEDUP_WINDOW_S + 1
    assert len(s.poll()) == 1 and s.total == 1


def test_without_a_known_proxy_address_nothing_is_merged(tmp_path):
    eve = tmp_path / "eve.json"
    s = store(eve)  # DNS unavailable: behave as before, never hide an alert
    s.poll()
    append(eve, line(), hop(0.5))
    assert len(s.poll()) == 2 and s.merged_hops == 0


def test_alerts_from_separate_sensor_files_keep_their_sensor_name(tmp_path):
    ingress, udp = tmp_path / "eve.json", tmp_path / "eve-udp.json"
    s = store(lambda: [p for p in (ingress, udp) if p.exists()])
    s.poll()
    append(ingress, line())
    append(udp, line(0.2, proto="UDP", dest_port=5300, src_ip="172.18.0.20", dest_ip="172.18.0.5"))
    assert {a["sensor"]: a["protocol"] for a in s.poll()} == {"ingress": "TCP", "udp": "UDP"}


def test_recent_filters_newest_first(tmp_path):
    eve = tmp_path / "eve.json"
    append(eve, line(), line(5, alert={**EVE_ALERT["alert"], "signature_id": 7, "severity": 1}))
    s = store(eve)
    s.poll()
    assert [a["signature_id"] for a in s.recent()] == [7, 1000001]
    assert [a["signature_id"] for a in s.recent(min_severity=1)] == [7]
    assert [a["signature_id"] for a in s.recent(signature_id=1000001)] == [1000001]
    assert len(s.recent(limit=1)) == 1
    assert {(c["signature_id"], c["count"]) for c in s.signature_counts()} == {(7, 1), (1000001, 1)}


# ---------------------------------------------------------------- correlation and engine
def test_correlation_reports_the_peak_detector_poll_within_the_window():
    history = [
        {"ts": 100.0, "confidence": 0.2, "threshold": 500.0, "request_rate": 9.0, "state": "normal"},
        {"ts": 105.0, "confidence": 0.8, "threshold": 300.0, "request_rate": 90.0, "state": "normal"},
    ]
    near = correlate(104.0, history)
    assert near["ml_available"] and near["ml_flagged"] is True
    assert near["confidence"] == 0.8 and near["request_rate"] == 90.0 and near["threshold_rps"] == 300.0
    calm = correlate(95.0, [history[0]])
    assert calm["ml_flagged"] is False and calm["confidence"] == 0.2
    none = correlate(500.0, history)
    assert none["ml_available"] is False and none["ml_flagged"] is None


def test_engine_serves_alerts_with_ml_context_and_never_changes_the_rate_limit(tmp_path, monkeypatch):
    import engine
    from fastapi.testclient import TestClient

    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(now))
    eve = tmp_path / "eve.json"
    eve.write_text(line(timestamp=stamp) + "\n", encoding="utf-8")
    s = AlertStore(eve)
    s.poll()
    monkeypatch.setattr(engine, "suricata_store", s)
    monkeypatch.setattr(engine, "_eve_files", lambda: [eve])
    monkeypatch.setattr(engine, "_ml_history", type(engine._ml_history)(
        [{"ts": now, "confidence": 0.7, "threshold": 120.0, "request_rate": 80.0, "state": "mitigating"}], maxlen=10))
    threshold_before = dict(engine._state)

    client = TestClient(engine.app)
    alerts = client.get("/suricata/alerts").json()
    assert alerts["total_ingested"] == 1
    (alert,) = alerts["alerts"]
    assert alert["signature_id"] == 1000001 and alert["ml"]["ml_flagged"] is True and alert["ml"]["request_rate"] == 80.0
    assert alert["interfaces"] == ["eth1"]
    assert client.get("/suricata/alerts?min_severity=1").json()["alerts"] == []

    summary = client.get("/suricata/summary").json()
    assert summary["eve_file_present"] and summary["recent_alerts"] == 1 and summary["ml_flagged_alerts"] == 1
    assert summary["eve_files"] == ["eve.json"] and summary["merged_duplicate_sightings"] == 0
    assert summary["signatures"][0]["count"] == 1
    assert engine._state == threshold_before  # advisory only: nothing about the limit moved


def test_missing_eve_file_is_reported_not_fatal(tmp_path, monkeypatch):
    import engine
    from fastapi.testclient import TestClient

    monkeypatch.setattr(engine, "suricata_store", AlertStore(tmp_path / "absent.json"))
    monkeypatch.setattr(engine, "_eve_files", lambda: [])
    summary = TestClient(engine.app).get("/suricata/summary").json()
    assert summary["eve_file_present"] is False and summary["total_ingested"] == 0
