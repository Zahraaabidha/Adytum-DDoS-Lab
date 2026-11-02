"""Persistence of detector history and unified incidents: round trips, restart behaviour, duplicate prevention,
retention, and failure handling. Synthetic data, a temporary SQLite file, no Docker."""
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense"))

import incidents  # noqa: E402
from state_store import FREEZE_AFTER_S, MAX_ALERTS_PER_INCIDENT, StateStore, information  # noqa: E402

NOW = 1_800_000_000.0
KW = {"baseline_cap": 500.0, "policy": "guarded", "current_cap": 500.0, "suricata_available": True}


def make_store(tmp_path, clock_now=NOW, **kw):
    return StateStore(tmp_path / "state.db", clock=lambda: clock_now, **kw)


def poll(ts, conf=0.2, threshold=500.0, model="m.joblib", state="normal"):
    return {"ts": ts, "confidence": conf, "threshold": threshold, "request_rate": 9.0, "state": state,
            "features": {"request_rate": 9.0, "established_connections": 0.0}, "blocked_rps": 0.0, "model": model}


def alert(ts, sid=1000001, src="172.18.0.3", sensor="ingress"):
    return {"ts": ts, "timestamp": "t", "signature_id": sid, "signature": f"sig {sid}", "src_ip": src, "dest_ip": "d",
            "dest_port": 8080, "protocol": "TCP", "sensor": sensor, "in_iface": "eth0", "interfaces": ["eth0"], "hop_alerts": 0}


def history(attack_from=None, attack_to=None, model="m.joblib"):
    out = []
    for t in range(-60, 200, 5):
        flagged = attack_from is not None and attack_from <= t <= attack_to
        out.append(poll(NOW + t, 0.8 if flagged else 0.2, 60.0 if flagged else 500.0, model, "mitigating" if flagged else "normal"))
    return out


def record(alerts, hist, series=None, now=NOW + 400, ml_available=True):
    """A real incident record, built by the unchanged correlation code."""
    groups, _ = incidents.plan(alerts, hist)
    return incidents.assemble(groups[0], None, hist, series, now, ml_available=ml_available, **KW), groups[0]["alerts"]


# ------------------------------------------------------------------ detector polls
def test_polls_round_trip_exactly_and_a_gap_stays_a_gap(tmp_path):
    store = make_store(tmp_path)
    for ts in (NOW, NOW + 5, NOW + 10, NOW + 100, NOW + 105):  # the engine was down between +10 and +100
        store.save_poll(poll(ts))
    loaded = store.load_polls(NOW - 1, 100, "m.joblib")
    assert [p["ts"] for p in loaded] == [NOW, NOW + 5, NOW + 10, NOW + 100, NOW + 105]  # nothing filled in
    assert loaded[0]["features"] == {"request_rate": 9.0, "established_connections": 0.0} and loaded[0]["state"] == "normal"


def test_saving_the_same_poll_twice_does_not_duplicate_it(tmp_path):
    store = make_store(tmp_path)
    store.save_poll(poll(NOW))
    store.save_poll(poll(NOW, conf=0.9))
    assert [p["confidence"] for p in store.load_polls(0, 10, "m.joblib")] == [0.9]


def test_polls_scored_by_another_model_are_not_restored(tmp_path):
    store = make_store(tmp_path)
    store.save_poll(poll(NOW, model="model.joblib"))
    store.save_poll(poll(NOW + 5, model="model.candidate.joblib"))
    store.save_poll(poll(NOW + 10, model=None))
    assert [p["ts"] for p in store.load_polls(0, 10, "model.candidate.joblib")] == [NOW + 5]
    assert [p["ts"] for p in store.load_polls(0, 10, None)] == [NOW + 10]


def test_load_returns_the_newest_polls_within_the_limit_oldest_first(tmp_path):
    store = make_store(tmp_path)
    for i in range(10):
        store.save_poll(poll(NOW + i))
    assert [p["ts"] for p in store.load_polls(0, 3, "m.joblib")] == [NOW + 7, NOW + 8, NOW + 9]


def test_poll_retention_by_age_and_by_row_count(tmp_path):
    store = make_store(tmp_path, clock_now=NOW + 100_000, poll_retention_s=86_400, max_polls=3)
    for ts in (NOW, NOW + 20_000, NOW + 30_000, NOW + 90_000, NOW + 95_000, NOW + 99_000):
        store.save_poll(poll(ts))
    result = store.prune()
    assert [p["ts"] for p in store.load_polls(0, 10, "m.joblib")] == [NOW + 90_000, NOW + 95_000, NOW + 99_000]
    assert result["polls_deleted"] == 3


# ------------------------------------------------------------------ incidents: restart, duplicates, evidence
def test_regrouped_incident_after_a_restart_updates_the_stored_one_instead_of_duplicating(tmp_path):
    store = make_store(tmp_path)
    first, alerts = record([alert(NOW + 12), alert(NOW + 22), alert(NOW + 32)], history(0, 60))
    store.reconcile([(first, alerts)])
    # After a restart the earliest alert has aged out of the EVE history, so the regrouped start (and id) differs.
    again, alerts2 = record([alert(NOW + 22), alert(NOW + 32), alert(NOW + 42)], history(0, 60))
    assert again["id"] != first["id"]
    stored = store.reconcile([(again, alerts2)])
    assert len(stored) == 1 and stored[0]["id"] == first["id"]
    assert store.stats()["incident_alerts"] == 4  # 12, 22, 32, 42: replayed alerts were not stored twice


def test_replaying_the_same_evidence_is_a_no_op(tmp_path):
    store = make_store(tmp_path)
    rec, alerts = record([alert(NOW + 12), alert(NOW + 22)], history(0, 60))
    for _ in range(3):
        store.reconcile([(rec, alerts)])
    assert store.stats()["incidents"] == 1 and store.stats()["incident_alerts"] == 2


def test_different_types_and_separate_bursts_stay_separate_incidents(tmp_path):
    store = make_store(tmp_path)
    http, a1 = record([alert(NOW + 12)], history(0, 60))
    udp, a2 = record([alert(NOW + 12, sid=1000003, sensor="udp")], history(0, 60))
    later, a3 = record([alert(NOW + 12 + 300)], history(0, 60))
    stored = store.reconcile([(http, a1), (udp, a2), (later, a3)])
    assert sorted((r["attack_type"], int(r["start"] - NOW)) for r in stored) == [("http_flood", 12), ("http_flood", 312), ("udp_flood", 12)]


def test_a_detector_episode_whose_alerts_have_aged_out_does_not_become_a_second_incident(tmp_path):
    """The bug the Docker restart test found: after a restart the EVE backfill no longer reached the old alerts,
    the restored detector history still showed the episode, and it was recorded as an 'ML only' duplicate."""
    hist = history(0, 60)
    rec, alerts = record([alert(NOW + 12), alert(NOW + 22), alert(NOW + 32)], hist)
    store = make_store(tmp_path, clock_now=rec["end"] + FREEZE_AFTER_S + 1)
    store.reconcile([(rec, alerts)])
    _, lone = incidents.plan([], hist)  # restart: no Suricata alerts left, the detector history is back
    assert len(lone) == 1
    ml_only = incidents.assemble(None, lone[0], hist, None, NOW + 400, **KW)
    stored = store.reconcile([(ml_only, [])])
    assert len(stored) == 1 and stored[0]["attack_type"] == "http_flood"


def test_a_genuine_ml_only_episode_elsewhere_is_still_recorded(tmp_path):
    hist = history(0, 60) + [poll(NOW + 600 + i * 5, 0.8, 60.0, "m.joblib", "mitigating") for i in range(14)]
    rec, alerts = record([alert(NOW + 12)], history(0, 60))
    store = make_store(tmp_path)
    store.reconcile([(rec, alerts)])
    _, lone = incidents.plan([alert(NOW + 12)], hist)
    ml_only = incidents.assemble(None, lone[0], hist, None, NOW + 1000, **KW)
    assert len(store.reconcile([(ml_only, [])])) == 2


def test_an_open_ml_only_incident_is_dropped_when_suricata_alerts_later_explain_it(tmp_path):
    hist = history(0, 60)
    _, lone = incidents.plan([], hist)
    store = make_store(tmp_path)
    store.reconcile([(incidents.assemble(None, lone[0], hist, None, NOW + 80, **KW), [])])
    assert store.recent()[0]["attack_type"] is None
    rec, alerts = record([alert(NOW + 12), alert(NOW + 22)], hist, now=NOW + 80)
    stored = store.reconcile([(rec, alerts)])
    assert [r["attack_type"] for r in stored] == ["http_flood"]


def test_a_closed_incident_is_frozen_and_served_as_stored_even_if_its_evidence_is_gone(tmp_path):
    rec, alerts = record([alert(NOW + 12), alert(NOW + 22)], history(0, 60), series=[(NOW + d, 10.0 if d < 0 else 120.0) for d in range(-150, 60, 5)])
    assert rec["metrics"]["state"] == "elevated" and rec["detectors"]["ml"]["state"] == "flagged"
    store = make_store(tmp_path, clock_now=rec["end"] + FREEZE_AFTER_S + 1)
    stored = store.reconcile([(rec, alerts)])
    assert stored[0]["source"] == "stored" and store.stats()["frozen_incidents"] == 1
    # Later, after a restart with no alerts, no detector history and no Prometheus data at all:
    poorer, _ = record([alert(NOW + 12), alert(NOW + 22)], [], series=None)
    assert poorer["detectors"]["ml"]["state"] == "no_data"
    again = store.reconcile([(poorer, alerts)])
    assert again[0]["detectors"]["ml"]["state"] == "flagged" and again[0]["metrics"]["state"] == "elevated"  # not rewritten
    assert again[0]["source"] == "stored" and store.reconcile([])[0]["id"] == rec["id"]  # and it survives with no live data


def test_an_open_incident_never_loses_richer_evidence_to_a_poorer_recompute(tmp_path):
    store = make_store(tmp_path)
    rich, alerts = record([alert(NOW + 12), alert(NOW + 22)], history(0, 60))
    store.reconcile([(rich, alerts)])
    poor, poor_alerts = record([alert(NOW + 12), alert(NOW + 22), alert(NOW + 32)], [])  # detector history missing after a restart
    assert information(poor) < information(rich)
    (stored,) = store.reconcile([(poor, poor_alerts)])
    assert stored["detectors"]["ml"]["state"] == "flagged" and stored["assessment"] == "corroborated"
    assert store.stats()["incident_alerts"] == 3  # the new alert is still recorded as evidence


def test_a_richer_recompute_replaces_the_stored_open_incident(tmp_path):
    store = make_store(tmp_path)
    poor, alerts = record([alert(NOW + 12)], [])
    store.reconcile([(poor, alerts)])
    rich, alerts2 = record([alert(NOW + 12), alert(NOW + 22)], history(0, 60))
    (stored,) = store.reconcile([(rich, alerts2)])
    assert stored["detectors"]["ml"]["state"] == "flagged" and stored["detectors"]["suricata"]["alerts"] == 2


def test_missing_signals_are_stored_as_no_data_never_filled_in(tmp_path):
    rec, alerts = record([alert(NOW + 12)], [])
    store = make_store(tmp_path, clock_now=rec["end"] + FREEZE_AFTER_S + 1)
    (stored,) = store.reconcile([(rec, alerts)])
    assert stored["detectors"]["ml"]["state"] == "no_data" and stored["metrics"]["state"] == "no_data"
    assert stored["mitigation"]["samples"] == 0 and stored["mitigation"]["cap_lowered"] is None
    assert stored["assessment"] == "suricata_ml_unavailable"


def test_status_is_recomputed_when_read_not_taken_from_the_stored_copy(tmp_path):
    rec, alerts = record([alert(NOW + 12)], history(0, 60), now=NOW + 15)
    assert rec["status"] == "active"
    store = make_store(tmp_path, clock_now=NOW + 15)
    assert store.reconcile([(rec, alerts)])[0]["status"] == "active"
    store._clock = lambda: NOW + 1000  # the engine was down for a long time
    assert store.recent()[0]["status"] == "closed"
    assert store.freeze_stale() == 1 and store.recent()[0]["source"] == "stored"


def test_get_returns_the_incident_with_its_supporting_alerts_in_order(tmp_path):
    store = make_store(tmp_path)
    rec, alerts = record([alert(NOW + 32), alert(NOW + 12), alert(NOW + 22)], history(0, 60))
    (stored,) = store.reconcile([(rec, alerts)])
    full = store.get(stored["id"])
    assert [round(a["ts"] - NOW) for a in full["alerts"]] == [12, 22, 32] and store.get("nope") is None


def test_stored_alerts_per_incident_are_capped(tmp_path):
    store = make_store(tmp_path)
    alerts = [alert(NOW + 12 + i * 0.01, src=f"10.0.{i // 250}.{i % 250}") for i in range(MAX_ALERTS_PER_INCIDENT + 50)]
    rec, _ = record(alerts[:5], history(0, 60))
    store.reconcile([(rec, alerts)])
    assert store.stats()["incident_alerts"] == MAX_ALERTS_PER_INCIDENT


def test_incident_retention_by_age_and_count_removes_their_alerts_too(tmp_path):
    store = make_store(tmp_path, clock_now=NOW + 10 * 86_400, incident_retention_s=7 * 86_400, max_incidents=2)
    for i, off in enumerate((12, 100_000, 400_000, 700_000, 800_000)):
        rec, alerts = record([alert(NOW + off)], history(0, 60), now=NOW + off + 400)
        store.reconcile([(rec, alerts)])
    store.prune()
    stats = store.stats()
    assert stats["incidents"] == 2 and stats["incident_alerts"] == 2
    assert [round(r["start"] - NOW) for r in store.recent()] == [800_000, 700_000]


# ------------------------------------------------------------------ failure handling
def test_an_unusable_location_disables_persistence_without_raising(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    store = StateStore(blocker / "state.db")
    assert store.ok is False and store.error
    store.save_poll(poll(NOW))
    assert store.load_polls(0, 10) == [] and store.reconcile([]) is None and store.get("x") is None
    assert store.prune() == {"polls_deleted": 0, "incidents_deleted": 0} and store.stats()["enabled"] is False


def test_a_damaged_database_is_moved_aside_and_replaced_not_deleted(tmp_path):
    path = tmp_path / "state.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    store = StateStore(path)
    assert store.ok and "recovered" in store.error
    assert len(list(tmp_path.glob("state.db.corrupt-*"))) == 1  # kept for inspection
    store.save_poll(poll(NOW))
    assert len(store.load_polls(0, 10, "m.joblib")) == 1


def test_data_survives_closing_and_reopening_the_file(tmp_path):
    store = make_store(tmp_path)
    store.save_poll(poll(NOW))
    rec, alerts = record([alert(NOW + 12)], history(0, 60))
    store.reconcile([(rec, alerts)])
    store.close()
    reopened = make_store(tmp_path)
    assert len(reopened.load_polls(0, 10, "m.joblib")) == 1 and reopened.recent()[0]["id"] == rec["id"]


# ------------------------------------------------------------------ the engine: restore on start
def test_the_engine_restores_polls_for_the_current_model_and_recent_mitigation_actions(tmp_path, monkeypatch):
    import engine

    db = tmp_path / "state.db"
    seed = StateStore(db)
    now = time.time()
    for i in range(6):
        seed.save_poll(poll(now - 600 + i * 5, model="model.candidate.joblib"))
    seed.save_poll(poll(now - 300, model="model.joblib"))  # another model: must not come back
    seed.save_poll(poll(now - RESTORE_AGE, model="model.candidate.joblib"))  # older than the restore window
    seed.close()
    log = tmp_path / "mitigation_log.jsonl"
    log.write_text("\n".join([json.dumps({"ts": now - 50, "new_threshold": 40.0, "confidence": 0.9}), "garbage",
                              json.dumps({"ts": now - 40, "new_threshold": 30.0, "confidence": 0.9})]), encoding="utf-8")
    monkeypatch.setattr(engine, "STATE_DB_PATH", db)
    monkeypatch.setattr(engine, "MITIGATION_LOG_PATH", log)
    monkeypatch.setattr(engine, "MODEL_PATH", Path("model.candidate.joblib"))
    monkeypatch.setattr(engine, "_model", object())
    monkeypatch.setattr(engine, "state_store", None)
    monkeypatch.setattr(engine, "_ml_history", type(engine._ml_history)(maxlen=4320))
    monkeypatch.setitem(engine._state, "recent_actions", [])
    asyncio.run(engine._open_state_store())
    assert engine.state_store is not None and engine.state_store.ok
    assert len(engine._ml_history) == 6 and all(p["model"] == "model.candidate.joblib" for p in engine._ml_history)
    assert [a["new_threshold"] for a in engine._state["recent_actions"]] == [40.0, 30.0]
    engine.state_store.close()


RESTORE_AGE = 7 * 3600


def test_a_missing_database_location_leaves_the_engine_running_in_memory(tmp_path, monkeypatch):
    import engine

    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(engine, "STATE_DB_PATH", blocker / "state.db")
    monkeypatch.setattr(engine, "state_store", None)
    asyncio.run(engine._open_state_store())
    assert engine.state_store is None  # nothing raised; incidents are served from memory


def test_incidents_endpoint_survives_a_simulated_restart_with_evidence_intact(tmp_path, monkeypatch):
    import engine
    from fastapi.testclient import TestClient
    from suricata_alerts import AlertStore

    now = time.time()
    eve = tmp_path / "eve.json"

    def write_alerts(offsets):
        lines = []
        for off in offsets:
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(now + off))
            lines.append(json.dumps({"timestamp": stamp, "event_type": "alert", "in_iface": "eth1", "src_ip": "172.19.0.3",
                                     "src_port": 1, "dest_ip": "172.19.0.2", "dest_port": 8080, "proto": "TCP",
                                     "alert": {"signature_id": 1000001, "signature": "SENTINEL LAB: possible HTTP flood",
                                               "severity": 2, "action": "allowed"}}))
        eve.write_text("\n".join(lines) + "\n", encoding="utf-8")

    async def fake_series(kind, start, end):
        return [(start + d, 10.0 if d < 0 else 120.0) for d in range(-150, 60, 5)]

    def boot(history_polls):
        store = AlertStore(eve)
        store.poll()
        monkeypatch.setattr(engine, "suricata_store", store)
        monkeypatch.setattr(engine, "_eve_files", lambda: [eve])
        monkeypatch.setattr(engine, "_ml_history", type(engine._ml_history)(history_polls, maxlen=4320))
        monkeypatch.setattr(engine, "_metric_series", fake_series)
        monkeypatch.setattr(engine, "_model", object())

    # an attack that finished four minutes ago
    write_alerts([-300, -290, -280])
    polls = [{**poll(now - 320 + i * 5, 0.8, 60.0, "m", "mitigating"), "blocked_rps": 3.0} for i in range(14)]
    monkeypatch.setattr(engine, "state_store", StateStore(tmp_path / "state.db"))
    boot(polls)
    client = TestClient(engine.app)
    before = client.get("/incidents").json()
    (inc,) = before["incidents"]
    assert inc["assessment"] == "corroborated" and inc["source"] == "stored" and before["inputs"]["persistence"]["enabled"]

    # restart: new objects, the EVE history has aged out, the in-memory detector history is gone
    engine.state_store.close()
    monkeypatch.setattr(engine, "state_store", StateStore(tmp_path / "state.db"))
    eve.write_text("", encoding="utf-8")
    boot([])
    after = client.get("/incidents").json()
    (restored,) = after["incidents"]
    assert restored["id"] == inc["id"] and restored["source"] == "stored"
    assert restored["detectors"]["ml"]["state"] == "flagged" and restored["metrics"]["state"] == "elevated"
    assert restored["mitigation"]["cap_lowered"] is True and restored["evidence"] == inc["evidence"]
    detail = client.get(f"/incidents/{inc['id']}").json()
    assert len(detail["alerts"]) == 3 and client.get("/incidents/nope").status_code == 404
    engine.state_store.close()
