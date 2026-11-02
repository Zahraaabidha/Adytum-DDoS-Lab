"""Guarded mitigation policy across an engine restart: what is saved, when it may be used again, and what happens to
an HTTP flood and to legitimate traffic when it is. Synthetic polls, no Docker."""
import math
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense"))

from mitigation import MITIGATING, NORMAL, GuardedPolicy  # noqa: E402
from policy_state import CAP_MAX_AGE_S, make_snapshot, plan_restore  # noqa: E402
from state_store import StateStore  # noqa: E402

NOW = 1_800_000_000.0
POLL = 5.0
CONFIG = {"baseline": 500.0, "min_cap": 20.0, "headroom": 6.0, "fallback_cap": 50.0, "normal_polls": 60,
          "poll_interval": POLL, "model": "model.candidate.joblib"}


def new_policy():
    return GuardedPolicy(500.0, 20.0, headroom=6.0, fallback_cap=50.0)


def learn_normal(policy, rate=10.0, polls=20):
    for _ in range(polls):
        policy.update(0.2, rate, 0.0)


def flood(policy, polls, rate=100.0, blocked=60.0):
    return [policy.update(0.9, rate, blocked) for _ in range(polls)]


def saved_mid_flood(age=10.0, normal=10.0):
    policy = new_policy()
    learn_normal(policy, normal)
    flood(policy, 8)
    assert policy.state == MITIGATING
    return policy, make_snapshot(policy, CONFIG, NOW - age)


# ------------------------------------------------------------------ the problem, reproduced
def test_without_restoring_a_restart_mid_flood_opens_the_limiter_and_loses_the_protective_cap():
    policy, _ = saved_mid_flood()
    protective = policy.protective_cap()
    assert protective == 60.0  # 6 x the legitimate peak of 10 req/s
    fresh = new_policy()
    first_polls = flood(fresh, 4)
    assert first_polls[:2] == [500.0, 500.0]  # fully open until three flagged polls have been seen
    assert fresh.protective_cap() == 50.0  # and the legitimate peak is forgotten: the fixed fallback


# ------------------------------------------------------------------ restoring
def test_restoring_mid_flood_keeps_the_cap_closed_from_the_first_poll():
    _, snap = saved_mid_flood(age=10.0)
    plan = plan_restore(snap, NOW, CONFIG)
    assert plan["mode"] == "full" and plan["state"] == MITIGATING
    restored = new_policy()
    restored.restore(plan["limit"], plan["state"], plan["recent_normal"])
    caps = flood(restored, 6)
    assert max(caps) <= plan["limit"] + 1e-9 and caps[0] < 500.0  # never opened up
    assert restored.protective_cap() == 60.0  # the learned legitimate peak survived, so legitimate traffic fits


def test_a_restored_cap_leaves_by_the_normal_rules_once_the_attack_is_over():
    _, snap = saved_mid_flood(age=10.0)
    plan = plan_restore(snap, NOW, CONFIG)
    restored = new_policy()
    restored.restore(plan["limit"], plan["state"], plan["recent_normal"])
    reference, _ = saved_mid_flood(age=10.0)

    def recovery_polls(policy):
        polls = 0
        while policy.limit < 0.9 * 500.0:
            policy.update(0.1, 10.0, 0.0)  # attack over: calm, nothing rejected
            polls += 1
            assert polls < 40
        return polls

    assert recovery_polls(restored) <= recovery_polls(reference) + 1  # restoring does not slow the recovery


def test_the_restored_policy_needs_fresh_polls_before_it_leaves_or_enters_mitigation():
    _, snap = saved_mid_flood(age=10.0)
    plan = plan_restore(snap, NOW, CONFIG)
    restored = new_policy()
    restored.restore(plan["limit"], plan["state"], plan["recent_normal"])
    assert restored._flagged == 0 and restored._calm == 0 and not restored._pending
    for _ in range(3):  # three calm polls are not enough to leave: four are needed, as always
        restored.update(0.1, 10.0, 0.0)
    assert restored.state == MITIGATING
    restored.update(0.1, 10.0, 0.0)
    assert restored.state == NORMAL


def test_a_stale_snapshot_never_restricts_legitimate_traffic():
    _, snap = saved_mid_flood(age=CAP_MAX_AGE_S + 30.0)
    plan = plan_restore(snap, NOW, CONFIG)
    assert plan["mode"] == "normal_only" and plan["limit"] == 500.0 and plan["state"] == NORMAL
    restored = new_policy()
    restored.restore(plan["limit"], plan["state"], plan["recent_normal"])
    assert restored.update(0.2, 10.0, 0.0) == 500.0  # the cap starts at the baseline
    assert restored.normal_load is not None  # but what was learned about legitimate load is still there


def test_each_remembered_poll_is_kept_only_while_it_is_still_inside_the_policy_memory():
    policy = new_policy()
    for rate in range(1, 41):  # 40 calm polls: rates 1..40, oldest first (the last 4 await confirmation)
        policy.update(0.2, float(rate), 0.0)
    held = make_snapshot(policy, CONFIG, NOW)["recent_normal"]
    assert len(held) == 36
    # 100 s of downtime: the newest entry is 100 s old, the 36th newest 100 + 35 * 5 = 275 s old: all still inside 300 s
    assert plan_restore(make_snapshot(policy, CONFIG, NOW - 100.0), NOW, CONFIG)["recent_normal"] == held
    # 250 s of downtime: only entries up to 300 s old survive, i.e. the newest 11
    assert plan_restore(make_snapshot(policy, CONFIG, NOW - 250.0), NOW, CONFIG)["recent_normal"] == held[-11:]
    # 300 s is the limit of the memory: nothing newer than that is left over, so nothing is restored
    assert plan_restore(make_snapshot(policy, CONFIG, NOW - 299.0), NOW, CONFIG)["recent_normal"] == held[-1:]


def test_snapshots_outside_the_policy_memory_or_from_the_future_are_discarded():
    _, old = saved_mid_flood(age=60 * POLL + 1)
    assert plan_restore(old, NOW, CONFIG)["mode"] == "none"
    _, future = saved_mid_flood(age=-5.0)
    assert plan_restore(future, NOW, CONFIG)["mode"] == "none" and "future" in plan_restore(future, NOW, CONFIG)["reason"]


def test_a_changed_model_or_setting_discards_the_snapshot():
    _, snap = saved_mid_flood()
    for change in ({"model": "model.joblib"}, {"headroom": 4.0}, {"baseline": 400.0}, {"fallback_cap": 30.0}, {"poll_interval": 10.0}):
        plan = plan_restore(snap, NOW, {**CONFIG, **change})
        assert plan["mode"] == "none" and "changed" in plan["reason"], change
    assert plan_restore({**snap, "version": 99}, NOW, CONFIG)["mode"] == "none"


def test_malformed_snapshots_fall_back_to_a_fresh_start():
    _, snap = saved_mid_flood()
    for bad in (None, {}, {**snap, "limit": math.nan}, {**snap, "limit": "high"}, {**snap, "recent_normal": [1, -3]},
                {**snap, "recent_normal": "x"}, {**snap, "saved_at": None}, {k: v for k, v in snap.items() if k != "state"}):
        assert plan_restore(bad, NOW, CONFIG)["mode"] == "none", bad


def test_restore_clamps_the_cap_into_the_policy_bounds():
    policy = new_policy()
    policy.restore(9999.0, NORMAL, [])
    assert policy.limit == 500.0
    policy.restore(0.1, MITIGATING, [])
    assert policy.limit == 20.0


def test_a_normal_state_with_a_recovering_cap_is_restored_and_keeps_climbing():
    policy = new_policy()
    learn_normal(policy)
    flood(policy, 8)
    for _ in range(4):
        policy.update(0.1, 10.0, 0.0)  # leaves mitigation; the cap starts climbing
    assert policy.state == NORMAL and policy.limit < 500.0
    plan = plan_restore(make_snapshot(policy, CONFIG, NOW - 10.0), NOW, CONFIG)
    assert plan["mode"] == "full" and plan["state"] == NORMAL
    restored = new_policy()
    restored.restore(plan["limit"], plan["state"], plan["recent_normal"])
    before = restored.limit
    assert restored.update(0.1, 10.0, 0.0) > before


# ------------------------------------------------------------------ storage
def test_the_policy_snapshot_round_trips_and_an_unreadable_one_is_ignored(tmp_path):
    store = StateStore(tmp_path / "state.db")
    assert store.load_policy() is None
    _, snap = saved_mid_flood()
    store.save_policy(snap)
    store.save_policy(snap)  # one row, replaced
    assert store.load_policy() == snap
    store._db.execute("UPDATE policy_state SET snapshot='not json'")
    store._db.commit()
    assert store.load_policy() is None
    store.close()


# ------------------------------------------------------------------ the engine
def test_the_engine_restores_the_policy_at_startup_and_reports_it(tmp_path, monkeypatch):
    import asyncio

    import engine
    from fastapi.testclient import TestClient

    guard = GuardedPolicy(engine.BASELINE_THRESHOLD, engine.GUARD_MIN_CAP, headroom=engine.GUARD_HEADROOM,
                          fallback_cap=engine.GUARD_FALLBACK_CAP)
    monkeypatch.setattr(engine, "guard", guard)
    monkeypatch.setattr(engine, "MITIGATION_POLICY", "guarded")
    monkeypatch.setattr(engine, "MODEL_PATH", Path("model.candidate.joblib"))
    monkeypatch.setattr(engine, "_model", object())
    monkeypatch.setattr(engine, "STATE_DB_PATH", tmp_path / "state.db")
    monkeypatch.setattr(engine, "state_store", None)
    monkeypatch.setattr(engine, "MITIGATION_LOG_PATH", tmp_path / "none.jsonl")
    monkeypatch.setattr(engine, "_ml_history", type(engine._ml_history)(maxlen=4320))
    monkeypatch.setitem(engine._state, "threshold", engine.BASELINE_THRESHOLD)

    # a previous run, flooded, saved 15 s ago
    old = GuardedPolicy(engine.BASELINE_THRESHOLD, engine.GUARD_MIN_CAP, headroom=engine.GUARD_HEADROOM,
                        fallback_cap=engine.GUARD_FALLBACK_CAP)
    learn_normal(old, 10.0)
    flood(old, 8)
    seed = StateStore(tmp_path / "state.db")
    seed.save_policy(make_snapshot(old, engine._policy_config(), time.time() - 15.0))
    seed.close()

    asyncio.run(engine._open_state_store())
    assert engine._state["threshold"] == old.limit < engine.BASELINE_THRESHOLD  # /threshold serves the restored cap at once
    assert guard.state == MITIGATING and guard.protective_cap() == 60.0
    health = TestClient(engine.app).get("/health").json()["policy_restore"]
    assert health["mode"] == "full" and health["state"] == MITIGATING and health["normal_polls"] > 0
    engine.state_store.close()


def test_the_engine_ignores_a_stale_or_foreign_snapshot_and_starts_at_the_baseline(tmp_path, monkeypatch):
    import asyncio

    import engine

    guard = GuardedPolicy(engine.BASELINE_THRESHOLD, engine.GUARD_MIN_CAP, headroom=engine.GUARD_HEADROOM,
                          fallback_cap=engine.GUARD_FALLBACK_CAP)
    monkeypatch.setattr(engine, "guard", guard)
    monkeypatch.setattr(engine, "MITIGATION_POLICY", "guarded")
    monkeypatch.setattr(engine, "MODEL_PATH", Path("model.candidate.joblib"))
    monkeypatch.setattr(engine, "_model", object())
    monkeypatch.setattr(engine, "STATE_DB_PATH", tmp_path / "state.db")
    monkeypatch.setattr(engine, "state_store", None)
    monkeypatch.setattr(engine, "MITIGATION_LOG_PATH", tmp_path / "none.jsonl")
    monkeypatch.setattr(engine, "_ml_history", type(engine._ml_history)(maxlen=4320))
    monkeypatch.setitem(engine._state, "threshold", engine.BASELINE_THRESHOLD)
    old = GuardedPolicy(engine.BASELINE_THRESHOLD, engine.GUARD_MIN_CAP, headroom=engine.GUARD_HEADROOM,
                        fallback_cap=engine.GUARD_FALLBACK_CAP)
    learn_normal(old, 10.0)
    flood(old, 8)
    seed = StateStore(tmp_path / "state.db")
    seed.save_policy(make_snapshot(old, {**engine._policy_config(), "model": "model.joblib"}, time.time() - 5.0))  # other model
    seed.close()
    asyncio.run(engine._open_state_store())
    assert engine._state["threshold"] == engine.BASELINE_THRESHOLD and guard.state == NORMAL
    assert engine.policy_restore_info["mode"] == "none"
    engine.state_store.close()
