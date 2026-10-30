"""Tests for the guarded mitigation policy (defense/mitigation.py) and its engine wiring."""
import json
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "defense"))

from mitigation import MITIGATING, NORMAL, GuardedPolicy  # noqa: E402

BASELINE = 500.0


def policy(**kwargs) -> GuardedPolicy:
    return GuardedPolicy(BASELINE, min_cap=20.0, fallback_cap=50.0, **kwargs)


def run(p: GuardedPolicy, polls: int, confidence: float, rate: float = 15.0, blocked: float = 0.0) -> list[float]:
    return [p.update(confidence, rate, blocked) for _ in range(polls)]


def test_ordinary_confidence_noise_never_lowers_the_cap():
    # The original linear mapping put legitimate traffic at confidence 0.25 on a 376 req/s cap.
    p = policy()
    rng = random.Random(1)
    caps = [p.update(rng.uniform(0.0, 0.49), rng.uniform(2, 30), 0.0) for _ in range(500)]
    assert set(caps) == {BASELINE} and p.state == NORMAL


def test_isolated_false_positives_are_ignored():
    p = policy()
    run(p, 20, 0.2)
    for _ in range(30):  # one or two flagged polls at a time, never three in a row
        assert run(p, 2, 0.9) == [BASELINE, BASELINE]
        assert run(p, 3, 0.2) == [BASELINE] * 3
    assert p.state == NORMAL


def test_sustained_attack_cuts_the_cap_in_bounded_steps_to_a_protective_level():
    p = policy()
    run(p, 40, 0.2, rate=15.0)  # normal traffic of about 15 req/s
    assert p.normal_load == pytest.approx(15.0, rel=0.05)
    before = run(p, 2, 0.8, rate=100.0)
    assert before == [BASELINE, BASELINE]  # persistence: not yet
    caps = [BASELINE] + run(p, 8, 0.8, rate=100.0, blocked=50.0)
    assert p.state == MITIGATING
    for previous, current in zip(caps, caps[1:]):
        assert current >= previous * (1 - p.max_step) - 1e-9  # each cut is bounded
    protective = p.headroom * p.normal_load
    assert caps[-1] == pytest.approx(protective, rel=0.02)  # lands where normal traffic still fits
    assert caps[-1] > 15.0 and caps[-1] < 100.0  # above legitimate load, below the flood


def test_cap_never_drops_below_the_floor():
    p = policy()
    run(p, 40, 0.2, rate=0.6)  # an idle system: 3 x 0.6 would be below the floor
    caps = run(p, 12, 0.9, rate=500.0, blocked=400.0)
    assert min(caps) == 20.0 and caps[-1] == 20.0


def test_without_any_normal_load_the_fallback_cap_applies():
    p = policy()
    caps = run(p, 10, 0.9, rate=300.0, blocked=100.0)
    assert caps[-1] == 50.0


def test_mitigation_holds_while_the_limiter_is_still_rejecting_even_if_confidence_falls():
    # Once the limit works the detector sees only the admitted traffic and calms down; the rejections say otherwise.
    p = policy()
    run(p, 40, 0.2)
    run(p, 6, 0.8, rate=100.0, blocked=50.0)
    assert p.state == MITIGATING
    caps = run(p, 30, 0.2, rate=45.0, blocked=60.0)  # confidence low, rejections high
    assert p.state == MITIGATING and caps[-1] == pytest.approx(p.headroom * 15.0, rel=0.05)


def test_hysteresis_confidence_hovering_between_exit_and_enter_does_not_release():
    p = policy()
    run(p, 40, 0.2)
    run(p, 6, 0.8, rate=100.0, blocked=50.0)
    run(p, 40, 0.47, rate=40.0, blocked=0.0)  # above the exit threshold (0.45), below the flag threshold
    assert p.state == MITIGATING


def test_release_after_the_attack_stops_then_bounded_recovery_to_the_baseline():
    p = policy()
    run(p, 40, 0.2)
    run(p, 6, 0.8, rate=100.0, blocked=50.0)
    protective = p.limit
    polls_to_release = 0
    while p.state == MITIGATING:
        p.update(0.2, 15.0, 0.0)
        polls_to_release += 1
        assert polls_to_release < 50
    assert polls_to_release == p.exit_polls  # exactly the configured hysteresis, no sooner
    caps = run(p, 12, 0.2, rate=15.0)
    assert caps[0] <= max(protective * p.recover_factor, protective + 5) + 1e-9  # bounded rise
    assert all(b >= a for a, b in zip(caps, caps[1:])) and caps[-1] == BASELINE
    assert max(caps) <= BASELINE  # never overshoots


def test_a_new_attack_during_recovery_is_met_again():
    p = policy()
    run(p, 40, 0.2)
    run(p, 6, 0.8, rate=100.0, blocked=50.0)
    while p.state == MITIGATING:
        p.update(0.2, 15.0, 0.0)
    run(p, 2, 0.2, rate=15.0)  # partly recovered
    caps = run(p, 6, 0.8, rate=100.0, blocked=50.0)
    assert p.state == MITIGATING and caps[-1] < 100.0


def test_flagged_and_ambiguous_polls_do_not_pollute_the_estimate_of_normal_load():
    p = policy()
    run(p, 40, 0.2, rate=15.0)
    run(p, 2, 0.9, rate=500.0)  # the start of an attack, not yet confirmed
    run(p, 2, 0.47, rate=400.0)  # above the exit threshold: ambiguous, not "normal" either
    assert p.normal_load == pytest.approx(15.0)


def test_a_quiet_spell_does_not_shrink_the_protective_cap():
    # An average would decay toward the idle rate and put the cap on the floor; the recent peak does not.
    p = policy()
    run(p, 20, 0.2, rate=20.0)  # legitimate users at about 20 req/s
    run(p, 40, 0.2, rate=0.6)  # a quiet spell: 40 polls = 200 s
    assert p.normal_load == 20.0
    run(p, 8, 0.9, rate=200.0, blocked=100.0)
    assert p.limit == pytest.approx(p.headroom * 20.0)


def test_the_normal_load_peak_forgets_old_traffic_after_its_window():
    p = policy(normal_polls=10)
    run(p, 5, 0.2, rate=80.0)
    run(p, 15, 0.2, rate=5.0)  # 10 confirmed polls at 5 push the 80s out of the window
    assert p.normal_load == 5.0


def test_attack_ramp_polls_are_not_learned_as_normal_load():
    # An attack ramps up over a poll or two while confidence is still low. Those polls must not raise the cap's basis.
    p = policy()
    run(p, 40, 0.2, rate=15.0)
    assert p.normal_load == 15.0
    p.update(0.30, 40.0, 0.0)  # ramp: calm confidence, rising load
    p.update(0.40, 70.0, 0.0)
    assert p.normal_load == 15.0  # still pending, not yet normal
    run(p, 3, 0.8, rate=120.0, blocked=0.0)  # confidence crosses the threshold: the pending ramp polls are discarded
    assert p.state == MITIGATING and p.normal_load == 15.0
    run(p, 8, 0.8, rate=120.0, blocked=80.0)
    assert p.limit == pytest.approx(p.headroom * 15.0)  # not headroom x 70


def test_a_calm_poll_becomes_normal_load_only_after_confirm_polls_more_calm_polls():
    p = policy()
    p.update(0.2, 25.0, 0.0)
    for _ in range(p.confirm_polls):
        assert p.normal_load is None
        p.update(0.2, 3.0, 0.0)
    assert p.normal_load == 25.0  # confirmed by the polls that followed


def test_an_ambiguous_poll_discards_the_polls_waiting_for_confirmation():
    p = policy()
    run(p, 30, 0.2, rate=10.0)
    p.update(0.2, 90.0, 0.0)
    p.update(0.47, 90.0, 0.0)  # between exit and enter: ambiguous
    run(p, 10, 0.2, rate=10.0)
    assert p.normal_load == 10.0


def test_mitigation_can_be_made_inert():
    p = GuardedPolicy(BASELINE, min_cap=BASELINE)  # what MIN_RATE_LIMIT=baseline means
    assert set(run(p, 20, 0.95, rate=500.0, blocked=400.0)) == {BASELINE}


# ---------------------------------------------------------------- engine wiring

@pytest.fixture
def engine():
    import engine as module
    return module


def test_engine_uses_the_configured_policy(engine, monkeypatch):
    from classifier.live_features import LiveFeatures

    features = LiveFeatures(100.0, 0.005, 0.01, 0.0, 3.0, 3.0)
    monkeypatch.setattr(engine, "guard", GuardedPolicy(500.0, 20.0, fallback_cap=50.0))
    monkeypatch.setitem(engine._state, "threshold", 500.0)

    monkeypatch.setattr(engine, "MITIGATION_POLICY", "linear")
    assert engine.decide_threshold(0.6, features, 0.0) == pytest.approx(engine.adapt_threshold(0.6))
    monkeypatch.setattr(engine, "MITIGATION_POLICY", "guarded")
    assert engine.decide_threshold(0.6, features, 0.0) == 500.0  # one flagged poll: persistence, no cut yet


def test_engine_logs_the_policy_state_and_serves_reports(engine, tmp_path, monkeypatch):
    from classifier.live_features import LiveFeatures
    from fastapi.testclient import TestClient

    monkeypatch.setattr(engine, "FEATURE_LOG_PATH", tmp_path / "feature_log.jsonl")
    engine.log_features(LiveFeatures(1, 2, 3, 4, 5, 6), confidence=0.3, threshold=500.0)
    entry = json.loads((tmp_path / "feature_log.jsonl").read_text(encoding="utf-8"))
    assert entry["policy"] == engine.MITIGATION_POLICY and entry["state"] in (NORMAL, MITIGATING, None)

    client = TestClient(engine.app)
    assert client.get("/threshold").json()["policy"] == engine.MITIGATION_POLICY
    monkeypatch.setattr(engine, "MITIGATION_REPORT_PATH", tmp_path / "mitigation.json")
    assert client.get("/mitigation-report").json() == {"available": False}
    (tmp_path / "mitigation.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
    assert client.get("/mitigation-report").json() == {"available": True, "rows": []}
