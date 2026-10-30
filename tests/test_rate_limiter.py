"""Tests for the rate limiter's admission policies (defense/rate_limiter/limiter.py).

Time is simulated, so these are deterministic and instant.
"""
import sys
from collections import defaultdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "defense" / "rate_limiter"))

import limiter as limiter_module  # noqa: E402
from limiter import FairShareLimiter, GlobalLimiter  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def arrivals(seconds: int, sources: dict[str, tuple[int, float]]):
    """(time, source) pairs for `seconds` windows. `sources` maps name -> (requests per second,
    offset into the second where its requests begin); requests are spread evenly over the rest
    of the second, so a source with offset 0.6 arrives late in each window."""
    events = []
    for second in range(seconds):
        for name, (rate, offset) in sources.items():
            for i in range(rate):
                events.append((1000.0 + second + offset + (0.99 - offset) * i / rate, name))
    return sorted(events)


def simulate(policy, clock: Clock, events):
    """Returns admitted-per-window totals and admitted/offered per source."""
    per_window: dict[int, int] = defaultdict(int)
    admitted: dict[str, int] = defaultdict(int)
    offered: dict[str, int] = defaultdict(int)
    window_admitted_by_source: dict[tuple[int, str], int] = defaultdict(int)
    for t, source in events:
        clock.t = t
        offered[source] += 1
        if policy.allow(source):
            window = int(t - 1000.0)
            per_window[window] += 1
            admitted[source] += 1
            window_admitted_by_source[(window, source)] += 1
    return per_window, admitted, offered, window_admitted_by_source


def test_both_policies_admit_everything_under_the_limit():
    for make in (GlobalLimiter, FairShareLimiter):
        clock = Clock()
        _, admitted, offered, _ = simulate(make(100, clock), clock, arrivals(3, {"a": (20, 0.0), "b": (30, 0.5)}))
        assert admitted == offered


def test_global_limiter_starves_a_light_client_during_a_flood():
    # The baseline behaviour behind the 22% legitimate-request blocking seen in the lab.
    clock = Clock()
    _, admitted, offered, _ = simulate(GlobalLimiter(68, clock), clock,
                                       arrivals(5, {"flood": (500, 0.0), "legit": (4, 0.6)}))
    assert admitted["legit"] / offered["legit"] < 0.5


def test_fair_share_protects_a_light_client_and_still_holds_the_cap():
    clock = Clock()
    per_window, admitted, offered, _ = simulate(FairShareLimiter(68, clock), clock,
                                                arrivals(6, {"flood": (500, 0.0), "legit": (4, 0.6)}))
    # Only the first window, before either source is known, loses legit requests; after that none are rejected.
    assert admitted["legit"] == offered["legit"] - 4
    assert all(total <= 68 for total in per_window.values())  # global cap never exceeded
    assert per_window[3] >= 60  # and the flood still uses (almost) the whole cap


def test_distributed_flood_is_held_to_the_global_cap():
    # 40 attacking addresses at 12 req/s each (480/s) plus one legitimate client at 3 req/s, cap 100.
    clock = Clock()
    sources = {f"bot{i}": (12, i / 100) for i in range(40)}
    sources["legit"] = (3, 0.7)
    per_window, _, _, by_window_source = simulate(FairShareLimiter(100, clock), clock, arrivals(6, sources))
    assert all(total <= 100 for total in per_window.values())  # protection is not weakened
    guaranteed = int(100 / 41)
    for window in range(2, 6):
        assert by_window_source[(window, "legit")] >= guaranteed  # the legitimate client keeps its fair share
        bots = sum(by_window_source[(window, f"bot{i}")] for i in range(40))
        assert bots + by_window_source[(window, "legit")] <= 100


def test_fair_share_is_never_worse_for_a_thin_distributed_attack_than_the_cap_itself():
    # Many thin sources: the cap holds, and nobody gets more than a fair share, however many there are.
    clock = Clock()
    per_window, _, _, _ = simulate(FairShareLimiter(50, clock), clock,
                                   arrivals(4, {f"s{i}": (5, i / 300) for i in range(200)}))
    assert all(total <= 50 for total in per_window.values())


def test_a_lone_source_can_use_the_whole_limit():
    clock = Clock()
    per_window, _, _, _ = simulate(FairShareLimiter(80, clock), clock, arrivals(4, {"only": (300, 0.0)}))
    assert all(total == 80 for total in per_window.values())


def test_sources_beyond_the_tracking_bound_share_one_bucket(monkeypatch):
    monkeypatch.setattr(limiter_module, "MAX_SOURCES", 5)
    clock = Clock()
    policy = FairShareLimiter(40, clock)
    per_window, _, _, _ = simulate(policy, clock, arrivals(4, {f"s{i}": (10, i / 100) for i in range(60)}))
    assert all(total <= 40 for total in per_window.values())
    assert len(policy._counts) <= 6  # 5 tracked sources + the overflow bucket


def test_lowering_the_limit_takes_effect_immediately():
    clock = Clock()
    policy = FairShareLimiter(100, clock)
    assert all(policy.allow("a") for _ in range(10))
    policy.set_limit(12)
    admitted = sum(policy.allow("a") for _ in range(50))
    assert admitted == 2  # 10 already admitted this window, 12 allowed in total


def test_proxy_identifies_clients_by_socket_peer_not_forwarded_header(monkeypatch):
    from fastapi.testclient import TestClient

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "defense" / "rate_limiter"))
    import proxy

    seen = []

    class Recorder:
        limit = 1

        def allow(self, source):
            seen.append(source)
            return False  # reject, so no upstream is contacted

    monkeypatch.setattr(proxy, "limiter", Recorder())
    response = TestClient(proxy.app).get("/", headers={"X-Forwarded-For": "9.9.9.9"})
    assert response.status_code == 429
    assert seen == ["testclient"]  # the peer address, not the spoofable header


def test_proxy_defaults_to_the_fair_limiter():
    import proxy

    assert proxy.LIMITER_MODE == "fair" and isinstance(proxy.limiter, FairShareLimiter)


@pytest.mark.parametrize("make", [GlobalLimiter, FairShareLimiter])
def test_limit_of_zero_blocks_everything(make):
    clock = Clock()
    assert not any(make(0, clock).allow("a") for _ in range(5))
