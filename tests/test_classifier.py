"""Unit tests for the SENTINEL LAB detection engine's classifier logic.

These tests don't require Docker or a running lab -- they exercise the
feature-extraction and scoring logic directly against synthetic event data,
so they're fast enough to run in CI on every push.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "defense" / "classifier"))

from features import FEATURE_NAMES, FeatureWindow, features_from_events  # noqa: E402


def make_events(n: int, interval: float, latency_ms: float, error_every: int | None = None, start_ts: float = 0.0):
    events = []
    for i in range(n):
        status = 500 if error_every and i % error_every == 0 else 200
        events.append({"ts": start_ts + i * interval, "latency_ms": latency_ms, "status": status})
    return events


def test_features_from_events_empty():
    fw = features_from_events([], window_seconds=5.0)
    assert fw.request_rate == 0
    assert fw.error_rate == 0
    assert fw.as_vector() == [0, 0, 0, 0, 0]


def test_features_from_events_legit_traffic():
    # Legit traffic: modest rate, human-like jitter, low error rate.
    events = make_events(10, interval=0.5, latency_ms=50, error_every=None)
    fw = features_from_events(events, window_seconds=5.0)
    assert fw.request_rate == 2.0  # 10 events / 5s window
    assert fw.error_rate == 0.0
    assert fw.avg_connection_duration < 0.1


def test_features_from_events_attack_traffic():
    # Attack traffic: very high rate, near-zero jitter (bots fire in lockstep),
    # elevated error rate as the target struggles.
    events = make_events(500, interval=0.01, latency_ms=800, error_every=3)
    fw = features_from_events(events, window_seconds=5.0)
    assert fw.request_rate == 100.0  # 500 events / 5s window
    assert fw.error_rate > 0.2
    assert fw.avg_connection_duration > 0.5


def test_feature_vector_order_matches_names():
    fw = FeatureWindow(1, 2, 3, 4, 5)
    assert fw.as_vector() == [1, 2, 3, 4, 5]
    assert len(FEATURE_NAMES) == len(fw.as_vector())


def test_attack_features_are_distinguishable_from_legit():
    legit = features_from_events(make_events(10, interval=0.5, latency_ms=50), window_seconds=5.0)
    attack = features_from_events(make_events(500, interval=0.01, latency_ms=800, error_every=3), window_seconds=5.0)
    # The whole premise of the classifier: these two vectors must be well
    # separated on at least rate and error-rate for IsolationForest to work.
    assert attack.request_rate > legit.request_rate * 10
    assert attack.error_rate > legit.error_rate
