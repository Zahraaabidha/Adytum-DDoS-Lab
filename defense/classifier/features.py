"""Feature extraction shared by classifier training and live inference.

Features are deliberately simple and directly tied to signals a real DDoS
defense system would have available: request rate, connection duration,
and packet/request inter-arrival timing (jitter), plus error rate.
"""
from dataclasses import dataclass

FEATURE_NAMES = [
    "request_rate",
    "avg_connection_duration",
    "inter_arrival_std",
    "error_rate",
    "active_connections",
]


@dataclass
class FeatureWindow:
    request_rate: float  # requests/sec in the window
    avg_connection_duration: float  # seconds
    inter_arrival_std: float  # stddev of gaps between requests, seconds
    error_rate: float  # fraction of requests that errored
    active_connections: float  # in-flight/open connections

    def as_vector(self):
        return [
            self.request_rate,
            self.avg_connection_duration,
            self.inter_arrival_std,
            self.error_rate,
            self.active_connections,
        ]


def features_from_events(events: list[dict], window_seconds: float) -> FeatureWindow:
    """Compute a FeatureWindow from a list of recorded SimEvent dicts
    (see attackers/common/recorder.py) that fall within one time window."""
    if not events:
        return FeatureWindow(0, 0, 0, 0, 0)

    timestamps = sorted(e["ts"] for e in events)
    gaps = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
    variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps) if gaps else 0.0
    inter_arrival_std = variance**0.5

    durations = [e["latency_ms"] / 1000.0 for e in events if e.get("latency_ms") is not None]
    avg_duration = sum(durations) / len(durations) if durations else 0.0

    error_count = sum(1 for e in events if e.get("status") and e["status"] >= 500)
    error_rate = error_count / len(events)

    request_rate = len(events) / window_seconds

    return FeatureWindow(
        request_rate=request_rate,
        avg_connection_duration=avg_duration,
        inter_arrival_std=inter_arrival_std,
        error_rate=error_rate,
        active_connections=float(len(events)),
    )
