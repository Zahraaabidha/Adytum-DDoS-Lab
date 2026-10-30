"""Attack-confidence scoring shared by the live engine and offline evaluation."""
import numpy as np

# An IsolationForest only splits inside the range it saw in training, so it scores
# a value far beyond that range about like the most extreme training sample, and it
# can never split on a feature that was constant in training. `range_excess` covers
# that gap: how far a value exceeds the training maximum, in units of the training
# range. The per-feature floor is the smallest change that means anything for that
# feature (one request/s, one connection, 0.1s of latency, 10 percentage points of
# errors) and keeps constant training features usable.
SPREAD_FLOORS = {
    "request_rate": 1.0,
    "avg_connection_duration": 0.1,
    "inter_arrival_std": 1.0,
    "error_rate": 0.1,
    "active_connections": 1.0,
    "established_connections": 1.0,
}
# Features where only an increase is anomalous. inter_arrival_std (1/request_rate)
# gets smaller under load, which request_rate already captures.
UPPER_ONLY_EXCLUDED = {"inter_arrival_std"}


def feature_ranges(vectors: list[list[float]], feature_names: list[str]) -> dict[str, list[float]]:
    """Per-feature [min, max] of the training vectors, stored in the model file."""
    matrix = np.array(vectors, dtype=float)
    return {name: [float(matrix[:, i].min()), float(matrix[:, i].max())] for i, name in enumerate(feature_names)}


def range_excess(vector: list[float], feature_names: list[str], ranges: dict[str, list[float]]) -> float:
    """Largest amount by which any feature exceeds its training maximum, in units of
    max(training range, floor). 0 when every feature is within what training saw."""
    worst = 0.0
    for value, name in zip(vector, feature_names):
        if name in UPPER_ONLY_EXCLUDED or name not in ranges:
            continue
        low, high = ranges[name]
        spread = max(high - low, SPREAD_FLOORS.get(name, 1.0))
        worst = max(worst, (value - high) / spread)
    return worst


def attack_confidence(model, vector: list[float], feature_names: list[str] | None = None,
                      ranges: dict[str, list[float]] | None = None) -> float:
    """Returns an attack-confidence score in [0, 1]. Higher = more anomalous.

    The IsolationForest score, or -- when training ranges are supplied -- the
    larger of that and the range-excess score excess/(1+excess), so a value far
    outside anything seen in training scores near 1 instead of near the boundary.
    """
    # IsolationForest.decision_function: higher = more normal. Flip + squash to [0,1].
    raw = model.decision_function(np.array([vector]))[0]
    confidence = 1.0 / (1.0 + np.exp(raw * 5))  # logistic squashing, tuned for typical score ranges
    if feature_names is not None and ranges:
        excess = range_excess(vector, feature_names, ranges)
        confidence = max(confidence, excess / (1.0 + excess))
    return float(np.clip(confidence, 0.0, 1.0))
