"""Trains the SENTINEL LAB traffic classifier.

Reads recorded simulation runs (attackers/recordings/*.jsonl -- both attack
runs and legitimate-load runs, including the legit "burst" control run) and
fits an IsolationForest to distinguish attack traffic from legitimate load,
using request-rate / connection-duration / packet-timing features.
"""
import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from features import FEATURE_NAMES, features_from_events

RECORDINGS_DIR = Path(
    os.environ.get(
        "RECORDINGS_DIR", str(Path(__file__).resolve().parent.parent.parent / "attackers" / "recordings")
    )
)
MODEL_PATH = Path(os.environ.get("MODEL_PATH", str(Path(__file__).resolve().parent / "model.joblib")))

WINDOW_SECONDS = 5.0


def load_events(run_name: str) -> list[dict]:
    path = RECORDINGS_DIR / f"{run_name}.jsonl"
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def windows_from_run(run_name: str, window_seconds: float = WINDOW_SECONDS):
    events = load_events(run_name)
    if not events:
        return []
    t0 = min(e["ts"] for e in events)
    t_max = max(e["ts"] for e in events)
    windows = []
    t = t0
    while t <= t_max:
        window_events = [e for e in events if t <= e["ts"] < t + window_seconds]
        windows.append(features_from_events(window_events, window_seconds))
        t += window_seconds
    return windows


def main():
    parser = argparse.ArgumentParser(description="Train SENTINEL LAB IsolationForest classifier")
    parser.add_argument(
        "--legit-runs", nargs="+", required=True, help="run_name(s) of legitimate-load recordings"
    )
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    all_windows = []
    for run in args.legit_runs:
        all_windows.extend(windows_from_run(run))

    if not all_windows:
        raise SystemExit("No training windows found -- record a legitimate-load run first.")

    X = np.array([w.as_vector() for w in all_windows])

    model = IsolationForest(n_estimators=200, contamination=args.contamination, random_state=42)
    model.fit(X)

    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, MODEL_PATH)
    print(f"Trained on {len(X)} windows from {len(args.legit_runs)} legitimate-load run(s).")
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
