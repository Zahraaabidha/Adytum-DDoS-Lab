"""Audits what a trained model was actually trained on.

Prints, for the model at MODEL_PATH: the legitimate runs and number of live
feature samples it was fit on, whether its feature names match the live
engine's, the spread of each feature in its training data (a feature that is
constant in training cannot be used by an IsolationForest), and how every
recording in the recordings directory is used.

    python classifier/audit.py
"""
import os
from pathlib import Path

import joblib
import numpy as np

import train
from dataset import discover_recordings, label_samples, load_feature_log
from live_features import LIVE_FEATURE_NAMES

MODEL_PATH = Path(os.environ.get("MODEL_PATH", str(Path(__file__).resolve().parent / "model.joblib")))


def main():
    blob = joblib.load(MODEL_PATH)
    trained_on = blob.get("legit_runs", [])
    names = blob.get("feature_names")
    print(f"Model: {MODEL_PATH}")
    print(f"  trained_at={blob.get('trained_at')} samples={blob.get('samples')} runs={trained_on}")
    print(f"  feature names match the live engine's: {names == LIVE_FEATURE_NAMES}")

    infos = discover_recordings(train.RECORDINGS_DIR)
    entries, bad = load_feature_log(train.FEATURE_LOG, LIVE_FEATURE_NAMES)
    wrong_keys = sum(1 for e in entries if set(e["features"]) != set(LIVE_FEATURE_NAMES))
    print(f"Feature log: {len(entries)} entries, {bad} unparseable, {wrong_keys} with feature names other than the live set")

    samples, unlabeled = label_samples(entries, infos, LIVE_FEATURE_NAMES)
    idle_windows = blob.get("idle_windows", [])
    vectors = np.array([s.vector for s in samples if s.run in trained_on or
                        (s.run is None and any(a <= s.ts <= b for a, b in idle_windows))])
    print(f"  contamination={blob.get('contamination')} idle_windows={idle_windows}")
    print(f"Training samples recomputed from the log: {len(vectors)} (model records {blob.get('samples')})")
    for run in trained_on:
        count = sum(1 for s in samples if s.run == run)
        info = next((i for i in infos if i.run == run), None)
        print(f"  {run}: {count} samples, {info.events if info else '?'} events recorded")
    if len(vectors):
        print("Training feature spread:")
        for i, name in enumerate(LIVE_FEATURE_NAMES):
            column = vectors[:, i]
            note = "  CONSTANT: the forest cannot split on it" if column.max() == column.min() else ""
            print(f"  {name:26} min={column.min():9.3f} max={column.max():9.3f} std={column.std():8.3f}{note}")

    print("Recordings:")
    per_run = {}
    for s in samples:
        if s.run:
            per_run[s.run] = per_run.get(s.run, 0) + 1
    for info in infos:
        if info.run in trained_on:
            role = "TRAINING"
        elif not info.usable:
            role = f"excluded ({info.reason})"
        elif per_run.get(info.run):
            role = f"evaluation ({per_run[info.run]} samples)"
        else:
            role = "not used (no feature-log samples)"
        print(f"  {info.run:34} {info.attack_type or '?':16} {role}")
    print(f"Unlabeled samples: {unlabeled}")


if __name__ == "__main__":
    main()
