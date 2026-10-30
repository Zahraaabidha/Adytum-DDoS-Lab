"""Trains the SENTINEL LAB traffic classifier.

Fits an IsolationForest on the live feature vectors the defense engine logged
(`feature_log.jsonl`, see live_features.py) while legitimate-load runs were
active, so the model sees exactly the features and units it will score in
production. A sample is attributed to a run by the recording's time span.

    python classifier/train.py --legit-runs legit_run_a legit_run_b [--idle-windows START:END ...]

A quiet system is normal too, so time ranges with no traffic at all (epoch seconds) can be
added with --idle-windows; those windows are recorded in the model and never evaluated.
"""
import argparse
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from dataset import discover_recordings, feature_log_path, label_samples, load_feature_log, recordings_dir
from live_features import LIVE_FEATURE_NAMES
from scoring import feature_ranges

RECORDINGS_DIR = recordings_dir()
FEATURE_LOG = feature_log_path()
MODEL_PATH = Path(os.environ.get("MODEL_PATH", str(Path(__file__).resolve().parent / "model.joblib")))
MIN_TRAIN_SAMPLES = 20


def training_vectors(legit_runs: list[str], idle_windows: list[tuple[float, float]] | None = None) -> list[list[float]]:
    """Live feature vectors logged while each of `legit_runs` was running, plus idle samples
    (no run active) inside any of `idle_windows`."""
    infos = discover_recordings(RECORDINGS_DIR)
    by_run = {i.run: i for i in infos}
    # Only recordings whose own events say "legitimate_load" and that the target
    # actually answered may be used as training data.
    for run in legit_runs:
        info = by_run.get(run)
        if info is None:
            raise SystemExit(f"Cannot train on {run}: no recording with that name in {RECORDINGS_DIR}")
        if info.label != "normal" or not info.usable:
            raise SystemExit(f"Cannot train on {run}: {info.reason or f'labeled {info.label}, not legitimate traffic'}")

    entries, bad = load_feature_log(FEATURE_LOG, LIVE_FEATURE_NAMES)
    labeled, _ = label_samples(entries, infos, LIVE_FEATURE_NAMES)
    vectors = []
    for run in legit_runs:
        run_vectors = [s.vector for s in labeled if s.run == run]
        print(f"Training run {run}: {len(run_vectors)} live feature samples ({by_run[run].events} events recorded)")
        vectors.extend(run_vectors)
    for start, end in idle_windows or []:
        idle = [s.vector for s in labeled if s.run is None and start <= s.ts <= end]
        print(f"Idle window {start:.0f}-{end:.0f}: {len(idle)} live feature samples")
        vectors.extend(idle)
    if bad:
        print(f"Note: {bad} unparseable feature-log line(s) ignored")
    return vectors


def main():
    parser = argparse.ArgumentParser(description="Train SENTINEL LAB IsolationForest classifier")
    parser.add_argument(
        "--legit-runs", nargs="+", required=True, help="run_name(s) of legitimate-load recordings"
    )
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--idle-windows", nargs="*", default=[], metavar="START:END",
                        help="epoch-second ranges with no traffic to include as normal")
    args = parser.parse_args()

    idle_windows = [(float(a), float(b)) for a, b in (w.split(":") for w in args.idle_windows)]
    vectors = training_vectors(args.legit_runs, idle_windows)
    if len(vectors) < MIN_TRAIN_SAMPLES:
        raise SystemExit(
            f"Only {len(vectors)} live feature samples fall inside the given runs (need {MIN_TRAIN_SAMPLES}). "
            "Was the defense engine running, with FEATURE_LOG_PATH writable, while they were recorded?"
        )

    ranges = feature_ranges(vectors, LIVE_FEATURE_NAMES)
    for name, (low, high) in ranges.items():
        if low == high:
            print(f"Note: {name} is constant ({low}) in the training data, so the forest cannot use it "
                  "(the range guard still scores values above it). Record more varied legitimate traffic.")

    model = IsolationForest(n_estimators=200, contamination=args.contamination, random_state=42)
    model.fit(np.array(vectors))

    # `legit_runs` lets evaluate.py refuse to score the model on its own training data.
    joblib.dump({
        "model": model,
        "feature_names": LIVE_FEATURE_NAMES,
        "feature_ranges": ranges,  # lets scoring catch values beyond training
        "legit_runs": args.legit_runs,
        "idle_windows": idle_windows,
        "contamination": args.contamination,
        "samples": len(vectors),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }, MODEL_PATH)
    print(f"Trained on {len(vectors)} live feature samples from {len(args.legit_runs)} legitimate-load run(s).")
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
