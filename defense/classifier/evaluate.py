"""Evaluates the SENTINEL LAB classifier on live feature samples from runs it
was not trained on.

Inputs are the recordings (ground truth for what traffic ran when) and the
defense engine's feature log (the live feature vectors, with the engine's own
confidence and rate limit at the time). Each logged sample is labeled by the
run whose time span contains it (dataset.py); runs the model was trained on
are never scored. Traffic types and counts:

* **Offline evaluation** -- samples logged while mitigation was inert, so the
  features are unaffected by the engine's own rate limiting. They are re-scored
  with the trained model; per attack type that type's samples are positives and
  all held-out legitimate-run samples are negatives. Idle samples (no run
  active) are reported separately.
* **Live end-to-end** -- samples logged while mitigation was active and a
  model was loaded. These use the engine's own logged confidence and report
  how far the rate limit actually dropped and, for HTTP runs, how many
  requests were really answered 429.

    python classifier/evaluate.py --output classifier/evaluation.json
"""
import argparse
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib

import train
from dataset import (
    HTTP_RESPONSE_TYPES, IDLE, LEGIT_TYPE, RecordingInfo, discover_recordings, label_samples, load_feature_log,
    requests_between, split_by_usability,
)
from live_features import LIVE_FEATURE_NAMES
from scoring import attack_confidence

MODEL_PATH = Path(os.environ.get("MODEL_PATH", str(Path(__file__).resolve().parent / "model.joblib")))
DEFAULT_THRESHOLD = 0.5
LOW_SAMPLE = 10  # below this many samples a traffic type's metrics are too noisy to trust
SAMPLE_UNIT = "engine feature samples (one per 5s poll; the 15s rate windows overlap, so neighbours are correlated)"


@dataclass
class DetectionMetrics:
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    f1: float
    accuracy: float
    threshold: float


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_metrics(labels: list[bool], confidences: list[float], threshold: float = DEFAULT_THRESHOLD) -> DetectionMetrics:
    """`labels[i]` is True for an attack sample; a sample is predicted to be an
    attack when its confidence is >= `threshold`. Ratios with an empty
    denominator are reported as 0.0 rather than raising."""
    if len(labels) != len(confidences):
        raise ValueError("labels and confidences must be the same length")

    tp = fp = tn = fn = 0
    for is_attack, confidence in zip(labels, confidences):
        predicted_attack = confidence >= threshold
        if is_attack and predicted_attack:
            tp += 1
        elif is_attack:
            fn += 1
        elif predicted_attack:
            fp += 1
        else:
            tn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return DetectionMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        false_positive_rate=_ratio(fp, fp + tn),
        f1=_ratio(2 * precision * recall, precision + recall),
        accuracy=_ratio(tp + tn, tp + fp + tn + fn),
        threshold=threshold,
    )


def by_type_metrics(rows: list[dict], threshold: float) -> list[dict]:
    """Per attack type: that type's samples as positives against all legitimate-run samples."""
    normal = [r["confidence"] for r in rows if r["label"] == "normal" and r["attack_type"] != IDLE]
    result = []
    for attack_type in sorted({r["attack_type"] for r in rows if r["label"] == "attack"}):
        positives = [r["confidence"] for r in rows if r["attack_type"] == attack_type]
        metrics = compute_metrics([True] * len(positives) + [False] * len(normal), positives + normal, threshold)
        result.append({
            "attack_type": attack_type,
            "runs": len({r["run"] for r in rows if r["attack_type"] == attack_type}),
            "samples": len(positives),
            "flagged": metrics.true_positives,
            "low_sample": len(positives) < LOW_SAMPLE,
            "metrics": asdict(metrics),
        })
    return result


def _normal_summary(rows: list[dict], threshold: float, attack_type: str) -> dict:
    subset = [r for r in rows if r["attack_type"] == attack_type]
    return {"samples": len(subset), "false_positives": sum(1 for r in subset if r["confidence"] >= threshold)}


def _run_rows(rows: list[dict], infos: dict[str, RecordingInfo], threshold: float) -> list[dict]:
    result = []
    for run in sorted({r["run"] for r in rows if r["run"]}, key=lambda name: infos[name].start_ts or 0.0):
        subset = [r for r in rows if r["run"] == run]
        result.append({
            "run": run, "attack_type": infos[run].attack_type, "label": infos[run].label, "samples": len(subset),
            "flagged": sum(1 for r in subset if r["confidence"] >= threshold), "events": infos[run].events,
            "warnings": infos[run].warnings,
        })
    return result


def live_section(samples, infos: dict[str, RecordingInfo], threshold: float) -> dict:
    """End-to-end results from samples logged with mitigation active, using the engine's own confidence."""
    rows = [{"run": s.run, "attack_type": s.attack_type, "label": s.label, "confidence": s.confidence} for s in samples]
    by_type = by_type_metrics(rows, threshold)
    for entry in by_type:
        entry["mitigation"] = _mitigation_effect(samples, infos, entry["attack_type"])
    legit = _normal_summary(rows, threshold, LEGIT_TYPE)
    legit["mitigation"] = _mitigation_effect(samples, infos, LEGIT_TYPE)
    normal_rows = [r for r in rows if r["label"] == "normal" and r["attack_type"] != IDLE]
    attack_rows = [r for r in rows if r["label"] == "attack"]
    overall = compute_metrics(
        [r["label"] == "attack" for r in normal_rows + attack_rows], [r["confidence"] for r in normal_rows + attack_rows],
        threshold,
    )
    return {
        "samples": {"normal": len(normal_rows), "attack": len(attack_rows)},
        "metrics": asdict(overall),
        "normal": legit,
        "idle": _normal_summary(rows, threshold, IDLE),
        "by_type": by_type,
        "runs": _run_rows(rows, infos, threshold),
    }


def _mitigation_effect(samples, infos: dict[str, RecordingInfo], attack_type: str) -> dict:
    """How low the engine pushed the rate limit during these runs and, for HTTP runs, the share of requests it blocked."""
    subset = [s for s in samples if s.attack_type == attack_type]
    runs = {s.run for s in subset if s.run}
    effect: dict = {"min_threshold_rps": min((s.threshold for s in subset), default=None)}
    if attack_type in HTTP_RESPONSE_TYPES:
        requests = sum(infos[r].events for r in runs)
        blocked = sum(infos[r].blocked_events for r in runs)
        effect.update({"requests": requests, "blocked": blocked, "blocked_fraction": _ratio(blocked, requests)})
    return effect


MIN_OVERLAP_SECONDS = 10.0


def collateral(infos: list[RecordingInfo]) -> list[dict]:
    """Legitimate requests blocked while an attack ran at the same time.

    For each usable legitimate HTTP run that overlaps usable attack runs, per attack type: the legitimate
    run's requests (and how many were answered 429) during the time the attack runs were active. Measured
    from the recordings' own response codes, so it needs no feature samples.
    """
    result = []
    for legit in (i for i in infos if i.usable and i.label == "normal" and i.start_ts is not None):
        overlapping: dict[str, list[RecordingInfo]] = {}
        for other in infos:
            if not (other.usable and other.label == "attack" and other.start_ts is not None and other.end_ts is not None):
                continue
            # Only attack runs that actually ran alongside this legitimate run count.
            if min(legit.end_ts, other.end_ts) - max(legit.start_ts, other.start_ts) >= MIN_OVERLAP_SECONDS:
                overlapping.setdefault(other.attack_type or "unknown", []).append(other)
        for attack_type, runs in sorted(overlapping.items()):
            start = max(legit.start_ts, min(r.start_ts for r in runs))
            end = min(legit.end_ts, max(r.end_ts for r in runs))
            requests, blocked = requests_between(legit, start, end)
            result.append({
                "legit_run": legit.run, "attack_type": attack_type, "attack_runs": len(runs),
                "overlap_seconds": round(end - start, 1), "requests": requests, "blocked": blocked,
                "blocked_fraction": _ratio(blocked, requests),
            })
    return result


def main():
    parser = argparse.ArgumentParser(description="Evaluate the SENTINEL LAB classifier on live feature samples")
    parser.add_argument("--runs", nargs="+", help="only evaluate samples from these run names (default: every run)")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--output", type=Path, help="write the report as JSON to this path")
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        raise SystemExit(f"No trained model at {MODEL_PATH} -- run classifier/train.py first.")
    blob = joblib.load(MODEL_PATH)
    if blob.get("feature_names") != LIVE_FEATURE_NAMES:
        raise SystemExit(
            f"Model was trained on features {blob.get('feature_names')}, not the live features {LIVE_FEATURE_NAMES}. "
            "Retrain with classifier/train.py."
        )
    model = blob["model"]
    ranges = blob.get("feature_ranges")
    trained_on = blob.get("legit_runs", [])

    infos = discover_recordings(train.RECORDINGS_DIR)
    if args.runs:
        missing = sorted(set(args.runs) - {i.run for i in infos})
        if missing:
            raise SystemExit(f"Unknown run(s): {', '.join(missing)}")
        overlap = sorted(set(args.runs) & set(trained_on))
        if overlap:
            raise SystemExit(f"Refusing to evaluate on training data: {', '.join(overlap)}.")
    by_run = {i.run: i for i in infos}

    entries, bad = load_feature_log(train.FEATURE_LOG, LIVE_FEATURE_NAMES)
    samples, unlabeled = label_samples(entries, infos, LIVE_FEATURE_NAMES)
    idle_windows = blob.get("idle_windows", [])  # idle time the model was trained on is not evaluated
    held_out = [
        s for s in samples
        if s.run not in trained_on and (not args.runs or s.run is None or s.run in args.runs)
        and not (s.run is None and any(start <= s.ts <= end for start, end in idle_windows))
    ]
    offline = [s for s in held_out if not s.mitigation]
    live = [s for s in held_out if s.mitigation and s.model]

    rows = [
        {"run": s.run, "attack_type": s.attack_type, "label": s.label,
         "confidence": attack_confidence(model, s.vector, LIVE_FEATURE_NAMES, ranges)}
        for s in offline
    ]
    normal_rows = [r for r in rows if r["label"] == "normal" and r["attack_type"] != IDLE]
    attack_rows = [r for r in rows if r["label"] == "attack"]
    if not normal_rows:
        raise SystemExit("Need held-out legitimate-run samples logged with mitigation inert (none found).")
    if not attack_rows:
        raise SystemExit("Need attack-run samples logged with mitigation inert (none found).")

    overall = compute_metrics(
        [r["label"] == "attack" for r in normal_rows + attack_rows], [r["confidence"] for r in normal_rows + attack_rows],
        args.threshold,
    )
    types = by_type_metrics(rows, args.threshold)
    idle = _normal_summary(rows, args.threshold, IDLE)
    normal = _normal_summary(rows, args.threshold, LEGIT_TYPE)

    sampled_runs = {s.run for s in held_out if s.run}
    _, excluded = split_by_usability(infos, {run: "used for training" for run in trained_on})
    excluded_rows = [{"run": i.run, "events": i.events, "reason": i.reason} for i in excluded]
    for info in infos:
        if info.usable and info.run not in trained_on and info.run not in sampled_runs and (not args.runs or info.run in args.runs):
            excluded_rows.append({
                "run": info.run, "events": info.events,
                "reason": "no usable feature-log samples during this run (recorded before the engine's feature log, "
                          "or the engine was not running)",
            })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "trained_on": trained_on,
        "feature_names": LIVE_FEATURE_NAMES,
        "sample_unit": SAMPLE_UNIT,
        "samples": {"normal": len(normal_rows), "attack": len(attack_rows)},
        "metrics": asdict(overall),
        "normal": normal,
        "idle": idle,
        "by_type": types,
        "runs": _run_rows(rows, by_run, args.threshold),
        "excluded": excluded_rows,
        "collateral": collateral([i for i in infos if not args.runs or i.run in args.runs]),
        "unlabeled_samples": unlabeled,
        "unparseable_feature_log_lines": bad,
    }
    if live:
        report["live"] = live_section(live, by_run, args.threshold)

    print(f"Threshold {args.threshold}; model trained on: {', '.join(trained_on) or 'unknown'}")
    print(f"Offline evaluation: {len(normal_rows)} normal + {len(attack_rows)} attack samples (+ {idle['samples']} idle); "
          f"{len(excluded_rows)} recording(s) not scored:")
    for row in excluded_rows:
        print(f"  EXCLUDED {row['run']} ({row['events']} events): {row['reason']}")
    for row in report["runs"]:
        print(f"  used     {row['run']} [{row['attack_type']}]: {row['flagged']}/{row['samples']} samples flagged")
    print(f"  overall: precision={overall.precision:.3f} recall={overall.recall:.3f} FPR={overall.false_positive_rate:.3f} "
          f"F1={overall.f1:.3f}; legitimate falsely flagged {normal['false_positives']}/{normal['samples']}, "
          f"idle {idle['false_positives']}/{idle['samples']}")
    for t in types:
        m = t["metrics"]
        note = "  (LOW SAMPLE)" if t["low_sample"] else ""
        print(f"  {t['attack_type']:<15} samples={t['samples']:<4} flagged={t['flagged']:<4} precision={m['precision']:.3f} "
              f"recall={m['recall']:.3f} F1={m['f1']:.3f}{note}")
    for row in report["collateral"]:
        print(f"  collateral: {row['legit_run']} during {row['attack_type']} ({row['attack_runs']} run(s), "
              f"{row['overlap_seconds']}s): {row['blocked']}/{row['requests']} legitimate requests blocked "
              f"({row['blocked_fraction']:.1%})")
    if live:
        section = report["live"]
        print(f"Live end-to-end ({len(live)} samples, engine's own confidence and rate limit):")
        print(f"  legitimate: {section['normal']['false_positives']}/{section['normal']['samples']} flagged, "
              f"mitigation {section['normal']['mitigation']}")
        for t in section["by_type"]:
            print(f"  {t['attack_type']:<15} samples={t['samples']:<4} flagged={t['flagged']:<4} mitigation={t['mitigation']}")

    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
