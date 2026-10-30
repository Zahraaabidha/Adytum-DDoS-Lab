"""Measures what the rate limiting actually did in controlled lab scenarios.

Scenario recordings are named `m_<config>_<scenario>`; the defense engine's feature
log (see engine.py) holds, every 5 seconds, the confidence it computed and the rate
limit it set. For each configuration and scenario this reports, from those two real
sources only:

* attack requests offered / blocked (answered 429) and the rate that got through
* legitimate requests blocked while the attack ran (or in total, for legitimate-only runs)
* the lowest and typical (median over the attack's second half) rate limit, and the seconds
  until it first fell below half the baseline
* the rate that got through in the attack's second half (after mitigation had time to act)
* the share of engine polls that flagged the traffic (false positives for legitimate runs)
* seconds from attack start to the first blocked request
* seconds after the attack stopped until the limit was back near the baseline

Scenarios: legit (legitimate traffic alone), flood (one source), dist (six sources),
floodL / distL (the same floods with legitimate traffic running at the same time) and
slowL (Slowloris with legitimate traffic: the rate limiter fronts HTTP only, so this shows what
a non-HTTP detection costs legitimate HTTP clients, not a mitigation).

Each row also records the engine's state and cap when the scenario began (`clean_start` is false
if the cap was still lowered by the previous scenario, which makes early blocking meaningless)
and how many requests were rejected before the engine had lowered the cap at all
(`blocked_before_engagement`: an initial burst above the baseline cap, not mitigation).

    python classifier/mitigation_report.py --output classifier/mitigation-comparison.json
"""
import argparse
import json
import re
import statistics
from datetime import datetime, timezone
from pathlib import Path

import train
from dataset import HTTP_RESPONSE_TYPES, RecordingInfo, discover_recordings, load_feature_log, requests_between

# Lab convention: which limiter and mitigation policy each configuration code stands for.
CONFIGS = {
    "gl": {"limiter": "global", "policy": "linear", "label": "global limiter + original linear policy"},
    "fl": {"limiter": "fair", "policy": "linear", "label": "fair limiter + original linear policy"},
    "fg": {"limiter": "fair", "policy": "guarded", "label": "fair limiter + guarded policy v1 (smoothed normal-load estimate)"},
    "fg2": {"limiter": "fair", "policy": "guarded", "label": "fair limiter + guarded policy v2 (peak normal-load estimate)"},
    "fgb": {"limiter": "fair", "policy": "guarded", "label": "guarded policy (estimator v2), original model.joblib"},
    "fgc": {"limiter": "fair", "policy": "guarded", "label": "guarded policy (estimator v2), candidate model, with override"},
    "fgd": {"limiter": "fair", "policy": "guarded", "label": "promoted default, plain docker compose (estimator v2: FAILED acceptance, see README)"},
    "fgf": {"limiter": "fair", "policy": "guarded", "label": "FINAL default: candidate model, guarded policy (estimator v3, headroom 6), fair limiter, plain docker compose"},
    "fh4": {"limiter": "fair", "policy": "guarded", "label": "estimator v3, MITIGATION_HEADROOM=4 (sweep)"},
    "fh6": {"limiter": "fair", "policy": "guarded", "label": "estimator v3, MITIGATION_HEADROOM=6 (sweep)"},
    "fge": {"limiter": "fair", "policy": "guarded", "label": "promoted default, plain docker compose, estimator v3 (ramp polls not learned as normal)"},
}
NAME = re.compile(r"^m_(?P<config>[a-z0-9]+)_(?P<scenario>legit|flood|dist|floodL|distL|slowL)(?:_(?P<suffix>\d+|legit\d*))?$")
FLAG_THRESHOLD = 0.5
WARMUP_SECONDS = 15.0
RECOVERY_FRACTION = 0.9
MAX_RECOVERY_SECONDS = 150.0
# A scenario run is at most a couple of minutes; a recording spanning much longer means the host was suspended
# or the clock jumped while it ran, and its rates and timings are meaningless.
MAX_RUN_SECONDS = 300.0


def _ratio(n: float, d: float) -> float:
    return n / d if d else 0.0


def first_block_offset(runs: list[RecordingInfo], start: float) -> float | None:
    first = None
    for info in runs:
        with open(info.path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("status") == 429 and (first is None or event["ts"] < first):
                    first = event["ts"]
    return None if first is None else round(first - start, 1)


def admitted_between(runs: list[RecordingInfo], start: float, end: float) -> int:
    """Requests with start <= ts <= end that were not answered 429."""
    return sum(requests_between(r, start, end)[0] - requests_between(r, start, end)[1] for r in runs)


def scenario_row(config: str, scenario: str, attack: list[RecordingInfo], legit: RecordingInfo | None,
                 log: list[dict], all_starts: list[float], baseline_limit: float) -> dict:
    row: dict = {"config": config, "scenario": scenario, "attack_sources": len(attack)}
    if attack:
        start = min(r.start_ts for r in attack)
        end = max(r.end_ts for r in attack)
    else:
        start, end = legit.start_ts, legit.end_ts
    seconds = max(end - start, 1e-9)
    row["seconds"] = round(seconds, 1)

    before = [e for e in log if e["ts"] <= start]
    if before and start - before[-1]["ts"] <= 30:
        row["start"] = {"cap_rps": before[-1]["threshold"], "state": before[-1].get("state"),
                        "clean": None if before[-1].get("state") is None
                        else before[-1].get("state") == "normal" and before[-1]["threshold"] >= 0.9 * baseline_limit}
    else:
        row["start"] = {"cap_rps": None, "state": None, "clean": None}

    if attack:
        offered = sum(r.events for r in attack)
        http = all(r.attack_type in HTTP_RESPONSE_TYPES for r in attack)
        if not http:  # slowloris / tcp / udp events have no HTTP status: nothing here is, or can be, blocked
            row["attack"] = {"http": False, "requests": offered, "offered_rps": offered / seconds}
        else:
            blocked = sum(r.blocked_events for r in attack)
            engaged_ts = next((e["ts"] for e in log if e["ts"] >= start and (e.get("state") == "mitigating"
                                                                              or e["threshold"] < 0.9 * baseline_limit)), None)
            early = 0 if engaged_ts is None else None
            if engaged_ts is not None:
                early = sum(requests_between(r, start, engaged_ts)[1] for r in attack)
            row["attack"] = {
                "http": True, "requests": offered, "blocked": blocked, "blocked_fraction": _ratio(blocked, offered),
                "offered_rps": offered / seconds, "admitted_rps": (offered - blocked) / seconds,
                "steady_admitted_rps": admitted_between(attack, start + seconds / 2, end) / (seconds / 2),
                "first_block_s": first_block_offset(attack, start),
                "blocked_before_engagement": blocked if engaged_ts is None else early,
            }
    if legit:
        requests, blocked = requests_between(legit, start, end)
        row["legit"] = {
            "requests": requests, "blocked": blocked, "blocked_fraction": _ratio(blocked, requests),
            "admitted_rps": (requests - blocked) / seconds,
            "steady_admitted_rps": admitted_between([legit], start + seconds / 2, end) / (seconds / 2),
        }

    during = [e for e in log if start <= e["ts"] <= end]
    steady = [e for e in during if e["ts"] >= start + WARMUP_SECONDS]
    limits = [e["threshold"] for e in during]
    second_half = [e["threshold"] for e in during if e["ts"] >= start + seconds / 2]
    engaged = next((e["ts"] - start for e in during if e["threshold"] < 0.5 * baseline_limit), None)
    row["limit"] = {
        "min_rps": min(limits, default=None),
        "typical_rps": statistics.median(second_half) if second_half else None,
        "below_half_baseline_s": None if engaged is None else round(max(engaged, 0.0), 1),
    }
    row["polls"] = len(steady)
    row["flagged_polls"] = sum(1 for e in steady if e["confidence"] >= FLAG_THRESHOLD)
    row["mitigating_polls"] = sum(1 for e in steady if e.get("state") == "mitigating")

    if attack:  # recovery: how long after the attack stopped until the limit was back near the baseline
        later = [s for s in all_starts if s > end + 1]
        horizon = min(end + MAX_RECOVERY_SECONDS, min(later) - 1 if later else end + MAX_RECOVERY_SECONDS)
        after = [e for e in log if end <= e["ts"] <= horizon]
        back = next((e["ts"] for e in after if e["threshold"] >= RECOVERY_FRACTION * baseline_limit), None)
        row["recovery"] = {
            "recovered": back is not None,
            "seconds": None if back is None else round(back - end, 1),
            "observed_seconds": round(horizon - end, 1),
        }
    return row


def build_report(infos: list[RecordingInfo], log: list[dict], baseline_limit: float,
                 exclude: dict[str, str] | None = None, configs: list[str] | None = None) -> dict:
    """`exclude` maps run name -> reason for runs the operator knows are invalid; they stay on disk
    and are listed in the report."""
    exclude = exclude or {}
    groups: dict[tuple[str, str], dict] = {}
    excluded_runs = []
    for info in infos:
        match = NAME.match(info.run)
        if not match or not info.usable or info.start_ts is None:
            continue
        if configs and match["config"] not in configs:
            continue
        if info.run in exclude:
            excluded_runs.append({"run": info.run, "reason": exclude[info.run]})
            continue
        if info.span_seconds > MAX_RUN_SECONDS:
            excluded_runs.append({"run": info.run, "reason": f"spans {info.span_seconds:.0f}s (more than {MAX_RUN_SECONDS:.0f}s): "
                                                             "the host was probably suspended while it ran"})
            continue
        group = groups.setdefault((match["config"], match["scenario"]), {"attack": [], "legit": None})
        if (match["suffix"] or "").startswith("legit") or (match["scenario"] == "legit" and match["suffix"] is None):
            group["legit"] = info
        else:
            group["attack"].append(info)
    starts = [i.start_ts for i in infos if i.start_ts is not None]
    order = {name: i for i, name in enumerate(["legit", "flood", "dist", "floodL", "distL", "slowL"])}
    rows = [
        scenario_row(config, scenario, g["attack"], g["legit"], log, starts, baseline_limit)
        for (config, scenario), g in sorted(groups.items(), key=lambda kv: (kv[0][1] not in order, order.get(kv[0][1], 0), kv[0][0]))
        if g["attack"] or g["legit"]
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_limit_rps": baseline_limit,
        "configs": {code: CONFIGS[code] for code in sorted({r["config"] for r in rows}) if code in CONFIGS},
        "rows": rows,
        "excluded_runs": excluded_runs,
    }


def main():
    parser = argparse.ArgumentParser(description="Measure rate-limiting behaviour in the controlled lab scenarios")
    parser.add_argument("--baseline-limit", type=float, default=500.0, help="the engine's baseline rate limit")
    parser.add_argument("--exclude", nargs="*", default=[], metavar="RUN", help="runs known to be invalid (listed in the report)")
    parser.add_argument("--configs", nargs="*", default=[], metavar="CODE", help="only report these configuration codes")
    parser.add_argument("--exclude-reason", default="excluded by the operator", help="why --exclude runs are invalid")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    infos = discover_recordings(train.RECORDINGS_DIR)
    log, _ = load_feature_log(train.FEATURE_LOG)
    report = build_report(infos, log, args.baseline_limit, {run: args.exclude_reason for run in args.exclude}, args.configs)
    if not report["rows"]:
        raise SystemExit("No m_<config>_<scenario> recordings found.")

    for excluded in report["excluded_runs"]:
        print(f"EXCLUDED {excluded['run']}: {excluded['reason']}")
    for row in report["rows"]:
        parts = [f"{row['config']:>2} {row['scenario']:<7}"]
        if "attack" in row and not row["attack"]["http"]:
            parts.append(f"attack NOT HTTP ({row['attack']['offered_rps']:.1f} events/s): not mitigated by the limiter")
        elif "attack" in row:
            a = row["attack"]
            parts.append(f"attack blocked {a['blocked_fraction']:6.1%} (admitted {a['admitted_rps']:6.1f}/s, "
                         f"steady {a['steady_admitted_rps']:6.1f}/s, offered {a['offered_rps']:7.1f}/s) first block {a['first_block_s']}s "
                         f"(before engagement: {a['blocked_before_engagement']})")
        if "legit" in row:
            parts.append(f"legit blocked {row['legit']['blocked']}/{row['legit']['requests']} "
                         f"({row['legit']['blocked_fraction']:.1%}, steady {row['legit']['steady_admitted_rps']:.1f}/s)")
        if row["start"]["clean"] is False:
            parts.append(f"UNCLEAN START (cap {row['start']['cap_rps']:.0f}, {row['start']['state']})")
        lim = row["limit"]
        if lim["min_rps"] is None:
            parts.append("NO ENGINE LOG SAMPLES in this window")
        else:
            parts.append(f"limit min {lim['min_rps']:.0f} typical {lim['typical_rps']:.0f} "
                         f"(<half baseline after {lim['below_half_baseline_s']}s)")
        parts.append(f"flagged {row['flagged_polls']}/{row['polls']}")
        if "recovery" in row:
            r = row["recovery"]
            parts.append(f"recovery {r['seconds']}s" if r["recovered"] else f"NOT recovered in {r['observed_seconds']}s")
        print(" | ".join(parts))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
