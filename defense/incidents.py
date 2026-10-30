"""Unified incidents: Suricata alerts, Isolation Forest detections and Prometheus metrics in one record.

Advisory and read-only. Nothing here changes the rate limit, the classifier, the Suricata rules or the mitigation
policy; it only *describes* what the existing components reported.

Rules that keep it honest:

* Two independent detectors exist, Suricata and the Isolation Forest. Metrics are evidence, never a detector.
  An incident is "corroborated" only when both detectors flagged the same period. Time overlap is how the
  periods are matched, so the record says "coincided", never "caused".
* The Isolation Forest scores anomaly, not attack type, so it cannot confirm *which* attack Suricata named.
* Its flag must persist: `ML_MIN_RUN` consecutive flagged polls (the guarded policy's own `enter_polls`),
  because a single flagged poll happens by chance on ordinary traffic (about 8% of legitimate samples).
* A missing signal is "no_data", never "not flagged". Nothing is estimated.
* Severity is a plain rule over the agreement (see `severity`), not a score.
"""
from collections import defaultdict
from collections.abc import Sequence
from statistics import median

# Signature id -> attack type; kept in step with defense/suricata/*.rules (a test checks it).
SIGNATURE_TYPES = {1000001: "http_flood", 1000002: "slowloris", 1000003: "udp_flood", 1000004: "tcp_exhaustion"}
TITLES = {
    "http_flood": "HTTP flood", "slowloris": "Slowloris", "udp_flood": "UDP flood",
    "tcp_exhaustion": "TCP connection exhaustion", None: "Anomalous traffic (no Suricata alert)",
}
# The Prometheus series that shows each attack type, and the smallest rise (over its own baseline) worth calling
# "elevated". These are reporting floors for the evidence column, not detector thresholds.
METRICS = {
    "http_flood": ("sum(rate(target_http_requests_total[15s]))", "req/s", 20.0),
    "slowloris": ("sum(target_http_established_sockets)", "sockets", 20.0),
    "udp_flood": ("sum(rate(target_udp_packets_total[15s]))", "packets/s", 100.0),
    "tcp_exhaustion": ("sum(target_tcp_active_connections)", "connections", 50.0),
}
MIN_RATIO = 3.0  # peak must be at least this many times the baseline (and exceed it by the floor)

INCIDENT_GAP_S = 60.0  # alerts of the same type closer than this belong to one incident
ML_PAD_S = 20.0  # how far either side of the alerts a detector flag still counts as the same period
ML_MIN_RUN = 3  # consecutive flagged polls needed to call the detector "flagged"
ML_FLAGGED = 0.5  # the cut-off the evaluation and the guarded policy use
BASELINE_FROM_S, BASELINE_TO_S = 120.0, 30.0  # baseline = median over [start-120, start-30]
EVIDENCE_TAIL_S = 30.0

HTTP_TYPES = {"http_flood"}
# Which attack types the existing mitigation can act on.
RATE_BASED = {"http_flood"}


def attack_type(signature_id) -> str:
    return SIGNATURE_TYPES.get(signature_id, "unknown")


def group_alerts(alerts: Sequence[dict], gap: float = INCIDENT_GAP_S) -> list[dict]:
    """Suricata alerts (already deduplicated across interfaces) -> one skeleton per (attack type, burst)."""
    by_type: dict[str, list[dict]] = defaultdict(list)
    for alert in sorted(alerts, key=lambda a: a["ts"]):
        by_type[attack_type(alert["signature_id"])].append(alert)
    skeletons = []
    for kind, items in by_type.items():
        current: list[dict] = []
        for alert in items:
            if current and alert["ts"] - current[-1]["ts"] > gap:
                skeletons.append({"attack_type": kind, "alerts": current})
                current = []
            current.append(alert)
        if current:
            skeletons.append({"attack_type": kind, "alerts": current})
    for sk in skeletons:
        sk["start"], sk["end"] = sk["alerts"][0]["ts"], sk["alerts"][-1]["ts"]
    return skeletons


def _runs(flags: list[bool]) -> int:
    best = run = 0
    for flag in flags:
        run = run + 1 if flag else 0
        best = max(best, run)
    return best


def _peak_features(polls: Sequence[dict]) -> dict | None:
    """Highest value of each live feature over the polls, or None if the history carries no features."""
    withfeatures = [h["features"] for h in polls if h.get("features")]
    return {k: max(f[k] for f in withfeatures) for k in withfeatures[0]} if withfeatures else None


def ml_view(history: Sequence[dict], start: float, end: float) -> dict:
    """What the Isolation Forest said around [start, end] (padded). `no_data` if it scored nothing then."""
    polls = sorted((h for h in history if start - ML_PAD_S <= h["ts"] <= end + ML_PAD_S), key=lambda h: h["ts"])
    if not polls:
        return {"state": "no_data", "polls": 0, "flagged_polls": 0, "longest_run": 0, "peak_confidence": None,
                "features": None}
    flags = [h["confidence"] >= ML_FLAGGED for h in polls]
    run = _runs(flags)
    peak = max(polls, key=lambda h: h["confidence"])
    return {
        "state": "flagged" if run >= ML_MIN_RUN else "not_flagged",
        "polls": len(polls), "flagged_polls": sum(flags), "longest_run": run,
        "peak_confidence": peak["confidence"],
        "features": _peak_features(polls),
    }


def ml_episodes(history: Sequence[dict], poll_gap: float = 15.0) -> list[dict]:
    """Runs of at least `ML_MIN_RUN` consecutive flagged polls: [{start, end, polls}]."""
    episodes, current = [], []
    for h in sorted(history, key=lambda h: h["ts"]):
        if h["confidence"] >= ML_FLAGGED and (not current or h["ts"] - current[-1]["ts"] <= poll_gap):
            current.append(h)
            continue
        if len(current) >= ML_MIN_RUN:
            episodes.append({"start": current[0]["ts"], "end": current[-1]["ts"], "polls": len(current)})
        current = [h] if h["confidence"] >= ML_FLAGGED else []
    if len(current) >= ML_MIN_RUN:
        episodes.append({"start": current[0]["ts"], "end": current[-1]["ts"], "polls": len(current)})
    return episodes


def metric_window(kind: str, start: float, end: float) -> tuple[float, float] | None:
    """The time range of the Prometheus series needed as evidence, or None if the type has none."""
    if kind not in METRICS:
        return None
    return start - BASELINE_FROM_S, end + EVIDENCE_TAIL_S


def metric_view(kind: str, series: Sequence[tuple[float, float]] | None, start: float, end: float) -> dict:
    """Baseline versus peak of the type-specific series. `series` None means Prometheus gave nothing."""
    if kind not in METRICS:
        return {"state": "not_applicable", "metric": None}
    query, unit, floor = METRICS[kind]
    base = {"metric": query, "unit": unit}
    if not series:
        return {**base, "state": "no_data"}
    peak_values = [v for t, v in series if start - EVIDENCE_TAIL_S <= t <= end + EVIDENCE_TAIL_S]
    baseline_values = [v for t, v in series if start - BASELINE_FROM_S <= t <= start - BASELINE_TO_S]
    if not peak_values:
        return {**base, "state": "no_data"}
    peak = max(peak_values)
    if not baseline_values:
        return {**base, "state": "no_baseline", "baseline": None, "peak": peak, "ratio": None}
    baseline = median(baseline_values)
    ratio = peak / baseline if baseline > 0 else None
    elevated = peak - baseline >= floor and (baseline == 0 or peak >= MIN_RATIO * baseline)
    return {**base, "state": "elevated" if elevated else "not_elevated", "baseline": baseline, "peak": peak,
            "ratio": ratio}


def mitigation_view(kind: str | None, history: Sequence[dict], start: float, end: float, baseline_cap: float,
                    policy: str, current_cap: float) -> dict:
    """What the existing mitigation did around the incident. Reports; never decides."""
    window = [h for h in history if start <= h["ts"] <= end + 30.0]
    applicable = None if kind is None else kind in RATE_BASED
    view = {
        "applicable": applicable, "policy": policy, "baseline_cap_rps": baseline_cap, "current_cap_rps": current_cap,
        "samples": len(window), "min_cap_rps": None, "cap_lowered": None, "states_seen": [], "blocked_rps_peak": None,
    }
    # Judged 30 s before the first alert (an attack is already running about 10-20 s before its alert), so a cap
    # still low then is left over from an earlier incident rather than this incident's own mitigation.
    before = [h for h in history if h["ts"] <= start - 30.0]
    view["lowered_before_start"] = (before[-1]["threshold"] < baseline_cap - 0.5) if before else None
    if window:
        low = min(h["threshold"] for h in window)
        view.update(min_cap_rps=low, cap_lowered=low < baseline_cap - 0.5,
                    states_seen=sorted({h["state"] for h in window if h.get("state")}))
        blocked = [h["blocked_rps"] for h in window if h.get("blocked_rps") is not None]
        view["blocked_rps_peak"] = max(blocked) if blocked else None
    if applicable is False:
        view["note"] = ("The rate limiter only protects HTTP. This attack is detected, not mitigated; a lowered HTTP cap "
                        "is not protection against it.")
    elif applicable is None:
        view["note"] = "No attack type is known, so it is not known whether the HTTP limiter is relevant."
    return view


def severity(assessment: str, metrics_state: str) -> str:
    """high: both detectors flagged. medium: one detector flagged and the type's metric rose. Otherwise low."""
    if assessment == "corroborated":
        return "high"
    if metrics_state == "elevated":
        return "medium"
    return "low"


def _suricata_view(alerts: Sequence[dict]) -> dict:
    sources: dict[str, int] = defaultdict(int)
    for alert in alerts:
        sources[alert["src_ip"]] += 1
    return {
        "state": "flagged", "alerts": len(alerts), "sightings": sum(1 + a.get("hop_alerts", 0) for a in alerts),
        "signatures": sorted({a["signature"] for a in alerts}),
        "sensors": sorted({a.get("sensor", "?") for a in alerts}),
        "interfaces": sorted({i for a in alerts for i in a.get("interfaces", [])}),
        "sources": [{"ip": ip, "alerts": n} for ip, n in sorted(sources.items(), key=lambda kv: -kv[1])],
    }


def _caveats(kind: str | None, suricata: dict, ml: dict) -> list[str]:
    notes = ["Matched by attack type and by time window (no flow-level link): the signals coincided, which is not proof "
             "that one caused the other."]
    if ml["state"] != "no_data":
        notes.append("The Isolation Forest scores anomaly, not attack type: it cannot confirm which attack Suricata named.")
    if kind == "http_flood":
        notes.append("The Suricata rule, the ML request-rate feature and the metric all measure request rate, so their "
                     "agreement is not independent, and legitimate load from one source above about 40 req/s looks the same.")
    if kind == "tcp_exhaustion":
        notes.append("The TCP threshold sits close to busy legitimate traffic (about 1.3x); treat a lone alert with care.")
    if suricata["state"] == "no_data":
        notes.append("No Suricata data is available (no EVE file), so the absence of an alert means nothing.")
    return notes


def _evidence(kind: str | None, suricata: dict, ml: dict, metrics: dict) -> list[str]:
    out = []
    if suricata["state"] == "flagged":
        sources = ", ".join(f"{s['ip']} ({s['alerts']})" for s in suricata["sources"][:4])
        out.append(f"Suricata: {suricata['alerts']} alert(s) on sensor(s) {', '.join(suricata['sensors'])}, interfaces "
                   f"{', '.join(suricata['interfaces']) or 'unknown'}; sources {sources}.")
    if ml["state"] == "flagged":
        out.append(f"Isolation Forest: flagged {ml['flagged_polls']} of {ml['polls']} polls (longest run {ml['longest_run']}), "
                   f"peak confidence {ml['peak_confidence']:.2f}.")
    elif ml["state"] == "not_flagged":
        out.append(f"Isolation Forest: did not flag (longest flagged run {ml['longest_run']} of {ml['polls']} polls, "
                   f"peak confidence {ml['peak_confidence']:.2f}).")
    else:
        out.append("Isolation Forest: no scored polls in this period.")
    if metrics["state"] in ("elevated", "not_elevated"):
        ratio = f", x{metrics['ratio']:.1f}" if metrics.get("ratio") else ""
        out.append(f"Prometheus {metrics['unit']}: peak {metrics['peak']:.1f} against a baseline of "
                   f"{metrics['baseline']:.1f}{ratio} ({metrics['state'].replace('_', ' ')}).")
    elif metrics["state"] == "no_baseline":
        out.append(f"Prometheus {metrics['unit']}: peak {metrics['peak']:.1f}, no earlier samples to compare with.")
    elif metrics["state"] == "no_data":
        out.append("Prometheus: no data for this period.")
    return out


def assemble(skeleton: dict | None, ml_episode: dict | None, history: Sequence[dict], series: Sequence | None,
             now: float, *, baseline_cap: float, policy: str, current_cap: float, suricata_available: bool,
             ml_available: bool = True) -> dict:
    """One incident record from a Suricata group (`skeleton`) or from a lone ML episode."""
    if skeleton is not None:
        kind = skeleton["attack_type"] if skeleton["attack_type"] != "unknown" else None
        start, end = skeleton["start"], skeleton["end"]
        suricata = _suricata_view(skeleton["alerts"])
    else:
        kind, start, end = None, ml_episode["start"], ml_episode["end"]
        suricata = {"state": "not_flagged" if suricata_available else "no_data", "alerts": 0, "sightings": 0,
                    "signatures": [], "sensors": [], "interfaces": [], "sources": []}
    # With no model loaded the engine scores 0 for everything: that is "no data", not "calm".
    ml = ml_view(history if ml_available else [], start, end)
    metrics = metric_view(kind, series if isinstance(series, list) else None, start, end) if kind else {
        "state": "not_applicable", "metric": None}
    flagged = [s for s, v in (("suricata", suricata), ("ml", ml)) if v["state"] == "flagged"]
    if len(flagged) == 2:
        assessment = "corroborated"
    elif flagged == ["suricata"]:
        assessment = {"not_flagged": "suricata_only", "no_data": "suricata_ml_unavailable"}.get(ml["state"], "suricata_only")
    else:
        assessment = "ml_only" if suricata["state"] == "not_flagged" else "ml_only_suricata_unavailable"
    return {
        "id": f"{kind or 'anomaly'}-{int(start)}",
        "attack_type": kind,
        "title": TITLES[kind] if (kind or skeleton is None) else "Unclassified Suricata alert",
        "status": "active" if now - end <= INCIDENT_GAP_S else "closed",
        "start": start, "end": end, "duration_s": round(end - start, 1),
        "severity": severity(assessment, metrics["state"]),
        "assessment": assessment,
        "detectors": {"suricata": suricata, "ml": ml},
        "metrics": metrics,
        "mitigation": mitigation_view(kind, history, start, end, baseline_cap, policy, current_cap),
        "evidence": _evidence(kind, suricata, ml, metrics),
        "caveats": _caveats(kind, suricata, ml)
        + (["Elevated traffic with no Suricata alert and no attack type may be legitimate high load."] if skeleton is None else []),
    }


def plan(alerts: Sequence[dict], history: Sequence[dict]) -> tuple[list[dict], list[dict]]:
    """Suricata groups, plus the ML episodes that no Suricata group accounts for (padded overlap)."""
    groups = group_alerts(alerts)
    lone = [
        ep for ep in ml_episodes(history)
        if not any(ep["start"] <= g["end"] + ML_PAD_S and ep["end"] >= g["start"] - ML_PAD_S for g in groups)
    ]
    return groups, lone
