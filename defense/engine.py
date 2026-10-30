"""SENTINEL LAB detection & mitigation engine.

Polls Prometheus for live traffic telemetry, computes the same
request-rate / connection-duration / packet-timing features used in
training, scores them with the trained IsolationForest classifier, and
adaptively adjusts a shared rate-limit threshold based on classifier
confidence (not a fixed rule). Every mitigation action is logged together
with the feature values and confidence that triggered it, and everything
is exposed as Prometheus metrics for Grafana.
"""
import asyncio
import json
import logging
import os
import time
from collections import deque
from pathlib import Path

import httpx
import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from starlette.responses import Response

from classifier.live_features import LIVE_FEATURE_NAMES, LiveFeatures, _prom_query, gather_features
from classifier.scoring import attack_confidence
from mitigation import MITIGATING, GuardedPolicy
import incidents
from suricata_alerts import AlertStore, correlate, dns_addresses, tail_forever

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinel-defense")

PROM_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "5"))
# The selected default is the candidate model (see README, "Model selection"). The original `model.joblib` is kept
# untouched as the rollback option: set MODEL_PATH (docker compose: SENTINEL_MODEL_PATH) to /app/classifier/model.joblib.
DEFAULT_MODEL_PATH = "/app/classifier/model.candidate.joblib"
DEFAULT_EVALUATION_PATH = "/app/classifier/evaluation.candidate.json"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", DEFAULT_MODEL_PATH))

MIN_THRESHOLD = float(os.environ.get("MIN_RATE_LIMIT", "5"))
MAX_THRESHOLD = float(os.environ.get("MAX_RATE_LIMIT", "1000"))
BASELINE_THRESHOLD = float(os.environ.get("BASELINE_RATE_LIMIT", "500"))
# "guarded": persistence, bounded cuts, hysteresis and recovery (mitigation.py). "linear": the original
# confidence -> cap mapping, kept for comparison.
MITIGATION_POLICY = os.environ.get("MITIGATION_POLICY", "guarded")
# The protective cap never goes below this (and is pinned at the baseline when MIN_RATE_LIMIT makes mitigation inert).
GUARD_MIN_CAP = max(float(os.environ.get("MITIGATION_MIN_CAP", "20")), MIN_THRESHOLD)
GUARD_HEADROOM = float(os.environ.get("MITIGATION_HEADROOM", "6"))
GUARD_FALLBACK_CAP = float(os.environ.get("MITIGATION_FALLBACK_CAP", "50"))

ATTACK_CONFIDENCE = Gauge("defense_classifier_attack_confidence", "Classifier attack-confidence in [0,1]")
RATE_LIMIT_THRESHOLD = Gauge("defense_rate_limit_threshold", "Current adaptive rate-limit threshold (req/s)")
MITIGATION_ACTIONS = Counter("defense_mitigation_actions_total", "Total mitigation actions taken")
SURICATA_ALERTS = Counter(
    "defense_suricata_alerts_total", "Suricata alerts ingested from EVE JSON", ["signature_id", "severity"]
)
MITIGATION_ACTIVE = Gauge("defense_mitigation_active", "1 while the guarded policy is holding a protective cap")
FEATURE_GAUGES = {name: Gauge(f"defense_feature_{name}", f"Live feature value: {name}") for name in LIVE_FEATURE_NAMES}

MITIGATION_LOG_PATH = Path(os.environ.get("MITIGATION_LOG_PATH", "/app/mitigation_log.jsonl"))
# Every scored feature vector is appended here; classifier/train.py and evaluate.py read it back.
FEATURE_LOG_PATH = Path(os.environ.get("FEATURE_LOG_PATH", "/app/feature_log.jsonl"))
# Written by `classifier/evaluate.py --output`; served as-is, never computed here.
EVALUATION_PATH = Path(os.environ.get("EVALUATION_PATH", DEFAULT_EVALUATION_PATH))
# Written by `classifier/mitigation_report.py`; likewise served as-is.
MITIGATION_REPORT_PATH = Path(os.environ.get("MITIGATION_REPORT_PATH", "/app/classifier/mitigation-comparison.json"))

# Suricata's EVE JSON, read-only from the shared `suricata-logs` volume. Alerts are advisory: they are shown and
# correlated with the ML detector's output but never change the rate limit.
SURICATA_EVE_DIR = Path(os.environ.get("SURICATA_EVE_DIR", "/var/log/suricata"))
# `eve.json` is the rate-limiter ingress sensor; `eve-<name>.json` are the optional target-tap sensors.
SURICATA_EVE_GLOB = os.environ.get("SURICATA_EVE_GLOB", "eve*.json")
# Where the read position is kept so a restart resumes instead of replaying alerts into the counter.
SURICATA_STATE_PATH = Path(os.environ.get("SURICATA_STATE_PATH", "/app/suricata_state.json"))
# The rate-limiter forwards HTTP to the load balancer inside the same namespace Suricata watches; that second sighting
# of the same event (source = the rate-limiter) is merged into the attacker-facing alert.
SURICATA_PROXY_HOSTS = [h.strip() for h in os.environ.get("SURICATA_PROXY_HOSTS", "rate-limiter").split(",") if h.strip()]


def _eve_files() -> list[Path]:
    return sorted(SURICATA_EVE_DIR.glob(SURICATA_EVE_GLOB))


suricata_store = AlertStore(_eve_files, state_path=SURICATA_STATE_PATH, proxy_addresses=dns_addresses(SURICATA_PROXY_HOSTS))
# Recent detector polls (ts, confidence, threshold, request_rate, state), only used to annotate Suricata alerts.
_ml_history: deque[dict] = deque(maxlen=720)

app = FastAPI(title="SENTINEL LAB defense engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

guard = GuardedPolicy(BASELINE_THRESHOLD, GUARD_MIN_CAP, headroom=GUARD_HEADROOM, fallback_cap=GUARD_FALLBACK_CAP)

_state = {
    "threshold": BASELINE_THRESHOLD,
    "confidence": 0.0,
    "last_features": None,
    "recent_actions": [],
}


_ranges: dict | None = None  # per-feature training [min, max], stored with the model
_model_info: dict | None = None  # what /health reports about the loaded model


def _load_model():
    global _ranges, _model_info
    if MODEL_PATH.exists():
        blob = joblib.load(MODEL_PATH)
        if blob.get("feature_names") != LIVE_FEATURE_NAMES:
            log.warning(
                "Model at %s was trained on features %s, not the live features %s -- ignoring it (pass-through, "
                "confidence=0). Retrain with classifier/train.py.",
                MODEL_PATH, blob.get("feature_names"), LIVE_FEATURE_NAMES,
            )
            return None
        _ranges = blob.get("feature_ranges")
        _model_info = {
            "file": MODEL_PATH.name, "trained_at": blob.get("trained_at"), "samples": blob.get("samples"),
            "legit_runs": blob.get("legit_runs", []), "idle_windows": len(blob.get("idle_windows", [])),
            "contamination": blob.get("contamination"),
        }
        log.info("Loaded classifier model from %s (trained %s on %s samples from %d legitimate run(s))",
                 MODEL_PATH, blob.get("trained_at"), blob.get("samples"), len(blob.get("legit_runs", [])))
        return blob["model"]
    log.warning("No trained model found at %s -- running in pass-through mode (confidence=0)", MODEL_PATH)
    return None


_model = _load_model()


def score(features: LiveFeatures) -> float:
    """Returns an attack-confidence score in [0, 1]. Higher = more anomalous."""
    if _model is None:
        return 0.0
    return attack_confidence(_model, features.as_vector(), LIVE_FEATURE_NAMES, _ranges)


def adapt_threshold(confidence: float) -> float:
    """Adaptive mitigation: the rate-limit threshold moves smoothly with
    classifier confidence rather than snapping between two fixed rule states.
    High confidence -> aggressively lower the allowed rate; low confidence ->
    relax back toward baseline."""
    current = _state["threshold"]
    target = BASELINE_THRESHOLD - confidence * (BASELINE_THRESHOLD - MIN_THRESHOLD)
    target = max(MIN_THRESHOLD, min(MAX_THRESHOLD, target))
    # Exponential smoothing so the threshold doesn't thrash on noisy single samples.
    new_threshold = current + 0.4 * (target - current)
    return new_threshold


def decide_threshold(confidence: float, features: LiveFeatures, blocked_rps: float) -> float:
    """The new rate limit for this poll under the configured policy."""
    if MITIGATION_POLICY == "guarded":
        return guard.update(confidence, features.request_rate, blocked_rps)
    return adapt_threshold(confidence)


def log_mitigation(features: LiveFeatures, confidence: float, old_threshold: float, new_threshold: float):
    entry = {
        "ts": time.time(),
        "confidence": confidence,
        "features": dict(zip(LIVE_FEATURE_NAMES, features.as_vector())),
        "old_threshold": old_threshold,
        "new_threshold": new_threshold,
        "reason": (
            f"classifier confidence={confidence:.3f} on request_rate={features.request_rate:.1f}/s, "
            f"active_connections={features.active_connections:.0f}, error_rate={features.error_rate:.3f} "
            f"-> threshold {old_threshold:.1f} -> {new_threshold:.1f} req/s"
        ),
    }
    _state["recent_actions"].append(entry)
    _state["recent_actions"] = _state["recent_actions"][-200:]
    with open(MITIGATION_LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    log.info(entry["reason"])
    MITIGATION_ACTIONS.inc()


def log_features(features: LiveFeatures, confidence: float, threshold: float):
    entry = {
        "ts": time.time(),
        "features": dict(zip(LIVE_FEATURE_NAMES, features.as_vector())),
        "confidence": confidence,
        "threshold": threshold,
        "model": _model is not None,
        # Mitigation can only move the threshold if MIN_RATE_LIMIT is below the baseline.
        "mitigation": MIN_THRESHOLD < BASELINE_THRESHOLD,
        "policy": MITIGATION_POLICY,
        "state": guard.state if MITIGATION_POLICY == "guarded" else None,
    }
    try:
        with open(FEATURE_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError as exc:
        log.warning("Could not write feature log %s: %s", FEATURE_LOG_PATH, exc)


async def detection_loop():
    async with httpx.AsyncClient() as client:
        while True:
            features = await gather_features(client, PROM_URL)
            if features is None:  # Prometheus unreachable: keep the last state rather than read it as "no traffic"
                await asyncio.sleep(POLL_INTERVAL)
                continue
            confidence = score(features)
            old_threshold = _state["threshold"]
            blocked_rps = 0.0
            if MITIGATION_POLICY == "guarded":  # what the limiter is rejecting says whether the attack is still on
                blocked_rps = await _prom_query(client, PROM_URL, "sum(rate(ratelimiter_blocked_total[15s]))") or 0.0
            new_threshold = decide_threshold(confidence, features, blocked_rps)
            MITIGATION_ACTIVE.set(1 if MITIGATION_POLICY == "guarded" and guard.state == MITIGATING else 0)

            _state["threshold"] = new_threshold
            _state["confidence"] = confidence
            _state["last_features"] = features

            ATTACK_CONFIDENCE.set(confidence)
            RATE_LIMIT_THRESHOLD.set(new_threshold)
            for name, value in zip(LIVE_FEATURE_NAMES, features.as_vector()):
                FEATURE_GAUGES[name].set(value)
            log_features(features, confidence, new_threshold)
            _ml_history.append({
                "ts": time.time(), "confidence": confidence, "threshold": new_threshold,
                "request_rate": features.request_rate, "state": guard.state if MITIGATION_POLICY == "guarded" else None,
                "features": dict(zip(LIVE_FEATURE_NAMES, features.as_vector())),
                "blocked_rps": blocked_rps if MITIGATION_POLICY == "guarded" else None,
            })

            if abs(new_threshold - old_threshold) > 0.5:
                log_mitigation(features, confidence, old_threshold, new_threshold)

            await asyncio.sleep(POLL_INTERVAL)


@app.on_event("startup")
async def startup():
    log.info("Mitigation policy: %s; model: %s", MITIGATION_POLICY, MODEL_PATH.name if _model is not None else "NONE (pass-through)")
    asyncio.create_task(detection_loop())
    asyncio.create_task(tail_forever(suricata_store, lambda a: SURICATA_ALERTS.labels(
        signature_id=str(a["signature_id"]), severity=a["severity_label"]).inc()))


@app.get("/")
async def index():
    """Landing page so this isn't a 404 when someone opens the engine's
    port directly -- links to the JSON endpoints and to the unified
    dashboard, which is the intended way to view this data."""
    return {
        "service": "SENTINEL LAB defense engine",
        "status": "ok" if _model is not None else "running (no trained model loaded yet)",
        "endpoints": ["/health", "/threshold", "/mitigations", "/evaluation", "/mitigation-report", "/suricata/alerts", "/suricata/summary", "/incidents", "/metrics"],
        "dashboard": "http://localhost:8090/ (unified SENTINEL LAB dashboard)",
    }


@app.get("/threshold")
async def get_threshold():
    """Consulted by the rate-limiter sidecar to know the current allowed req/s."""
    return {
        "threshold_rps": _state["threshold"], "confidence": _state["confidence"], "policy": MITIGATION_POLICY,
        "state": guard.state if MITIGATION_POLICY == "guarded" else None,
    }


@app.get("/mitigations")
async def get_mitigations(limit: int = 50):
    return {"actions": _state["recent_actions"][-limit:]}


def _read_report(path: Path) -> dict:
    """A report file served as-is, or `{"available": false}` if it is missing or unreadable."""
    if not path.exists():
        return {"available": False}
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("Could not read report at %s", path)
        return {"available": False}
    return {"available": True, **report}


@app.get("/evaluation")
async def get_evaluation():
    """Latest offline evaluation report from `classifier/evaluate.py`, or
    `{"available": false}` if none has been generated yet."""
    return _read_report(EVALUATION_PATH)


@app.get("/mitigation-report")
async def get_mitigation_report():
    """Latest measured mitigation comparison from `classifier/mitigation_report.py`."""
    return _read_report(MITIGATION_REPORT_PATH)


@app.get("/suricata/alerts")
async def get_suricata_alerts(limit: int = 100, min_severity: int | None = None, signature_id: int | None = None):
    """Recent Suricata alerts (newest first), each annotated with what the ML detector saw at that time.
    `min_severity` is a Suricata level (1 = high only, 2 = high and medium)."""
    limit = max(1, min(limit, 500))
    history = list(_ml_history)
    alerts = [{**a, "ml": correlate(a["ts"], history)} for a in suricata_store.recent(limit, min_severity, signature_id)]
    return {"alerts": alerts, "total_ingested": suricata_store.total}


@app.get("/suricata/summary")
async def get_suricata_summary(window: float = 300.0):
    """Counts per signature, and how the alerts of the last `window` seconds line up with the ML detector.
    Advisory only: a Suricata alert never changes the rate limit."""
    window = max(10.0, min(window, 3600.0))
    history = list(_ml_history)
    recent = suricata_store.recent(500, since=time.time() - window)
    annotated = [correlate(a["ts"], history) for a in recent]
    return {
        "eve_files": [f.name for f in _eve_files()],
        "eve_file_present": suricata_store.present(),
        "total_ingested": suricata_store.total,
        "skipped_lines": suricata_store.skipped_lines,
        "merged_duplicate_sightings": suricata_store.merged_hops,
        "window_seconds": window,
        "recent_alerts": len(recent),
        "ml_flagged_alerts": sum(1 for c in annotated if c["ml_flagged"]),
        "ml_not_flagged_alerts": sum(1 for c in annotated if c["ml_flagged"] is False),
        "no_ml_sample_alerts": sum(1 for c in annotated if not c["ml_available"]),
        "signatures": suricata_store.signature_counts(),
    }


_series_cache: dict = {}  # (type, start, end) -> (fetched_at, series)


async def _metric_series(kind: str, start: float, end: float):
    """The type-specific Prometheus series around an incident (query_range), or None if unavailable."""
    window = incidents.metric_window(kind, start, end)
    if window is None:
        return None
    key = (kind, int(start), int(end))
    ttl = 5.0 if time.time() - end < incidents.INCIDENT_GAP_S else 300.0  # a closed incident's history does not change
    cached = _series_cache.get(key)
    if cached and time.time() - cached[0] < ttl:
        return cached[1]
    lo, hi = window[0], min(window[1], time.time())
    step = max(5, int((hi - lo) / 600) + 1)
    series = None
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{PROM_URL}/api/v1/query_range", timeout=4,
                                    params={"query": incidents.METRICS[kind][0], "start": lo, "end": hi, "step": step})
            resp.raise_for_status()
            result = resp.json()["data"]["result"]
            series = [(float(t), float(v)) for t, v in (result[0]["values"] if result else []) if v not in ("NaN", "+Inf", "-Inf")]
    except Exception as exc:  # Prometheus down or slow: the incident says "no data", it does not guess
        log.warning("Incident metric query failed (%s): %s", kind, exc)
    if len(_series_cache) > 200:
        _series_cache.clear()
    _series_cache[key] = (time.time(), series)
    return series


@app.get("/incidents")
async def get_incidents(limit: int = 20):
    """Suricata alerts, Isolation Forest detections and Prometheus metrics combined into incident records.
    Advisory only: it describes what the existing detectors reported and never changes the rate limit."""
    limit = max(1, min(limit, 50))
    history = list(_ml_history)
    groups, lone = incidents.plan(suricata_store.recent(500), history)
    chosen = sorted([("group", g) for g in groups] + [("ml", e) for e in lone], key=lambda x: -x[1]["end"])[:limit]
    series = await asyncio.gather(*[
        _metric_series(g["attack_type"], g["start"], g["end"]) if kind == "group" else asyncio.sleep(0, None)
        for kind, g in chosen])
    now = time.time()
    records = [
        incidents.assemble(g if kind == "group" else None, g if kind == "ml" else None, history, series[i], now,
                           baseline_cap=BASELINE_THRESHOLD, policy=MITIGATION_POLICY, current_cap=_state["threshold"],
                           suricata_available=suricata_store.present(), ml_available=_model is not None)
        for i, (kind, g) in enumerate(chosen)
    ]
    return {
        "generated_at": now, "incidents": records,
        "inputs": {"suricata_files": len(_eve_files()), "ml_model_loaded": _model is not None,
                   "ml_polls": len(history), "ml_window_seconds": (history[-1]["ts"] - history[0]["ts"]) if len(history) > 1 else 0},
    }


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": _model is not None, "model": _model_info, "policy": MITIGATION_POLICY}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
