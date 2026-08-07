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
from pathlib import Path

import httpx
import joblib
import numpy as np
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from starlette.responses import Response

from classifier.features import FEATURE_NAMES, FeatureWindow

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinel-defense")

PROM_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "5"))
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "/app/classifier/model.joblib"))

MIN_THRESHOLD = float(os.environ.get("MIN_RATE_LIMIT", "5"))
MAX_THRESHOLD = float(os.environ.get("MAX_RATE_LIMIT", "1000"))
BASELINE_THRESHOLD = float(os.environ.get("BASELINE_RATE_LIMIT", "500"))

ATTACK_CONFIDENCE = Gauge("defense_classifier_attack_confidence", "Classifier attack-confidence in [0,1]")
RATE_LIMIT_THRESHOLD = Gauge("defense_rate_limit_threshold", "Current adaptive rate-limit threshold (req/s)")
MITIGATION_ACTIONS = Counter("defense_mitigation_actions_total", "Total mitigation actions taken")
FEATURE_GAUGES = {name: Gauge(f"defense_feature_{name}", f"Live feature value: {name}") for name in FEATURE_NAMES}

MITIGATION_LOG_PATH = Path(os.environ.get("MITIGATION_LOG_PATH", "/app/mitigation_log.jsonl"))

app = FastAPI(title="SENTINEL LAB defense engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

_state = {
    "threshold": BASELINE_THRESHOLD,
    "confidence": 0.0,
    "last_features": None,
    "recent_actions": [],
}


def _load_model():
    if MODEL_PATH.exists():
        blob = joblib.load(MODEL_PATH)
        log.info("Loaded classifier model from %s", MODEL_PATH)
        return blob["model"]
    log.warning("No trained model found at %s -- running in pass-through mode (confidence=0)", MODEL_PATH)
    return None


_model = _load_model()


async def _prom_query(client: httpx.AsyncClient, promql: str) -> float:
    try:
        resp = await client.get(f"{PROM_URL}/api/v1/query", params={"query": promql}, timeout=5)
        resp.raise_for_status()
        result = resp.json()["data"]["result"]
        if not result:
            return 0.0
        return float(result[0]["value"][1])
    except Exception as exc:
        log.warning("Prometheus query failed (%s): %s", promql, exc)
        return 0.0


async def gather_features(client: httpx.AsyncClient) -> FeatureWindow:
    # Each target type exports differently-named metrics (targets/web/app.py's
    # target_http_*, targets/tcp_service/server.py's target_tcp_*,
    # targets/dns_udp/server.py's target_udp_*) -- querying only the HTTP
    # ones here made udp-flood/tcp-exhaustion sandbox attacks structurally
    # invisible to the classifier: request_rate and active_connections never
    # moved no matter how hard those two attack types hit dns-udp/tcp-service,
    # so no mitigation action, Prometheus gauge change, or correlation signal
    # was ever produced for them. Summing across all three target types (they
    # all ultimately represent "load volume" / "concurrent load" for the
    # classifier's purposes, even though the underlying units -- HTTP
    # requests, TCP connections, UDP packets -- differ) closes that gap.
    # error_rate/avg_connection_duration stay HTTP-only: TCP/UDP targets have
    # no equivalent "error" or request-latency concept to report.
    http_request_rate = await _prom_query(client, "sum(rate(target_http_requests_total[15s]))")
    tcp_connection_rate = await _prom_query(client, "sum(rate(target_tcp_connections_total[15s]))")
    udp_packet_rate = await _prom_query(client, "sum(rate(target_udp_packets_total[15s]))")
    request_rate = http_request_rate + tcp_connection_rate + udp_packet_rate

    http_active_connections = await _prom_query(client, "sum(target_active_connections)")
    tcp_active_connections = await _prom_query(client, "sum(target_tcp_active_connections)")
    udp_inflight_datagrams = await _prom_query(client, "sum(target_udp_inflight_datagrams)")
    active_connections = http_active_connections + tcp_active_connections + udp_inflight_datagrams

    error_rate_num = await _prom_query(client, "sum(rate(target_http_errors_total[15s]))")
    p95_latency = await _prom_query(
        client, "histogram_quantile(0.95, sum(rate(target_http_request_duration_seconds_bucket[1m])) by (le))"
    )
    inter_arrival_std = 1.0 / request_rate if request_rate > 0 else 0.0
    error_rate = (error_rate_num / http_request_rate) if http_request_rate > 0 else 0.0

    return FeatureWindow(
        request_rate=request_rate,
        avg_connection_duration=p95_latency or 0.0,
        inter_arrival_std=inter_arrival_std,
        error_rate=error_rate,
        active_connections=active_connections,
    )


def score(features: FeatureWindow) -> float:
    """Returns an attack-confidence score in [0, 1]. Higher = more anomalous."""
    if _model is None:
        return 0.0
    vec = np.array([features.as_vector()])
    # IsolationForest.decision_function: higher = more normal. Flip + squash to [0,1].
    raw = _model.decision_function(vec)[0]
    confidence = 1.0 / (1.0 + np.exp(raw * 5))  # logistic squashing, tuned for typical score ranges
    return float(np.clip(confidence, 0.0, 1.0))


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


def log_mitigation(features: FeatureWindow, confidence: float, old_threshold: float, new_threshold: float):
    entry = {
        "ts": time.time(),
        "confidence": confidence,
        "features": dict(zip(FEATURE_NAMES, features.as_vector())),
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


async def detection_loop():
    async with httpx.AsyncClient() as client:
        while True:
            features = await gather_features(client)
            confidence = score(features)
            old_threshold = _state["threshold"]
            new_threshold = adapt_threshold(confidence)

            _state["threshold"] = new_threshold
            _state["confidence"] = confidence
            _state["last_features"] = features

            ATTACK_CONFIDENCE.set(confidence)
            RATE_LIMIT_THRESHOLD.set(new_threshold)
            for name, value in zip(FEATURE_NAMES, features.as_vector()):
                FEATURE_GAUGES[name].set(value)

            if abs(new_threshold - old_threshold) > 0.5:
                log_mitigation(features, confidence, old_threshold, new_threshold)

            await asyncio.sleep(POLL_INTERVAL)


@app.on_event("startup")
async def startup():
    asyncio.create_task(detection_loop())


@app.get("/")
async def index():
    """Landing page so this isn't a 404 when someone opens the engine's
    port directly -- links to the JSON endpoints and to the unified
    dashboard, which is the intended way to view this data."""
    return {
        "service": "SENTINEL LAB defense engine",
        "status": "ok" if _model is not None else "running (no trained model loaded yet)",
        "endpoints": ["/health", "/threshold", "/mitigations", "/metrics"],
        "dashboard": "http://localhost:8090/ (unified SENTINEL LAB dashboard)",
    }


@app.get("/threshold")
async def get_threshold():
    """Consulted by the rate-limiter sidecar to know the current allowed req/s."""
    return {"threshold_rps": _state["threshold"], "confidence": _state["confidence"]}


@app.get("/mitigations")
async def get_mitigations(limit: int = 50):
    return {"actions": _state["recent_actions"][-limit:]}


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": _model is not None}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
