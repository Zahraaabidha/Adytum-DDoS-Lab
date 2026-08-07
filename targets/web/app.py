"""SENTINEL LAB target: a small FastAPI web app instrumented with Prometheus metrics.

This is a deliberately simple, stateless service used purely as an attack
target inside the isolated lab network. It has no egress dependency.
"""
import os
import time

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from starlette.requests import Request

INSTANCE_ID = os.environ.get("HOSTNAME", "web-unknown")

app = FastAPI(title="SENTINEL LAB target web app")

REQUEST_COUNT = Counter(
    "target_http_requests_total", "Total HTTP requests", ["instance", "path", "method", "status"]
)
REQUEST_LATENCY = Histogram(
    "target_http_request_duration_seconds", "Request latency", ["instance", "path"]
)
ERROR_COUNT = Counter("target_http_errors_total", "Total HTTP 5xx responses", ["instance"])
ACTIVE_CONNECTIONS = Gauge("target_active_connections", "In-flight requests", ["instance"])


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    ACTIVE_CONNECTIONS.labels(instance=INSTANCE_ID).inc()
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        ERROR_COUNT.labels(instance=INSTANCE_ID).inc()
        raise
    finally:
        ACTIVE_CONNECTIONS.labels(instance=INSTANCE_ID).dec()
    duration = time.perf_counter() - start
    REQUEST_LATENCY.labels(instance=INSTANCE_ID, path=request.url.path).observe(duration)
    REQUEST_COUNT.labels(
        instance=INSTANCE_ID, path=request.url.path, method=request.method, status=response.status_code
    ).inc()
    if response.status_code >= 500:
        ERROR_COUNT.labels(instance=INSTANCE_ID).inc()
    return response


@app.get("/")
async def root():
    return {"service": "sentinel-lab-web", "instance": INSTANCE_ID}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/work")
async def work():
    """Simulates a small amount of CPU work, like a real endpoint would do."""
    total = 0
    for i in range(20000):
        total += i * i
    return {"result": total}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
