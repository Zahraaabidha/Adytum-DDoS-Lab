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
PORT = int(os.environ.get("WEB_PORT", "8000"))
TCP_ESTABLISHED = "01"

app = FastAPI(title="SENTINEL LAB target web app")

REQUEST_COUNT = Counter(
    "target_http_requests_total", "Total HTTP requests", ["instance", "path", "method", "status"]
)
REQUEST_LATENCY = Histogram(
    "target_http_request_duration_seconds", "Request latency", ["instance", "path"]
)
ERROR_COUNT = Counter("target_http_errors_total", "Total HTTP 5xx responses", ["instance"])
ACTIVE_CONNECTIONS = Gauge("target_active_connections", "In-flight requests", ["instance"])
ESTABLISHED_SOCKETS = Gauge(
    "target_http_established_sockets",
    "ESTABLISHED TCP sockets on the HTTP port. Unlike the request metrics this also counts connections held "
    "open without ever completing a request (Slowloris), which the app never sees.",
    ["instance"],
)


def count_established(proc_net_tcp_lines: list[str], port: int) -> int:
    """Counts ESTABLISHED sockets whose local port is `port` in /proc/net/tcp[6] lines (header excluded)."""
    count = 0
    for line in proc_net_tcp_lines:
        fields = line.split()
        if len(fields) > 3 and int(fields[1].rsplit(":", 1)[1], 16) == port and fields[3] == TCP_ESTABLISHED:
            count += 1
    return count


def established_sockets() -> int:
    total = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, encoding="ascii") as fh:
                total += count_established(fh.read().splitlines()[1:], PORT)
        except OSError:
            continue  # tcp6 may be absent; non-Linux hosts have neither
    return total


ESTABLISHED_SOCKETS.labels(instance=INSTANCE_ID).set_function(established_sockets)


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
