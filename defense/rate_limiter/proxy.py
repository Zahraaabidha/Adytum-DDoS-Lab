"""Adaptive rate-limiting reverse proxy.

Sits in front of the target web service. Enforces a requests-per-second cap
that it refreshes periodically from the defense engine's /threshold endpoint
-- the cap itself is decided by the ML classifier's confidence, not a fixed
rule baked into this proxy.
"""
import asyncio
import os

import httpx
from fastapi import FastAPI, Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from limiter import FairShareLimiter, GlobalLimiter
from starlette.responses import Response

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://web:8000")
ENGINE_URL = os.environ.get("ENGINE_URL", "http://defense-engine:9300")
REFRESH_INTERVAL = float(os.environ.get("REFRESH_INTERVAL", "3"))
# "fair" shares the cap fairly between source addresses, "global" is plain first-come-first-served
# (see limiter.py). Both enforce the same cap.
LIMITER_MODE = os.environ.get("LIMITER_MODE", "fair")

ALLOWED = Counter("ratelimiter_allowed_total", "Requests allowed through")
BLOCKED = Counter("ratelimiter_blocked_total", "Requests blocked by adaptive rate limit")
CURRENT_LIMIT = Gauge("ratelimiter_current_limit_rps", "Currently enforced requests/sec cap")

app = FastAPI(title="SENTINEL LAB adaptive rate limiter")

limiter = FairShareLimiter(500.0) if LIMITER_MODE == "fair" else GlobalLimiter(500.0)


async def refresh_loop():
    async with httpx.AsyncClient() as client:
        while True:
            try:
                resp = await client.get(f"{ENGINE_URL}/threshold", timeout=3)
                limiter.set_limit(resp.json()["threshold_rps"])
                CURRENT_LIMIT.set(limiter.limit)
            except Exception:
                pass
            await asyncio.sleep(REFRESH_INTERVAL)


@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh_loop())


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(path: str, request: Request):
    # The socket peer address, never X-Forwarded-For: a client must not be able to pick its own identity.
    if not limiter.allow(request.client.host if request.client else "unknown"):
        BLOCKED.inc()
        return Response(content="rate limited by SENTINEL LAB adaptive mitigation", status_code=429)

    ALLOWED.inc()
    async with httpx.AsyncClient() as client:
        upstream_resp = await client.request(
            request.method,
            f"{UPSTREAM_URL}/{path}",
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            content=await request.body(),
            timeout=10,
        )
    return Response(
        content=upstream_resp.content, status_code=upstream_resp.status_code, headers=dict(upstream_resp.headers)
    )
