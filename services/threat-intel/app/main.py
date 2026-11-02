"""SENTINEL LAB Global Threat Intelligence service.

Read-only: this service only ever downloads public threat feeds over HTTPS
(Stage B connectors) and serves the normalized result over REST/WebSocket
(Stage C). It never talks to the sandbox's `attacker_net`/`target_net` and
has no code path capable of sending attack traffic anywhere.

Stage A shipped the skeleton (app wiring, DB startup/shutdown, health
check). Stage B added provider connectors. Stage C added the REST/WebSocket
API, Redis-backed caching, and the ingestion scheduler that actually calls
those connectors on a loop and persists their output. Stage C.5 adds
geolocation enrichment (local MaxMind GeoLite2, own updater scheduler,
independent of the provider ingestion loop it plugs into via a single call
in `ingest.py`).
"""
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import provider as _provider_pkg  # noqa: F401  -- import for registration side effects (Stage B connectors)
from app.api.routes_correlation import router as correlation_router
from app.api.routes_geoip import router as geoip_router
from app.api.routes_providers import router as providers_router
from app.api.routes_threats import router as threats_router
from app.api.routes_ws import router as ws_router
from app.common import cache
from app.common import models as _models  # noqa: F401  -- import registers ORM tables on Base.metadata before init_db()
from app.common.db import dispose_engine, init_db
from app.enrich import backfill_geo
from app.geoip_updater import start_geoip_scheduler, stop_geoip_scheduler
from app.ingest import start_scheduler, stop_scheduler
from app.logging_config import configure_logging, get_logger
from app.provider.base import PROVIDER_REGISTRY
from app.settings import get_settings

configure_logging()
log = get_logger("threat-intel")


async def _startup_backfill() -> None:
    try:
        await backfill_geo()
    except Exception as exc:  # noqa: BLE001 -- backfill must never take the service down
        log.error("GeoIP startup backfill failed: %s", exc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    log.info("Starting threat-intel service (%d provider(s) registered)", len(PROVIDER_REGISTRY))
    await init_db()
    for provider_cls in PROVIDER_REGISTRY:
        provider = provider_cls()
        if provider.is_enabled(settings):
            log.info("Provider enabled: %s (poll every %ss)", provider.name, provider.poll_interval_seconds)
        else:
            log.warning("Provider disabled: %s (missing required configuration)", provider.name)
    start_scheduler(settings)
    start_geoip_scheduler(settings)
    # Existing rows may have been ingested before a database was available.
    backfill_task = asyncio.create_task(_startup_backfill())
    log.info("Startup complete")
    yield
    log.info("Shutting down threat-intel service")
    backfill_task.cancel()
    await stop_scheduler()
    stop_geoip_scheduler()
    await cache.close()
    await dispose_engine()
    log.info("Shutdown complete")


app = FastAPI(title="SENTINEL LAB Global Threat Intelligence", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().dashboard_origins_list,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(threats_router)
app.include_router(providers_router)
app.include_router(ws_router)
app.include_router(geoip_router)
app.include_router(correlation_router)


@app.get("/")
async def index():
    return {
        "service": "SENTINEL LAB Global Threat Intelligence",
        "status": "ok",
        "note": "Read-only public threat-intel ingestion. Never launches attacks.",
        "endpoints": [
            "/health",
            "/api/threats/live",
            "/api/threats/map",
            "/api/threats/countries",
            "/api/threats/types",
            "/api/threats/timeline",
            "/api/threats/search",
            "/api/threats/stats",
            "/api/threats/correlation",
            "/api/providers/status",
            "/api/geoip/status",
            "/ws/threats",
        ],
    }


@app.get("/health")
async def health():
    return {"status": "ok", "providers_registered": len(PROVIDER_REGISTRY)}
