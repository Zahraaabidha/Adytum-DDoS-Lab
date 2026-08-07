"""Ingestion scheduler: polls each enabled provider on its own interval,
persists normalized events, and publishes IOC events for the live feed.

Each provider's own `fetch()` already catches its own request/parsing
errors and degrades to an empty list (see `provider/base.py`'s docstring
and Stage B's fault-isolation test). This module adds a second,
belt-and-suspenders layer around the whole per-provider cycle (fetch +
persist) so a bug anywhere in that path -- including in the shared
persistence step, which isn't the connector's responsibility to guard --
can never take down the scheduler or block another provider's independent
job.
"""
import asyncio
import time
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.common import cache
from app.common.dedup import merge_or_insert, upsert_cve
from app.common.db import session_scope
from app.common.models import Ioc
from app.common.schema import CveEvent, ThreatEvent
from app.enrich import enrich_ioc
from app.logging_config import get_logger
from app.provider.base import PROVIDER_REGISTRY, ThreatProvider
from app.provider.http import new_client
from app.settings import Settings, get_settings

log = get_logger("threat-intel.ingest")

LIVE_CHANNEL = "threats:live"

_scheduler: AsyncIOScheduler | None = None
# APScheduler's AsyncIOExecutor doesn't actually block on `shutdown(wait=True)`
# for jobs that are asyncio coroutines (that flag is meaningful for its
# thread-pool executors, not this one) -- confirmed by reproducing a
# shutdown-during-ingestion run, which still produced CancelledError
# tracebacks with wait=True. So in-flight jobs are tracked here and
# explicitly awaited on shutdown instead of relying on that parameter.
_in_flight: set[asyncio.Task] = set()


def _ioc_live_payload(event: ThreatEvent, ioc: Ioc) -> dict:
    return {
        "ioc": ioc.ioc,
        "ioc_type": ioc.ioc_type,
        "country": ioc.country,
        "city": ioc.city,
        "lat": ioc.lat,
        "lon": ioc.lon,
        "threat_type": ioc.threat_type,
        "attack_family": ioc.attack_family,
        "confidence_score": ioc.confidence_score,
        "source": event.source,
        "timestamp": event.timestamp.isoformat(),
    }


async def _run_cycle(provider: ThreatProvider) -> None:
    settings = get_settings()
    started = time.monotonic()

    try:
        async with new_client() as client:
            events = await provider.fetch(client, settings)
    except Exception as exc:  # noqa: BLE001 -- a provider misbehaving must never take the scheduler down
        log.error("Provider %s: fetch cycle raised unexpectedly: %s", provider.name, exc)
        return

    if not events:
        log.info("Provider %s: 0 events this cycle (%.2fs)", provider.name, time.monotonic() - started)
        return

    persisted = 0
    try:
        async with session_scope() as session:
            for event in events:
                if isinstance(event, ThreatEvent):
                    ioc = await merge_or_insert(session, event)
                    # Geolocation enrichment is its own subsystem (see
                    # app/enrich.py) -- this is the entire integration
                    # point, a single call, not embedded ingestion logic.
                    await enrich_ioc(session, ioc)
                    persisted += 1
                    await cache.publish(LIVE_CHANNEL, _ioc_live_payload(event, ioc))
                elif isinstance(event, CveEvent):
                    await upsert_cve(session, event)
                    persisted += 1
            await session.commit()
    except Exception as exc:  # noqa: BLE001 -- persistence failures must not crash the scheduler either
        log.error("Provider %s: persistence failed after fetching %d event(s): %s", provider.name, len(events), exc)
        return

    log.info(
        "Provider %s: persisted %d/%d event(s) in %.2fs",
        provider.name,
        persisted,
        len(events),
        time.monotonic() - started,
    )


async def _run_cycle_tracked(provider: ThreatProvider) -> None:
    """Wraps `_run_cycle` so `stop_scheduler` can await this exact job's
    task to completion instead of letting it get cancelled mid-flight."""
    task = asyncio.current_task()
    if task is None:
        await _run_cycle(provider)
        return
    _in_flight.add(task)
    try:
        await _run_cycle(provider)
    finally:
        _in_flight.discard(task)


def start_scheduler(settings: Settings) -> AsyncIOScheduler:
    global _scheduler
    scheduler = AsyncIOScheduler()
    scheduled = 0
    for provider_cls in PROVIDER_REGISTRY:
        provider = provider_cls()
        if not provider.is_enabled(settings):
            continue
        scheduler.add_job(
            _run_cycle_tracked,
            "interval",
            seconds=provider.poll_interval_seconds,
            args=[provider],
            id=f"ingest:{provider.name}",
            next_run_time=datetime.now(timezone.utc),  # run once immediately, then on interval
            max_instances=1,
            coalesce=True,
            misfire_grace_time=60,
        )
        scheduled += 1
    scheduler.start()
    log.info("Ingestion scheduler started with %d enabled job(s)", scheduled)
    _scheduler = scheduler
    return scheduler


async def stop_scheduler() -> None:
    """Graceful shutdown, in the right order. `AsyncIOScheduler.shutdown()`
    -- regardless of its `wait` argument -- unconditionally cancels every
    pending job future (see `AsyncIOExecutor.shutdown` in apscheduler's
    source: "There is no way to honor wait=True... " followed by an
    unconditional `f.cancel()` on each one). Calling `shutdown()` before
    waiting on `_in_flight` was therefore cancelling the in-flight job
    *before* our own wait ever got a chance to run -- confirmed by
    reproducing a shutdown-during-ingestion run and observing the wait
    resolve in under 50ms instead of the ~15s the job actually needed.

    The fix is to `pause()` first (stops the scheduler from *starting* new
    runs, but doesn't touch already-submitted futures), wait for whatever
    is in `_in_flight` to finish on its own, and only call `shutdown()`
    once nothing is left pending -- at which point it has nothing to
    cancel."""
    global _scheduler
    if _scheduler is None:
        return
    _scheduler.pause()
    if _in_flight:
        log.info("Waiting for %d in-flight ingestion job(s) to finish before shutdown", len(_in_flight))
        await asyncio.gather(*list(_in_flight), return_exceptions=True)
    _scheduler.shutdown(wait=False)
    _scheduler = None
