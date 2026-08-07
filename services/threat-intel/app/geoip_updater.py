"""Periodic downloader/refresher for MaxMind's GeoLite2-City and
GeoLite2-ASN databases -- both free, both gated behind a (free) license
key from MaxMind's account portal.

Self-disables (no download attempted, logs a warning once) when
`MAXMIND_LICENSE_KEY` is unset -- the same missing-key pattern used for
AbuseIPDB/OTX in Stage B, just producing missing `.mmdb` files instead of a
disabled provider. `GeoIpEnricher` (`common/geoip.py`) independently
self-disables when those files aren't present, so the two failure modes
compose cleanly: no key -> no files -> no enrichment, with a clear log
trail at each step and no code path that needs to know about both at once.

Runs as its own small scheduler, deliberately separate from `ingest.py`'s
provider scheduler -- this isn't a threat-intel provider, it's
infrastructure the enrichment subsystem depends on.
"""
import io
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.common.geoip import get_enricher
from app.logging_config import get_logger
from app.provider.http import request_with_retry
from app.settings import Settings, get_settings

log = get_logger("threat-intel.geoip_updater")

DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"
EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
DOWNLOAD_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

_scheduler: AsyncIOScheduler | None = None


async def _download_edition(client: httpx.AsyncClient, edition_id: str, license_key: str, dest_dir: Path) -> bool:
    try:
        response = await request_with_retry(
            client,
            "GET",
            DOWNLOAD_URL,
            params={"edition_id": edition_id, "license_key": license_key, "suffix": "tar.gz"},
        )
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 -- a download failure must degrade, not crash the updater
        log.warning("GeoIP updater: failed to download %s: %s", edition_id, exc)
        return False

    try:
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.name.endswith(".mmdb")), None)
            if member is None:
                log.error("GeoIP updater: %s archive contained no .mmdb file", edition_id)
                return False
            extracted = tar.extractfile(member)
            if extracted is None:
                return False
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / f"{edition_id}.mmdb"
            tmp_path = dest_dir / f"{edition_id}.mmdb.tmp"
            tmp_path.write_bytes(extracted.read())
            tmp_path.replace(dest_path)  # atomic swap -- a cancelled/interrupted download can't leave a truncated .mmdb
    except Exception as exc:  # noqa: BLE001
        log.error("GeoIP updater: failed to extract %s: %s", edition_id, exc)
        return False

    log.info("GeoIP updater: refreshed %s -> %s", edition_id, dest_path)
    return True


async def run_update_cycle(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if not settings.MAXMIND_LICENSE_KEY:
        log.warning("GeoIP enrichment disabled: MAXMIND_LICENSE_KEY not set")
        return

    dest_dir = Path(settings.GEOIP_DB_DIR)
    any_refreshed = False
    async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT) as client:
        for edition_id in EDITIONS:
            if await _download_edition(client, edition_id, settings.MAXMIND_LICENSE_KEY, dest_dir):
                any_refreshed = True

    if any_refreshed:
        get_enricher().reload()  # pick up the new file(s) without a service restart


def start_geoip_scheduler(settings: Settings) -> AsyncIOScheduler | None:
    global _scheduler
    if not settings.MAXMIND_LICENSE_KEY:
        log.warning("GeoIP enrichment disabled: MAXMIND_LICENSE_KEY not set")
        return None

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_update_cycle,
        "interval",
        seconds=settings.GEOIP_UPDATE_POLL_SECONDS,
        args=[settings],
        id="geoip-updater",
        next_run_time=datetime.now(timezone.utc),
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )
    scheduler.start()
    log.info("GeoIP updater scheduler started (refresh every %ss)", settings.GEOIP_UPDATE_POLL_SECONDS)
    _scheduler = scheduler
    return scheduler


def stop_geoip_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.pause()
        _scheduler.shutdown(wait=False)
    _scheduler = None
