"""Deduplication and multi-source confidence scoring.

An IOC is keyed by `(ioc, threat_type)`. Every sighting is recorded
verbatim in `ioc_sightings` (audit trail); the `iocs` row is an upsert that
only raises `source_count`/`confidence_score` when a *distinct* source has
reported this IOC within `CONFIDENCE_WINDOW_HOURS` -- so ten sightings from
the same feed's daily re-poll don't inflate confidence, but corroboration
across independent feeds does.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.models import Cve, Ioc, IocSighting
from app.common.schema import CveEvent, ThreatEvent
from app.settings import get_settings

# Per-provider trust weight used as the confidence floor for a single-source
# sighting. Curated blocklists (Spamhaus) are weighted highest; open/community
# feeds sit in the middle. Tunable without touching the scoring formula itself.
PROVIDER_BASE_CONFIDENCE: dict[str, float] = {
    "spamhaus_drop": 0.7,
    "threatfox": 0.6,
    "otx": 0.55,
    "abuseipdb": 0.5,
    "emerging_threats": 0.5,
}
DEFAULT_BASE_CONFIDENCE = 0.5
CONFIDENCE_PER_EXTRA_SOURCE = 0.15


async def _distinct_source_count(session: AsyncSession, ioc_id: int, window_start: datetime) -> int:
    result = await session.execute(
        select(func.count(func.distinct(IocSighting.source))).where(
            IocSighting.ioc_id == ioc_id, IocSighting.reported_at >= window_start
        )
    )
    return result.scalar_one()


def _compute_confidence(source: str, distinct_sources: int) -> float:
    base = PROVIDER_BASE_CONFIDENCE.get(source, DEFAULT_BASE_CONFIDENCE)
    boosted = base + CONFIDENCE_PER_EXTRA_SOURCE * max(0, distinct_sources - 1)
    return min(1.0, boosted)


async def merge_or_insert(session: AsyncSession, event: ThreatEvent) -> Ioc:
    """Inserts a sighting and upserts the parent IOC row. Caller is
    responsible for committing the session (kept out of this function so
    an ingestion cycle can batch many events in one transaction)."""
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=get_settings().CONFIDENCE_WINDOW_HOURS)

    result = await session.execute(select(Ioc).where(Ioc.ioc == event.ioc, Ioc.threat_type == event.threat_type))
    ioc_row = result.scalar_one_or_none()

    if ioc_row is None:
        ioc_row = Ioc(
            ioc=event.ioc,
            ioc_type=event.ioc_type,
            country=event.country,
            lat=event.lat,
            lon=event.lon,
            asn=event.asn,
            organization=event.organization,
            threat_type=event.threat_type,
            attack_family=event.attack_family,
            category=event.category,
            confidence_score=_compute_confidence(event.source, distinct_sources=1),
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            source_count=1,
        )
        session.add(ioc_row)
        await session.flush()  # populate ioc_row.id for the sighting FK below
    else:
        ioc_row.last_seen = max(ioc_row.last_seen, event.timestamp)
        # Refresh descriptive fields with the latest sighting's values when present.
        ioc_row.country = event.country or ioc_row.country
        ioc_row.lat = event.lat if event.lat is not None else ioc_row.lat
        ioc_row.lon = event.lon if event.lon is not None else ioc_row.lon
        ioc_row.asn = event.asn or ioc_row.asn
        ioc_row.organization = event.organization or ioc_row.organization
        ioc_row.attack_family = event.attack_family or ioc_row.attack_family
        ioc_row.category = event.category or ioc_row.category

    session.add(
        IocSighting(
            ioc_id=ioc_row.id,
            source=event.source,
            reported_at=event.timestamp,
            category=event.category,
            raw=event.raw,
        )
    )
    await session.flush()

    distinct_sources = await _distinct_source_count(session, ioc_row.id, window_start)
    ioc_row.source_count = distinct_sources
    ioc_row.confidence_score = _compute_confidence(event.source, distinct_sources)

    return ioc_row


async def upsert_cve(session: AsyncSession, event: CveEvent) -> Cve:
    """CVE-ID-keyed upsert for CISA KEV/NVD events -- the `cves` table
    counterpart to `merge_or_insert` above. Kept as a separate function
    rather than overloading `merge_or_insert` since CVEs have no
    `(ioc, threat_type)` key or sighting history, just a simple
    first_seen/last_seen upsert."""
    now = datetime.now(timezone.utc)
    result = await session.execute(select(Cve).where(Cve.cve_id == event.cve_id))
    cve_row = result.scalar_one_or_none()

    if cve_row is None:
        cve_row = Cve(
            cve_id=event.cve_id,
            description=event.description,
            severity=event.severity,
            published=event.published,
            source=event.source,
            vendor_project=event.vendor_project,
            product=event.product,
            first_seen=now,
            last_seen=now,
        )
        session.add(cve_row)
    else:
        cve_row.last_seen = now
        cve_row.description = event.description or cve_row.description
        cve_row.severity = event.severity or cve_row.severity
        cve_row.vendor_project = event.vendor_project or cve_row.vendor_project
        cve_row.product = event.product or cve_row.product

    await session.flush()
    return cve_row
