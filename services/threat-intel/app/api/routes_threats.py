"""REST endpoints over the normalized threat-intel dataset.

Aggregate/list endpoints are Redis-cached with short TTLs -- traffic here
is read-heavy and the underlying data changes at most as often as the
fastest provider's poll interval (5 minutes). `/search` is deliberately
uncached: its parameter space is effectively unbounded, so caching it
would mostly just fill Redis with one-hit keys.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.common import cache
from app.common.db import session_scope
from app.common.models import Cve, Ioc

router = APIRouter(prefix="/api/threats", tags=["threats"])

LIVE_LIMIT_DEFAULT = 100
MAP_LIMIT = 2000
MAP_CACHE_TTL = 30
AGG_CACHE_TTL = 60
STATS_CACHE_TTL = 30


def _ioc_to_dict(ioc: Ioc) -> dict:
    return {
        "ioc": ioc.ioc,
        "ioc_type": ioc.ioc_type,
        "country": ioc.country,
        "lat": ioc.lat,
        "lon": ioc.lon,
        "asn": ioc.asn,
        "organization": ioc.organization,
        "threat_type": ioc.threat_type,
        "attack_family": ioc.attack_family,
        "category": ioc.category,
        "confidence_score": ioc.confidence_score,
        "source_count": ioc.source_count,
        "first_seen": ioc.first_seen.isoformat(),
        "last_seen": ioc.last_seen.isoformat(),
    }


@router.get("/live")
async def live(limit: int = Query(default=LIVE_LIMIT_DEFAULT, le=500)):
    """Most recently updated IOCs -- the dashboard's live feed source."""
    async with session_scope() as session:
        result = await session.execute(select(Ioc).order_by(Ioc.last_seen.desc()).limit(limit))
        return {"events": [_ioc_to_dict(row) for row in result.scalars().all()]}


@router.get("/map")
async def threats_map(
    since_hours: int = 24,
    country: str | None = None,
    threat_type: str | None = None,
    min_confidence: float = 0.0,
):
    """Coordinates + metadata for the globe. Only IOCs with known lat/lon
    are returned -- Spamhaus/ET/ThreatFox events without geolocation are
    invisible here until Stage C.5 enrichment lands."""
    cache_key = f"threats:map:{since_hours}:{country}:{threat_type}:{min_confidence}"
    cached = await cache.get_json(cache_key)
    if cached is not None:
        return cached

    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    stmt = select(Ioc).where(
        Ioc.last_seen >= since,
        Ioc.confidence_score >= min_confidence,
        Ioc.lat.is_not(None),
        Ioc.lon.is_not(None),
    )
    if country:
        stmt = stmt.where(Ioc.country == country)
    if threat_type:
        stmt = stmt.where(Ioc.threat_type == threat_type)
    stmt = stmt.order_by(Ioc.last_seen.desc()).limit(MAP_LIMIT)

    async with session_scope() as session:
        result = await session.execute(stmt)
        payload = {"events": [_ioc_to_dict(row) for row in result.scalars().all()]}

    await cache.set_json(cache_key, payload, MAP_CACHE_TTL)
    return payload


@router.get("/countries")
async def countries():
    cache_key = "threats:agg:countries"
    cached = await cache.get_json(cache_key)
    if cached is not None:
        return cached

    async with session_scope() as session:
        result = await session.execute(
            select(Ioc.country, func.count().label("count"))
            .where(Ioc.country.is_not(None))
            .group_by(Ioc.country)
            .order_by(func.count().desc())
            .limit(50)
        )
        payload = {"countries": [{"country": c, "count": n} for c, n in result.all()]}

    await cache.set_json(cache_key, payload, AGG_CACHE_TTL)
    return payload


@router.get("/types")
async def types():
    cache_key = "threats:agg:types"
    cached = await cache.get_json(cache_key)
    if cached is not None:
        return cached

    async with session_scope() as session:
        result = await session.execute(
            select(Ioc.threat_type, func.count().label("count")).group_by(Ioc.threat_type).order_by(func.count().desc())
        )
        payload = {"types": [{"threat_type": t, "count": n} for t, n in result.all()]}

    await cache.set_json(cache_key, payload, AGG_CACHE_TTL)
    return payload


@router.get("/timeline")
async def timeline(bucket: str = "hour", since_hours: int = 48):
    bucket = bucket if bucket in ("hour", "day") else "hour"
    cache_key = f"threats:agg:timeline:{bucket}:{since_hours}"
    cached = await cache.get_json(cache_key)
    if cached is not None:
        return cached

    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    async with session_scope() as session:
        result = await session.execute(
            select(func.date_trunc(bucket, Ioc.last_seen).label("bucket"), func.count().label("count"))
            .where(Ioc.last_seen >= since)
            .group_by("bucket")
            .order_by("bucket")
        )
        payload = {"buckets": [{"bucket": b.isoformat(), "count": n} for b, n in result.all()]}

    await cache.set_json(cache_key, payload, AGG_CACHE_TTL)
    return payload


@router.get("/search")
async def search(ip: str | None = None, asn: int | None = None, country: str | None = None, limit: int = 100):
    stmt = select(Ioc)
    if ip:
        stmt = stmt.where(Ioc.ioc == ip)
    if asn is not None:
        stmt = stmt.where(Ioc.asn == asn)
    if country:
        stmt = stmt.where(Ioc.country == country)
    stmt = stmt.order_by(Ioc.last_seen.desc()).limit(min(limit, 500))

    async with session_scope() as session:
        result = await session.execute(stmt)
        return {"results": [_ioc_to_dict(row) for row in result.scalars().all()]}


@router.get("/stats")
async def stats():
    cache_key = "threats:agg:stats"
    cached = await cache.get_json(cache_key)
    if cached is not None:
        return cached

    async with session_scope() as session:
        total_iocs = (await session.execute(select(func.count()).select_from(Ioc))).scalar_one()
        total_cves = (await session.execute(select(func.count()).select_from(Cve))).scalar_one()
        distinct_countries = (
            await session.execute(select(func.count(func.distinct(Ioc.country))).where(Ioc.country.is_not(None)))
        ).scalar_one()
        top_family_row = (
            await session.execute(
                select(Ioc.attack_family, func.count().label("count"))
                .where(Ioc.attack_family.is_not(None))
                .group_by(Ioc.attack_family)
                .order_by(func.count().desc())
                .limit(1)
            )
        ).first()

    payload = {
        "total_iocs": total_iocs,
        "total_cves": total_cves,
        "distinct_countries": distinct_countries,
        "top_attack_family": top_family_row[0] if top_family_row else None,
    }
    await cache.set_json(cache_key, payload, STATS_CACHE_TTL)
    return payload
