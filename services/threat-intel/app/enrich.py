"""Geolocation enrichment pass -- deliberately its own module rather than
folded into `dedup.merge_or_insert`, so this subsystem can be built,
tested, and reasoned about independently of the ingestion pipeline it
plugs into (`ingest.py` calls `enrich_ioc` once per persisted IOC; that's
the entire integration surface).

Only IOC-kind rows with `ioc_type in ("ip", "cidr")` and no prior
`geo_enriched_at` are candidates -- CVEs have no IP to geolocate. An
already-enriched row is skipped even if the lookup previously came back
empty (private/reserved address, or no local database available at the
time), so a permanently un-geolocatable address isn't retried forever.
"""
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.common import geo_cache
from app.common.geoip import GeoResult, get_enricher
from app.common.models import Ioc
from app.logging_config import get_logger

log = get_logger("threat-intel.enrich")

ENRICHABLE_IOC_TYPES = ("ip", "cidr")


def _lookup_address(ioc: Ioc) -> str:
    # CIDRs are stored as e.g. "185.220.101.0/24" (see spamhaus_drop.py) --
    # geolocate the network address itself, not a fabricated host within it.
    return ioc.ioc.split("/")[0] if ioc.ioc_type == "cidr" else ioc.ioc


def _result_to_dict(result: GeoResult) -> dict[str, Any]:
    return {
        "country": result.country,
        "city": result.city,
        "lat": result.lat,
        "lon": result.lon,
        "asn": result.asn,
        "organization": result.organization,
        "source": result.source,
    }


async def enrich_ioc(session: AsyncSession, ioc: Ioc) -> bool:
    """Mutates `ioc` in place (caller flushes/commits). Returns True if an
    enrichment attempt was made this call (whether or not it found data) --
    False means the row was skipped as not applicable or already done."""
    if ioc.geo_enriched_at is not None:
        return False
    if ioc.ioc_type not in ENRICHABLE_IOC_TYPES:
        return False

    address = _lookup_address(ioc)
    found, cached_result = await geo_cache.get_cached(address)
    if found:
        result_dict = cached_result
    else:
        result = get_enricher().lookup(address)
        result_dict = _result_to_dict(result) if result is not None else None
        await geo_cache.set_cached(address, result_dict)

    if result_dict is not None:
        ioc.country = result_dict.get("country") or ioc.country
        ioc.city = result_dict.get("city")
        if result_dict.get("lat") is not None:
            ioc.lat = result_dict["lat"]
        if result_dict.get("lon") is not None:
            ioc.lon = result_dict["lon"]
        ioc.asn = result_dict.get("asn") or ioc.asn
        ioc.organization = result_dict.get("organization") or ioc.organization
        ioc.geo_source = result_dict.get("source")

    ioc.geo_enriched_at = datetime.now(timezone.utc)
    return True
