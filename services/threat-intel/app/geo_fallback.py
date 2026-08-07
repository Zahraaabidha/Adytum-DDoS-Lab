"""Optional public IP-geolocation API fallback -- per the approved design,
reserved for interactive single-IP lookups only and OFF by default
(`GEOIP_FALLBACK_API_ENABLED`). Never called from the bulk ingestion path
(`enrich.py`/`ingest.py` never import this module) -- only a future
single-IP lookup path (e.g. an on-demand endpoint) would call
`lookup_via_fallback` after checking the flag and finding no local-DB
result, to avoid sending every observed malicious IP to a third party
by default.

Uses ip-api.com's free, keyless endpoint since the local-DB path already
covers the common case and this is meant to be an occasional supplement,
not a primary source needing an account.
"""
import httpx

from app.common.geoip import GeoResult
from app.logging_config import get_logger
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.geo_fallback")

API_URL_TEMPLATE = "http://ip-api.com/json/{ip}"
FALLBACK_SOURCE = "fallback_api"


async def lookup_via_fallback(client: httpx.AsyncClient, ip: str, settings: Settings) -> GeoResult | None:
    if not settings.GEOIP_FALLBACK_API_ENABLED:
        return None
    try:
        response = await request_with_retry(
            client, "GET", API_URL_TEMPLATE.format(ip=ip), params={"fields": "status,country,city,lat,lon,as,org"}
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 -- fallback lookups must degrade, not raise
        log.warning("Fallback geolocation lookup failed for %s: %s", ip, exc)
        return None

    if payload.get("status") != "success":
        return None

    asn = None
    as_field = payload.get("as")  # e.g. "AS15169 Google LLC"
    if as_field and as_field.startswith("AS"):
        try:
            asn = int(as_field.split()[0][2:])
        except ValueError:
            asn = None

    return GeoResult(
        country=payload.get("country"),
        city=payload.get("city"),
        lat=payload.get("lat"),
        lon=payload.get("lon"),
        asn=asn,
        organization=payload.get("org"),
        source=FALLBACK_SOURCE,
    )
