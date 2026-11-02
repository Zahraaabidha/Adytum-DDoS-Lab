"""GeoIP subsystem transparency endpoint -- same pattern as
`/api/providers/status`: report what's actually configured/loaded rather
than making the dashboard guess from missing lat/lon fields.
"""
from pathlib import Path

from fastapi import APIRouter

from app.common.geoip import ASN_DB_FILENAME, CITY_DB_FILENAME, get_enricher
from app.settings import get_settings

router = APIRouter(prefix="/api/geoip", tags=["geoip"])


@router.get("/status")
async def geoip_status():
    settings = get_settings()
    db_dir = Path(settings.GEOIP_DB_DIR)
    enricher = get_enricher()
    return {
        **enricher.status(),
        "license_key_configured": bool(settings.MAXMIND_LICENSE_KEY),
        "city_db_present": (db_dir / CITY_DB_FILENAME).exists(),
        "asn_db_present": (db_dir / ASN_DB_FILENAME).exists(),
        "enrichment_available": enricher.is_available(),
        "fallback_api_enabled": settings.GEOIP_FALLBACK_API_ENABLED,
    }
