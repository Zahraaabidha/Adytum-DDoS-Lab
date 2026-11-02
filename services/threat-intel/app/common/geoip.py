"""Local MaxMind GeoLite2 lookups -- the primary (and, by default, only)
geolocation source, per the approved design: local DB for all bulk
ingestion-time enrichment; a public API is reserved for a later,
off-by-default, single-IP interactive fallback (see `geo_fallback.py`).

Self-disables (every lookup returns `None`) when the `.mmdb` file isn't
present at `GEOIP_DB_DIR` -- the same missing-key self-disable pattern used
for AbuseIPDB/OTX in Stage B, just gated on a file's presence instead of an
env var being set. The ASN database is optional on top of that: if it's
missing but the City database is present, country/city/lat/lon are still
enriched and only asn/organization stay `None`.
"""
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import geoip2.database
import geoip2.errors

from app.logging_config import get_logger
from app.settings import get_settings

log = get_logger("threat-intel.geoip")

CITY_DB_FILENAME = "GeoLite2-City.mmdb"
ASN_DB_FILENAME = "GeoLite2-ASN.mmdb"


@dataclass
class GeoResult:
    country: str | None
    city: str | None
    lat: float | None
    lon: float | None
    asn: int | None
    organization: str | None
    source: str = "geolite2"


def _is_routable(ip: str) -> bool:
    """Never fabricate geolocation for addresses that structurally can't
    have one -- private/loopback/link-local/reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # `is_global` is False for private, loopback, link-local, reserved,
    # CGNAT (100.64/10) and documentation ranges; multicast is excluded too.
    return addr.is_global and not addr.is_multicast


class GeoIpEnricher:
    """Lazily opens the `.mmdb` reader(s) on first use rather than at
    import time, so a service restart always re-checks whether the updater
    has produced a database yet instead of caching a stale "disabled"
    verdict from before the file existed."""

    def __init__(self) -> None:
        self._city_reader: geoip2.database.Reader | None = None
        self._asn_reader: geoip2.database.Reader | None = None
        self._attempted_load = False

    def reload(self) -> None:
        """Called by the updater after a successful refresh so a running
        process picks up newly downloaded databases without a restart."""
        self._attempted_load = False
        self._city_reader = None
        self._asn_reader = None

    def _ensure_loaded(self) -> None:
        if self._attempted_load:
            return
        self._attempted_load = True

        db_dir = Path(get_settings().GEOIP_DB_DIR)
        city_path = db_dir / CITY_DB_FILENAME
        asn_path = db_dir / ASN_DB_FILENAME

        if not city_path.exists():
            log.warning(
                "GeoIP enrichment disabled: no database at %s "
                "(set MAXMIND_LICENSE_KEY and wait for the updater's first cycle)",
                city_path,
            )
            return

        try:
            self._city_reader = geoip2.database.Reader(str(city_path))
            log.info("GeoIP City database loaded from %s", city_path)
        except Exception as exc:  # noqa: BLE001 -- a corrupt/unreadable DB must degrade, not crash the service
            log.error("Failed to load GeoIP City database at %s: %s", city_path, exc)
            self._city_reader = None
            return

        if asn_path.exists():
            try:
                self._asn_reader = geoip2.database.Reader(str(asn_path))
                log.info("GeoIP ASN database loaded from %s", asn_path)
            except Exception as exc:  # noqa: BLE001
                log.warning("Failed to load GeoIP ASN database at %s: %s (asn/organization will stay empty)", asn_path, exc)
                self._asn_reader = None
        else:
            log.info("No GeoIP ASN database at %s -- asn/organization will stay empty", asn_path)

    def status(self) -> dict:
        """What is actually loaded right now (not merely which files exist)."""
        self._ensure_loaded()

        def build_date(reader: geoip2.database.Reader | None) -> str | None:
            if reader is None:
                return None
            return datetime.fromtimestamp(reader.metadata().build_epoch, tz=timezone.utc).date().isoformat()

        return {
            "city_db_loaded": self._city_reader is not None,
            "asn_db_loaded": self._asn_reader is not None,
            "city_db_build_date": build_date(self._city_reader),
            "asn_db_build_date": build_date(self._asn_reader),
        }

    def is_available(self) -> bool:
        self._ensure_loaded()
        return self._city_reader is not None

    def lookup(self, ip: str) -> GeoResult | None:
        self._ensure_loaded()
        if self._city_reader is None:
            return None
        if not _is_routable(ip):
            return None

        try:
            city_response = self._city_reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as exc:  # noqa: BLE001
            log.debug("GeoIP city lookup failed for %s: %s", ip, exc)
            return None

        asn: int | None = None
        organization: str | None = None
        if self._asn_reader is not None:
            try:
                asn_response = self._asn_reader.asn(ip)
                asn = asn_response.autonomous_system_number
                organization = asn_response.autonomous_system_organization
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as exc:  # noqa: BLE001
                log.debug("GeoIP ASN lookup failed for %s: %s", ip, exc)

        return GeoResult(
            country=city_response.country.iso_code,
            city=city_response.city.name,
            lat=city_response.location.latitude,
            lon=city_response.location.longitude,
            asn=asn,
            organization=organization,
        )


_enricher: GeoIpEnricher | None = None


def get_enricher() -> GeoIpEnricher:
    global _enricher
    if _enricher is None:
        _enricher = GeoIpEnricher()
    return _enricher
