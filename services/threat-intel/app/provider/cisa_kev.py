"""CISA Known Exploited Vulnerabilities (KEV) catalog -- no API key required.

CVE-ID-keyed, not IP-centric, so this connector produces `CveEvent`s that
persist to the `cves` table rather than `iocs` -- see `event_kind` on
`ThreatProvider` and the docstrings on `ThreatEvent`/`CveEvent` in
`schema.py`.
"""
from datetime import datetime, timezone

import httpx

from app.common.schema import CveEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.cisa_kev")

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@register_provider
class CisaKevProvider(ThreatProvider):
    name = "cisa_kev"
    requires_key = False
    poll_interval_seconds = 3600
    event_kind = "cve"

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[CveEvent]:
        try:
            response = await request_with_retry(client, "GET", FEED_URL)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("CISA KEV fetch failed: %s", exc)
            return []

        events: list[CveEvent] = []
        for item in payload.get("vulnerabilities", []):
            try:
                events.append(
                    CveEvent(
                        cve_id=item["cveID"],
                        description=item.get("shortDescription"),
                        severity="known_exploited",  # KEV membership itself is the severity signal it provides
                        published=_parse_date(item.get("dateAdded")),
                        source=self.name,
                        vendor_project=item.get("vendorProject"),
                        product=item.get("product"),
                        raw=item,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("CISA KEV: skipping malformed item: %s", exc)
                continue

        log.info("CISA KEV: fetched %d CVE(s)", len(events))
        return events
