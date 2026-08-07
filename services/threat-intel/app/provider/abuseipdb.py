"""AbuseIPDB blacklist -- requires a free API key.

https://docs.abuseipdb.com/#blacklist-endpoint. `is_enabled()` gates this
connector on `settings.ABUSEIPDB_API_KEY` being non-empty; when it's unset,
the ingestion scheduler (Stage C) never calls `fetch()` at all -- every
other provider keeps running normally.
"""
from datetime import datetime, timezone

import httpx

from app.common.schema import ThreatEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.abuseipdb")

API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
MIN_CONFIDENCE_MINIMUM = 50


@register_provider
class AbuseIpdbProvider(ThreatProvider):
    name = "abuseipdb"
    requires_key = True
    poll_interval_seconds = 900
    event_kind = "ioc"

    def is_enabled(self, settings: Settings) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[ThreatEvent]:
        if not settings.ABUSEIPDB_API_KEY:
            # Defensive: fetch() should never be called while disabled, but
            # a provider must never assume its caller got that right.
            return []
        try:
            response = await request_with_retry(
                client,
                "GET",
                API_URL,
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"confidenceMinimum": str(MIN_CONFIDENCE_MINIMUM)},
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("AbuseIPDB fetch failed: %s", exc)
            return []

        now = datetime.now(timezone.utc)
        events: list[ThreatEvent] = []
        for item in payload.get("data", []):
            try:
                events.append(
                    ThreatEvent(
                        ioc=item["ipAddress"],
                        ioc_type="ip",
                        threat_type="reported_abuse",
                        confidence_score=min(1.0, float(item.get("abuseConfidenceScore", 50)) / 100.0),
                        source=self.name,
                        timestamp=now,
                        category="abuseipdb_blacklist",
                        raw=item,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("AbuseIPDB: skipping malformed item: %s", exc)
                continue

        log.info("AbuseIPDB: fetched %d event(s)", len(events))
        return events
