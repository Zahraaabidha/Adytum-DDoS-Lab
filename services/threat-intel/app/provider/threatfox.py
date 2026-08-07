"""abuse.ch ThreatFox connector -- no API key required.

API docs: https://threatfox.abuse.ch/api/. We only keep IOCs of type
`ip:port` (ThreatFox also reports domains/URLs/hashes, which don't fit the
IP-centric `iocs` schema and are skipped). ThreatFox does not provide
geolocation, so `country`/`lat`/`lon` are left `None` here -- Stage A's
schema treats those as optional for exactly this reason.
"""
from datetime import datetime, timezone

import httpx

from app.common.schema import ThreatEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.threatfox")

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


@register_provider
class ThreatFoxProvider(ThreatProvider):
    name = "threatfox"
    requires_key = False
    poll_interval_seconds = 300
    event_kind = "ioc"

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[ThreatEvent]:
        try:
            response = await request_with_retry(client, "POST", API_URL, json={"query": "get_iocs", "days": 1})
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001 -- any failure here must degrade to "no events", never crash
            log.warning("ThreatFox fetch failed: %s", exc)
            return []

        if payload.get("query_status") != "ok":
            log.info("ThreatFox returned query_status=%s, no data this cycle", payload.get("query_status"))
            return []

        events: list[ThreatEvent] = []
        for item in payload.get("data", []):
            try:
                if item.get("ioc_type") != "ip:port":
                    continue
                ip = str(item["ioc"]).split(":")[0]
                events.append(
                    ThreatEvent(
                        ioc=ip,
                        ioc_type="ip",
                        threat_type=item.get("threat_type") or "unknown",
                        confidence_score=min(1.0, float(item.get("confidence_level", 50)) / 100.0),
                        source=self.name,
                        timestamp=_parse_timestamp(item.get("last_seen") or item.get("first_seen")),
                        category=item.get("threat_type_desc"),
                        attack_family=item.get("malware_printable") or item.get("malware"),
                        raw=item,
                    )
                )
            except Exception as exc:  # noqa: BLE001 -- one malformed row must not drop the rest of the batch
                log.debug("ThreatFox: skipping malformed item: %s", exc)
                continue

        log.info("ThreatFox: fetched %d ip:port event(s)", len(events))
        return events
