"""Spamhaus DROP/EDROP -- no API key required.

Plaintext CIDR blocklists: https://www.spamhaus.org/drop/drop.txt and
edrop.txt. Each line looks like `185.220.101.0/24 ; SBL401831`. We store
the CIDR itself as the IOC (`ioc_type="cidr"`) rather than expanding it to
every host address -- expanding a /16 into 65k rows would blow up table
size for a blocklist that's meant to be consumed as network ranges, not
individual hosts. This is a deliberate simplification.
"""
from datetime import datetime, timezone

import httpx

from app.common.schema import ThreatEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.spamhaus_drop")

FEED_URLS = [
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
]


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith(";"):
        return None
    parts = line.split(";")
    cidr = parts[0].strip()
    ref = parts[1].strip() if len(parts) > 1 else ""
    if not cidr or "/" not in cidr:
        return None
    return cidr, ref


@register_provider
class SpamhausDropProvider(ThreatProvider):
    name = "spamhaus_drop"
    requires_key = False
    poll_interval_seconds = 3600
    event_kind = "ioc"

    async def _fetch_one(self, client: httpx.AsyncClient, url: str) -> list[ThreatEvent]:
        now = datetime.now(timezone.utc)
        try:
            response = await request_with_retry(client, "GET", url)
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("Spamhaus DROP fetch failed for %s: %s", url, exc)
            return []

        events: list[ThreatEvent] = []
        for raw_line in response.text.splitlines():
            parsed = _parse_line(raw_line)
            if parsed is None:
                continue
            cidr, ref = parsed
            events.append(
                ThreatEvent(
                    ioc=cidr,
                    ioc_type="cidr",
                    threat_type="known_bad_network",
                    confidence_score=0.7,
                    source=self.name,
                    timestamp=now,
                    category="spamhaus_drop",
                    raw={"cidr": cidr, "reference": ref, "list": url.rsplit("/", 1)[-1]},
                )
            )
        return events

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[ThreatEvent]:
        events: list[ThreatEvent] = []
        for url in FEED_URLS:
            events.extend(await self._fetch_one(client, url))
        log.info("Spamhaus DROP: fetched %d network(s)", len(events))
        return events
