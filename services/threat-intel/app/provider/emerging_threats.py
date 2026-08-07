"""Emerging Threats Open (Proofpoint) compromised-hosts list -- no API key required.

Plaintext, one IP per line: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
"""
import ipaddress
from datetime import datetime, timezone

import httpx

from app.common.schema import ThreatEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.emerging_threats")

FEED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"


@register_provider
class EmergingThreatsProvider(ThreatProvider):
    name = "emerging_threats"
    requires_key = False
    poll_interval_seconds = 900
    event_kind = "ioc"

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[ThreatEvent]:
        try:
            response = await request_with_retry(client, "GET", FEED_URL)
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("Emerging Threats fetch failed: %s", exc)
            return []

        now = datetime.now(timezone.utc)
        events: list[ThreatEvent] = []
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_address(line)
            except ValueError:
                continue
            events.append(
                ThreatEvent(
                    ioc=line,
                    ioc_type="ip",
                    threat_type="compromised_host",
                    confidence_score=0.5,
                    source=self.name,
                    timestamp=now,
                    category="emerging_threats_compromised",
                    raw={"ip": line},
                )
            )

        log.info("Emerging Threats: fetched %d compromised host(s)", len(events))
        return events
