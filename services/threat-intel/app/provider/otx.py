"""AlienVault OTX (Open Threat Exchange) -- requires a free API key.

https://otx.alienvault.com/api/v1/pulses/subscribed, header `X-OTX-API-KEY`.
Same self-disable pattern as `abuseipdb.py`: `is_enabled()` checks
`settings.OTX_API_KEY`. Pulses bundle indicators of many types (IPv4,
domain, URL, hash, ...); only `IPv4` indicators fit the IP-centric `iocs`
schema, so everything else is skipped here.
"""
from datetime import datetime, timezone

import httpx

from app.common.schema import ThreatEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.otx")

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
PULSE_LIMIT = 20


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


@register_provider
class OtxProvider(ThreatProvider):
    name = "otx"
    requires_key = True
    poll_interval_seconds = 600
    event_kind = "ioc"

    def is_enabled(self, settings: Settings) -> bool:
        return bool(settings.OTX_API_KEY)

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[ThreatEvent]:
        if not settings.OTX_API_KEY:
            return []
        try:
            response = await request_with_retry(
                client,
                "GET",
                API_URL,
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
                params={"limit": str(PULSE_LIMIT)},
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("OTX fetch failed: %s", exc)
            return []

        events: list[ThreatEvent] = []
        for pulse in payload.get("results", []):
            pulse_ts = _parse_timestamp(pulse.get("created"))
            malware_families = pulse.get("malware_families") or []
            tags = pulse.get("tags") or []
            for indicator in pulse.get("indicators", []):
                try:
                    if indicator.get("type") != "IPv4":
                        continue
                    events.append(
                        ThreatEvent(
                            ioc=indicator["indicator"],
                            ioc_type="ip",
                            threat_type=(tags[0] if tags else "otx_pulse"),
                            confidence_score=0.55,
                            source=self.name,
                            timestamp=pulse_ts,
                            category=pulse.get("name"),
                            attack_family=malware_families[0] if malware_families else None,
                            raw=indicator,
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    log.debug("OTX: skipping malformed indicator: %s", exc)
                    continue

        log.info("OTX: fetched %d IPv4 indicator(s) across %d pulse(s)", len(events), len(payload.get("results", [])))
        return events
