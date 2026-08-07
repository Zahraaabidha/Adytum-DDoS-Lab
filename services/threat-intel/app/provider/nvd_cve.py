"""NIST NVD CVE 2.0 feed -- no API key required for low-volume, unauthenticated use.

https://services.nvd.nist.gov/rest/json/cves/2.0. NVD's documented
anonymous rate limit is a handful of requests per 30s, so this provider
polls infrequently (see `poll_interval_seconds`) and asks for a bounded
page of recently *published* CVEs each cycle rather than the full catalog.
CVE-ID-keyed -- persists to `cves`, like `cisa_kev.py`.
"""
from datetime import datetime, timedelta, timezone

import httpx

from app.common.schema import CveEvent
from app.logging_config import get_logger
from app.provider.base import ThreatProvider, register_provider
from app.provider.http import request_with_retry
from app.settings import Settings

log = get_logger("threat-intel.provider.nvd_cve")

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LOOKBACK_HOURS = 24
RESULTS_PER_PAGE = 100


def _nvd_timestamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _extract_severity(cve: dict) -> str | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            return entries[0].get("cvssData", {}).get("baseSeverity") or entries[0].get("baseSeverity")
    return None


def _extract_description(cve: dict) -> str | None:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value")
    return None


def _parse_published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@register_provider
class NvdCveProvider(ThreatProvider):
    name = "nvd_cve"
    requires_key = False
    poll_interval_seconds = 900
    event_kind = "cve"

    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> list[CveEvent]:
        now = datetime.now(timezone.utc)
        params = {
            "pubStartDate": _nvd_timestamp(now - timedelta(hours=LOOKBACK_HOURS)),
            "pubEndDate": _nvd_timestamp(now),
            "resultsPerPage": str(RESULTS_PER_PAGE),
        }
        try:
            response = await request_with_retry(client, "GET", API_URL, params=params)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            log.warning("NVD CVE fetch failed: %s", exc)
            return []

        events: list[CveEvent] = []
        for entry in payload.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            try:
                events.append(
                    CveEvent(
                        cve_id=cve["id"],
                        description=_extract_description(cve),
                        severity=_extract_severity(cve),
                        published=_parse_published(cve.get("published")),
                        source=self.name,
                        raw=cve,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("NVD CVE: skipping malformed item: %s", exc)
                continue

        log.info("NVD CVE: fetched %d CVE(s) published in the last %dh", len(events), LOOKBACK_HOURS)
        return events
