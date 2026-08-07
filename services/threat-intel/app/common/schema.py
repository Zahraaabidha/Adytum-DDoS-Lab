"""Canonical normalized threat-intel event schema.

Every provider connector (Stage B) must translate its provider-specific
payload into a `ThreatEvent` before handing it to `dedup.merge_or_insert`.
This is the one shape the rest of the service (storage, API, correlation)
is written against, so a new provider never requires touching anything
outside its own connector module.
"""
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatEvent(BaseModel):
    ioc: str = Field(..., description="Indicator of compromise, typically an IP address")
    ioc_type: str = Field(default="ip", description="ip | cidr | domain (only 'ip'/'cidr' populate the globe/map)")
    country: str | None = None
    lat: float | None = None
    lon: float | None = None
    threat_type: str = Field(..., description="Normalized category, e.g. botnet_cc, compromised_host, scanner")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source: str = Field(..., description="Provider name, e.g. 'threatfox'")
    timestamp: datetime = Field(..., description="Event/report time as provided by the source")
    category: str | None = Field(default=None, description="Provider's raw category/tag, kept verbatim")
    asn: int | None = None
    organization: str | None = None
    attack_family: str | None = Field(default=None, description="e.g. malware family, botnet name")
    raw: dict[str, Any] = Field(default_factory=dict, description="Original provider payload, for audit/debug")

    @field_validator("timestamp")
    @classmethod
    def _ensure_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class CveEvent(BaseModel):
    """CISA KEV / NVD entries are keyed by CVE ID, not IP, and have no
    coordinates -- they are stored separately from `ThreatEvent`/`iocs` so
    the globe/map endpoints (which need lat/lon) never have to filter them
    out at query time."""

    cve_id: str
    description: str | None = None
    severity: str | None = None
    published: datetime | None = None
    source: str
    vendor_project: str | None = None
    product: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
