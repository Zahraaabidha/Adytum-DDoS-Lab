"""Common connector interface + provider registry.

A provider is any class implementing `ThreatProvider` and decorated with
`@register_provider`. Stage C's ingestion scheduler iterates
`PROVIDER_REGISTRY`, skips instances where `is_enabled()` is False (this is
the whole mechanism behind "a missing API key disables only that
provider"), and schedules each enabled one on its own
`poll_interval_seconds`. A provider that raises inside `fetch()` is caught
by the scheduler per-cycle, logged, and skipped -- it never takes down the
service or blocks other providers (enforced in Stage C, not here, but the
interface is written narrow enough -- one `fetch()` call per cycle -- that
there's no shared mutable state between providers to corrupt).
"""
from abc import ABC, abstractmethod
from typing import Literal

import httpx

from app.common.schema import CveEvent, ThreatEvent
from app.settings import Settings

PROVIDER_REGISTRY: list[type["ThreatProvider"]] = []


def register_provider(cls: type["ThreatProvider"]) -> type["ThreatProvider"]:
    PROVIDER_REGISTRY.append(cls)
    return cls


class ThreatProvider(ABC):
    """Subclass this and add `@register_provider` to plug in a new source."""

    name: str
    requires_key: bool = False
    poll_interval_seconds: int = 300
    # "ioc" providers (ip-centric, have coordinates) persist to the `iocs`
    # table; "cve" providers (CISA KEV, NVD) persist to `cves` instead --
    # see schema.py's ThreatEvent/CveEvent docstrings for why they're kept
    # apart. Stage C's ingestion loop dispatches on this field.
    event_kind: Literal["ioc", "cve"] = "ioc"

    def is_enabled(self, settings: Settings) -> bool:
        """Override when `requires_key=True` to check the relevant
        settings field is non-empty. Default: always enabled (correct for
        every no-key provider)."""
        return True

    @abstractmethod
    async def fetch(self, client: httpx.AsyncClient, settings: Settings) -> "list[ThreatEvent] | list[CveEvent]":
        """Fetch and normalize this cycle's events. Return an empty list
        -- never fabricated data -- if the source is unreachable, rate
        limited, or has nothing new. Implementations must catch their own
        request/parsing errors internally (log + return `[]`) rather than
        raising, so one provider's outage can never take down the ingestion
        service or block other providers."""
        raise NotImplementedError
