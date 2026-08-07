"""Shared HTTP plumbing reused by every connector.

Factored out so retry/timeout/User-Agent policy lives in one place instead
of being copy-pasted into each provider module (SOLID: connectors own only
their source-specific parsing, not generic HTTP resilience).
"""
import asyncio

import httpx

from app.logging_config import get_logger

log = get_logger("threat-intel.provider.http")

DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
USER_AGENT = "SentinelLab-ThreatIntel/1.0 (+https://github.com/; read-only public feed ingestion)"


def new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_attempts: int = 3,
    backoff_seconds: float = 1.5,
    **kwargs,
) -> httpx.Response:
    """Retries transient network/5xx failures with exponential backoff.
    Raises on the final attempt's failure -- callers (connectors) are
    expected to catch that and return `[]` rather than let it propagate."""
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = await client.request(method, url, **kwargs)
            if response.status_code >= 500:
                response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.TransportError) as exc:
            last_exc = exc
            if attempt < max_attempts:
                log.debug("Attempt %d/%d failed for %s %s: %s -- retrying", attempt, max_attempts, method, url, exc)
                await asyncio.sleep(backoff_seconds * attempt)
    assert last_exc is not None
    raise last_exc
