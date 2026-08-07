"""Redis-backed cache of GeoIP lookup results, keyed by IP address.

Independent of `iocs.geo_enriched_at` (which marks a specific *IOC row* as
done): this cache exists because the same IP address can appear across
multiple `Ioc` rows -- the dedup key is `(ioc, threat_type)`, so one IP
flagged by ThreatFox as `botnet_cc` and by Emerging Threats as
`compromised_host` is two separate rows. Caching by IP means the second
row's enrichment is a cache hit, not a second database/API lookup.

Distinguishes "not cached yet" from "cached, and the answer was negative"
(e.g. a private/unresolvable address) so both cases skip a repeat lookup.
"""
import json
from typing import Any

from app.common.cache import get_redis
from app.settings import get_settings

CACHE_PREFIX = "geo:ip:"


async def get_cached(ip: str) -> tuple[bool, dict[str, Any] | None]:
    """Returns (found_in_cache, value). `value` is `None` both when the
    key isn't cached (found=False) and when it's cached as a negative
    result (found=True, value=None) -- callers must check `found`."""
    raw = await get_redis().get(f"{CACHE_PREFIX}{ip}")
    if raw is None:
        return False, None
    return True, json.loads(raw)


async def set_cached(ip: str, result: dict[str, Any] | None) -> None:
    ttl = get_settings().GEOIP_CACHE_TTL_SECONDS
    await get_redis().set(f"{CACHE_PREFIX}{ip}", json.dumps(result), ex=ttl)
