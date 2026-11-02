"""Verifies the enrichment pass (app/enrich.py) applies GeoResult data to
an Ioc row, skips already-enriched rows, and that the geo cache prevents a
second lookup for an IP already seen -- using an in-memory fake cache so
these tests don't need a real Redis.
"""
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.common.geoip import GeoResult
from app.common.models import Ioc
from app.enrich import enrich_ioc

pytestmark = pytest.mark.asyncio


def make_ioc(**overrides) -> Ioc:
    defaults = dict(
        ioc="8.8.8.8",
        ioc_type="ip",
        threat_type="botnet_cc",
        confidence_score=0.6,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        source_count=1,
    )
    defaults.update(overrides)
    return Ioc(**defaults)


class FakeCache:
    """In-memory stand-in for app.common.geo_cache, tracking call counts
    so tests can assert a second enrichment of the same IP is a cache hit
    rather than a second lookup."""

    def __init__(self):
        self.store: dict[str, dict | None] = {}
        self.get_calls = 0
        self.set_calls = 0

    async def get_cached(self, ip: str):
        self.get_calls += 1
        if ip in self.store:
            return True, self.store[ip]
        return False, None

    async def set_cached(self, ip: str, result):
        self.set_calls += 1
        self.store[ip] = result


async def test_enrich_applies_geoip_result_to_ioc():
    ioc = make_ioc()
    fake_cache = FakeCache()
    fake_result = GeoResult(country="US", city="Mountain View", lat=37.386, lon=-122.0838, asn=15169, organization="GOOGLE")

    with (
        patch("app.enrich.geo_cache", fake_cache),
        patch("app.enrich.get_enricher") as mock_get_enricher,
    ):
        mock_get_enricher.return_value.lookup.return_value = fake_result
        applied = await enrich_ioc(AsyncMock(), ioc)

    assert applied is True
    assert ioc.country == "US"
    assert ioc.city == "Mountain View"
    assert ioc.lat == pytest.approx(37.386)
    assert ioc.lon == pytest.approx(-122.0838)
    assert ioc.asn == 15169
    assert ioc.organization == "GOOGLE"
    assert ioc.geo_source == "geolite2"
    assert ioc.geo_enriched_at is not None


async def test_already_enriched_ioc_is_skipped_entirely():
    ioc = make_ioc(geo_enriched_at=datetime.now(timezone.utc), country="US")
    fake_cache = FakeCache()

    with (
        patch("app.enrich.geo_cache", fake_cache),
        patch("app.enrich.get_enricher") as mock_get_enricher,
    ):
        applied = await enrich_ioc(AsyncMock(), ioc)

    assert applied is False
    mock_get_enricher.assert_not_called()
    assert fake_cache.get_calls == 0  # never even touches the cache for an already-done row


async def test_cve_kind_rows_are_not_applicable():
    ioc = make_ioc(ioc="CVE-2026-0001", ioc_type="cve")
    fake_cache = FakeCache()

    with patch("app.enrich.geo_cache", fake_cache):
        applied = await enrich_ioc(AsyncMock(), ioc)

    assert applied is False
    assert fake_cache.get_calls == 0


async def test_second_ioc_with_same_ip_is_a_cache_hit_not_a_second_lookup():
    """Two different Ioc rows (different threat_type -> different dedup
    key) sharing the same IP: the second enrichment must not call the
    GeoIP database again."""
    fake_cache = FakeCache()
    fake_result = GeoResult(country="AU", city="Sydney", lat=-33.8688, lon=151.2093, asn=None, organization=None)

    with (
        patch("app.enrich.geo_cache", fake_cache),
        patch("app.enrich.get_enricher") as mock_get_enricher,
    ):
        mock_get_enricher.return_value.lookup.return_value = fake_result

        ioc_a = make_ioc(ioc="1.1.1.1", threat_type="botnet_cc")
        await enrich_ioc(AsyncMock(), ioc_a)

        ioc_b = make_ioc(ioc="1.1.1.1", threat_type="compromised_host")
        await enrich_ioc(AsyncMock(), ioc_b)

        assert mock_get_enricher.return_value.lookup.call_count == 1  # only the FIRST call hit the "database"
        assert ioc_b.country == "AU"  # second row still got the data, from cache
        assert ioc_b.city == "Sydney"


async def test_negative_lookup_marks_enriched_but_is_not_cached():
    """An IP the local DB has no entry for: the row is marked attempted, but
    the negative is never cached (it could outlive a database update)."""
    fake_cache = FakeCache()

    with (
        patch("app.enrich.geo_cache", fake_cache),
        patch("app.enrich.get_enricher") as mock_get_enricher,
    ):
        mock_get_enricher.return_value.lookup.return_value = None
        ioc = make_ioc(ioc="203.0.113.5")
        applied = await enrich_ioc(AsyncMock(), ioc)

    assert applied is True
    assert ioc.country is None
    assert ioc.lat is None and ioc.lon is None  # never invented
    assert ioc.geo_enriched_at is not None
    assert "203.0.113.5" not in fake_cache.store


async def test_unavailable_database_leaves_row_unenriched_and_uncached():
    """No database loaded: the row must stay eligible for a later pass."""
    fake_cache = FakeCache()

    with (
        patch("app.enrich.geo_cache", fake_cache),
        patch("app.enrich.get_enricher") as mock_get_enricher,
    ):
        mock_get_enricher.return_value.is_available.return_value = False
        ioc = make_ioc()
        applied = await enrich_ioc(AsyncMock(), ioc)

    assert applied is False
    assert ioc.geo_enriched_at is None
    assert ioc.lat is None
    assert fake_cache.store == {}
