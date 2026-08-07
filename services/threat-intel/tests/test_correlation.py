"""Stage I verification: the correlation heuristic's Prometheus-text
parsing, graceful degradation when defense-engine is unreachable, and the
structural no-attribution guarantee (the response never contains anything
other than a percentage, a count, and this module's own fixed feature
names / template sentences).
"""
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from app.correlation.engine import (
    FEATURE_NAMES,
    FIXED_DISCLAIMER,
    UNAVAILABLE_OBSERVATION,
    compute_correlation,
    fetch_sandbox_features,
    parse_prometheus_text,
)
from app.settings import Settings

pytestmark = pytest.mark.asyncio

METRICS_URL = "http://defense-engine:9300/metrics"

SAMPLE_METRICS_TEXT = """
# HELP defense_classifier_attack_confidence Classifier attack-confidence in [0,1]
# TYPE defense_classifier_attack_confidence gauge
defense_classifier_attack_confidence 0.82
# TYPE defense_rate_limit_threshold gauge
defense_rate_limit_threshold 120.5
defense_feature_request_rate 250.0
defense_feature_avg_connection_duration 1.5
defense_feature_inter_arrival_std 0.01
defense_feature_error_rate 0.4
defense_feature_active_connections 300.0
"""


def make_settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def make_session(scalar_return: int = 0) -> AsyncMock:
    session = AsyncMock()
    result = AsyncMock()
    result.scalar_one = lambda: scalar_return
    session.execute.return_value = result
    return session


async def test_parse_prometheus_text_ignores_comments_and_reads_gauges():
    parsed = parse_prometheus_text(SAMPLE_METRICS_TEXT)
    assert parsed["defense_feature_request_rate"] == 250.0
    assert parsed["defense_feature_active_connections"] == 300.0
    assert parsed["defense_classifier_attack_confidence"] == 0.82
    assert "defense_rate_limit_threshold" in parsed


@respx.mock
async def test_fetch_sandbox_features_parses_all_five_feature_gauges():
    respx.get(METRICS_URL).mock(return_value=httpx.Response(200, text=SAMPLE_METRICS_TEXT))
    settings = make_settings()
    async with httpx.AsyncClient() as client:
        features = await fetch_sandbox_features(client, settings)
    assert features is not None
    assert set(features.keys()) == set(FEATURE_NAMES)
    assert features["request_rate"] == 250.0


@respx.mock
async def test_fetch_sandbox_features_returns_none_when_unreachable():
    respx.get(METRICS_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    settings = make_settings()
    async with httpx.AsyncClient() as client:
        features = await fetch_sandbox_features(client, settings)
    assert features is None


@respx.mock
async def test_fetch_sandbox_features_returns_none_when_gauge_missing():
    respx.get(METRICS_URL).mock(return_value=httpx.Response(200, text="defense_feature_request_rate 10.0\n"))
    settings = make_settings()
    async with httpx.AsyncClient() as client:
        features = await fetch_sandbox_features(client, settings)
    assert features is None  # missing the other four expected gauges


@respx.mock
async def test_compute_correlation_degrades_gracefully_when_defense_engine_down():
    """Safety requirement: an unreachable defense-engine must produce a
    neutral/unavailable result, never a raised exception or a fabricated
    percentage."""
    respx.get(METRICS_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    settings = make_settings()
    session = make_session(scalar_return=5)

    async with httpx.AsyncClient() as client:
        result = await compute_correlation(session, client, settings)

    assert result.available is False
    assert result.correlation_percentage is None
    assert result.observation == UNAVAILABLE_OBSERVATION
    assert result.matched_features == []
    assert result.disclaimer == FIXED_DISCLAIMER


@respx.mock
async def test_compute_correlation_returns_percentage_and_matched_features_when_available():
    respx.get(METRICS_URL).mock(return_value=httpx.Response(200, text=SAMPLE_METRICS_TEXT))
    settings = make_settings()
    session = make_session(scalar_return=25)  # half of IOC_VOLUME_REFERENCE (50)

    async with httpx.AsyncClient() as client:
        result = await compute_correlation(session, client, settings)

    assert result.available is True
    assert result.correlation_percentage is not None
    assert 0.0 <= result.correlation_percentage <= 100.0
    assert set(result.matched_features).issubset(set(FEATURE_NAMES))
    assert result.compared_ioc_count == 25
    assert result.disclaimer == FIXED_DISCLAIMER


@respx.mock
async def test_compute_correlation_never_mentions_attribution_terms():
    """Structural no-attribution check: scan the actual response text for
    anything that would read as attribution. This is a coarse guard, not a
    substitute for the fact that `_build_observation` has no code path
    capable of interpolating an IP/actor/malware family in the first
    place."""
    respx.get(METRICS_URL).mock(return_value=httpx.Response(200, text=SAMPLE_METRICS_TEXT))
    settings = make_settings()
    session = make_session(scalar_return=40)

    async with httpx.AsyncClient() as client:
        result = await compute_correlation(session, client, settings)

    # Only the freely-generated `observation` sentence is checked here --
    # `disclaimer` is a fixed string that legitimately *names* these terms
    # in order to disclaim them ("does not identify any actor...").
    forbidden_terms = ["actor", "campaign", "malware family", "botnet", "attacker is", "attributed to"]
    observation_lower = result.observation.lower()
    for term in forbidden_terms:
        assert term not in observation_lower, f"unexpected attribution-adjacent term found in observation: {term!r}"
    assert "not attribution" in result.disclaimer.lower()


async def test_correlation_percentage_is_zero_when_no_recent_high_confidence_iocs():
    """No global signal -> zero correlation regardless of sandbox intensity,
    since the percentage is the minimum of the two intensities."""
    with respx.mock:
        respx.get(METRICS_URL).mock(return_value=httpx.Response(200, text=SAMPLE_METRICS_TEXT))
        settings = make_settings()
        session = make_session(scalar_return=0)

        async with httpx.AsyncClient() as client:
            result = await compute_correlation(session, client, settings)

    assert result.available is True
    assert result.correlation_percentage == 0.0
