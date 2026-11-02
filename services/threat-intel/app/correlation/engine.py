"""Stage I -- heuristic correlation between live sandbox telemetry and
recently observed global threat indicators.

This is a fixed heuristic, not a trained model and not an attribution
system. It never claims that current sandbox traffic originates from any
specific actor, malware family, campaign, or IOC -- `_build_observation`
below is the one place the response sentence is assembled, and it only
ever interpolates numbers (a percentage, a count, and a whitelist of this
module's own five feature names). There is no code path that can put an
IP, country, threat_type, attack_family, or category into the response.

The heuristic reduces two independently observed signals to a single
[0, 1] "intensity" each, then compares magnitudes -- it never compares a
sandbox feature value against any individual IOC's fields:

1. `_sandbox_intensity` -- how anomalous the sandbox's own live traffic
   currently looks, read from `defense-engine`'s existing Prometheus
   `/metrics` endpoint (approved telemetry source; `/mitigations` was
   rejected as the primary source since it only updates on a
   threshold-changing action, not every poll cycle).
2. `_global_intensity` -- how much high-confidence threat activity this
   service has itself ingested recently, as a plain count from its own
   `iocs` table.

`defense-engine` (`defense/engine.py`) is not modified by this stage --
this module only parses output it already publishes for Grafana, over
`public_net`, the network `threat-intel` and `defense-engine` already
share).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.models import Ioc
from app.logging_config import get_logger
from app.settings import Settings

log = get_logger("threat-intel.correlation")

FEATURE_NAMES = ("request_rate", "avg_connection_duration", "inter_arrival_std", "error_rate", "active_connections")

# Reference magnitudes used only to normalize each raw feature into a [0, 1]
# "how elevated does this look" value -- tuned against defense/engine.py's
# own defaults (BASELINE_RATE_LIMIT=500, MAX_RATE_LIMIT=1000), not against
# any external dataset. These never appear in the API response themselves;
# they only shape the single intensity number.
_FEATURE_REFERENCE_MAX = {
    "request_rate": 300.0,  # req/s
    "avg_connection_duration": 2.0,  # seconds of p95 latency
    "error_rate": 1.0,  # already a fraction
    "active_connections": 500.0,
}

NOTABLE_FEATURE_THRESHOLD = 0.5  # a feature's normalized value at/above this counts as "notable" in matched_features
IOC_VOLUME_REFERENCE = 50  # recent high-confidence IOC count that reads as "elevated global activity"

FIXED_DISCLAIMER = (
    "Heuristic behavioral similarity only. This is not attribution: it does not identify "
    "any actor, malware family, campaign, or specific indicator as the source of current "
    "sandbox traffic."
)

UNAVAILABLE_OBSERVATION = "Correlation unavailable: sandbox telemetry (defense-engine) could not be reached."

_METRIC_LINE_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)\s*$")


@dataclass
class CorrelationResult:
    available: bool
    correlation_percentage: float | None
    observation: str
    matched_features: list[str]
    disclaimer: str
    compared_ioc_count: int
    generated_at: str


def parse_prometheus_text(text: str) -> dict[str, float]:
    """Minimal Prometheus text-exposition parser -- just enough to read the
    plain (unlabeled) gauges `defense/engine.py` exports
    (`defense_feature_*`). Not a general Prometheus client: no
    histogram/summary handling, since none of the metrics this module
    reads are histograms. Unparseable lines are skipped, never raised."""
    values: dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _METRIC_LINE_RE.match(line)
        if not match:
            continue
        name, _labels, raw_value = match.groups()
        try:
            values[name] = float(raw_value)
        except ValueError:
            continue
    return values


async def fetch_sandbox_features(client: httpx.AsyncClient, settings: Settings) -> dict[str, float] | None:
    """Reads defense-engine's existing `/metrics` over `public_net`.
    `defense-engine` is never modified or called with anything other than
    a plain GET. Returns None (never raises) on any failure -- unreachable,
    non-200, unparseable, or missing an expected gauge -- so the caller
    degrades to an 'unavailable' result rather than erroring out."""
    try:
        response = await client.get(settings.DEFENSE_ENGINE_METRICS_URL, timeout=httpx.Timeout(5.0, connect=3.0))
        response.raise_for_status()
    except (httpx.HTTPError, httpx.TransportError) as exc:
        log.warning("defense-engine /metrics unreachable, degrading to unavailable: %s", exc)
        return None

    parsed = parse_prometheus_text(response.text)
    features = {name: parsed.get(f"defense_feature_{name}") for name in FEATURE_NAMES}
    missing = [name for name, value in features.items() if value is None]
    if missing:
        log.warning("defense-engine /metrics missing expected gauge(s) %s, degrading to unavailable", missing)
        return None
    return {name: value for name, value in features.items() if value is not None}


def _normalize_feature(name: str, value: float) -> float:
    if name == "inter_arrival_std":
        # Smaller stddev between requests reads as burstier/more anomalous
        # traffic (near-zero gaps => a flood-like pattern); there is no
        # fixed upper reference for this one, unlike the others.
        return max(0.0, min(1.0, 1.0 - value))
    reference = _FEATURE_REFERENCE_MAX[name]
    return max(0.0, min(1.0, value / reference))


def _sandbox_intensity(features: dict[str, float]) -> tuple[float, list[str]]:
    normalized = {name: _normalize_feature(name, value) for name, value in features.items()}
    matched = [name for name in FEATURE_NAMES if normalized[name] >= NOTABLE_FEATURE_THRESHOLD]
    intensity = sum(normalized.values()) / len(normalized)
    return intensity, matched


def _global_intensity(ioc_count: int) -> float:
    return max(0.0, min(1.0, ioc_count / IOC_VOLUME_REFERENCE))


async def recent_high_confidence_ioc_count(session: AsyncSession, settings: Settings) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=settings.CORRELATION_WINDOW_HOURS)
    result = await session.execute(
        select(func.count())
        .select_from(Ioc)
        .where(Ioc.last_seen >= since, Ioc.confidence_score >= settings.CORRELATION_MIN_CONFIDENCE)
    )
    return result.scalar_one()


def _build_observation(percentage: float, matched_features: list[str], ioc_count: int) -> str:
    if not matched_features:
        return (
            f"Current sandbox traffic shows {percentage:.0f}% behavioral-intensity similarity to "
            f"{ioc_count} recently observed high-confidence threat indicators; no individual traffic "
            "feature is currently elevated enough to call out."
        )
    feature_list = ", ".join(matched_features)
    return (
        f"Current sandbox traffic shows {percentage:.0f}% behavioral-intensity similarity to "
        f"{ioc_count} recently observed high-confidence threat indicators, driven by elevated {feature_list}."
    )


async def compute_correlation(session: AsyncSession, client: httpx.AsyncClient, settings: Settings) -> CorrelationResult:
    """The one function `routes_correlation.py` calls. Always returns a
    result -- degrades to `available=False` rather than raising when
    sandbox telemetry can't be read (Safety Requirement: no fabricated
    data, and no failure of one module ever surfaces as an error from the
    other)."""
    generated_at = datetime.now(timezone.utc).isoformat()
    ioc_count = await recent_high_confidence_ioc_count(session, settings)
    features = await fetch_sandbox_features(client, settings)

    if features is None:
        return CorrelationResult(
            available=False,
            correlation_percentage=None,
            observation=UNAVAILABLE_OBSERVATION,
            matched_features=[],
            disclaimer=FIXED_DISCLAIMER,
            compared_ioc_count=ioc_count,
            generated_at=generated_at,
        )

    sandbox_intensity, matched_features = _sandbox_intensity(features)
    global_intensity = _global_intensity(ioc_count)
    # Agreement in magnitude between two independently observed signals --
    # never a comparison against any individual IOC's own fields.
    percentage = round(100.0 * min(sandbox_intensity, global_intensity), 2)

    return CorrelationResult(
        available=True,
        correlation_percentage=percentage,
        observation=_build_observation(percentage, matched_features, ioc_count),
        matched_features=matched_features,
        disclaimer=FIXED_DISCLAIMER,
        compared_ioc_count=ioc_count,
        generated_at=generated_at,
    )
