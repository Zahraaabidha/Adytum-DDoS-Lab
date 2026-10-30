"""The one definition of SENTINEL LAB's live traffic features.

Computed from Prometheus target metrics. The defense engine scores these
vectors live, writes each one to its feature log, and training/evaluation
read that log, so the model is trained and measured on exactly the features
(and units) it sees in production. (`features.py` describes the older
recording-derived features and is no longer used for training.)
"""
import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger("sentinel-defense")

# The first five names are the ones threat-intel's correlation engine reads;
# keep their order and names stable.
LIVE_FEATURE_NAMES = [
    "request_rate",  # requests + TCP connections + UDP packets per second (15s window)
    "avg_connection_duration",  # p95 HTTP request latency, seconds (1m window)
    "inter_arrival_std",  # 1 / request_rate, seconds (mean spacing; 0 with no traffic)
    "error_rate",  # HTTP 5xx / HTTP requests
    "active_connections",  # in-flight HTTP requests + open TCP connections + in-flight UDP datagrams
    "established_connections",  # ESTABLISHED TCP sockets on the web port (sees half-open Slowloris connections)
]


@dataclass
class LiveFeatures:
    request_rate: float
    avg_connection_duration: float
    inter_arrival_std: float
    error_rate: float
    active_connections: float
    established_connections: float

    def as_vector(self) -> list[float]:
        return [getattr(self, name) for name in LIVE_FEATURE_NAMES]


async def _prom_query(client: httpx.AsyncClient, prom_url: str, promql: str) -> float | None:
    """The first result's value; 0.0 when the metric has no series yet; None if Prometheus failed."""
    try:
        resp = await client.get(f"{prom_url}/api/v1/query", params={"query": promql}, timeout=5)
        resp.raise_for_status()
        result = resp.json()["data"]["result"]
        return float(result[0]["value"][1]) if result else 0.0
    except Exception as exc:
        log.warning("Prometheus query failed (%s): %s", promql, exc)
        return None


async def gather_features(client: httpx.AsyncClient, prom_url: str) -> LiveFeatures | None:
    """Current feature vector, or None if any Prometheus query failed (so a
    Prometheus outage is never mistaken for "no traffic")."""
    # Each target type exports differently-named metrics (targets/web/app.py's
    # target_http_*, targets/tcp_service/server.py's target_tcp_*,
    # targets/dns_udp/server.py's target_udp_*). Summing them treats HTTP
    # requests, TCP connections and UDP packets as the same "load volume" so
    # every attack type moves request_rate/active_connections.
    # error_rate/avg_connection_duration stay HTTP-only: TCP/UDP targets have
    # no equivalent error or request-latency concept.
    async def q(promql: str) -> float | None:
        return await _prom_query(client, prom_url, promql)

    values = {
        "http_rate": await q("sum(rate(target_http_requests_total[15s]))"),
        "tcp_rate": await q("sum(rate(target_tcp_connections_total[15s]))"),
        "udp_rate": await q("sum(rate(target_udp_packets_total[15s]))"),
        "http_active": await q("sum(target_active_connections)"),
        "tcp_active": await q("sum(target_tcp_active_connections)"),
        "udp_inflight": await q("sum(target_udp_inflight_datagrams)"),
        "http_errors": await q("sum(rate(target_http_errors_total[15s]))"),
        "p95_latency": await q(
            "histogram_quantile(0.95, sum(rate(target_http_request_duration_seconds_bucket[1m])) by (le))"
        ),
        "established": await q("sum(target_http_established_sockets)"),
    }
    if any(v is None for v in values.values()):
        return None
    v = {name: float(value) for name, value in values.items() if value is not None}

    request_rate = v["http_rate"] + v["tcp_rate"] + v["udp_rate"]
    # histogram_quantile is NaN when there were no requests in the window.
    p95_latency = v["p95_latency"] if v["p95_latency"] == v["p95_latency"] else 0.0
    return LiveFeatures(
        request_rate=request_rate,
        avg_connection_duration=p95_latency,
        inter_arrival_std=1.0 / request_rate if request_rate > 0 else 0.0,
        error_rate=(v["http_errors"] / v["http_rate"]) if v["http_rate"] > 0 else 0.0,
        active_connections=v["http_active"] + v["tcp_active"] + v["udp_inflight"],
        established_connections=v["established"],
    )
