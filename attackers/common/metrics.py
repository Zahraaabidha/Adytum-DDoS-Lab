"""Prometheus metrics shared by all attacker simulation modules."""
from prometheus_client import Counter, Gauge, start_http_server

REQUESTS_SENT = Counter(
    "attacker_requests_sent_total", "Total simulated requests/packets sent", ["attack_type", "target"]
)
ERRORS = Counter("attacker_errors_total", "Total send errors", ["attack_type", "target"])
ACTIVE_WORKERS = Gauge("attacker_active_workers", "Currently active attack worker tasks", ["attack_type"])


def serve_metrics(port: int):
    start_http_server(port)
