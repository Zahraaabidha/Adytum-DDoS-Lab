"""Legitimate load-test mode.

Generates a realistic, non-malicious traffic pattern (moderate concurrency,
human-like think-time between requests, occasional bursts) against the web
target. Used to train/test the classifier's ability to distinguish real
traffic spikes (e.g. a flash-sale surge) from actual attack traffic, so the
lab can measure false-positive rate.
"""
import argparse
import asyncio
import os
import random
import time

import aiohttp

from common.identity import random_fake_identity
from common.metrics import ACTIVE_WORKERS, ERRORS, REQUESTS_SENT, serve_metrics
from common.recorder import Recorder, SimEvent

ATTACK_TYPE = "legitimate_load"


async def user_session(session: aiohttp.ClientSession, target_url: str, recorder: Recorder, stop_at: float):
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
        # Human-like think time between page views, occasionally longer.
        await asyncio.sleep(random.choice([random.uniform(0.5, 2.0), random.uniform(2.0, 6.0)]))


async def run(target_url: str, concurrency: int, duration: int, run_name: str, burst: bool):
    recorder = Recorder(run_name)
    stop_at = time.time() + duration
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [user_session(session, target_url, recorder, stop_at) for _ in range(concurrency)]
        if burst:
            # Simulate a legitimate traffic spike partway through (e.g. a flash sale),
            # which the classifier must learn NOT to flag as an attack.
            async def burst_task():
                await asyncio.sleep(duration / 3)
                burst_stop = min(stop_at, time.time() + duration / 6)
                await asyncio.gather(
                    *[user_session(session, target_url, recorder, burst_stop) for _ in range(concurrency * 3)]
                )

            tasks.append(burst_task())
        await asyncio.gather(*tasks)
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(0)
    recorder.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL LAB: legitimate load-test mode")
    parser.add_argument("--target", default=os.environ.get("TARGET_URL", "http://web:8000/"))
    parser.add_argument("--concurrency", type=int, default=int(os.environ.get("CONCURRENCY", "10")))
    parser.add_argument("--duration", type=int, default=int(os.environ.get("DURATION", "120")))
    parser.add_argument("--burst", action="store_true", default=os.environ.get("BURST", "false").lower() == "true")
    parser.add_argument("--run-name", default=os.environ.get("RUN_NAME", f"legit_load_{int(time.time())}"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9404")))
    args = parser.parse_args()

    serve_metrics(args.metrics_port)
    asyncio.run(run(args.target, args.concurrency, args.duration, args.run_name, args.burst))
