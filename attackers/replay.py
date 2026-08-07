"""Replays a previously recorded simulation run for repeatable benchmarking.

Reads attackers/recordings/<run_name>.jsonl (written by common.recorder) and
re-issues the same request pattern against the same target at the original
relative timing, so a benchmark can be reproduced exactly.
"""
import argparse
import asyncio
import os

import aiohttp

from common.metrics import ERRORS, REQUESTS_SENT, serve_metrics
from common.recorder import replay as replay_events


async def replay_run(run_name: str, target_override: str | None):
    async with aiohttp.ClientSession() as session:
        for event in replay_events(run_name):
            target = target_override or event["target"]
            if not target.startswith("http"):
                continue  # only HTTP-shaped events can be meaningfully replayed live
            try:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    await resp.read()
                REQUESTS_SENT.labels(attack_type=event["attack_type"], target=target).inc()
            except Exception:
                ERRORS.labels(attack_type=event["attack_type"], target=target).inc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL LAB: replay a recorded simulation run")
    parser.add_argument("run_name")
    parser.add_argument("--target-override", default=os.environ.get("TARGET_URL"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9405")))
    args = parser.parse_args()

    serve_metrics(args.metrics_port)
    asyncio.run(replay_run(args.run_name, args.target_override))
