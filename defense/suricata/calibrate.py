"""Threshold calibration for the Suricata target taps (no dependencies beyond the standard library).

Thresholds are measured, not guessed. Run the taps with `calibrate.rules` (it alerts on EVERY matching packet, no
threshold), drive labelled legitimate and attack traffic, then ask how many matching packets one source produced in the
busiest 10-second window of each labelled period:

    python calibrate.py traffic udp --pps 50 --seconds 30            # legitimate-looking UDP queries from one source
    python calibrate.py traffic tcp --cps 10 --seconds 30 [--burst 40]  # short TCP sessions from one source
    python calibrate.py analyze eve-udp.json --window 10 \
        --period legit-normal=START:END --period flood=START:END     # START/END in epoch seconds

`analyze` prints, per period and source address, the maximum number of alerts in any `window` seconds.
"""
import argparse
import json
import os
import random
import socket
import sys
import time
from collections import defaultdict
from datetime import datetime


def udp_traffic(host: str, port: int, pps: float, seconds: float, burst: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent, end = 0, time.time() + seconds
    burst_at = time.time() + seconds / 2 if burst else None
    while time.time() < end:
        sock.sendto(os.urandom(48), (host, port))
        sent += 1
        if burst_at and time.time() >= burst_at:
            for _ in range(burst):
                sock.sendto(os.urandom(48), (host, port))
                sent += 1
            burst_at = None
        time.sleep(random.expovariate(pps))  # Poisson arrivals, not a metronome
    return sent


def tcp_traffic(host: str, port: int, cps: float, seconds: float, burst: int) -> int:
    done, end = 0, time.time() + seconds
    burst_at = time.time() + seconds / 2 if burst else None

    def session() -> None:
        try:
            with socket.create_connection((host, port), timeout=3) as conn:
                conn.sendall(b"ping\n")
                conn.settimeout(1)
                try:
                    conn.recv(64)
                except OSError:
                    pass
        except OSError:
            pass

    while time.time() < end:
        session()
        done += 1
        if burst_at and time.time() >= burst_at:
            for _ in range(burst):
                session()
                done += 1
                time.sleep(2.0 / burst)  # the burst spreads over about two seconds
            burst_at = None
        time.sleep(random.expovariate(cps))
    return done


def parse_ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def busiest_window(stamps: list[float], window: float) -> int:
    stamps = sorted(stamps)
    best, lo = 0, 0
    for hi, stamp in enumerate(stamps):
        while stamp - stamps[lo] > window:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def analyze(path: str, window: float, periods: dict[str, tuple[float, float]], sid: int | None = None) -> dict:
    by_source: dict[str, list[float]] = defaultdict(list)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if '"event_type":"alert"' not in line:
                continue
            event = json.loads(line)
            if sid is not None and event["alert"]["signature_id"] != sid:
                continue
            by_source[event["src_ip"]].append(parse_ts(event["timestamp"]))
    result = {}
    for label, (start, end) in periods.items():
        per_source = {src: busiest_window([t for t in stamps if start <= t <= end], window) for src, stamps in by_source.items()}
        per_source = {src: n for src, n in per_source.items() if n}
        result[label] = {"max_per_window": max(per_source.values(), default=0), "by_source": per_source}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    traffic = sub.add_parser("traffic")
    traffic.add_argument("kind", choices=["udp", "tcp"])
    traffic.add_argument("--host")
    traffic.add_argument("--port", type=int)
    traffic.add_argument("--pps", type=float, default=10)
    traffic.add_argument("--cps", type=float, default=2)
    traffic.add_argument("--seconds", type=float, default=30)
    traffic.add_argument("--burst", type=int, default=0, help="extra packets/connections sent once, mid-run")
    check = sub.add_parser("analyze")
    check.add_argument("eve")
    check.add_argument("--window", type=float, default=10)
    check.add_argument("--sid", type=int, help="only count this signature id (the calibration rules have one each)")
    check.add_argument("--period", action="append", default=[], metavar="LABEL=START:END")
    args = parser.parse_args()
    if args.cmd == "traffic":
        host = args.host or ("dns-udp" if args.kind == "udp" else "tcp-service")
        port = args.port or (5300 if args.kind == "udp" else 9000)
        n = (udp_traffic(host, port, args.pps, args.seconds, args.burst) if args.kind == "udp"
             else tcp_traffic(host, port, args.cps, args.seconds, args.burst))
        print(json.dumps({"kind": args.kind, "sent": n, "start_hint": time.time() - args.seconds}))
        return
    periods = {}
    for spec in args.period:
        label, rng = spec.split("=", 1)
        start, end = rng.split(":")
        periods[label] = (float(start), float(end))
    json.dump(analyze(args.eve, args.window, periods, args.sid), sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
