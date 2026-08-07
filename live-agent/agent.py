"""SENTINEL LAB live traffic agent -- REAL data, not part of the sandbox.

Runs directly on the host (never inside Docker: the lab's attacker_net/
target_net are deliberately isolated from the real host NIC, so a container
can't see this data even if it wanted to). Reads the OS's own connection
table via psutil -- the same information `netstat` shows -- and real NIC
byte counters. No packet capture, no raw sockets, no admin/root privileges,
no third-party driver. It only ever looks at connections to/from this
machine, never promiscuous/whole-LAN traffic.

This is intentionally the safe, low-privilege tier of "real traffic"
monitoring. A deeper tier (actual packet capture via scapy + Npcap, which
needs admin rights and a driver install) is a separate, bigger step not
implemented here.
"""
import time
from collections import Counter

import psutil
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SENTINEL LAB live traffic agent (real, host-local)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local-only tool; the dashboard fetches this directly from the browser
    allow_methods=["GET"],
    allow_headers=["*"],
)

_boot_io = psutil.net_io_counters()
_last_sample = {"ts": time.time(), "bytes_sent": _boot_io.bytes_sent, "bytes_recv": _boot_io.bytes_recv}


def _rate_since_last_sample():
    now = time.time()
    io = psutil.net_io_counters()
    elapsed = max(now - _last_sample["ts"], 0.001)
    sent_rate = max((io.bytes_sent - _last_sample["bytes_sent"]) / elapsed, 0)
    recv_rate = max((io.bytes_recv - _last_sample["bytes_recv"]) / elapsed, 0)
    _last_sample["ts"] = now
    _last_sample["bytes_sent"] = io.bytes_sent
    _last_sample["bytes_recv"] = io.bytes_recv
    return sent_rate, recv_rate


@app.get("/live")
async def live():
    conns = psutil.net_connections(kind="inet")
    by_status = Counter(c.status for c in conns)
    remote_ips = Counter(c.raddr.ip for c in conns if c.raddr)

    sent_rate, recv_rate = _rate_since_last_sample()

    return {
        "synthetic": False,
        "source": "psutil (OS connection table + NIC counters) -- this machine only",
        "updated": time.time(),
        "connections_total": len(conns),
        "connections_by_status": dict(by_status),
        "top_remote_ips": remote_ips.most_common(10),
        "bytes_sent_per_sec": round(sent_rate, 1),
        "bytes_recv_per_sec": round(recv_rate, 1),
    }


@app.get("/")
async def index():
    return {
        "service": "sentinel-lab-live-agent",
        "note": "Real host traffic monitor. See /live for data.",
    }
