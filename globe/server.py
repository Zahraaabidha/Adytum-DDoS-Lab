"""Tiny static + API server for the SENTINEL LAB globe dashboard.

Serves index.html/app.js and a /api/feed endpoint that reads the most
recently modified simulation recording (attackers/recordings/*.jsonl,
written by attackers/common/recorder.py) and returns its last N events.
This is the ONLY data source for the globe -- synthetic attacker metadata,
never real traffic.

Also exposes /api/attacks/* sandbox controls, which shell out to
`docker compose` (over the docker.sock mounted into this container, see
docker-compose.yml) to start/stop the attacker-* containers defined there.
Every attack type these controls can touch is one already gated behind a
Compose profile that is never started by a plain `docker compose up` --
this just gives that same start/stop action a button instead of a terminal.
"""
import json
import os
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

RECORDINGS_DIR = Path(
    os.environ.get("RECORDINGS_DIR", str(Path(__file__).resolve().parent.parent / "attackers" / "recordings"))
)
STATIC_DIR = Path(__file__).resolve().parent

# type -> (compose service name, compose profile name), matching docker-compose.yml
ATTACKS = {
    "http-flood": ("attacker-http-flood", "attack-http-flood"),
    "slowloris": ("attacker-slowloris", "attack-slowloris"),
    "udp-flood": ("attacker-udp-flood", "attack-udp-flood"),
    "tcp-exhaustion": ("attacker-tcp-exhaustion", "attack-tcp-exhaustion"),
    "legit-load": ("legit-load", "legit-load"),
}

app = FastAPI(title="SENTINEL LAB globe feed")


def latest_recording() -> Path | None:
    if not RECORDINGS_DIR.exists():
        return None
    files = sorted(RECORDINGS_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


@app.get("/api/feed")
async def feed(window_seconds: int = 30, limit: int = 300):
    path = latest_recording()
    if path is None:
        return JSONResponse({"run_name": None, "events": []})

    cutoff = time.time() - window_seconds
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e["ts"] >= cutoff:
                events.append(e)
    return JSONResponse({"run_name": path.stem, "events": events[-limit:]})


def _container_running(service: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project=ddos-attack",
         "--filter", f"label=com.docker.compose.service={service}",
         "--filter", "status=running", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=10,
    )
    return bool(result.stdout.strip())


@app.get("/api/attacks/status")
async def attacks_status():
    return {"running": {attack_type: _container_running(service) for attack_type, (service, _) in ATTACKS.items()}}


@app.post("/api/attacks/{attack_type}/start")
async def attacks_start(attack_type: str):
    if attack_type not in ATTACKS:
        raise HTTPException(404, f"unknown attack type: {attack_type}")
    service, profile = ATTACKS[attack_type]
    result = subprocess.run(
        ["docker", "compose", "--profile", profile, "up", "-d", service],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise HTTPException(500, result.stderr.strip() or "docker compose up failed")
    return {"ok": True, "attack_type": attack_type}


@app.post("/api/attacks/{attack_type}/stop")
async def attacks_stop(attack_type: str):
    if attack_type not in ATTACKS:
        raise HTTPException(404, f"unknown attack type: {attack_type}")
    service, profile = ATTACKS[attack_type]
    result = subprocess.run(
        ["docker", "compose", "--profile", profile, "stop", service],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise HTTPException(500, result.stderr.strip() or "docker compose stop failed")
    return {"ok": True, "attack_type": attack_type}


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/", StaticFiles(directory=STATIC_DIR), name="static")
