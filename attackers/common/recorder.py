"""Traffic replay/recording for SENTINEL LAB simulation runs.

Records a simulation run's event stream (attack type, target, per-request
timestamps, synthetic attacker identity, and outcome) to a JSON-lines file so
it can be replayed later for repeatable benchmarking, and so the globe/report
stages have a durable artifact to read from.
"""
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "recordings"
RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class SimEvent:
    ts: float
    attack_type: str
    target: str
    fake_ip: str
    city: str
    lat: float
    lon: float
    status: Optional[int] = None
    latency_ms: Optional[float] = None
    extra: dict = field(default_factory=dict)


class Recorder:
    def __init__(self, run_name: str):
        self.run_name = run_name
        self.path = RECORDINGS_DIR / f"{run_name}.jsonl"
        self._fh = open(self.path, "a", buffering=1, encoding="utf-8")
        self._start_ts = time.time()
        self._attack_type: Optional[str] = None

    def record(self, event: SimEvent):
        self._attack_type = event.attack_type
        self._fh.write(json.dumps(asdict(event)) + "\n")

    def close(self):
        self._fh.close()
        # The events alone don't say how long the run lasted (tcp_exhaustion, for one, logs every
        # connection in the first instant and then just holds them), so keep the run's real span.
        meta = {"run": self.run_name, "attack_type": self._attack_type, "start_ts": self._start_ts, "end_ts": time.time()}
        self.path.with_suffix(".meta.json").write_text(json.dumps(meta), encoding="utf-8")


def replay(run_name: str):
    """Yields SimEvent dicts from a prior recording, in original order,
    preserving inter-event timing so the run can be replayed at real speed."""
    path = RECORDINGS_DIR / f"{run_name}.jsonl"
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    events.sort(key=lambda e: e["ts"])
    prev_ts = None
    for e in events:
        if prev_ts is not None:
            time.sleep(max(0.0, e["ts"] - prev_ts))
        prev_ts = e["ts"]
        yield e
