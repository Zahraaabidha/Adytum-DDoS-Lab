"""Suricata EVE JSON alert ingestion for the defense engine.

Read-only and advisory: this module tails the EVE files Suricata writes to the shared
`suricata-logs` volume, normalizes alert events, and keeps a bounded in-memory window. It never
changes the rate limit, the classifier or the mitigation policy; a Suricata alert on its own
triggers nothing. `correlate` only *annotates* an alert with what the ML detector saw nearby.

Design points:

* Incremental: each file is read in bounded chunks from a saved offset; non-alert EVE records
  (flows, stats) are skipped before JSON parsing. The offset and inode are persisted, so after an
  engine restart ingestion resumes exactly where it stopped: events written while the engine was
  down are counted once, events it already counted are never replayed into the counter.
* Replay is history, not news: lines that were already counted (or that pre-date the very first
  start) fill the alert history but are not returned as new, so they never reach the Prometheus
  counter.
* One logical alert per event: the rate-limiter's namespace has an attacker-facing and a
  target-facing interface, so a flood is seen twice, the second time as the rate-limiter itself
  forwarding it. That "proxy hop" sighting is merged into the attacker-facing alert (same
  signature, within `DEDUP_WINDOW_S`), keeping the capture interfaces of both.
* Bounded: history is capped by count and age, signature counters and unmatched-hop buffers are
  capped, oversized lines are dropped, and one poll reads at most `POLL_BUDGET_BYTES`.
"""
import asyncio
import json
import logging
import os
import socket
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

log = logging.getLogger("sentinel-defense.suricata")

# Suricata severity: 1 is the most severe.
SEVERITY_LABELS = {1: "high", 2: "medium", 3: "low"}
# An alert and an ML sample this close in time (seconds) are treated as describing the same moment.
CORRELATION_WINDOW_S = 10.0
FLAGGED_CONFIDENCE = 0.5  # same cut-off the offline evaluation and the guarded policy use to call a poll flagged
INITIAL_BACKFILL_BYTES = 2_000_000  # how much of an existing eve.json fills the history on the first start
MAX_LINE_BYTES = 64_000  # a longer line is not an EVE event we care about
READ_CHUNK_BYTES = 1_000_000
POLL_BUDGET_BYTES = 8_000_000  # one poll never reads more than this; the rest waits for the next poll
DEDUP_WINDOW_S = 15.0  # a proxy-hop sighting this close to an attacker-facing alert is the same event
MAX_ALERT_AGE_S = 6 * 3600
MAX_SIGNATURES = 200
MAX_UNMATCHED_HOPS = 200
MAX_OBSERVATIONS = 5

_ALERT_MARKERS = (b'"event_type":"alert"', b'"event_type": "alert"')


def parse_timestamp(value: str) -> float | None:
    """EVE timestamps look like `2026-10-30T12:00:00.123456+0000`; returns epoch seconds."""
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return None


def normalize_alert(line: str) -> dict | None:
    """One EVE JSON line -> a normalized alert, or None if it is not a usable alert event."""
    if len(line) > MAX_LINE_BYTES:
        return None
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None
    alert = event.get("alert")
    ts = parse_timestamp(event.get("timestamp", ""))
    if not isinstance(alert, dict) or ts is None or not event.get("src_ip") or not event.get("dest_ip"):
        return None
    try:
        severity = int(alert.get("severity", 3))
    except (TypeError, ValueError):
        severity = 3
    iface = event.get("in_iface")
    return {
        "ts": ts,
        "timestamp": event["timestamp"],
        "signature_id": alert.get("signature_id"),
        "signature": str(alert.get("signature", "unknown")),
        "category": alert.get("category"),
        "severity": severity,
        "severity_label": SEVERITY_LABELS.get(severity, "low"),
        "action": alert.get("action"),
        "src_ip": event["src_ip"],
        "src_port": event.get("src_port"),
        "dest_ip": event["dest_ip"],
        "dest_port": event.get("dest_port"),
        "protocol": str(event.get("proto", "unknown")).upper(),
        "app_proto": event.get("app_proto"),
        "in_iface": iface,
        "interfaces": [iface] if iface else [],
        "hop_alerts": 0,
        "observations": [],
        "flow_id": event.get("flow_id"),
    }


def correlate(alert_ts: float, history: Sequence[dict], window: float = CORRELATION_WINDOW_S) -> dict:
    """What the ML detector saw around an alert, from the engine's recent polls.

    `history` items carry `ts`, `confidence`, `threshold`, `request_rate` (the Prometheus-derived
    feature) and `state`. Returns the highest-confidence poll within `window` seconds (so `ml_flagged`
    and the reported confidence always agree).
    """
    near = [h for h in history if abs(h["ts"] - alert_ts) <= window]
    if not near:
        return {"ml_available": False, "ml_flagged": None, "confidence": None, "request_rate": None,
                "threshold_rps": None, "policy_state": None}
    peak = max(near, key=lambda h: (h["confidence"], -abs(h["ts"] - alert_ts)))
    return {
        "ml_available": True,
        "ml_flagged": peak["confidence"] >= FLAGGED_CONFIDENCE,
        "confidence": peak["confidence"],
        "request_rate": peak["request_rate"],
        "threshold_rps": peak["threshold"],
        "policy_state": peak.get("state"),
    }


def dns_addresses(hosts: Sequence[str], ttl: float = 30.0, clock: Callable[[], float] = time.monotonic) -> Callable[[], set[str]]:
    """A cached resolver for the addresses of `hosts` (the rate-limiter, as seen from this container).
    On a lookup failure the previous answer is kept; with none, no alert is treated as a proxy hop."""
    cache: dict = {"at": None, "addresses": set()}

    def resolve() -> set[str]:
        if cache["at"] is not None and clock() - cache["at"] < ttl:
            return cache["addresses"]
        found: set[str] = set()
        for host in hosts:
            try:
                found.update(info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
            except OSError:
                pass
        if found:
            cache["addresses"] = found
        cache["at"] = clock()
        return cache["addresses"]

    return resolve


def sensor_name(path: Path) -> str:
    """`eve.json` is the rate-limiter ingress sensor; `eve-udp.json` is the sensor named `udp`."""
    stem = path.stem
    return "ingress" if stem == "eve" else stem.removeprefix("eve-")


def _inode(path: Path) -> int | None:
    try:
        return path.stat().st_ino
    except OSError:
        return None


class _Tail:
    """Read position of one EVE file, persisted so a restart resumes instead of replaying."""

    def __init__(self, path: Path):
        self.path = path
        self.sensor = sensor_name(path)
        self.pos: int | None = None
        self.inode: int | None = None
        self.buffer = b""
        self.counted_from = 0  # lines starting before this offset are history, not news
        self.skip_partial = False

    @property
    def committed(self) -> int:
        """Offset of the first byte not yet fully processed (the start of any partial line)."""
        return (self.pos or 0) - len(self.buffer)


class AlertStore:
    """Tails EVE files and keeps the most recent normalized, deduplicated alerts."""

    def __init__(self, paths: Path | Sequence[Path] | Callable[[], Sequence[Path]], max_alerts: int = 1000,
                 state_path: Path | None = None, proxy_addresses: Callable[[], set[str]] | None = None,
                 clock: Callable[[], float] = time.time):
        if callable(paths):
            self._paths_fn = paths
        else:
            fixed = [paths] if isinstance(paths, Path) else list(paths)
            self._paths_fn = lambda: fixed
        self.state_path = state_path
        self._proxy_addresses = proxy_addresses or (lambda: set())
        self._clock = clock
        self.alerts: deque[dict] = deque(maxlen=max_alerts)
        self.total = 0  # logical alerts held or seen (history included)
        self.merged_hops = 0
        self.skipped_lines = 0
        self.behind = False  # True when a poll stopped at its read budget
        self.by_signature: Counter = Counter()
        self._tails: dict[Path, _Tail] = {}
        self._unmatched: deque[tuple[dict, bool]] = deque(maxlen=MAX_UNMATCHED_HOPS)
        self._latest_ts = 0.0
        self._absent_seen = False
        self._polls = 0
        self._saved: dict = self._load_state()
        self._lock = threading.RLock()
        self._warned_state = False

    # ------------------------------------------------------------------ state
    def _load_state(self) -> dict:
        if self.state_path is None:
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self) -> None:
        if self.state_path is None:
            return
        state = {str(t.path): {"inode": t.inode, "offset": t.committed} for t in self._tails.values() if t.inode is not None}
        if state == self._saved:
            return
        try:
            tmp = self.state_path.with_name(self.state_path.name + ".tmp")
            tmp.write_text(json.dumps(state), encoding="utf-8")
            os.replace(tmp, self.state_path)
            self._saved = state
        except OSError as exc:
            if not self._warned_state:
                log.warning("Could not save Suricata read position to %s (%s); a restart will not resume exactly",
                            self.state_path, exc)
                self._warned_state = True

    # --------------------------------------------------------------- ingestion
    def _init_tail(self, tail: _Tail, st: os.stat_result) -> None:
        saved = self._saved.get(str(tail.path))
        tail.inode = st.st_ino
        if saved and saved.get("inode") == st.st_ino and 0 <= saved.get("offset", -1) <= st.st_size:
            counted_from = saved["offset"]  # resume: everything before this was counted by an earlier run
        elif saved and saved.get("inode") is not None and saved.get("inode") != st.st_ino:
            # The file was rotated while we were down: finish the old one from the saved offset (it still exists
            # under a rotated name), then read the new one from the top. The normal rotation path does both.
            offset = max(0, saved.get("offset", 0))
            tail.inode, tail.counted_from = saved["inode"], offset
            tail.pos = max(0, offset - INITIAL_BACKFILL_BYTES)
            tail.skip_partial = tail.pos > 0
            self._backfill_history(tail, before_inode=saved["inode"])
            return
        elif self._absent_seen:
            counted_from = 0  # the file appeared after we started: all of it is news
        else:
            counted_from = st.st_size  # an existing file with no saved position: history only
        tail.counted_from = counted_from
        tail.pos = max(0, min(counted_from, st.st_size) - INITIAL_BACKFILL_BYTES) if counted_from else 0
        tail.skip_partial = tail.pos > 0
        self._backfill_history(tail)

    def _backfill_history(self, tail: _Tail, before_inode: int | None = None) -> None:
        """Fills the history (never the counter) from recent rotated files, so a restart shortly after a
        rotation does not show an empty list. With `before_inode`, only files older than that one."""
        rotated = sorted(tail.path.parent.glob(tail.path.name + ".*"))
        if before_inode is not None:
            idx = next((i for i, c in enumerate(rotated) if _inode(c) == before_inode), None)
            rotated = rotated[:idx] if idx is not None else rotated
        chosen, budget = [], INITIAL_BACKFILL_BYTES
        for candidate in reversed(rotated):  # newest first, until the byte budget is used
            if budget <= 0:
                break
            try:
                size = candidate.stat().st_size
            except OSError:
                continue
            chosen.append((candidate, min(size, budget)))
            budget -= size
        for candidate, take in reversed(chosen):  # then ingest oldest first
            try:
                with open(candidate, "rb") as fh:
                    size = os.fstat(fh.fileno()).st_size
                    fh.seek(size - take)
                    data = fh.read(take)
            except OSError:
                continue
            lines = data.split(b"\n")
            if take < size:
                lines = lines[1:]  # started mid-line
            for raw in lines:
                if not any(marker in raw for marker in _ALERT_MARKERS):
                    continue
                alert = normalize_alert(raw.decode("utf-8", errors="replace"))
                if alert is not None:
                    alert["sensor"] = tail.sensor
                    self._ingest(alert, counted=False)

    def poll(self) -> list[dict]:
        """Reads what was appended since the last call. Returns the new logical alerts (not history,
        not merged duplicates): these, and only these, are what should be counted."""
        with self._lock:
            return self._poll()

    def _poll(self) -> list[dict]:
        new: list[dict] = []
        budget = POLL_BUDGET_BYTES
        self.behind = False
        for path in self._paths_fn():
            if path not in self._tails and self._polls > 0:
                self._absent_seen = True  # a file that shows up after we started is all news
            tail = self._tails.setdefault(path, _Tail(path))
            try:
                fh = open(path, "rb")
            except OSError:
                self._absent_seen = True
                continue
            with fh:
                st = os.fstat(fh.fileno())  # one handle for stat and read: a rotation cannot slip in between
                if tail.pos is None:
                    self._init_tail(tail, st)
                if st.st_ino != tail.inode:  # rotated: finish the old file, then start the new one from the top
                    new.extend(self._drain_rotated(tail))
                    tail.inode, tail.pos, tail.buffer, tail.counted_from, tail.skip_partial = st.st_ino, 0, b"", 0, False
                elif st.st_size < tail.pos:  # truncated in place: nothing left to recover
                    tail.pos, tail.buffer, tail.counted_from, tail.skip_partial = 0, b"", 0, False
                while tail.pos < st.st_size and budget > 0:
                    fh.seek(tail.pos)
                    chunk = fh.read(min(READ_CHUNK_BYTES, st.st_size - tail.pos, budget))
                    if not chunk:
                        break
                    budget -= len(chunk)
                    new.extend(self._consume(tail, chunk))
                if tail.pos < st.st_size:
                    self.behind = True
        new.extend(self._promote_unmatched())
        self._polls += 1
        self._prune()
        self._save_state()
        return new

    def _drain_rotated(self, tail: _Tail) -> list[dict]:
        """Reads what is left of the file `tail` was reading, which has been renamed (`eve.json.<timestamp>`),
        and then any later rotated files (more than one rotation since the last read), oldest first."""
        out: list[dict] = []
        rotated = sorted(tail.path.parent.glob(tail.path.name + ".*"))  # the timestamp suffix sorts chronologically
        start = next((i for i, c in enumerate(rotated) if _inode(c) == tail.inode), None)
        if start is None:
            log.warning("%s was rotated and the old file is gone; alerts written since the last read are lost", tail.path)
            return out
        for n, old in enumerate(rotated[start:]):
            if n:
                tail.pos, tail.buffer, tail.counted_from = 0, b"", 0
            try:
                with open(old, "rb") as fh:
                    size = os.fstat(fh.fileno()).st_size
                    while tail.pos < size:
                        fh.seek(tail.pos)
                        chunk = fh.read(min(READ_CHUNK_BYTES, size - tail.pos))
                        if not chunk:
                            break
                        out.extend(self._consume(tail, chunk))
            except OSError as exc:
                log.warning("Could not finish reading rotated %s: %s", old, exc)
        return out

    def _consume(self, tail: _Tail, chunk: bytes) -> list[dict]:
        data_start = tail.committed
        tail.pos += len(chunk)
        data = tail.buffer + chunk
        lines = data.split(b"\n")
        tail.buffer = lines.pop()  # an incomplete last line waits for the next read
        if len(tail.buffer) > 2 * MAX_LINE_BYTES:
            tail.buffer = b""  # a runaway line with no newline: drop it rather than grow without bound
        offset = data_start
        out: list[dict] = []
        for index, raw in enumerate(lines):
            line_start, offset = offset, offset + len(raw) + 1
            if index == 0 and tail.skip_partial:
                tail.skip_partial = False  # started mid-line
                continue
            if not raw.strip() or not any(marker in raw for marker in _ALERT_MARKERS):
                continue  # flows, stats, dns... are skipped before parsing
            alert = normalize_alert(raw.decode("utf-8", errors="replace"))
            if alert is None:
                self.skipped_lines += 1
                continue
            alert["sensor"] = tail.sensor
            fresh = self._ingest(alert, counted=line_start >= tail.counted_from)
            if fresh is not None:
                out.append(fresh)
        return out

    # ------------------------------------------------------------------ dedup
    def _is_hop(self, alert: dict) -> bool:
        return alert["src_ip"] in self._proxy_addresses()

    @staticmethod
    def _merge(primary: dict, hop: dict) -> None:
        for iface in hop["interfaces"]:
            if iface not in primary["interfaces"]:
                primary["interfaces"].append(iface)
        primary["hop_alerts"] += 1 + hop["hop_alerts"]
        if len(primary["observations"]) < MAX_OBSERVATIONS:
            primary["observations"].append({
                "in_iface": hop["in_iface"], "src_ip": hop["src_ip"], "dest_ip": hop["dest_ip"],
                "dest_port": hop["dest_port"], "timestamp": hop["timestamp"],
            })

    def _ingest(self, alert: dict, counted: bool) -> dict | None:
        self._latest_ts = max(self._latest_ts, alert["ts"])
        if self._is_hop(alert):
            for held in reversed(self.alerts):
                if held["ts"] < alert["ts"] - 2 * DEDUP_WINDOW_S:
                    break  # history is in file order, so everything further back is older still
                if held["signature_id"] == alert["signature_id"] and not held.get("hop")                         and abs(held["ts"] - alert["ts"]) <= DEDUP_WINDOW_S:
                    self._merge(held, alert)
                    self.merged_hops += 1
                    return None
            alert["hop"] = True
            self._unmatched.append((alert, counted))  # its attacker-facing twin may still arrive
            return None
        self._absorb_unmatched(alert)
        return self._record(alert, counted)

    def _absorb_unmatched(self, primary: dict) -> None:
        keep: deque[tuple[dict, bool]] = deque(maxlen=MAX_UNMATCHED_HOPS)
        for hop, counted in self._unmatched:
            if hop["signature_id"] == primary["signature_id"] and abs(hop["ts"] - primary["ts"]) <= DEDUP_WINDOW_S:
                self._merge(primary, hop)
                self.merged_hops += 1
            else:
                keep.append((hop, counted))
        self._unmatched = keep

    def _promote_unmatched(self) -> list[dict]:
        """A hop sighting whose attacker-facing twin never came is a real alert in its own right."""
        horizon = max(self._latest_ts, self._clock()) - DEDUP_WINDOW_S
        promoted, keep = [], deque(maxlen=MAX_UNMATCHED_HOPS)
        for hop, counted in self._unmatched:
            if hop["ts"] < horizon:
                fresh = self._record(hop, counted)
                if fresh is not None:
                    promoted.append(fresh)
            else:
                keep.append((hop, counted))
        self._unmatched = keep
        return promoted

    def _record(self, alert: dict, counted: bool) -> dict | None:
        self.alerts.append(alert)
        self.total += 1
        key = (alert["signature_id"], alert["signature"], alert["severity_label"])
        if key not in self.by_signature and len(self.by_signature) >= MAX_SIGNATURES:
            key = (None, "other signatures", "low")
        self.by_signature[key] += 1
        return alert if counted else None

    def _prune(self) -> None:
        cutoff = self._clock() - MAX_ALERT_AGE_S
        while self.alerts and self.alerts[0]["ts"] < cutoff:
            self.alerts.popleft()

    # ------------------------------------------------------------------ reads
    def present(self) -> bool:
        return any(path.exists() for path in self._paths_fn())

    def recent(self, limit: int = 100, min_severity: int | None = None, signature_id: int | None = None,
               since: float | None = None) -> list[dict]:
        """Newest first. `min_severity` is a Suricata level: 1 returns only high, 3 returns everything."""
        with self._lock:
            snapshot = list(self.alerts)
        out = []
        for alert in reversed(snapshot):
            if min_severity is not None and alert["severity"] > min_severity:
                continue
            if signature_id is not None and alert["signature_id"] != signature_id:
                continue
            if since is not None and alert["ts"] < since:
                continue
            out.append(alert)
            if len(out) >= limit:
                break
        return out

    def signature_counts(self) -> list[dict]:
        with self._lock:
            items = self.by_signature.most_common()
        return [{"signature_id": sid, "signature": sig, "severity_label": sev, "count": count}
                for (sid, sig, sev), count in items]


async def tail_forever(store: AlertStore, on_alert, interval: float = 2.0) -> None:
    """Polls forever (in a worker thread, so file and DNS I/O never block the engine);
    `on_alert(alert)` is called for each new logical alert."""
    while True:
        try:
            for alert in await asyncio.to_thread(store.poll):
                on_alert(alert)
        except Exception:  # an ingestion problem must never take the detection engine down
            log.exception("Suricata ingestion error")
        if not store.behind:
            await asyncio.sleep(interval)
