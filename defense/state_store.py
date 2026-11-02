"""Small local SQLite store for the defense engine's detector history and unified incidents.

Why SQLite and not the threat-intel PostgreSQL: the engine sits on `target_net` and `public_net`, and the
PostgreSQL service deliberately lives on its own network that never touches the lab networks. Joining them would
break that isolation, so the engine keeps a single file on its own named volume instead. No new service.

What is stored, and how it is kept honest:

* `detector_polls`: one row per engine poll (confidence, rate-limit cap, policy state, blocked rate, live
  features). Restored into the engine's in-memory history on start, so the ML and mitigation evidence of recent
  incidents survives a restart. The gap while the engine was down stays a gap: nothing is filled in.
* `incidents` and `incident_alerts`: the unified incident records and the Suricata alerts that support them.
  An incident is updated in place while it is open and frozen once it has been closed long enough, after which
  the stored copy is authoritative and never recomputed, so evidence that has since expired from the EVE files or
  the in-memory history is not lost and a restart cannot rewrite it.
* Duplicates: an incident is identified by its attack type and time overlap, not by an id derived from its
  first alert, so regrouping the same alerts after a restart updates the stored incident instead of creating a
  second. Supporting alerts are keyed so replaying them is a no-op.
* A replacement never throws evidence away: if a recomputed incident has fewer real signals than the stored
  one (typically because history was missing after a restart), the stored record is kept.
* Persistence is best effort. Any storage failure is logged and reported; the engine keeps working in memory.

Retention (all configurable): polls 24 h and at most 20,000 rows; incidents 7 days and at most 500; at most 500
stored alerts per incident.
"""
import json
import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

log = logging.getLogger("sentinel-defense.state")

SCHEMA_VERSION = 1
FREEZE_AFTER_S = 120.0  # an incident closed this long is frozen (60 s of silence closes it, 60 s more for late evidence)
MAX_ALERTS_PER_INCIDENT = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detector_polls (
    ts REAL PRIMARY KEY, confidence REAL NOT NULL, threshold REAL NOT NULL, request_rate REAL,
    state TEXT, blocked_rps REAL, features TEXT, model TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, attack_type TEXT, start REAL NOT NULL, end REAL NOT NULL,
    frozen INTEGER NOT NULL DEFAULT 0, record TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_end ON incidents (end);
CREATE TABLE IF NOT EXISTS policy_state (
    id INTEGER PRIMARY KEY CHECK (id = 1), snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL, alert_key TEXT NOT NULL, alert TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_key)
);
"""


def alert_key(alert: dict) -> str:
    return f"{alert['ts']:.6f}|{alert.get('signature_id')}|{alert.get('src_ip')}|{alert.get('sensor')}|{alert.get('in_iface')}"


def _alert_row(alert: dict) -> dict:
    keep = ("ts", "timestamp", "signature_id", "signature", "src_ip", "dest_ip", "dest_port", "protocol", "sensor",
            "in_iface", "interfaces", "hop_alerts")
    return {k: alert.get(k) for k in keep}


def information(record: dict) -> int:
    """How many real signals a record rests on (a `no_data` / `no_baseline` signal counts for nothing)."""
    detectors = record["detectors"]
    score = sum(1 for d in detectors.values() if d["state"] in ("flagged", "not_flagged"))
    score += 1 if record["metrics"]["state"] in ("elevated", "not_elevated") else 0
    score += 1 if record["mitigation"].get("samples", 0) > 0 else 0
    return score


class StateStore:
    def __init__(self, path: Path, *, poll_retention_s: float = 86400.0, max_polls: int = 20000,
                 incident_retention_s: float = 7 * 86400.0, max_incidents: int = 500,
                 clock: Callable[[], float] = time.time):
        self.path = path
        self.poll_retention_s, self.max_polls = poll_retention_s, max_polls
        self.incident_retention_s, self.max_incidents = incident_retention_s, max_incidents
        self._clock = clock
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None
        self.error: str | None = None
        self._open()

    @property
    def ok(self) -> bool:
        return self._db is not None

    # ---------------------------------------------------------------- setup
    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=5)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA quick_check")
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            db.commit()
        except sqlite3.Error:
            db.close()  # release the file first (Windows cannot rename an open file)
            raise
        return db

    def _open(self) -> None:
        try:
            self._db = self._connect()
            return
        except (sqlite3.Error, OSError) as exc:
            failure = exc
            self.error = f"{type(exc).__name__}: {exc}"
        if isinstance(failure, sqlite3.DatabaseError) and self.path.exists():
            # A damaged file is moved aside (never deleted) and a fresh one started.
            aside = self.path.with_name(f"{self.path.name}.corrupt-{int(self._clock())}")
            try:
                self.path.rename(aside)
                for suffix in ("-wal", "-shm"):
                    self.path.with_name(self.path.name + suffix).unlink(missing_ok=True)
                self._db = self._connect()
                log.warning("State database was damaged (%s); moved to %s and started a new one", failure, aside.name)
                self.error = f"recovered from a damaged database (kept as {aside.name})"
                return
            except (sqlite3.Error, OSError) as exc:
                self.error = f"{type(exc).__name__}: {exc}"
        self._db = None
        log.warning("Persistence disabled, running in memory only: %s", self.error)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _run(self, fn):
        """Runs `fn(db)` and returns (succeeded, value). A storage failure is logged and reported, never raised."""
        if self._db is None:
            return False, None
        with self._lock:
            try:
                return True, fn(self._db)
            except sqlite3.Error as exc:
                self.error = f"{type(exc).__name__}: {exc}"
                log.warning("State store error: %s", exc)
                return False, None

    # ---------------------------------------------------------------- detector polls
    def save_poll(self, poll: dict) -> None:
        def write(db):
            db.execute(
                "INSERT OR REPLACE INTO detector_polls (ts, confidence, threshold, request_rate, state, blocked_rps, features, model) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (poll["ts"], poll["confidence"], poll["threshold"], poll.get("request_rate"), poll.get("state"),
                 poll.get("blocked_rps"), json.dumps(poll["features"]) if poll.get("features") else None, poll.get("model")))
            db.commit()
        self._run(write)

    def load_polls(self, since: float, limit: int, model: str | None = None) -> list[dict]:
        """The most recent polls since `since` that were scored by `model` (None: polls scored with no model),
        oldest first. Exactly what was stored, nothing interpolated; polls from another model are left out
        because their confidences mean something different."""
        def read(db):
            rows = db.execute(
                "SELECT ts, confidence, threshold, request_rate, state, blocked_rps, features, model FROM detector_polls "
                "WHERE ts >= ? AND model IS ? ORDER BY ts DESC LIMIT ?", (since, model, limit)).fetchall()
            return [{"ts": r[0], "confidence": r[1], "threshold": r[2], "request_rate": r[3], "state": r[4],
                     "blocked_rps": r[5], "features": json.loads(r[6]) if r[6] else None, "model": r[7]}
                    for r in reversed(rows)]
        return self._run(read)[1] or []

    # ---------------------------------------------------------------- guarded policy state
    def save_policy(self, snapshot: dict) -> None:
        """The single latest guarded-policy snapshot (see policy_state.py for how it is validated before use)."""
        def write(db):
            db.execute("INSERT OR REPLACE INTO policy_state (id, snapshot) VALUES (1, ?)", (json.dumps(snapshot),))
            db.commit()
        self._run(write)

    def load_policy(self) -> dict | None:
        def read(db):
            row = db.execute("SELECT snapshot FROM policy_state WHERE id=1").fetchone()
            return json.loads(row[0]) if row else None
        try:
            return self._run(read)[1]
        except ValueError:
            return None  # unreadable snapshot: the policy starts fresh

    # ---------------------------------------------------------------- incidents
    @staticmethod
    def _overlap(db, attack_type, start, end):
        return db.execute(
            "SELECT id, frozen, record FROM incidents WHERE attack_type IS ? AND start <= ? AND end >= ? "
            "ORDER BY frozen DESC, end DESC LIMIT 1", (attack_type, end, start)).fetchone()

    @staticmethod
    def _explained_by_suricata_incident(db, start, end, pad: float = 20.0) -> bool:
        """True if a stored incident that has Suricata alerts covers this period (padded like the live matching)."""
        for (text,) in db.execute("SELECT record FROM incidents WHERE start <= ? AND end >= ?", (end + pad, start - pad)):
            if json.loads(text)["detectors"]["suricata"]["alerts"] > 0:
                return True
        return False

    @staticmethod
    def _supersede_ml_only(db, start, end, pad: float = 20.0) -> None:
        """An open ML-only incident is dropped once Suricata alerts turn out to cover the same period."""
        for incident_id, frozen, text in db.execute(
                "SELECT id, frozen, record FROM incidents WHERE attack_type IS NULL AND start <= ? AND end >= ?",
                (end + pad, start - pad)).fetchall():
            if not frozen and json.loads(text)["detectors"]["suricata"]["alerts"] == 0:
                db.execute("DELETE FROM incidents WHERE id=?", (incident_id,))
                db.execute("DELETE FROM incident_alerts WHERE incident_id=?", (incident_id,))

    def reconcile(self, live: Sequence[tuple[dict, Sequence[dict]]], limit: int = 20) -> list[dict] | None:
        """Records the freshly computed incidents (with their supporting alerts) and returns the stored list,
        newest first. None means storage is unavailable and the caller should use its own list."""
        now = self._clock()

        def write(db):
            for record, alerts in live:
                ml_only = record["detectors"]["suricata"]["alerts"] == 0
                if ml_only and self._explained_by_suricata_incident(db, record["start"], record["end"]):
                    continue  # the detector episode belongs to a stored Suricata-based incident (its alerts may have aged out)
                if not ml_only:
                    self._supersede_ml_only(db, record["start"], record["end"])
                row = self._overlap(db, record["attack_type"], record["start"], record["end"])
                if row is not None and row[1]:
                    continue  # already frozen: the stored copy is authoritative
                incident_id = row[0] if row else record["id"]
                if row is not None:
                    stored = json.loads(row[2])
                    if information(record) < information(stored):
                        record = stored  # keep the richer evidence; the new alerts below are still added
                record = {**record, "id": incident_id}
                closed_long_enough = record["status"] == "closed" and now - record["end"] >= FREEZE_AFTER_S
                db.execute(
                    "INSERT INTO incidents (id, attack_type, start, end, frozen, record, updated_at) VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET attack_type=excluded.attack_type, start=excluded.start, end=excluded.end, "
                    "frozen=excluded.frozen, record=excluded.record, updated_at=excluded.updated_at",
                    (incident_id, record["attack_type"], record["start"], record["end"], int(closed_long_enough),
                     json.dumps(record), now))
                have = db.execute("SELECT COUNT(*) FROM incident_alerts WHERE incident_id=?", (incident_id,)).fetchone()[0]
                for alert in alerts:
                    if have >= MAX_ALERTS_PER_INCIDENT:
                        break
                    cur = db.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_key, alert) VALUES (?,?,?)",
                                     (incident_id, alert_key(alert), json.dumps(_alert_row(alert))))
                    have += cur.rowcount
            db.commit()
        succeeded, _ = self._run(write)
        return self.recent(limit) if succeeded else None

    def freeze_stale(self) -> int:
        """Freezes open incidents nothing has touched since they closed (e.g. after a long outage)."""
        cutoff = self._clock() - FREEZE_AFTER_S - 60.0
        def run(db):
            cur = db.execute("UPDATE incidents SET frozen=1 WHERE frozen=0 AND end < ?", (cutoff,))
            db.commit()
            return cur.rowcount
        return self._run(run)[1] or 0

    def recent(self, limit: int = 20) -> list[dict]:
        now = self._clock()

        def read(db):
            out = []
            for frozen, text in db.execute("SELECT frozen, record FROM incidents ORDER BY end DESC LIMIT ?", (limit,)):
                record = json.loads(text)
                # Whether it is still open is a fact about now, not about when it was stored.
                record["status"] = "active" if (not frozen and now - record["end"] <= 60.0) else "closed"
                record["source"] = "stored" if frozen else "live"
                out.append(record)
            return out
        return self._run(read)[1] or []

    def get(self, incident_id: str) -> dict | None:
        def read(db):
            row = db.execute("SELECT frozen, record FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if row is None:
                return None
            record = json.loads(row[1])
            record["source"] = "stored" if row[0] else "live"
            record["alerts"] = [json.loads(a[0]) for a in db.execute(
                "SELECT alert FROM incident_alerts WHERE incident_id=? ORDER BY json_extract(alert, '$.ts')", (incident_id,))]
            return record
        return self._run(read)[1]

    # ---------------------------------------------------------------- retention
    def prune(self) -> dict:
        now = self._clock()

        def run(db):
            polls = db.execute("DELETE FROM detector_polls WHERE ts < ?", (now - self.poll_retention_s,)).rowcount
            polls += db.execute("DELETE FROM detector_polls WHERE ts NOT IN (SELECT ts FROM detector_polls ORDER BY ts DESC LIMIT ?)",
                                (self.max_polls,)).rowcount
            gone = db.execute("DELETE FROM incidents WHERE end < ?", (now - self.incident_retention_s,)).rowcount
            gone += db.execute("DELETE FROM incidents WHERE id NOT IN (SELECT id FROM incidents ORDER BY end DESC LIMIT ?)",
                               (self.max_incidents,)).rowcount
            db.execute("DELETE FROM incident_alerts WHERE incident_id NOT IN (SELECT id FROM incidents)")
            db.commit()
            return {"polls_deleted": polls, "incidents_deleted": gone}
        return self._run(run)[1] or {"polls_deleted": 0, "incidents_deleted": 0}

    def stats(self) -> dict:
        def read(db):
            return {
                "polls": db.execute("SELECT COUNT(*) FROM detector_polls").fetchone()[0],
                "incidents": db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
                "frozen_incidents": db.execute("SELECT COUNT(*) FROM incidents WHERE frozen=1").fetchone()[0],
                "incident_alerts": db.execute("SELECT COUNT(*) FROM incident_alerts").fetchone()[0],
            }
        return {"enabled": self.ok, "path": str(self.path), "error": self.error, **(self._run(read)[1] or {})}
