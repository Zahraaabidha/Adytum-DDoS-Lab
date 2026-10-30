"""Discovery and validation of recorded simulation runs, and labeling of the
engine's live feature log with them.

Every `*.jsonl` file in the recordings directory is inspected and reported as
either usable or excluded *with a reason*; nothing is deleted or skipped
silently. A run's label comes from the `attack_type` of its own events, never
from its file name: `legitimate_load` is "normal", anything else is "attack".

The recordings are the ground truth for *when* each kind of traffic was
running; the defense engine's feature log (`engine.py`) holds the feature
vectors it computed live. A feature-log sample takes the label of the run whose
time span contains it.
"""
import json
import os
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

LEGIT_TYPE = "legitimate_load"
# Attack/load types whose events carry an HTTP status. If none of a run's events
# got a response, the target never answered: the recording is attacker-side
# connection failures, not traffic the target actually handled. (slowloris,
# tcp_exhaustion and udp_flood legitimately have no status.)
HTTP_RESPONSE_TYPES = {"http_flood", LEGIT_TYPE}
UNREACHABLE_FRACTION = 0.95
MAX_PARSE_ERROR_FRACTION = 0.01
WINDOW_SECONDS = 5.0
# Live features use 15s/1m Prometheus rate windows, so samples just after a run
# starts or ends still contain the previous state and are not labeled.
WARMUP_SECONDS = 15.0
COOLDOWN_SECONDS = 20.0
IDLE = "idle"

DEFAULT_RECORDINGS_DIR = Path(__file__).resolve().parent.parent.parent / "attackers" / "recordings"
DEFAULT_FEATURE_LOG = Path(__file__).resolve().parent.parent / "feature_log.jsonl"
EXPORT_HINT = (
    "Recordings live in the Docker volume `ddos-attack_attacker-recordings`. Run this inside the defense-engine "
    "container (it mounts the volume at /app/recordings), or export them to the host with: "
    'docker run --rm -v ddos-attack_attacker-recordings:/data -v "$PWD/attackers/recordings:/host" alpine cp -a /data/. /host/'
)


@dataclass
class RecordingInfo:
    run: str
    path: str
    events: int
    parse_errors: int
    attack_types: list[str]
    label: str | None  # "normal" | "attack" | None when the run cannot be labeled
    attack_type: str | None
    start_ts: float | None
    end_ts: float | None  # the run's true end when the recorder wrote a .meta.json, else its last event
    span_seconds: float
    windows: int  # non-empty 5-second windows of events
    no_response_fraction: float | None  # share of events without an HTTP status (HTTP-type runs only)
    usable: bool
    reason: str | None = None  # why the run is excluded
    warnings: list[str] = field(default_factory=list)
    blocked_events: int = 0  # events answered 429 by the rate limiter (mitigation)

    def summary(self) -> dict:
        data = asdict(self)
        data.pop("path")
        return data


def recordings_dir() -> Path:
    return Path(os.environ.get("RECORDINGS_DIR", str(DEFAULT_RECORDINGS_DIR)))


def feature_log_path() -> Path:
    return Path(os.environ.get("FEATURE_LOG_PATH", str(DEFAULT_FEATURE_LOG)))


def _read_meta(path: Path) -> dict | None:
    """The recorder's `<run>.meta.json` (real start/end of the run), if present and valid."""
    try:
        meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
        return {"start_ts": float(meta["start_ts"]), "end_ts": float(meta["end_ts"])}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def inspect_recording(path: Path) -> RecordingInfo:
    run = path.stem
    parse_errors = 0
    types: Counter[str] = Counter()
    timestamps: list[float] = []
    no_status = 0
    blocked = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                timestamps.append(float(event["ts"]))
                types[str(event["attack_type"])] += 1
            except (ValueError, KeyError, TypeError):
                parse_errors += 1
                continue
            if event.get("status") is None:
                no_status += 1
            elif event["status"] == 429:
                blocked += 1

    events = len(timestamps)
    meta = _read_meta(path)
    attack_types = sorted(types)
    attack_type = attack_types[0] if len(attack_types) == 1 else None
    label = None if attack_type is None else ("normal" if attack_type == LEGIT_TYPE else "attack")
    start = min(timestamps) if timestamps else None
    end = max(timestamps) if timestamps else None
    if meta and start is not None and end is not None:
        start, end = min(start, meta["start_ts"]), max(end, meta["end_ts"])
    span = (end - start) if start is not None and end is not None else 0.0
    first = min(timestamps) if timestamps else 0.0
    windows = len({int((t - first) // WINDOW_SECONDS) for t in timestamps}) if timestamps else 0
    no_response = (no_status / events) if events and attack_type in HTTP_RESPONSE_TYPES else None

    reason = None
    if events == 0:
        reason = "no valid events"
    elif parse_errors / (events + parse_errors) > MAX_PARSE_ERROR_FRACTION:
        reason = f"{parse_errors} unparseable lines ({parse_errors / (events + parse_errors):.1%})"
    elif attack_type is None:
        reason = f"mixed labels in one run: {', '.join(attack_types)}"
    elif no_response is not None and no_response >= UNREACHABLE_FRACTION:
        reason = (
            f"target never responded: {no_response:.0%} of {events} {attack_type} events have no HTTP status "
            "(attacker-side connection failures, not traffic the target handled)"
        )

    warnings = []
    if 0 < parse_errors and reason is None:
        warnings.append(f"{parse_errors} unparseable line(s) ignored")
    if reason is None and span == 0:
        warnings.append("all events share one timestamp and there is no .meta.json with the run's real span")
    return RecordingInfo(
        run=run, path=str(path), events=events, parse_errors=parse_errors, attack_types=attack_types, label=label,
        attack_type=attack_type, start_ts=start, end_ts=end, span_seconds=span, windows=windows,
        no_response_fraction=no_response, usable=reason is None, reason=reason, warnings=warnings,
        blocked_events=blocked,
    )


def discover_recordings(directory: Path | None = None) -> list[RecordingInfo]:
    """Inspects every `*.jsonl` in the directory, oldest recording first."""
    directory = directory or recordings_dir()
    if not directory.is_dir():
        raise SystemExit(f"Recordings directory not found: {directory}\n{EXPORT_HINT}")
    infos = [inspect_recording(p) for p in sorted(directory.glob("*.jsonl"))]
    if not infos:
        raise SystemExit(f"No *.jsonl recordings in {directory}\n{EXPORT_HINT}")
    return sorted(infos, key=lambda i: (i.start_ts is None, i.start_ts or 0.0, i.run))


def split_by_usability(infos: list[RecordingInfo], exclude: dict[str, str] | None = None):
    """Returns (used, excluded) where `excluded` rows carry the reason. `exclude`
    maps run name -> extra reason (e.g. "used for training")."""
    exclude = exclude or {}
    used: list[RecordingInfo] = []
    excluded: list[RecordingInfo] = []
    for info in infos:
        if info.run in exclude and info.usable:
            info = RecordingInfo(**{**asdict(info), "usable": False, "reason": exclude[info.run]})
        (used if info.usable else excluded).append(info)
    return used, excluded


@dataclass
class LabeledSample:
    ts: float
    vector: list[float]
    run: str | None  # None for idle samples
    attack_type: str  # "idle" when no run was active
    label: str  # "normal" | "attack"
    confidence: float  # what the engine itself computed at the time
    threshold: float  # the rate limit the engine set at the time
    model: bool  # the engine had a model loaded
    mitigation: bool  # the engine was allowed to lower the rate limit


def load_feature_log(path: Path | None = None, feature_names: list[str] | None = None) -> tuple[list[dict], int]:
    """Parsed feature-log entries and the number of unparseable lines. Entries
    missing any of `feature_names` count as unparseable."""
    path = path or feature_log_path()
    if not path.is_file():
        raise SystemExit(
            f"Feature log not found: {path}\nThe defense engine writes it while it runs "
            "(FEATURE_LOG_PATH, default /app/feature_log.jsonl, a bind mount of ./defense/feature_log.jsonl). "
            "Run the lab with traffic first."
        )
    entries: list[dict] = []
    bad = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                float(entry["ts"])
                for name in feature_names or []:
                    float(entry["features"][name])
                entries.append(entry)
            except (ValueError, KeyError, TypeError):
                bad += 1
    return entries, bad


def label_samples(
    entries: list[dict], infos: list[RecordingInfo], feature_names: list[str]
) -> tuple[list[LabeledSample], dict[str, int]]:
    """Labels each feature-log entry from the recordings' time spans.

    Returns (labeled, excluded_counts). A sample is excluded, and counted by
    reason, if it falls in a run's warm-up or cool-down margin, inside an
    unusable recording, or inside runs of two different traffic types at once. A sample outside every run
    and margin is labeled idle (normal, attack_type "idle").
    """
    spans = [(i, i.start_ts, i.end_ts) for i in infos if i.start_ts is not None and i.end_ts is not None]
    labeled: list[LabeledSample] = []
    excluded: dict[str, int] = {}

    for entry in entries:
        ts = float(entry["ts"])
        active = [i for i, a, b in spans if a + WARMUP_SECONDS <= ts <= b]
        in_margin = any(a <= ts < a + WARMUP_SECONDS or b < ts <= b + COOLDOWN_SECONDS for _, a, b in spans)
        reason = None
        # Several runs of the *same* traffic type at once (a distributed flood from many containers)
        # are unambiguous; different types at once cannot be told apart.
        if len({i.attack_type for i in active}) > 1:
            reason = "overlapping runs"
        elif active and not active[0].usable:
            reason = "inside an unusable recording"
        elif in_margin and not active:
            reason = "warm-up/cool-down margin"
        if reason:
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        if active:
            info = min(active, key=lambda i: (i.start_ts or 0.0, i.run))  # concurrent same-type runs count under the earliest
            run, attack_type, label = info.run, info.attack_type or "unknown", info.label or "attack"
        else:
            run, attack_type, label = None, IDLE, "normal"
        labeled.append(LabeledSample(
            ts=ts, vector=[float(entry["features"][n]) for n in feature_names], run=run, attack_type=attack_type,
            label=label, confidence=float(entry.get("confidence", 0.0)), threshold=float(entry.get("threshold", 0.0)),
            model=bool(entry.get("model", False)), mitigation=bool(entry.get("mitigation", False)),
        ))
    return labeled, excluded


def requests_between(info: RecordingInfo, start: float, end: float) -> tuple[int, int]:
    """(requests, requests answered 429) of a recording's events with start <= ts <= end."""
    requests = blocked = 0
    with open(info.path, encoding="utf-8") as fh:
        for line in fh:
            try:
                event = json.loads(line)
                ts = float(event["ts"])
            except (ValueError, KeyError, TypeError):
                continue
            if start <= ts <= end:
                requests += 1
                blocked += event.get("status") == 429
    return requests, blocked
