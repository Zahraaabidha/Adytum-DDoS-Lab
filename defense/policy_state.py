"""Saving and validating the guarded mitigation policy's state across an engine restart.

Without this, a restart resets the policy to the baseline cap with nothing learned. Measured with an HTTP flood
running (rate limiter polling the engine every 3 s): the limiter held its cap while the engine was down, then the
restarted engine served the 500 req/s baseline and the limiter was open for about 11-14 s until the guard
re-detected the attack; and with the learned normal load gone, the protective cap fell back to the fixed
`MITIGATION_FALLBACK_CAP` instead of `headroom` times the legitimate peak, which throttles legitimate traffic
that peaks above about 8 req/s.

Restoring a *stale* cap would be the opposite mistake, so a snapshot is only used when it is still true:

* It must have been written by the same configuration (baseline, minimum cap, headroom, fallback cap, model,
  poll interval, memory length). Anything else, such as a model rollback or a changed headroom, discards it.
* The cap and the mitigating/normal state are restored only if the snapshot is at most `CAP_MAX_AGE_S` old. Past
  that, the cap starts at the baseline: the engine was down long enough that the attack may be over, and
  nothing here may keep legitimate traffic restricted on a guess.
* The learned normal load is restored only for as long as the policy would have remembered it anyway. The
  policy looks back `normal_polls` polls (5 minutes); a remembered poll that is by now older than that (its age
  plus the downtime) is dropped, and nothing older than the memory is used.
* Decision counters start at zero. A restored policy leaves mitigation by the normal rule (consecutive calm
  polls with nothing rejected) and the cap then climbs back by the normal recovery factor, so a restored cap
  never outlives the attack by more than that recovery time.

Anything malformed, from the future, or non-finite is discarded; the policy then starts as it always did.
"""
import math

SNAPSHOT_VERSION = 1
CAP_MAX_AGE_S = 120.0

_CONFIG_KEYS = ("baseline", "min_cap", "headroom", "fallback_cap", "normal_polls", "poll_interval", "model")


def make_snapshot(guard, config: dict, now: float) -> dict:
    return {"version": SNAPSHOT_VERSION, "saved_at": now, "config": {k: config[k] for k in _CONFIG_KEYS},
            **guard.snapshot()}


def _finite(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def plan_restore(saved: dict | None, now: float, config: dict) -> dict:
    """What to put back: `{"mode": "none" | "normal_only" | "full", "reason": str, "age_s": ..., ...values}`."""
    none = {"mode": "none", "limit": None, "state": None, "recent_normal": [], "age_s": None}
    if not saved:
        return {**none, "reason": "no saved policy state"}
    try:
        if saved.get("version") != SNAPSHOT_VERSION:
            return {**none, "reason": "saved by a different version"}
        if saved.get("config") != {k: config[k] for k in _CONFIG_KEYS}:
            return {**none, "reason": "configuration or model changed since it was saved"}
        saved_at, limit, state, normal = saved["saved_at"], saved["limit"], saved["state"], saved["recent_normal"]
        if not (_finite(saved_at) and _finite(limit) and isinstance(normal, list) and all(_finite(v) and v >= 0 for v in normal)):
            return {**none, "reason": "saved state is malformed"}
    except (KeyError, TypeError):
        return {**none, "reason": "saved state is malformed"}
    age = now - saved_at
    if age < 0:
        return {**none, "reason": "saved in the future (clock changed)", "age_s": age}
    memory_s = config["normal_polls"] * config["poll_interval"]
    if age > memory_s:
        return {**none, "reason": f"{age:.0f} s old, past the policy's {memory_s:.0f} s memory", "age_s": age}
    # Entry k polls before the newest is `age + k * poll_interval` old now; keep it only while that is inside the memory.
    keep = int((memory_s - age) / config["poll_interval"]) + 1
    kept = normal[-keep:] if keep > 0 else []
    result = {"age_s": age, "recent_normal": kept}
    if age > CAP_MAX_AGE_S or state not in ("normal", "mitigating"):
        return {**result, "mode": "normal_only", "limit": config["baseline"], "state": "normal",
                "reason": f"{age:.0f} s old: learned normal load kept, cap starts at the baseline"}
    return {**result, "mode": "full", "limit": float(limit), "state": state,
            "reason": f"{age:.0f} s old: cap {limit:.1f} req/s and state {state} restored"}
