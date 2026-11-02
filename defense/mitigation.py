"""Turns detector confidence into a rate limit.

The original policy (`adapt_threshold` in engine.py) maps every confidence
linearly to a cap. It has no memory, so a single odd sample moves the cap, ordinary
traffic at confidence 0.25 already sits at 376 req/s, and a ~105 req/s flood is only
throttled once confidence exceeds 0.80 -- which a model trained on varied legitimate
load rarely reaches.

`GuardedPolicy` is a small state machine instead:

* NORMAL -- the cap stays at the baseline, however the confidence wanders below the
  flag threshold. It recovers toward the baseline if it was lowered.
* Entering MITIGATING needs `enter_polls` consecutive flagged polls (persistence), so an
  isolated false positive changes nothing.
* Normal load is only learned from polls that stayed calm: a calm poll is committed to the
  history after `confirm_polls` further polls, and any flagged or ambiguous poll discards the
  polls still waiting. An attack ramps up over a poll or two *before* its confidence crosses the
  flag threshold; without this delay those ramp polls would be recorded as normal load, inflate
  the peak, and lift the protective cap to about the attack's own rate.
* MITIGATING -- the cap steps down by at most `max_step` per poll toward a protective cap
  of `headroom` times the *peak* unflagged load of the last `normal_polls` polls (never below
  `min_cap`), so legitimate traffic at its usual level fits under it and a flood does not. A
  peak, not an average: an average decays toward the idle rate during quiet periods and would
  set the cap far below what legitimate users need.
* Leaving MITIGATING needs `exit_polls` consecutive calm polls (hysteresis): confidence
  below `exit` *and* the limiter rejecting almost nothing. The detector sees the already
  rate-limited traffic, so confidence falls once the limit works; the rejection rate is
  what says the attack is still there.
* After leaving, the cap climbs back by at most `recover_factor` per poll.
"""
from collections import deque
from dataclasses import dataclass

NORMAL = "normal"
MITIGATING = "mitigating"


@dataclass
class GuardedPolicy:
    baseline: float
    min_cap: float
    # protective cap = headroom x the recent peak load seen while NORMAL. 6 was chosen by a pre-declared lab sweep of 2, 4 and 6
    # (README, "Model selection"): with a cap of about 6x legitimate peak a legitimate client keeps its share under a six-source flood.
    headroom: float = 6.0
    fallback_cap: float | None = None  # protective cap before any normal load has been seen
    enter: float = 0.5  # confidence at or above this is a flagged poll
    exit: float = 0.45  # confidence must fall below this (and rejections stop) to leave
    enter_polls: int = 3
    exit_polls: int = 4
    hold_blocked_rps: float = 2.0  # rejecting more than this keeps mitigation on
    max_step: float = 0.6  # largest fractional cut of the cap per poll
    recover_factor: float = 1.5  # largest multiplicative rise of the cap per poll
    normal_polls: int = 60  # how many recent unflagged polls the normal-load peak looks back over
    confirm_polls: int = 4  # calm polls that must follow a poll before it counts as normal load

    def __post_init__(self):
        self.limit = self.baseline
        self.state = NORMAL
        self._recent_normal: deque[float] = deque(maxlen=self.normal_polls)
        self._pending: deque[float] = deque()  # calm polls not yet confirmed
        self._flagged = 0
        self._calm = 0

    @property
    def normal_load(self) -> float | None:
        """Peak request rate over the recent unflagged polls, or None before any."""
        return max(self._recent_normal) if self._recent_normal else None

    def protective_cap(self) -> float:
        raw = self.fallback_cap if self.normal_load is None else self.headroom * self.normal_load
        if raw is None:
            raw = self.baseline * 0.1
        return max(self.min_cap, min(self.baseline, raw))

    def snapshot(self) -> dict:
        """What the policy has learned and decided so far, for `policy_state.py` to save across an engine restart."""
        return {"limit": self.limit, "state": self.state, "recent_normal": list(self._recent_normal)}

    def restore(self, limit: float, state: str, recent_normal: list[float]) -> None:
        """Puts back state that `policy_state.plan_restore` has already validated. The decision counters start from
        zero: a restored policy must see fresh flagged or calm polls before it enters or leaves mitigation, and the
        polls still waiting for confirmation are not carried over. `update` itself is unchanged."""
        self.limit = min(self.baseline, max(self.min_cap, limit))
        self.state = state
        self._recent_normal.extend(recent_normal)
        self._pending.clear()
        self._flagged = 0
        self._calm = 0

    def update(self, confidence: float, request_rate: float, blocked_rps: float) -> float:
        """One poll. `request_rate` is the load reaching the targets, `blocked_rps` what the
        limiter rejected. Returns the new cap."""
        if self.state == NORMAL:
            flagged = confidence >= self.enter
            self._flagged = self._flagged + 1 if flagged else 0
            if confidence < self.exit:  # only clearly calm polls count as normal load, and only once confirmed
                self._pending.append(request_rate)
                if len(self._pending) > self.confirm_polls:
                    self._recent_normal.append(self._pending.popleft())
            else:  # flagged or ambiguous: whatever just happened may be the start of an attack
                self._pending.clear()
            if self._flagged >= self.enter_polls:
                self.state, self._calm = MITIGATING, 0
                self._pending.clear()
            elif self.limit < self.baseline:
                self.limit = min(self.baseline, max(self.limit * self.recover_factor, self.limit + 5.0))
        if self.state == MITIGATING:
            self.limit = max(self.protective_cap(), self.limit * (1.0 - self.max_step))
            calm = confidence < self.exit and blocked_rps < self.hold_blocked_rps
            self._calm = self._calm + 1 if calm else 0
            if self._calm >= self.exit_polls:
                self.state, self._flagged = NORMAL, 0
        return self.limit
