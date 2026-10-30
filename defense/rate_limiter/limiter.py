"""Request admission policies for the adaptive rate limiter.

Both policies enforce the same global cap (limit requests per one-second
window, set by the defense engine) and never admit more than that. They differ
in *who* loses requests once the cap is reached:

* `GlobalLimiter` -- first come, first served. A flood fills the window early,
  so a light legitimate client arriving later in the second is rejected.
* `FairShareLimiter` -- max-min fairness per source address. Every source seen
  in the previous window is guaranteed an equal share of the cap; a source
  within its share is always admitted (while the cap allows), and a source over
  its share may only use capacity that is not still reserved for others (what
  they asked for last window, up to their share). A
  distributed flood is still held to the global cap, and its sources each get no
  more than a fair share; but a light legitimate client is no longer starved by
  heavy ones. Trade-off: the share is per source address, so an attacker using
  many addresses takes many shares (the cap still holds), and many legitimate
  users behind one address share one.
"""
import math
import time
from collections.abc import Callable

# Capacity held back for a known source is what it asked for in the previous window times
# this headroom (capped at its guaranteed share), so light clients keep room to grow a little
# without a quiet client's whole share sitting idle while a flood is being rejected.
HEADROOM = 1.5

# Bounds memory if a client cycles source addresses: sources beyond this many
# in one window share a single bucket. The global cap is unaffected.
MAX_SOURCES = 4096
OVERFLOW = "__overflow__"


class GlobalLimiter:
    def __init__(self, limit_rps: float, clock: Callable[[], float] = time.monotonic):
        self.limit = limit_rps
        self._clock = clock
        self._window_start = clock()
        self._count = 0

    def set_limit(self, limit_rps: float) -> None:
        self.limit = limit_rps

    def allow(self, source: str) -> bool:
        now = self._clock()
        if now - self._window_start >= 1.0:
            self._window_start, self._count = now, 0
        self._count += 1
        return self._count <= self.limit


class FairShareLimiter:
    def __init__(self, limit_rps: float, clock: Callable[[], float] = time.monotonic):
        self.limit = limit_rps
        self._clock = clock
        self._window_start = clock()
        self._counts: dict[str, int] = {}  # admitted requests per source this window
        self._offered: dict[str, int] = {}  # requests per source this window, admitted or not
        self._total = 0
        self._known: dict[str, int] = {}  # requests per source in the previous window
        self._reservation: dict[str, int] = {}
        self._guarantee = max(1, int(limit_rps))  # whole requests per source per window
        self._reserved_left = 0.0  # capacity still held back for known sources' guaranteed shares

    def set_limit(self, limit_rps: float) -> None:
        self.limit = limit_rps

    def _roll_window(self, now: float) -> None:
        # Sources count as active if they merely *tried*: a client that was rejected all window
        # must still be given its share next window.
        self._known = self._offered
        self._offered, self._counts, self._total = {}, {}, 0
        # Rounded *down* so the guarantees of all known sources never add up to more than the cap
        # (with more sources than the cap allows, each still gets one and the cap decides who).
        self._guarantee = max(1, int(self.limit / max(1, len(self._known))))
        self._reservation = {
            source: min(self._guarantee, math.ceil(HEADROOM * asked) + 1) for source, asked in self._known.items()
        }
        self._reserved_left = min(float(self.limit), float(sum(self._reservation.values())))
        self._window_start = now

    @property
    def active_sources(self) -> int:
        return len(self._known)

    def allow(self, source: str) -> bool:
        now = self._clock()
        if now - self._window_start >= 1.0:
            self._roll_window(now)
        if source not in self._offered and len(self._offered) >= MAX_SOURCES:
            source = OVERFLOW
        self._offered[source] = self._offered.get(source, 0) + 1
        if self._total >= self.limit:
            return False

        used = self._counts.get(source, 0)
        if used < self._guarantee:
            admit = True  # within this source's guaranteed share
            if used < self._reservation.get(source, 0):
                self._reserved_left = max(0.0, self._reserved_left - 1)
        else:
            # Over its share: only capacity beyond what other sources are still guaranteed.
            admit = (self.limit - self._total) > self._reserved_left
        if admit:
            self._counts[source] = used + 1
            self._total += 1
        return admit
