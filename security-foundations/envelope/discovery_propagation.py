"""Discovery propagation integrity v0 (Phase 3 Track A A3).

Closes the propagation-integrity half of A3 ("Discovery and Routing
Integrity"):

- "Signed updates and freshness checks." — Phase 1's
  :mod:`discovery_record` already covers signed + windowed updates.
  The freshness add-on landed here is :class:`DiscoveryFreshnessTracker`,
  which pins the highest ``issued_at`` seen per
  ``(workload_iss, workload_kid)`` and refuses any record whose
  timestamp goes backwards. That catches operator-mistake rewinds
  *and* an adversary who recovers an old (still-in-window) signed
  record and tries to overwrite a newer one.
- "Rate-limited propagation channels." —
  :class:`DiscoveryPropagationLimiter` enforces a per-workload
  sliding-window quota on how many new records the substrate is
  willing to admit. Operators set a sensible cap (e.g. one republish
  every 60 s) and republishes beyond that surface
  :class:`DenyReason.DISCOVERY_RATE_LIMITED`. The limiter is
  layered above signature verification, not below it — running it
  pre-auth would let any spoofed ``workload_iss`` exhaust another
  workload's allowance.

:class:`DiscoveryAdmissionGate` composes both checks into one entry
point; callers verify the discovery record with
:func:`discovery_record.verify_record` first, then call
:meth:`DiscoveryAdmissionGate.admit` to run freshness + rate-limit.

Out of scope for v0
-------------------
- Cross-process / cluster-wide propagation state. Both the
  freshness tracker and the rate limiter keep in-process maps;
  multi-replica operators swap in a distributed store behind the
  ABCs.
- Anomaly detection on endpoints (e.g. "this workload suddenly
  advertises 100 new endpoints"). The freshness check is timestamp-
  based; structural anomaly checks belong in a higher-level slice.
- Eviction of old freshness pins. The tracker grows monotonically;
  in long-running deployments operators garbage-collect entries
  whose `expires_at` has long passed via
  :meth:`InMemoryDiscoveryFreshnessTracker.evict_older_than`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from deny_reason import DenyReason
from discovery_record import DiscoveryRecord


def _parse_rfc3339(s: str) -> datetime:
    """Local helper — mirrors the discovery-record parse semantics."""
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)


class DiscoveryPropagationError(ValueError):
    """Raised when propagation inputs violate v0 invariants."""


@dataclass(frozen=True)
class PropagationDecision:
    allowed: bool
    reason: str
    reason_code: str = ""


# ---------------------------------------------------------------------
# Freshness tracker
# ---------------------------------------------------------------------


class DiscoveryFreshnessTracker(ABC):
    @abstractmethod
    def check(self, record: DiscoveryRecord) -> PropagationDecision:
        ...

    @abstractmethod
    def commit(self, record: DiscoveryRecord) -> None:
        ...


@dataclass
class InMemoryDiscoveryFreshnessTracker(DiscoveryFreshnessTracker):
    """Per ``(workload_iss, workload_kid)`` highest-issued_at map."""

    _highest: dict[tuple[str, str], datetime] = field(default_factory=dict)

    def _key(self, record: DiscoveryRecord) -> tuple[str, str]:
        return (record.workload_iss, record.workload_kid)

    def check(self, record: DiscoveryRecord) -> PropagationDecision:
        try:
            ts = _parse_rfc3339(record.issued_at)
        except (ValueError, TypeError) as exc:
            raise DiscoveryPropagationError(
                f"record.issued_at is not parseable RFC 3339: "
                f"{record.issued_at!r}"
            ) from exc
        previous = self._highest.get(self._key(record))
        if previous is not None and ts <= previous:
            return PropagationDecision(
                allowed=False,
                reason=(
                    f"discovery record for {record.workload_iss!r}/"
                    f"{record.workload_kid!r} is not fresher: "
                    f"issued_at={ts.isoformat()}, "
                    f"previous_highest={previous.isoformat()}"
                ),
                reason_code=DenyReason.DISCOVERY_REWOUND.value,
            )
        return PropagationDecision(allowed=True, reason="ok", reason_code="ok")

    def commit(self, record: DiscoveryRecord) -> None:
        """Record this record's ``issued_at`` as the new high-water mark.

        Idempotent: committing a record whose ``issued_at`` is older
        than what we already pinned is a no-op (so a re-run of an
        out-of-order admission doesn't accidentally lower the pin).
        """
        try:
            ts = _parse_rfc3339(record.issued_at)
        except (ValueError, TypeError) as exc:
            raise DiscoveryPropagationError(
                f"record.issued_at is not parseable RFC 3339: "
                f"{record.issued_at!r}"
            ) from exc
        key = self._key(record)
        previous = self._highest.get(key)
        if previous is None or ts > previous:
            self._highest[key] = ts

    def evict_older_than(self, cutoff: datetime) -> int:
        """Drop pins older than ``cutoff``. Returns the eviction count."""
        if cutoff.tzinfo is None:
            raise DiscoveryPropagationError(
                "cutoff must be a timezone-aware datetime"
            )
        cutoff_utc = cutoff.astimezone(UTC)
        to_drop = [k for k, ts in self._highest.items() if ts < cutoff_utc]
        for k in to_drop:
            del self._highest[k]
        return len(to_drop)


# ---------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------


class DiscoveryPropagationLimiter(ABC):
    @abstractmethod
    def check(self, record: DiscoveryRecord, *, at: datetime) -> PropagationDecision:
        ...

    @abstractmethod
    def commit(self, record: DiscoveryRecord, *, at: datetime) -> None:
        ...


@dataclass
class InMemoryDiscoveryPropagationLimiter(DiscoveryPropagationLimiter):
    """Sliding-window per-workload republish limiter."""

    window: timedelta = timedelta(minutes=1)
    max_per_window: int = 1
    _events: dict[tuple[str, str], deque[datetime]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.window, timedelta) or self.window <= timedelta(0):
            raise DiscoveryPropagationError(
                "window must be a positive timedelta"
            )
        if not isinstance(self.max_per_window, int) or self.max_per_window < 1:
            raise DiscoveryPropagationError(
                "max_per_window must be a positive int"
            )

    def _key(self, record: DiscoveryRecord) -> tuple[str, str]:
        return (record.workload_iss, record.workload_kid)

    def _trim(self, queue: deque[datetime], at: datetime) -> None:
        cutoff = at.astimezone(UTC) - self.window
        while queue and queue[0] < cutoff:
            queue.popleft()

    def check(self, record: DiscoveryRecord, *, at: datetime) -> PropagationDecision:
        if at.tzinfo is None:
            raise DiscoveryPropagationError(
                "at must be a timezone-aware datetime"
            )
        queue = self._events.get(self._key(record))
        if queue is None:
            return PropagationDecision(
                allowed=True, reason="ok", reason_code="ok"
            )
        self._trim(queue, at)
        if len(queue) >= self.max_per_window:
            return PropagationDecision(
                allowed=False,
                reason=(
                    f"discovery republish rate-limited for "
                    f"{record.workload_iss!r}/{record.workload_kid!r}: "
                    f"{len(queue)} events in last {self.window}"
                    f" (cap {self.max_per_window})"
                ),
                reason_code=DenyReason.DISCOVERY_RATE_LIMITED.value,
            )
        return PropagationDecision(allowed=True, reason="ok", reason_code="ok")

    def commit(self, record: DiscoveryRecord, *, at: datetime) -> None:
        if at.tzinfo is None:
            raise DiscoveryPropagationError(
                "at must be a timezone-aware datetime"
            )
        key = self._key(record)
        queue = self._events.setdefault(key, deque())
        queue.append(at.astimezone(UTC))
        self._trim(queue, at)


# ---------------------------------------------------------------------
# Composite gate
# ---------------------------------------------------------------------


@dataclass
class DiscoveryAdmissionGate:
    """Compose freshness + rate-limit into one admit() entry point.

    Callers verify the record's signature + window via
    :func:`discovery_record.verify_record` BEFORE calling
    :meth:`admit`. Running the rate limiter pre-auth would let any
    spoofed ``workload_iss`` exhaust another workload's allowance.
    """

    freshness: DiscoveryFreshnessTracker
    limiter: DiscoveryPropagationLimiter

    def evaluate(
        self, record: DiscoveryRecord, *, at: datetime
    ) -> PropagationDecision:
        f = self.freshness.check(record)
        if not f.allowed:
            return f
        r = self.limiter.check(record, at=at)
        if not r.allowed:
            return r
        return PropagationDecision(allowed=True, reason="ok", reason_code="ok")

    def admit(
        self, record: DiscoveryRecord, *, at: datetime
    ) -> PropagationDecision:
        """Evaluate + commit on success."""
        decision = self.evaluate(record, at=at)
        if decision.allowed:
            self.freshness.commit(record)
            self.limiter.commit(record, at=at)
        return decision
