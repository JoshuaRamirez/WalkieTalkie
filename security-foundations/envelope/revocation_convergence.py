"""Revocation convergence v0 (Phase 3 Track D D2).

Closes D2 ("Revocation Convergence") on top of the Phase 2 E1
:class:`InMemoryRevocationLedger`:

- "Push + pull propagation." — :class:`RevocationBroadcast` is the
  push-side announcement shape. Each consumer node ACKs the
  broadcast via :meth:`ConvergenceTracker.record_ack`. Pull-side
  consumers that arrive late record the same way; the tracker
  doesn't distinguish push from pull — what matters is that a node
  has confirmed it sees the revocation.

- "Emergency fast-path revocation." — broadcasts carry a
  :attr:`RevocationBroadcast.fast_path` flag. Pair with an
  :class:`SLOPolicy` that gives fast-path broadcasts a tighter
  deadline. The tracker records the timestamp of every ack so SLO
  evaluation can compute exact time-to-converge.

- "Convergence SLO telemetry." — :func:`evaluate_slo` returns a
  :class:`SLOStatus` (``MEETING`` / ``PENDING`` / ``MISSED``) plus a
  :class:`ConvergenceSnapshot` carrying coverage percent,
  acks-received vs. expected, and timing data suitable for
  dashboards.

The Phase 2 E1 acceptance criterion — "Revoked capability cannot
commit writes post-revocation checkpoint" — already holds via
:func:`checkpointed_execution.validate_checkpoint`. D2 adds the
operational layer: operators can prove, with timestamps, that the
revocation propagated everywhere it needed to inside the SLO.

Out of scope for v0
-------------------
- Signed broadcasts and signed acks. Same signing-ready dataclass
  shape pattern as the other Phase 3 modules; a follow-up adds the
  EdDSA + JCS body.
- Distributed convergence state. The :class:`InMemoryConvergenceTracker`
  is single-process; cluster-wide consistency belongs to a
  distributed store behind the :class:`ConvergenceTracker` ABC.
- Probabilistic / sampling-based propagation. v0 expects every node
  in ``expected_nodes`` to ACK individually.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from verify_envelope import UUID_V7_RE


class RevocationConvergenceError(ValueError):
    """Raised when convergence inputs violate v0 invariants."""


@dataclass(frozen=True)
class RevocationBroadcast:
    """The push-side announcement that capability ``jti`` is revoked."""

    jti: str
    issued_at: datetime
    fast_path: bool
    reason: str
    expected_nodes: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.jti, str) or not UUID_V7_RE.match(self.jti):
            raise RevocationConvergenceError(
                f"jti must be UUIDv7: {self.jti!r}"
            )
        if not isinstance(self.issued_at, datetime) or self.issued_at.tzinfo is None:
            raise RevocationConvergenceError(
                "issued_at must be a timezone-aware datetime"
            )
        if not isinstance(self.fast_path, bool):
            raise RevocationConvergenceError(
                f"fast_path must be bool: {self.fast_path!r}"
            )
        if not isinstance(self.reason, str) or not self.reason:
            raise RevocationConvergenceError(
                "reason must be a non-empty string"
            )
        if not isinstance(self.expected_nodes, frozenset):
            raise RevocationConvergenceError(
                "expected_nodes must be a frozenset of node ids"
            )
        if not self.expected_nodes:
            raise RevocationConvergenceError(
                "expected_nodes must be non-empty"
            )
        for node in self.expected_nodes:
            if not isinstance(node, str) or not node:
                raise RevocationConvergenceError(
                    f"node ids must be non-empty strings: {node!r}"
                )


class ConvergenceTracker(ABC):
    @abstractmethod
    def register_broadcast(self, broadcast: RevocationBroadcast) -> None:
        ...

    @abstractmethod
    def record_ack(self, jti: str, node_id: str, *, at: datetime) -> None:
        ...

    @abstractmethod
    def acks_for(self, jti: str) -> dict[str, datetime]:
        ...

    @abstractmethod
    def broadcast(self, jti: str) -> RevocationBroadcast | None:
        ...


@dataclass
class InMemoryConvergenceTracker(ConvergenceTracker):
    """v0 single-process tracker.

    Operators wanting cluster-wide convergence should swap in a
    distributed implementation behind the :class:`ConvergenceTracker`
    ABC; the SLO evaluator works against either.
    """

    _broadcasts: dict[str, RevocationBroadcast] = field(default_factory=dict)
    _acks: dict[str, dict[str, datetime]] = field(default_factory=dict)

    def register_broadcast(self, broadcast: RevocationBroadcast) -> None:
        if broadcast.jti in self._broadcasts:
            raise RevocationConvergenceError(
                f"broadcast for jti={broadcast.jti!r} already registered"
            )
        self._broadcasts[broadcast.jti] = broadcast
        self._acks.setdefault(broadcast.jti, {})

    def record_ack(self, jti: str, node_id: str, *, at: datetime) -> None:
        if jti not in self._broadcasts:
            raise RevocationConvergenceError(
                f"no broadcast registered for jti={jti!r}"
            )
        broadcast = self._broadcasts[jti]
        if node_id not in broadcast.expected_nodes:
            raise RevocationConvergenceError(
                f"node {node_id!r} is not in the expected_nodes set for "
                f"broadcast jti={jti!r}"
            )
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise RevocationConvergenceError(
                "at must be a timezone-aware datetime"
            )
        at_utc = at.astimezone(UTC)
        # Earliest-ack wins — a node re-acking later is benign but
        # shouldn't advance our convergence clock.
        existing = self._acks[jti].get(node_id)
        if existing is None or at_utc < existing:
            self._acks[jti][node_id] = at_utc

    def acks_for(self, jti: str) -> dict[str, datetime]:
        return dict(self._acks.get(jti, {}))

    def broadcast(self, jti: str) -> RevocationBroadcast | None:
        return self._broadcasts.get(jti)


# ---------------------------------------------------------------------
# SLO evaluation
# ---------------------------------------------------------------------


class SLOStatus(StrEnum):
    MEETING = "meeting"     # coverage met within deadline
    PENDING = "pending"     # not yet met, but deadline hasn't passed
    MISSED = "missed"       # deadline passed without meeting coverage


@dataclass(frozen=True)
class SLOPolicy:
    """Two-tier SLO with separate normal / fast-path deadlines.

    Coverage is the fraction of ``expected_nodes`` that have ACK'd.
    A broadcast meets SLO when coverage reaches ``target_coverage``
    on-or-before its tier's deadline.
    """

    target_coverage: float            # 0.0..1.0
    normal_deadline: timedelta
    fast_path_deadline: timedelta

    def __post_init__(self) -> None:
        if not isinstance(self.target_coverage, float) and not isinstance(
            self.target_coverage, int
        ):
            raise RevocationConvergenceError(
                f"target_coverage must be a number in [0,1]: "
                f"{self.target_coverage!r}"
            )
        if not (0.0 < self.target_coverage <= 1.0):
            raise RevocationConvergenceError(
                f"target_coverage must be in (0, 1]: {self.target_coverage!r}"
            )
        for name, value in (
            ("normal_deadline", self.normal_deadline),
            ("fast_path_deadline", self.fast_path_deadline),
        ):
            if not isinstance(value, timedelta) or value <= timedelta(0):
                raise RevocationConvergenceError(
                    f"{name} must be a positive timedelta: {value!r}"
                )

    def deadline_for(self, broadcast: RevocationBroadcast) -> timedelta:
        return (
            self.fast_path_deadline if broadcast.fast_path else self.normal_deadline
        )


@dataclass(frozen=True)
class ConvergenceSnapshot:
    jti: str
    acks_received: int
    acks_expected: int
    coverage: float
    time_to_target: timedelta | None   # None until target met
    elapsed: timedelta                  # since broadcast.issued_at
    deadline: timedelta
    status: SLOStatus
    fast_path: bool


def evaluate_slo(
    *,
    tracker: ConvergenceTracker,
    jti: str,
    policy: SLOPolicy,
    now: datetime,
) -> ConvergenceSnapshot:
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise RevocationConvergenceError(
            "now must be a timezone-aware datetime"
        )
    broadcast = tracker.broadcast(jti)
    if broadcast is None:
        raise RevocationConvergenceError(
            f"no broadcast registered for jti={jti!r}"
        )
    acks = tracker.acks_for(jti)
    expected = len(broadcast.expected_nodes)
    received = sum(1 for node in acks if node in broadcast.expected_nodes)
    coverage = received / expected if expected else 0.0

    deadline = policy.deadline_for(broadcast)
    elapsed = now.astimezone(UTC) - broadcast.issued_at.astimezone(UTC)

    # When did coverage first reach the target?
    time_to_target: timedelta | None = None
    if coverage >= policy.target_coverage:
        sorted_acks = sorted(
            acks[n] for n in broadcast.expected_nodes if n in acks
        )
        # Number of acks needed to hit target_coverage exactly.
        needed = max(1, int(-(-policy.target_coverage * expected // 1)))
        if needed <= len(sorted_acks):
            time_to_target = (
                sorted_acks[needed - 1] - broadcast.issued_at.astimezone(UTC)
            )

    if coverage >= policy.target_coverage and time_to_target is not None:
        # Met target — did it happen inside the deadline?
        status = (
            SLOStatus.MEETING
            if time_to_target <= deadline
            else SLOStatus.MISSED
        )
    elif elapsed > deadline:
        status = SLOStatus.MISSED
    else:
        status = SLOStatus.PENDING

    return ConvergenceSnapshot(
        jti=jti,
        acks_received=received,
        acks_expected=expected,
        coverage=coverage,
        time_to_target=time_to_target,
        elapsed=elapsed,
        deadline=deadline,
        status=status,
        fast_path=broadcast.fast_path,
    )


def pending_broadcasts(
    tracker: ConvergenceTracker,
    *,
    jtis: Iterable[str],
    policy: SLOPolicy,
    now: datetime,
) -> tuple[ConvergenceSnapshot, ...]:
    """Return snapshots for every jti whose status is not MEETING.

    Useful as the foundation for an alerting / dashboard query — feed
    it the in-flight jti set and surface anything pending or missed.
    """
    out: list[ConvergenceSnapshot] = []
    for jti in jtis:
        snap = evaluate_slo(tracker=tracker, jti=jti, policy=policy, now=now)
        if snap.status is not SLOStatus.MEETING:
            out.append(snap)
    return tuple(out)
