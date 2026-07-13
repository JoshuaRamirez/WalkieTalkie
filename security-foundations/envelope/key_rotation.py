"""Key rotation drills v0 (Phase 3 Track D D1).

Closes D1 ("Key Rotation Drills"):

- "Overlap windows and deterministic cutovers." — :class:`KeyRotationPlan`
  describes the rotation of one ``(subject_iss, old_kid)`` to a new
  ``(subject_iss, new_kid)``. Three timestamps define the schedule:
  ``overlap_start`` (when the new kid begins to be accepted alongside
  the old), ``cutover_at`` (the deterministic moment after which new
  signings SHOULD use ``new_kid``), and ``overlap_end`` (when the old
  kid stops being accepted at all). For any clock time ``now``,
  :func:`current_phase` returns exactly one :class:`RotationPhase` and
  :func:`accepted_kids` returns the deterministic set of kids the
  verifier should honor.

- "Compatibility validation during transition." — :class:`RotationRegistry`
  holds many concurrent plans and answers
  :meth:`RotationRegistry.is_accepted` so callers can validate every
  incoming envelope against the active rotation state. Conflicting
  plans (e.g. two different ``new_kid`` rotations on the same
  ``(subject_iss, old_kid)`` overlapping in time) are rejected at
  registration with :class:`DenyReason.ROTATION_PLAN_CONFLICT`.

Rejection of a kid that is not in any active acceptance window
surfaces :class:`DenyReason.ROTATION_KID_NOT_ACCEPTED`.

Out of scope for v0
-------------------
- Signed rotation manifests. The shape is signing-ready; a follow-up
  would mirror the bootstrap-bundle / delegation-receipt pattern with
  an EdDSA-signed JCS body.
- Distributed rotation coordination across nodes. Operators wanting
  cluster-wide consistency point all replicas at a central rotation
  registry or back this with a distributed store.
- Automatic key generation / publishing. v0 takes the new kid as
  input; how it's minted is upstream.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from deny_reason import DenyReason
from verify_envelope import KID_RE, SPIFFE_ID_RE


class KeyRotationError(ValueError):
    """Raised when rotation inputs violate v0 invariants."""


class RotationPhase(StrEnum):
    PRE_OVERLAP = "pre_overlap"     # only old_kid accepted
    OVERLAP = "overlap"             # both accepted
    POST_CUTOVER = "post_cutover"   # both accepted (sunset window)
    COMPLETE = "complete"           # only new_kid accepted


@dataclass(frozen=True)
class KeyRotationPlan:
    """One scheduled rotation from ``old_kid`` to ``new_kid``."""

    subject_iss: str
    old_kid: str
    new_kid: str
    overlap_start: datetime
    cutover_at: datetime
    overlap_end: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.subject_iss, str) or not SPIFFE_ID_RE.match(self.subject_iss):
            raise KeyRotationError(
                f"invalid subject_iss: {self.subject_iss!r}"
            )
        if not isinstance(self.old_kid, str) or not KID_RE.match(self.old_kid):
            raise KeyRotationError(f"invalid old_kid: {self.old_kid!r}")
        if not isinstance(self.new_kid, str) or not KID_RE.match(self.new_kid):
            raise KeyRotationError(f"invalid new_kid: {self.new_kid!r}")
        if self.old_kid == self.new_kid:
            raise KeyRotationError("old_kid and new_kid must differ")
        for name, value in (
            ("overlap_start", self.overlap_start),
            ("cutover_at", self.cutover_at),
            ("overlap_end", self.overlap_end),
        ):
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise KeyRotationError(
                    f"{name} must be a timezone-aware datetime"
                )
        # overlap_start <= cutover_at <= overlap_end (strict for cutover
        # vs. start; equality permitted for "zero-overlap drills")
        if self.cutover_at < self.overlap_start:
            raise KeyRotationError(
                "cutover_at must be >= overlap_start"
            )
        if self.overlap_end < self.cutover_at:
            raise KeyRotationError(
                "overlap_end must be >= cutover_at"
            )


def current_phase(plan: KeyRotationPlan, *, now: datetime) -> RotationPhase:
    """Return the deterministic phase of ``plan`` at ``now``."""
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise KeyRotationError("now must be a timezone-aware datetime")
    now_utc = now.astimezone(UTC)
    if now_utc < plan.overlap_start.astimezone(UTC):
        return RotationPhase.PRE_OVERLAP
    if now_utc < plan.cutover_at.astimezone(UTC):
        return RotationPhase.OVERLAP
    if now_utc <= plan.overlap_end.astimezone(UTC):
        return RotationPhase.POST_CUTOVER
    return RotationPhase.COMPLETE


def accepted_kids(plan: KeyRotationPlan, *, now: datetime) -> frozenset[str]:
    """Return the kids a verifier should honor for ``plan`` at ``now``.

    - PRE_OVERLAP → ``{old_kid}``
    - OVERLAP / POST_CUTOVER → ``{old_kid, new_kid}``
    - COMPLETE → ``{new_kid}``
    """
    phase = current_phase(plan, now=now)
    if phase is RotationPhase.PRE_OVERLAP:
        return frozenset({plan.old_kid})
    if phase is RotationPhase.COMPLETE:
        return frozenset({plan.new_kid})
    return frozenset({plan.old_kid, plan.new_kid})


def _intervals_overlap(
    a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime
) -> bool:
    return a_start <= b_end and b_start <= a_end


@dataclass
class RotationRegistry:
    """Multiple in-flight plans, queryable by ``(subject_iss, kid)``.

    A registered plan claims the interval
    ``[overlap_start, overlap_end]`` for the ``(subject_iss, old_kid)``
    and ``(subject_iss, new_kid)`` pairs it touches. Two plans on the
    same ``subject_iss`` that overlap in time AND share at least one
    kid are rejected — operators must serialize them or pick distinct
    new kids.
    """

    _plans: list[KeyRotationPlan] = field(default_factory=list)

    def register(self, plan: KeyRotationPlan) -> None:
        if not isinstance(plan, KeyRotationPlan):
            raise KeyRotationError("plan must be a KeyRotationPlan")
        for existing in self._plans:
            if existing.subject_iss != plan.subject_iss:
                continue
            if not _intervals_overlap(
                plan.overlap_start.astimezone(UTC),
                plan.overlap_end.astimezone(UTC),
                existing.overlap_start.astimezone(UTC),
                existing.overlap_end.astimezone(UTC),
            ):
                continue
            shared = {plan.old_kid, plan.new_kid} & {
                existing.old_kid,
                existing.new_kid,
            }
            if shared:
                raise KeyRotationError(
                    f"conflicting plan for {plan.subject_iss!r}: "
                    f"shares kid(s) {sorted(shared)!r} with an existing "
                    f"plan in an overlapping time window "
                    f"[code={DenyReason.ROTATION_PLAN_CONFLICT.value}]"
                )
        self._plans.append(plan)

    def accepted_kids_for(
        self, subject_iss: str, *, now: datetime
    ) -> frozenset[str]:
        kids: set[str] = set()
        for plan in self._plans:
            if plan.subject_iss != subject_iss:
                continue
            kids |= accepted_kids(plan, now=now)
        return frozenset(kids)

    def is_accepted(
        self, subject_iss: str, kid: str, *, now: datetime
    ) -> bool:
        return kid in self.accepted_kids_for(subject_iss, now=now)

    def evict_completed(self, *, now: datetime) -> int:
        """Drop plans whose ``overlap_end`` has long passed.

        Returns the number of plans evicted. Evicted plans no longer
        contribute to :meth:`accepted_kids_for` — so callers should
        ensure their replacement plans (or a steady-state trust store
        re-load) have taken effect before evicting.
        """
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise KeyRotationError("now must be a timezone-aware datetime")
        now_utc = now.astimezone(UTC)
        before = len(self._plans)
        self._plans = [
            p for p in self._plans if p.overlap_end.astimezone(UTC) >= now_utc
        ]
        return before - len(self._plans)

    def snapshot(self) -> tuple[KeyRotationPlan, ...]:
        return tuple(self._plans)


def require_accepted_kid(
    registry: RotationRegistry,
    *,
    subject_iss: str,
    kid: str,
    now: datetime,
) -> None:
    """Raise :class:`KeyRotationError` if ``kid`` is not in the
    rotation-accepted set for ``subject_iss`` at ``now``.

    Callers can fall back to the static trust store when this raises
    — the registry's role is to OVERRIDE the static store with
    transitional acceptance, not to replace it.
    """
    if registry.is_accepted(subject_iss, kid, now=now):
        return
    raise KeyRotationError(
        f"kid {kid!r} is not accepted for subject {subject_iss!r} "
        f"at {now.isoformat()} "
        f"[code={DenyReason.ROTATION_KID_NOT_ACCEPTED.value}]"
    )


def build_plan(
    *,
    subject_iss: str,
    old_kid: str,
    new_kid: str,
    overlap_start: datetime,
    cutover_at: datetime,
    overlap_end: datetime,
) -> KeyRotationPlan:
    """Convenience constructor for the common case."""
    return KeyRotationPlan(
        subject_iss=subject_iss,
        old_kid=old_kid,
        new_kid=new_kid,
        overlap_start=overlap_start,
        cutover_at=cutover_at,
        overlap_end=overlap_end,
    )


def build_registry(plans: Iterable[KeyRotationPlan] = ()) -> RotationRegistry:
    reg = RotationRegistry()
    for plan in plans:
        reg.register(plan)
    return reg
