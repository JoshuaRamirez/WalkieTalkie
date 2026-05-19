"""Checkpointed execution v0 (Phase 2 Track E E1).

Closes E1 ("Checkpointed Execution"):

- "Revalidate capability and policy at commit points."
- "Abort or downgrade behavior on revocation or policy epoch mismatch."

A long-running task interleaves *deliberation* (model thinking, tool
planning, drafting outputs) with *commit points* (moments where some
action becomes externally observable: a database write, an outbound
message, a tool call). The substrate already validates the capability
token at task entry; v0 here extends that check to every commit point,
so revocation or policy rotation that happens *during* a task takes
effect immediately.

A :class:`Checkpoint` is the in-process artifact a runtime constructs
just before committing. :func:`validate_checkpoint` re-checks three
things:

1. The capability's time window is still current — covers the case
   where the task ran long enough for ``exp`` to pass.
2. The capability's ``jti`` is not in the :class:`RevocationLedger` —
   covers operator-initiated revocation.
3. The active policy epoch still matches the epoch the task was
   authorized under — covers policy hot-reload between commit points.

The acceptance criterion for E ("Revoked capability cannot commit
writes post-revocation checkpoint") is verified by the unit test
:func:`test_revoked_capability_blocked_at_next_checkpoint`. Per the
plan's "abort or downgrade" guidance, operators configure the action
that fires on each failure mode via :class:`CheckpointPolicy`.

Out of scope for v0
-------------------
- Distributed revocation ledger / cluster-wide consistency. The
  in-process :class:`InMemoryRevocationLedger` is the v0 primitive;
  swapping in a distributed store (Redis, etcd) is the operator's
  concern.
- Partial-rollback semantics for compound actions. v0 stops at "commit
  vs. abort vs. downgrade"; carrying a half-committed batch backward
  is up to the task runtime.
- Multi-capability checkpoints. v0 validates one
  :class:`CapabilityClaims` per checkpoint; tasks spanning multiple
  capabilities (e.g. delegation chains) check each capability
  independently.
- Audit checkpoint emission. The validator's outcome is returnable;
  wiring a ``checkpoint.evaluate`` event is a follow-up that pairs
  with the rest of the Phase 2 checkpoint suite.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from capability_token import CapabilityClaims
from deny_reason import DenyReason
from verify_envelope import UUID_V7_RE


class CheckpointError(ValueError):
    """Raised when checkpoint inputs violate v0 invariants."""


class CheckpointAction(StrEnum):
    """What the runtime should do given the checkpoint verdict."""

    COMMIT = "commit"
    ABORT = "abort"
    DOWNGRADE = "downgrade"


@dataclass(frozen=True)
class Checkpoint:
    """One commit point in a long-running task."""

    checkpoint_id: str
    task_id: str
    step: int
    requested_at: str  # RFC 3339
    intended_action: str

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint_id, str) or not UUID_V7_RE.match(
            self.checkpoint_id
        ):
            raise CheckpointError(
                f"checkpoint_id must be UUIDv7: {self.checkpoint_id!r}"
            )
        if not isinstance(self.task_id, str) or not UUID_V7_RE.match(self.task_id):
            raise CheckpointError(f"task_id must be UUIDv7: {self.task_id!r}")
        if not isinstance(self.step, int) or isinstance(self.step, bool) or self.step < 0:
            raise CheckpointError(
                f"step must be a non-negative int: {self.step!r}"
            )
        if not isinstance(self.requested_at, str) or not self.requested_at:
            raise CheckpointError("requested_at must be a non-empty string")
        if not isinstance(self.intended_action, str) or not self.intended_action:
            raise CheckpointError("intended_action must be a non-empty string")


class RevocationLedger(ABC):
    """Bookkeeping for revoked capability ``jti`` values."""

    @abstractmethod
    def is_revoked(self, jti: str) -> bool:
        ...


@dataclass
class InMemoryRevocationLedger(RevocationLedger):
    """v0 single-process implementation.

    A revocation entry is just the set membership of a ``jti``; the
    timestamp/reason are recorded for inspection but not consulted at
    lookup. Operators wanting cluster-wide consistency should swap in
    a distributed implementation behind the same ABC.
    """

    revoked: dict[str, tuple[datetime, str]] = field(default_factory=dict)

    def revoke(
        self,
        jti: str,
        *,
        at: datetime,
        reason: str,
    ) -> None:
        if not isinstance(jti, str) or not UUID_V7_RE.match(jti):
            raise CheckpointError(f"jti must be UUIDv7: {jti!r}")
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise CheckpointError(
                "revoke 'at' must be a timezone-aware datetime"
            )
        if not isinstance(reason, str) or not reason:
            raise CheckpointError("reason must be a non-empty string")
        self.revoked[jti] = (at.astimezone(UTC), reason)

    def is_revoked(self, jti: str) -> bool:
        return jti in self.revoked


@dataclass(frozen=True)
class CheckpointPolicy:
    """Per-runtime configuration for the checkpoint validator.

    ``expected_epoch`` is the policy epoch the task was authorized
    under. Operators rotate the epoch when they push a new policy
    bundle; checkpoints in flight that were authorized under the old
    epoch will then fail their epoch check and resolve via
    ``on_epoch_mismatch``.
    """

    expected_epoch: str
    on_capability_expired: CheckpointAction = CheckpointAction.ABORT
    on_capability_revoked: CheckpointAction = CheckpointAction.ABORT
    on_epoch_mismatch: CheckpointAction = CheckpointAction.ABORT

    def __post_init__(self) -> None:
        if not isinstance(self.expected_epoch, str) or not self.expected_epoch:
            raise CheckpointError(
                "expected_epoch must be a non-empty string"
            )
        for name, value in (
            ("on_capability_expired", self.on_capability_expired),
            ("on_capability_revoked", self.on_capability_revoked),
            ("on_epoch_mismatch", self.on_epoch_mismatch),
        ):
            if not isinstance(value, CheckpointAction):
                raise CheckpointError(
                    f"{name} must be a CheckpointAction: {value!r}"
                )
            if value is CheckpointAction.COMMIT:
                raise CheckpointError(
                    f"{name} must be ABORT or DOWNGRADE — COMMIT is "
                    f"reserved for the success path"
                )


@dataclass(frozen=True)
class CheckpointDecision:
    action: CheckpointAction
    reason: str
    reason_code: str = ""


def validate_checkpoint(
    *,
    checkpoint: Checkpoint,
    capability: CapabilityClaims,
    active_epoch: str,
    policy: CheckpointPolicy,
    ledger: RevocationLedger,
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
) -> CheckpointDecision:
    """Decide whether ``checkpoint`` may commit.

    Checks, in order:

    1. Capability ``exp`` against ``current`` (with ``max_clock_skew``).
       Failure → ``policy.on_capability_expired``.
    2. Capability ``jti`` against the revocation ledger. Failure →
       ``policy.on_capability_revoked``.
    3. ``active_epoch`` against ``policy.expected_epoch``. Failure →
       ``policy.on_epoch_mismatch``.

    A success returns :class:`CheckpointAction.COMMIT`.
    """
    if not isinstance(checkpoint, Checkpoint):
        raise CheckpointError("checkpoint must be a Checkpoint")
    if not isinstance(capability, CapabilityClaims):
        raise CheckpointError("capability must be a CapabilityClaims")
    if not isinstance(active_epoch, str) or not active_epoch:
        raise CheckpointError("active_epoch must be a non-empty string")

    current_utc = current.astimezone(UTC)
    exp_dt = datetime.fromtimestamp(capability.exp, tz=UTC)
    if current_utc - max_clock_skew > exp_dt:
        return CheckpointDecision(
            action=policy.on_capability_expired,
            reason=(
                f"capability expired at exp={exp_dt.isoformat()}, "
                f"current={current_utc.isoformat()}"
            ),
            reason_code=DenyReason.CHECKPOINT_CAPABILITY_EXPIRED.value,
        )

    if ledger.is_revoked(capability.jti):
        return CheckpointDecision(
            action=policy.on_capability_revoked,
            reason=f"capability jti={capability.jti!r} has been revoked",
            reason_code=DenyReason.CHECKPOINT_CAPABILITY_REVOKED.value,
        )

    if active_epoch != policy.expected_epoch:
        return CheckpointDecision(
            action=policy.on_epoch_mismatch,
            reason=(
                f"policy epoch mismatch: expected={policy.expected_epoch!r}, "
                f"active={active_epoch!r}"
            ),
            reason_code=DenyReason.CHECKPOINT_POLICY_EPOCH_MISMATCH.value,
        )

    return CheckpointDecision(
        action=CheckpointAction.COMMIT,
        reason="ok",
        reason_code="ok",
    )
