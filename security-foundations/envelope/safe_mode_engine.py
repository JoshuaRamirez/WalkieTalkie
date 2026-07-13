"""Compound-failure safe-mode engine v0 (Phase 3 Track C C1+C2+C3).

Implements the §4.2 global safe-mode state semantics (S0..S4) plus
the §4.1 authority hierarchy and the §4.3 deterministic transition
workflow:

- C1 Trigger Detection
    :class:`Trigger` + :class:`TriggerKind` taxonomy covering clock
    trust failure, ledger divergence, policy rollback, revocation
    uncertainty, and critical anomaly quarantine signal.
- C2 State Computation
    :class:`SafeModeEngine.observe` computes the minimum required
    safe-mode state across all currently-active triggers. The
    resolved state is always ``max(trigger.minimum_state for trigger
    in active)`` — i.e. the most severe trigger wins. The
    :class:`TriggerCategory` taxonomy carries the §4.1 authority
    hierarchy (CRYPTO_TRUST > AUTHORIZATION > DATA_PROTECTION >
    AVAILABILITY).
- C3 Transition Runtime
    Deterministic, idempotent state transitions. Observing the same
    trigger twice is a no-op. Clearing a non-active trigger is a
    no-op. Every state change emits a :class:`StateTransition`
    record with the trigger set and category. Manual downgrades
    require either every trigger to be cleared (automatic recovery)
    or a :class:`DowngradeApproval` whose authority category
    outranks every still-active trigger.

The Track C acceptance criterion — "Compound failures always result
in predictable state and logs" — is pinned by the determinism tests:
two engines processing the same trigger sequence reach the same
state and emit the same transitions.

Out of scope for v0
-------------------
- Signed :class:`StateTransition` and :class:`DowngradeApproval`
  artifacts. The shapes are designed so an EdDSA-signed JCS body
  fits non-breakingly later (same pattern as
  :mod:`delegation_receipt` and :mod:`reviewer_workflow`).
- Compound-failure drill harness. The engine is the foundation; the
  drill harness lives in a follow-up under Track D.
- Per-state side effects (freeze writes / push revalidation /
  increase forensic logging — §4.2 transition workflow). The engine
  emits transitions; runtimes wire side effects to them.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from deny_reason import DenyReason


class SafeModeEngineError(ValueError):
    """Raised when engine inputs violate v0 invariants."""


class SafeModeState(StrEnum):
    """Plan §4.2 global state semantics, ordered by severity."""

    S0_NORMAL = "s0_normal"
    S1_GUARDED = "s1_guarded"
    S2_RESTRICTED = "s2_restricted"
    S3_QUARANTINE = "s3_quarantine"
    S4_LOCKDOWN = "s4_lockdown"


_STATE_RANK = {
    SafeModeState.S0_NORMAL: 0,
    SafeModeState.S1_GUARDED: 1,
    SafeModeState.S2_RESTRICTED: 2,
    SafeModeState.S3_QUARANTINE: 3,
    SafeModeState.S4_LOCKDOWN: 4,
}


def is_more_severe_state(a: SafeModeState, b: SafeModeState) -> bool:
    return _STATE_RANK[a] > _STATE_RANK[b]


def max_state(states: Iterable[SafeModeState]) -> SafeModeState:
    best = SafeModeState.S0_NORMAL
    for s in states:
        if _STATE_RANK[s] > _STATE_RANK[best]:
            best = s
    return best


class TriggerCategory(StrEnum):
    """Plan §4.1 authority hierarchy, ordered by precedence.

    Cryptographic trust integrity outranks authorization, which
    outranks data protection, which outranks availability. A
    downgrade approval can only override triggers in its own
    category or below.
    """

    CRYPTO_TRUST = "crypto_trust"
    AUTHORIZATION = "authorization"
    DATA_PROTECTION = "data_protection"
    AVAILABILITY = "availability"


_CATEGORY_RANK = {
    TriggerCategory.AVAILABILITY: 0,
    TriggerCategory.DATA_PROTECTION: 1,
    TriggerCategory.AUTHORIZATION: 2,
    TriggerCategory.CRYPTO_TRUST: 3,
}


def is_higher_authority(a: TriggerCategory, b: TriggerCategory) -> bool:
    return _CATEGORY_RANK[a] > _CATEGORY_RANK[b]


class TriggerKind(StrEnum):
    """Plan §C1 trigger taxonomy."""

    CLOCK_TRUST_FAILURE = "clock_trust_failure"
    LEDGER_DIVERGENCE = "ledger_divergence"
    POLICY_ROLLBACK = "policy_rollback"
    REVOCATION_UNCERTAINTY = "revocation_uncertainty"
    ANOMALY_QUARANTINE = "anomaly_quarantine"


# Default kind → state + category mapping derived from §4.1 / §4.2.
# Operators can construct a Trigger with their own minimum_state /
# category to override.
_DEFAULT_TRIGGER_PROFILE: dict[TriggerKind, tuple[SafeModeState, TriggerCategory]] = {
    TriggerKind.CLOCK_TRUST_FAILURE: (
        SafeModeState.S3_QUARANTINE,
        TriggerCategory.CRYPTO_TRUST,
    ),
    TriggerKind.LEDGER_DIVERGENCE: (
        SafeModeState.S4_LOCKDOWN,
        TriggerCategory.CRYPTO_TRUST,
    ),
    TriggerKind.POLICY_ROLLBACK: (
        SafeModeState.S2_RESTRICTED,
        TriggerCategory.AUTHORIZATION,
    ),
    TriggerKind.REVOCATION_UNCERTAINTY: (
        SafeModeState.S2_RESTRICTED,
        TriggerCategory.AUTHORIZATION,
    ),
    TriggerKind.ANOMALY_QUARANTINE: (
        SafeModeState.S3_QUARANTINE,
        TriggerCategory.DATA_PROTECTION,
    ),
}


def default_profile_for(kind: TriggerKind) -> tuple[SafeModeState, TriggerCategory]:
    """Return the (state, category) defaults for ``kind``."""
    return _DEFAULT_TRIGGER_PROFILE[kind]


@dataclass(frozen=True)
class Trigger:
    """One active condition that forces the engine into a minimum state."""

    kind: TriggerKind
    category: TriggerCategory
    minimum_state: SafeModeState
    observed_at: datetime
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TriggerKind):
            raise SafeModeEngineError(
                f"kind must be a TriggerKind: {self.kind!r}"
            )
        if not isinstance(self.category, TriggerCategory):
            raise SafeModeEngineError(
                f"category must be a TriggerCategory: {self.category!r}"
            )
        if not isinstance(self.minimum_state, SafeModeState):
            raise SafeModeEngineError(
                f"minimum_state must be a SafeModeState: {self.minimum_state!r}"
            )
        if self.minimum_state is SafeModeState.S0_NORMAL:
            raise SafeModeEngineError(
                "minimum_state=S0_NORMAL is reserved for 'no active triggers'"
            )
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise SafeModeEngineError(
                "observed_at must be a timezone-aware datetime"
            )
        if not isinstance(self.detail, str):
            raise SafeModeEngineError("detail must be a string")


def trigger_for(
    kind: TriggerKind,
    *,
    observed_at: datetime,
    detail: str = "",
    minimum_state: SafeModeState | None = None,
    category: TriggerCategory | None = None,
) -> Trigger:
    """Convenience constructor using the default profile for ``kind``."""
    default_state, default_category = default_profile_for(kind)
    return Trigger(
        kind=kind,
        category=category if category is not None else default_category,
        minimum_state=minimum_state if minimum_state is not None else default_state,
        observed_at=observed_at,
        detail=detail,
    )


@dataclass(frozen=True)
class DowngradeApproval:
    """An out-of-band approval to downgrade safe-mode state.

    ``authority`` MUST be at least as high as every still-active
    trigger's category. The shape is signing-ready: a future slice
    can add EdDSA + JCS body fields next to ``approver_iss`` /
    ``approver_kid`` without breaking the data model.
    """

    approver_iss: str
    approver_kid: str
    authority: TriggerCategory
    issued_at: datetime
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.approver_iss, str) or not self.approver_iss:
            raise SafeModeEngineError("approver_iss must be a non-empty string")
        if not isinstance(self.approver_kid, str) or not self.approver_kid:
            raise SafeModeEngineError("approver_kid must be a non-empty string")
        if not isinstance(self.authority, TriggerCategory):
            raise SafeModeEngineError(
                f"authority must be a TriggerCategory: {self.authority!r}"
            )
        if not isinstance(self.issued_at, datetime) or self.issued_at.tzinfo is None:
            raise SafeModeEngineError(
                "issued_at must be a timezone-aware datetime"
            )


@dataclass(frozen=True)
class StateTransition:
    from_state: SafeModeState
    to_state: SafeModeState
    transition_at: datetime
    cause: str  # "trigger" | "clear" | "downgrade"
    active_kinds: tuple[TriggerKind, ...]
    detail: str = ""


@dataclass
class SafeModeEngine:
    current: SafeModeState = SafeModeState.S0_NORMAL
    _active: dict[TriggerKind, Trigger] = field(default_factory=dict)

    # --------- observation ---------

    def observe(self, trigger: Trigger) -> StateTransition | None:
        if not isinstance(trigger, Trigger):
            raise SafeModeEngineError("trigger must be a Trigger")
        previous = self.current
        # Idempotent: re-observing a trigger with the same kind is a
        # no-op unless minimum_state changes upward.
        existing = self._active.get(trigger.kind)
        if existing is not None and not is_more_severe_state(
            trigger.minimum_state, existing.minimum_state
        ):
            return None
        self._active[trigger.kind] = trigger
        new_state = self._compute_state()
        return self._maybe_transition(
            previous=previous,
            new_state=new_state,
            cause="trigger",
            at=trigger.observed_at,
            detail=f"{trigger.kind.value}: {trigger.detail}",
        )

    def clear(
        self, kind: TriggerKind, *, at: datetime, detail: str = ""
    ) -> StateTransition | None:
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise SafeModeEngineError("at must be a timezone-aware datetime")
        if kind not in self._active:
            return None
        del self._active[kind]
        previous = self.current
        new_state = self._compute_state()
        return self._maybe_transition(
            previous=previous,
            new_state=new_state,
            cause="clear",
            at=at,
            detail=f"cleared {kind.value}: {detail}",
        )

    def downgrade(
        self,
        *,
        to_state: SafeModeState,
        approval: DowngradeApproval,
    ) -> StateTransition:
        """Manual downgrade. Requires :class:`DowngradeApproval` whose
        authority outranks every still-active trigger's category.

        Idempotent only in the trivial case (downgrading to the current
        state, no triggers blocking). Raises
        :class:`SafeModeEngineError` with the corresponding
        :class:`DenyReason` otherwise.
        """
        if not isinstance(to_state, SafeModeState):
            raise SafeModeEngineError(
                f"to_state must be a SafeModeState: {to_state!r}"
            )
        if is_more_severe_state(to_state, self.current):
            raise SafeModeEngineError(
                f"downgrade target {to_state.value!r} is more severe "
                f"than current {self.current.value!r}; use observe()"
            )
        # Verify approval authority dominates every active trigger.
        for trigger in self._active.values():
            if is_higher_authority(trigger.category, approval.authority):
                raise SafeModeEngineError(
                    f"downgrade unauthorized: approval authority "
                    f"{approval.authority.value!r} is below active "
                    f"trigger {trigger.kind.value!r} "
                    f"(category {trigger.category.value!r})"
                )
        # The target state cannot be lower than what active triggers
        # require — the engine refuses to silently mask a current
        # cryptographic-trust failure with a downgrade.
        floor = self._compute_state()
        if is_more_severe_state(floor, to_state):
            raise SafeModeEngineError(
                f"downgrade to {to_state.value!r} blocked: active "
                f"triggers require at least {floor.value!r}; clear "
                f"them first or target {floor.value!r} or higher"
            )

        previous = self.current
        self.current = to_state
        return StateTransition(
            from_state=previous,
            to_state=to_state,
            transition_at=approval.issued_at,
            cause="downgrade",
            active_kinds=tuple(self._active.keys()),
            detail=(
                f"downgrade authorized by {approval.approver_iss!r}: "
                f"{approval.detail}"
            ),
        )

    # --------- introspection ---------

    @property
    def active_triggers(self) -> tuple[Trigger, ...]:
        return tuple(self._active.values())

    @property
    def active_kinds(self) -> tuple[TriggerKind, ...]:
        return tuple(self._active.keys())

    # --------- internals ---------

    def _compute_state(self) -> SafeModeState:
        if not self._active:
            return SafeModeState.S0_NORMAL
        return max_state(t.minimum_state for t in self._active.values())

    def _maybe_transition(
        self,
        *,
        previous: SafeModeState,
        new_state: SafeModeState,
        cause: str,
        at: datetime,
        detail: str,
    ) -> StateTransition | None:
        if new_state == previous:
            return None
        # Auto-elevation is unconditional. Auto-recovery (drop in
        # severity) is also unconditional when ALL triggers covering
        # the higher severity have been cleared — that is, the engine
        # only re-bases on the actual active set. Manual downgrade
        # to a lower state requires DowngradeApproval (downgrade()).
        self.current = new_state
        return StateTransition(
            from_state=previous,
            to_state=new_state,
            transition_at=at,
            cause=cause,
            active_kinds=tuple(self._active.keys()),
            detail=detail,
        )


def require_authorized_downgrade(
    engine: SafeModeEngine,
    *,
    to_state: SafeModeState,
    approval: DowngradeApproval,
) -> StateTransition:
    """Wrap :meth:`SafeModeEngine.downgrade` with a DenyReason-aware
    raise. Operators that want a deny-code on failure call this; the
    raw method raises :class:`SafeModeEngineError` without a
    DenyReason."""
    try:
        return engine.downgrade(to_state=to_state, approval=approval)
    except SafeModeEngineError as exc:
        msg = str(exc)
        if "unauthorized" in msg:
            raise SafeModeEngineError(
                f"{msg} [code={DenyReason.SAFE_MODE_DOWNGRADE_UNAUTHORIZED.value}]"
            ) from exc
        if "blocked" in msg or "active triggers require" in msg:
            raise SafeModeEngineError(
                f"{msg} [code={DenyReason.SAFE_MODE_DOWNGRADE_TRIGGERS_ACTIVE.value}]"
            ) from exc
        raise
