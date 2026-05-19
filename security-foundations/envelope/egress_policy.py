"""Policy-adaptive egress v0 (Phase 2 Track C C2).

Closes C2 ("Policy-Adaptive Egress"):

- "Deny, allow, or quarantine based on risk and data class."
- "Mandatory NO_EXPORT for restricted-class outputs where required."

An :class:`EgressPolicy` is consulted *after* the output scanner runs
(Phase 2 Track C C1) and decides one of three actions:

- :class:`EgressAction.ALLOW` — release the artifact downstream.
- :class:`EgressAction.QUARANTINE` — hold the artifact pending human
  review (the C3 slice will give that queue a signed-decision shape).
- :class:`EgressAction.DENY` — refuse to release the artifact.

The v0 policy (:class:`MatrixEgressPolicy`) is a 2-D matrix indexed by
(``RiskLevel``, ``DataClass``). Unmatched cells default to
:class:`EgressAction.DENY` — closed-allowlist semantics. Operators
opt into release at every cell explicitly.

NO_EXPORT override
------------------
:class:`MatrixEgressPolicy.restricted_no_export` (default ``True``)
forces every ``DataClass.RESTRICTED`` artifact to :class:`EgressAction.DENY`,
regardless of risk score and regardless of matrix entries — that's the
"mandatory NO_EXPORT" rule. Operators can flip it off
(``restricted_no_export=False``) to take responsibility for restricted
artifacts in the matrix instead.

Risk-score input
----------------
:meth:`MatrixEgressPolicy.evaluate` takes the artifact's risk
(:class:`output_scanning.RiskLevel`) directly, not a :class:`ScanResult`.
That lets callers decide whether they want the result of the built-in
scanner, a custom registry, an ML classifier (Phase 2's deferred C1 half),
or a manual upgrade based on out-of-band context.

Out of scope for v0
-------------------
- Quarantine handoff to a review queue. v0 returns the
  ``EgressAction.QUARANTINE`` verdict; the C3 slice will turn that into
  a signed reviewer-decision record.
- Per-recipient (audience) policy variation. The matrix is keyed on
  ``(risk, data_class)`` only. Per-recipient overrides belong on top of
  this primitive in a higher-level coordinator.
- Per-tenant policy variation. Operators can compose multiple
  :class:`MatrixEgressPolicy` instances behind a per-tenant dispatcher.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

from data_classification import DataClass
from deny_reason import DenyReason
from output_scanning import RiskLevel


class EgressAction(StrEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    DENY = "deny"


@dataclass(frozen=True)
class EgressDecision:
    action: EgressAction
    reason: str
    reason_code: str = ""


@dataclass(frozen=True)
class EgressMatrixCell:
    risk: RiskLevel
    data_class: DataClass
    action: EgressAction

    def __post_init__(self) -> None:
        if not isinstance(self.risk, RiskLevel):
            raise ValueError(f"risk must be a RiskLevel: {self.risk!r}")
        if not isinstance(self.data_class, DataClass):
            raise ValueError(f"data_class must be a DataClass: {self.data_class!r}")
        if not isinstance(self.action, EgressAction):
            raise ValueError(f"action must be an EgressAction: {self.action!r}")


class EgressPolicy(ABC):
    @abstractmethod
    def evaluate(
        self,
        *,
        risk: RiskLevel,
        data_class: DataClass,
    ) -> EgressDecision:
        ...


@dataclass(frozen=True)
class MatrixEgressPolicy(EgressPolicy):
    """Default-deny (risk, data_class) decision matrix.

    ``restricted_no_export`` (default ``True``) forces any artifact whose
    ``data_class`` is :class:`DataClass.RESTRICTED` to be denied, taking
    precedence over the matrix. Set ``False`` to require the matrix to
    handle restricted artifacts explicitly.
    """

    cells: tuple[EgressMatrixCell, ...]
    restricted_no_export: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.cells, tuple):
            raise ValueError("cells must be a tuple")
        seen: set[tuple[RiskLevel, DataClass]] = set()
        for index, cell in enumerate(self.cells):
            if not isinstance(cell, EgressMatrixCell):
                raise ValueError(
                    f"cells[{index}] must be an EgressMatrixCell"
                )
            key = (cell.risk, cell.data_class)
            if key in seen:
                raise ValueError(
                    f"duplicate matrix cell for (risk={cell.risk.value}, "
                    f"data_class={cell.data_class.value})"
                )
            seen.add(key)
        if not isinstance(self.restricted_no_export, bool):
            raise ValueError(
                f"restricted_no_export must be bool: {self.restricted_no_export!r}"
            )

    def evaluate(
        self,
        *,
        risk: RiskLevel,
        data_class: DataClass,
    ) -> EgressDecision:
        # Mandatory NO_EXPORT first — overrides every matrix entry.
        if self.restricted_no_export and data_class is DataClass.RESTRICTED:
            return EgressDecision(
                action=EgressAction.DENY,
                reason=(
                    "restricted artifacts are blocked from egress "
                    "(restricted_no_export=True)"
                ),
                reason_code=DenyReason.EGRESS_RESTRICTED_NO_EXPORT.value,
            )

        for cell in self.cells:
            if cell.risk is risk and cell.data_class is data_class:
                if cell.action is EgressAction.ALLOW:
                    return EgressDecision(
                        action=EgressAction.ALLOW,
                        reason="ok",
                        reason_code="ok",
                    )
                if cell.action is EgressAction.QUARANTINE:
                    return EgressDecision(
                        action=EgressAction.QUARANTINE,
                        reason=(
                            f"quarantine: risk={risk.value}, "
                            f"data_class={data_class.value}"
                        ),
                        reason_code="egress_quarantined",
                    )
                # EgressAction.DENY explicitly listed in the matrix.
                return EgressDecision(
                    action=EgressAction.DENY,
                    reason=(
                        f"matrix denies (risk={risk.value}, "
                        f"data_class={data_class.value})"
                    ),
                    reason_code=DenyReason.EGRESS_DENIED_BY_POLICY.value,
                )

        return EgressDecision(
            action=EgressAction.DENY,
            reason=(
                f"no matrix entry for (risk={risk.value}, "
                f"data_class={data_class.value}); default-deny"
            ),
            reason_code=DenyReason.EGRESS_NO_MATRIX_ENTRY.value,
        )


class EgressError(ValueError):
    """Raised by :func:`require_egress` on non-ALLOW verdicts."""

    def __init__(self, decision: EgressDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def require_egress(
    *,
    risk: RiskLevel,
    data_class: DataClass,
    policy: EgressPolicy,
) -> EgressDecision:
    """Evaluate ``policy`` and raise :class:`EgressError` unless ALLOW.

    Quarantine and deny both raise — callers that need to distinguish
    them should call :meth:`EgressPolicy.evaluate` directly.
    """
    decision = policy.evaluate(risk=risk, data_class=data_class)
    if decision.action is not EgressAction.ALLOW:
        raise EgressError(decision)
    return decision
