"""Retrieval policy v0 (Phase 2 Track B B2).

Closes B2 ("Purpose-of-Use Policy Enforcement"):

- "Retrieval denied unless class + purpose + identity align."
- "Cross-tenant retrieval denied by default."

A :class:`RetrievalPolicy` is consulted before a workload retrieves a
piece of :class:`data_classification.ClassifiedData`. The default v0
implementation (:class:`AllowlistRetrievalPolicy`) checks two things:

1. **Tenant boundary**. The data's *origin tenant* is the trust-domain
   component of the first lineage tag's ``actor_iss``. If the caller's
   trust domain differs and ``cross_tenant=DENY``, retrieval is rejected
   regardless of class — that's the "cross-tenant retrieval denied by
   default" rule.

2. **Identity + purpose + class alignment**. A retrieval is permitted
   only if a :class:`RetrievalRule` with the caller's exact SPIFFE ID and
   the exact ``purpose_of_use`` exists in the allowlist, and the data's
   class is at most as restrictive as the rule's ``max_class``.

Out of scope for v0
-------------------
- Wildcard / pattern rules (e.g. trust-domain-wildcard callers). v0 takes
  exact-match for the SPIFFE ID; operators compose multiple
  :class:`RetrievalRule` entries.
- Per-data-element column-level redaction (B3 territory).
- Tenant federation rules ("allow retrieval from domain A only when X").
- Audit checkpoint emission. Follow-up; pairs with the rest of Phase 2's
  checkpoint suite.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum

from audit_query import trust_domain_of
from data_classification import ClassifiedData, DataClass, is_more_restrictive
from deny_reason import DenyReason
from verify_envelope import SPIFFE_ID_RE


class CrossTenantRetrieval(StrEnum):
    """Default-deny config dial. Operators must opt in to allow cross-tenant."""

    DENY = "deny"
    ALLOW = "allow"


@dataclass(frozen=True)
class RetrievalDecision:
    allowed: bool
    reason: str
    reason_code: str = ""


@dataclass(frozen=True)
class RetrievalRule:
    caller_iss: str
    purpose_of_use: str
    max_class: DataClass

    def __post_init__(self) -> None:
        if not isinstance(self.caller_iss, str) or not SPIFFE_ID_RE.match(self.caller_iss):
            raise ValueError(f"invalid caller_iss: {self.caller_iss!r}")
        if not isinstance(self.purpose_of_use, str) or not self.purpose_of_use:
            raise ValueError("purpose_of_use must be a non-empty string")
        if not isinstance(self.max_class, DataClass):
            raise ValueError(f"max_class must be a DataClass: {self.max_class!r}")


class RetrievalPolicy(ABC):
    @abstractmethod
    def evaluate(
        self,
        *,
        caller_iss: str,
        purpose_of_use: str,
        data: ClassifiedData,
    ) -> RetrievalDecision:
        ...


@dataclass(frozen=True)
class AllowlistRetrievalPolicy(RetrievalPolicy):
    """Closed allowlist of ``(caller_iss, purpose_of_use, max_class)`` rules.

    Rules are evaluated in declaration order; the first matching
    ``(caller_iss, purpose_of_use)`` wins. The first-match semantic lets
    operators put narrow exceptions before broad defaults.
    """

    rules: tuple[RetrievalRule, ...]
    cross_tenant: CrossTenantRetrieval = field(
        default_factory=lambda: CrossTenantRetrieval.DENY
    )

    def __post_init__(self) -> None:
        if not isinstance(self.rules, tuple):
            raise ValueError("rules must be a tuple")
        for index, rule in enumerate(self.rules):
            if not isinstance(rule, RetrievalRule):
                raise ValueError(f"rules[{index}] must be a RetrievalRule")
        if not isinstance(self.cross_tenant, CrossTenantRetrieval):
            raise ValueError(
                f"cross_tenant must be a CrossTenantRetrieval value: {self.cross_tenant!r}"
            )

    def evaluate(
        self,
        *,
        caller_iss: str,
        purpose_of_use: str,
        data: ClassifiedData,
    ) -> RetrievalDecision:
        # Tenant check first. The origin tenant is the trust-domain of the
        # first lineage entry's actor_iss.
        if self.cross_tenant == CrossTenantRetrieval.DENY:
            caller_td = trust_domain_of(caller_iss)
            origin_iss = data.lineage[0].actor_iss
            origin_td = trust_domain_of(origin_iss)
            if caller_td and origin_td and caller_td != origin_td:
                return RetrievalDecision(
                    allowed=False,
                    reason=(
                        f"cross-tenant retrieval denied: caller in {caller_td!r}, "
                        f"data origin in {origin_td!r}"
                    ),
                    reason_code=DenyReason.RETRIEVAL_CROSS_TENANT.value,
                )

        # Identity + purpose + class alignment.
        for rule in self.rules:
            if rule.caller_iss == caller_iss and rule.purpose_of_use == purpose_of_use:
                if is_more_restrictive(data.data_class, rule.max_class):
                    return RetrievalDecision(
                        allowed=False,
                        reason=(
                            f"data class {data.data_class.value!r} exceeds rule "
                            f"max {rule.max_class.value!r} for "
                            f"({caller_iss}, {purpose_of_use})"
                        ),
                        reason_code=DenyReason.RETRIEVAL_CLASS_EXCEEDS_RULE.value,
                    )
                return RetrievalDecision(
                    allowed=True, reason="ok", reason_code="ok"
                )

        return RetrievalDecision(
            allowed=False,
            reason=(
                f"no retrieval rule matches caller={caller_iss!r}, "
                f"purpose_of_use={purpose_of_use!r}"
            ),
            reason_code=DenyReason.RETRIEVAL_NO_RULE_MATCH.value,
        )


class RetrievalError(ValueError):
    """Raised by :func:`require_retrieval` on denial."""

    def __init__(self, decision: RetrievalDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def require_retrieval(
    *,
    caller_iss: str,
    purpose_of_use: str,
    data: ClassifiedData,
    policy: RetrievalPolicy,
) -> RetrievalDecision:
    """Evaluate the policy and raise :class:`RetrievalError` on denial."""
    decision = policy.evaluate(
        caller_iss=caller_iss, purpose_of_use=purpose_of_use, data=data
    )
    if not decision.allowed:
        raise RetrievalError(decision)
    return decision
