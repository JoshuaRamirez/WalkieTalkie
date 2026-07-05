"""Structured policy engine + decision IDs (Phase 5 Track B, D5.3). [RUNNABLE]

Closes the "policy engine" part of the vision's Layer C. The vision
wants "a policy engine (OPA/Rego or Cedar) for runtime authZ
decisions" where "every tool invocation must carry a provable chain:
caller identity, delegated capability, **policy decision ID**."

Phases 1–2 shipped hard-coded allowlist gates (`tool_policy_gate`,
`retrieval_policy`, `egress_policy`). Those enforce the right things
but they're bespoke code, not a uniform decision authority, and they
don't emit a decision ID a forensic trace can point at. This module
adds the missing engine: a single `PolicyEngine.decide(request)` that
takes a structured `(principal, action, resource, context)`, evaluates
it against ordered rules, and returns a `PolicyDecision` carrying a
`permit|deny` effect, the matched rule name, and a **UUIDv7 decision
id** for the audit chain.

Design choices (documented, deliberate):

- **Structured, not a DSL.** v0 is a native evaluator over
  dataclasses, not a Rego/Cedar parser. A rule matches on exact or
  wildcard `principal` / `action` / `resource` plus a small set of
  typed `conditions` on the `context` dict. Cedar/Rego *interop* — a
  parser that compiles their syntax into these rules — is a follow-up
  (see DEFERRED.md). The `PolicyEngine` ABC is the seam that swap
  goes behind.
- **Deny-by-default.** No matching permit ⇒ deny, matching the
  vision's deny-by-default posture.
- **First-match wins**, so operators put narrow exceptions before
  broad rules — same convention as `retrieval_policy`.

The `policy.decide` audit wiring and the baseline rule library that
mirrors the existing gates land in the companion B2 slice; this slice
is the engine itself.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from capability_issuer import generate_uuidv7

# A wildcard token that matches any principal / action / resource.
ANY = "*"


class PolicyEngineError(ValueError):
    """Raised when policy inputs violate v0 invariants."""


class Effect(StrEnum):
    PERMIT = "permit"
    DENY = "deny"


class ConditionOp(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"


@dataclass(frozen=True)
class Condition:
    """A typed predicate over one key of the request context."""

    key: str
    op: ConditionOp
    value: Any

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise PolicyEngineError("condition key must be a non-empty string")
        if not isinstance(self.op, ConditionOp):
            raise PolicyEngineError(f"op must be a ConditionOp: {self.op!r}")
        if self.op in (ConditionOp.IN, ConditionOp.NOT_IN):
            if not isinstance(self.value, (list, tuple, set, frozenset)):
                raise PolicyEngineError(
                    f"{self.op.value} condition value must be a collection"
                )

    def matches(self, context: dict[str, Any]) -> bool:
        present = self.key in context
        actual = context.get(self.key)
        if self.op is ConditionOp.EQUALS:
            return present and actual == self.value
        if self.op is ConditionOp.NOT_EQUALS:
            # A missing key is "not equal" to any concrete value.
            return actual != self.value
        if self.op is ConditionOp.IN:
            return present and actual in self.value
        if self.op is ConditionOp.NOT_IN:
            return actual not in self.value
        raise PolicyEngineError(f"unhandled op: {self.op!r}")  # pragma: no cover


@dataclass(frozen=True)
class PolicyRule:
    name: str
    effect: Effect
    principal: str = ANY
    action: str = ANY
    resource: str = ANY
    conditions: tuple[Condition, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise PolicyEngineError("rule name must be a non-empty string")
        if not isinstance(self.effect, Effect):
            raise PolicyEngineError(f"effect must be an Effect: {self.effect!r}")
        for attr in ("principal", "action", "resource"):
            v = getattr(self, attr)
            if not isinstance(v, str) or not v:
                raise PolicyEngineError(f"{attr} must be a non-empty string")
        if not isinstance(self.conditions, tuple):
            raise PolicyEngineError("conditions must be a tuple")
        for c in self.conditions:
            if not isinstance(c, Condition):
                raise PolicyEngineError("each condition must be a Condition")

    def _field_matches(self, rule_val: str, req_val: str) -> bool:
        return rule_val == ANY or rule_val == req_val

    def matches(self, request: PolicyRequest) -> bool:
        return (
            self._field_matches(self.principal, request.principal)
            and self._field_matches(self.action, request.action)
            and self._field_matches(self.resource, request.resource)
            and all(c.matches(request.context) for c in self.conditions)
        )


@dataclass(frozen=True)
class PolicyRequest:
    principal: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for attr in ("principal", "action", "resource"):
            v = getattr(self, attr)
            if not isinstance(v, str) or not v:
                raise PolicyEngineError(f"{attr} must be a non-empty string")
        if not isinstance(self.context, dict):
            raise PolicyEngineError("context must be a dict")


@dataclass(frozen=True)
class PolicyDecision:
    effect: Effect
    decision_id: str
    matched_rule: str  # "" when deny-by-default (no rule matched)
    reason: str

    @property
    def permitted(self) -> bool:
        return self.effect is Effect.PERMIT


class PolicyEngine(ABC):
    @abstractmethod
    def decide(
        self, request: PolicyRequest, *, now: datetime | None = None
    ) -> PolicyDecision:
        ...


@dataclass(frozen=True)
class NativePolicyEngine(PolicyEngine):
    """First-match, deny-by-default evaluator over a rule tuple.

    ``rules`` are evaluated in order; the first rule that matches the
    request decides (permit or deny). If no rule matches, the effect
    is deny (the vision's deny-by-default posture).
    """

    rules: tuple[PolicyRule, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.rules, tuple):
            raise PolicyEngineError("rules must be a tuple")
        seen: set[str] = set()
        for index, rule in enumerate(self.rules):
            if not isinstance(rule, PolicyRule):
                raise PolicyEngineError(f"rules[{index}] must be a PolicyRule")
            if rule.name in seen:
                raise PolicyEngineError(f"duplicate rule name: {rule.name!r}")
            seen.add(rule.name)

    def decide(
        self, request: PolicyRequest, *, now: datetime | None = None
    ) -> PolicyDecision:
        if not isinstance(request, PolicyRequest):
            raise PolicyEngineError("request must be a PolicyRequest")
        decision_id = generate_uuidv7(now=now)
        for rule in self.rules:
            if rule.matches(request):
                return PolicyDecision(
                    effect=rule.effect,
                    decision_id=decision_id,
                    matched_rule=rule.name,
                    reason=(
                        f"rule {rule.name!r} → {rule.effect.value} for "
                        f"({request.principal}, {request.action}, "
                        f"{request.resource})"
                    ),
                )
        return PolicyDecision(
            effect=Effect.DENY,
            decision_id=decision_id,
            matched_rule="",
            reason=(
                f"deny-by-default: no rule matched "
                f"({request.principal}, {request.action}, {request.resource})"
            ),
        )
