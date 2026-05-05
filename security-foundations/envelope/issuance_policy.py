"""Capability issuance policy v0.

Closes Phase 1 Track C C1 ("Capability Issuance Rules") and the Track C
acceptance criteria ("Policy error path is fail-closed" /
"Issuance service cannot mint broader scope than policy permits").

A :class:`CapabilityIssuer` consults an :class:`IssuancePolicy` before
minting. The default ``AllowAllPolicy`` preserves the pre-policy behavior
for callers that haven't opted in. Production callers should swap in
``AllowlistPolicy`` (or a custom subclass) so issuance is gated by an
explicit (sub, aud, scope) tuple plus a maximum TTL.

Out of scope for v0
-------------------
- Policy bundle format (Cedar / OPA Rego). v0 is a Python interface; future
  work can wrap a bundle compiler around it.
- Policy versioning, anti-rollback, canary (Phase 1 Track C C3, separate
  slice).
- Per-caller authorization for *who can request which policy decisions*
  (this is the issuance API surface, deferred until transport lands).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass(frozen=True)
class PolicyDecision:
    """Result of an :class:`IssuancePolicy` evaluation."""

    allowed: bool
    reason: str


class IssuancePolicyError(ValueError):
    """Raised by :meth:`CapabilityIssuer.issue` when the policy denies.

    Carries the underlying :class:`PolicyDecision` so callers wrapping the
    issuer (e.g., an HTTP API surface) can render it without re-deriving.
    """

    def __init__(self, message: str, *, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision


class IssuancePolicy(ABC):
    @abstractmethod
    def evaluate(
        self,
        *,
        sub: str,
        aud: str,
        scope: str,
        ttl: timedelta,
    ) -> PolicyDecision:
        ...


class AllowAllPolicy(IssuancePolicy):
    """Permissive default. Equivalent to no policy at all.

    Useful in tests and for migration: existing callers that didn't pass a
    policy continue to behave as before. Documented here as the explicit
    "no constraints" choice rather than an accidental default.
    """

    def evaluate(self, *, sub: str, aud: str, scope: str, ttl: timedelta) -> PolicyDecision:
        return PolicyDecision(allowed=True, reason="permissive")


@dataclass(frozen=True)
class AllowlistPolicy(IssuancePolicy):
    """Allow only explicitly listed (sub, aud, scope) tuples.

    Closes the C1 sub-bullets:

    - "Enforce least privilege at issuance" — every grant is opt-in.
    - "Explicit purpose-of-use required" — ``scope`` is the third tuple
      element and must match exactly.
    - "Audience pinning" — ``aud`` is the second tuple element.
    - "Minimum viable TTL" — ``max_ttl`` defaults to 5 minutes; per-call
      TTLs above this are denied. (The plan's wording "minimum viable"
      means *the smallest TTL that still works*; we enforce that by
      capping the maximum and letting callers pass smaller values.)
    """

    allowed_grants: frozenset[tuple[str, str, str]]
    max_ttl: timedelta = field(default_factory=lambda: timedelta(minutes=5))

    def __post_init__(self) -> None:
        if self.max_ttl <= timedelta(0):
            raise ValueError("max_ttl must be positive")

    def evaluate(self, *, sub: str, aud: str, scope: str, ttl: timedelta) -> PolicyDecision:
        if (sub, aud, scope) not in self.allowed_grants:
            return PolicyDecision(
                allowed=False,
                reason=f"grant ({sub}, {aud}, {scope}) not in allowlist",
            )
        if ttl > self.max_ttl:
            return PolicyDecision(
                allowed=False,
                reason=f"requested ttl {ttl} exceeds policy max {self.max_ttl}",
            )
        return PolicyDecision(allowed=True, reason="ok")
