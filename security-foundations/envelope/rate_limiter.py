"""Identity-aware rate limiting (Phase 1 D1.5).

Closes the first half of D1.5 ("Operational Guardrails"):

- "Identity-aware rate limits."

(The second half — "anomaly alerts for token usage spikes and repeated reject
patterns" — landed in :mod:`alerting`.)

:class:`IdentityRateLimiter` keeps a per-identity sliding window of request
timestamps. ``check(identity)`` returns a :class:`RateLimitDecision`
indicating whether the request is allowed and, if not, how long the caller
should back off before retrying. The decision is opt-in: callers that want
to enforce throttling at envelope-verification time wrap a :class:`Verifier`
in :class:`RateLimitedVerifier`; raw callers can use the limiter directly.

Out of scope for v0
-------------------
- Distributed / cross-process limiter state. The replay cache's
  SQLite/atomic pattern can be ported here once the transport layer
  defines what "per identity" means across nodes.
- Token-bucket smoothing (this is a fixed rolling count, not a leak rate).
- Per-method or per-scope weighting (operators can compose multiple
  limiters for different operation classes).
- Cross-tenant attempt tracking (see :mod:`audit_query.cross_tenant_attempts`).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from deny_reason import DenyReason
from verifier import VerificationResult, Verifier
from verify_envelope import EnvelopeVerificationError

if TYPE_CHECKING:
    pass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    identity: str
    reason: str
    retry_after_seconds: int = 0


class RateLimitExceededError(EnvelopeVerificationError):
    """Raised by :meth:`RateLimitedVerifier.verify` when the limit is hit.

    Subclasses :class:`EnvelopeVerificationError` so callers that catch
    that exception (e.g., the audit-emitting verifier) also catch this
    one without special-casing.
    """

    def __init__(self, decision: RateLimitDecision) -> None:
        super().__init__(decision.reason, reason=DenyReason.RATE_LIMITED)
        self.decision = decision


@dataclass
class IdentityRateLimiter:
    """Per-identity fixed-count sliding-window limiter.

    ``check(identity)`` records the call timestamp (regardless of outcome) so
    repeated checks count toward the limit. Operators who want only *allowed*
    requests to count can split the check from the consume — but v0 takes the
    simpler interpretation: every call to ``check`` consumes a unit.
    """

    limit: int
    window: timedelta = field(default_factory=lambda: timedelta(minutes=1))
    overrides: dict[str, int] = field(default_factory=dict)
    _buckets: dict[str, deque[datetime]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("limit must be >= 1")
        if self.window <= timedelta(0):
            raise ValueError("window must be positive")
        for ident, override in self.overrides.items():
            if not isinstance(ident, str) or not ident:
                raise ValueError(f"override identity must be a non-empty string: {ident!r}")
            if override < 1:
                raise ValueError(f"override limit for {ident!r} must be >= 1")

    def _effective_limit(self, identity: str) -> int:
        return self.overrides.get(identity, self.limit)

    def check(self, identity: str, *, now: datetime | None = None) -> RateLimitDecision:
        ts = (now or datetime.now(UTC)).astimezone(UTC)
        cutoff = ts - self.window
        bucket = self._buckets.setdefault(identity, deque())
        # Purge timestamps that fall outside the window.
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(ts)

        effective = self._effective_limit(identity)
        if len(bucket) > effective:
            # The oldest in-window timestamp dictates when this identity's
            # bucket will drain enough to allow another request.
            oldest = bucket[0]
            retry_after = max(0, int((oldest + self.window - ts).total_seconds()) + 1)
            return RateLimitDecision(
                allowed=False,
                identity=identity,
                reason=(
                    f"rate limit exceeded for {identity}: "
                    f"{len(bucket)} > {effective} within {self.window}"
                ),
                retry_after_seconds=retry_after,
            )
        return RateLimitDecision(
            allowed=True, identity=identity, reason="ok", retry_after_seconds=0
        )

    def reset(self, identities: Iterable[str] | None = None) -> None:
        """Drop the sliding-window state for ``identities`` (or all)."""
        if identities is None:
            self._buckets.clear()
        else:
            for ident in identities:
                self._buckets.pop(ident, None)


@dataclass
class RateLimitedVerifier:
    """Decorate a :class:`Verifier` with per-identity rate limiting.

    The limiter runs **after** the inner verifier authenticates the envelope.
    This is a deliberate hardening choice: if we throttled on the *claimed*
    ``sender_spiffe_id`` before signature verification, an attacker could DoS
    any workload by sending fake envelopes with the victim's SPIFFE ID — the
    verifier would reject the signatures but the limiter would already have
    burned the victim's allowance.

    Throttled requests have already consumed their replay-cache slot (the
    inner verifier ran to completion). Callers MUST mint a fresh nonce on
    retry; that matches normal envelope semantics anyway.

    ``verify`` raises :class:`RateLimitExceededError`; ``try_verify``
    returns a :class:`VerificationResult` with ``ok=False`` and
    ``reason="rate_limited: ..."``. The limiter only counts requests that
    the verifier *accepted*, so only authentic senders consume slots.
    """

    inner: Verifier
    limiter: IdentityRateLimiter

    def verify(self, envelope: dict, *, now: datetime | None = None):
        # Authenticate first so the limiter only sees verified identities.
        claims = self.inner.verify(envelope, now=now)
        identity = (
            envelope.get("sender_spiffe_id", "") if isinstance(envelope, dict) else ""
        )
        decision = self.limiter.check(identity, now=now)
        if not decision.allowed:
            raise RateLimitExceededError(decision)
        return claims

    def try_verify(self, envelope: dict, *, now: datetime | None = None) -> VerificationResult:
        try:
            claims = self.verify(envelope, now=now)
        except EnvelopeVerificationError as exc:
            return VerificationResult(ok=False, reason=str(exc), claims=None)
        return VerificationResult(ok=True, reason="ok", claims=claims)
