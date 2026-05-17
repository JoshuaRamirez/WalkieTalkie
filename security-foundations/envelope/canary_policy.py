"""Canary + auto-rollback for policy releases (Phase 1 Track C C3 third sub-bullet).

A :class:`CanaryPolicy` wraps two :class:`issuance_policy.IssuancePolicy`
instances — a *stable* one (today's production policy) and a *candidate*
one (the next version being rolled out). The candidate handles a
configurable fraction of issuance traffic; the rest stays on stable.

If the candidate's denial count crosses ``rollback_after_denials`` within
the lifetime of the :class:`CanaryPolicy` instance, the canary is
**auto-rolled-back**: all subsequent ``evaluate()`` calls route to stable.
Rollback is sticky for the lifetime of the instance — operators are
expected to investigate, build a new candidate, and re-deploy a fresh
:class:`CanaryPolicy`.

Traffic-split semantics
-----------------------
The bucket function is deterministic over ``(sub, aud, scope)``:

    bucket = int(sha256(f"{sub}|{aud}|{scope}".encode()).hexdigest()[:8], 16) % 100

If ``bucket < canary_buckets``, the candidate is consulted; otherwise the
stable. Because the bucket is deterministic, a given grant always sees the
same side of the split until ``canary_buckets`` changes — that's what
makes "ramp 5% → 25% → 100%" a meaningful operation.

Out of scope for v0
-------------------
- Cross-process / distributed counter state. v0's auto-rollback fires
  per-process. A future revision can persist the denial counter (the same
  pattern the rollback guard already uses for policy bundles).
- Time-windowed rollback ("rollback if N denials in the last 5 minutes").
  v0 counts total denials over the instance's lifetime.
- Cross-bundle attribution. If the candidate is identical to the stable
  for some grants, denials on those grants still count toward the
  candidate's threshold because the candidate was the consulted side.
- Automatic re-promotion of the candidate. v0 only ever rolls *back*.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import timedelta

from issuance_policy import IssuancePolicy, PolicyDecision


@dataclass
class CanaryPolicy(IssuancePolicy):
    """Stable / candidate split with sticky auto-rollback on the candidate.

    ``canary_buckets`` is an integer in ``[0, 100]`` — the *percentage* of
    grants routed to the candidate. ``0`` means all stable;
    ``100`` means all candidate.
    """

    stable: IssuancePolicy
    candidate: IssuancePolicy
    canary_buckets: int = 0
    rollback_after_denials: int = 10
    _candidate_denials: int = field(default=0, init=False, repr=False)
    _rolled_back: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not 0 <= self.canary_buckets <= 100:
            raise ValueError("canary_buckets must be in [0, 100]")
        if self.rollback_after_denials < 1:
            raise ValueError("rollback_after_denials must be >= 1")

    @property
    def rolled_back(self) -> bool:
        return self._rolled_back

    @property
    def candidate_denials(self) -> int:
        return self._candidate_denials

    @staticmethod
    def _bucket(sub: str, aud: str, scope: str) -> int:
        key = f"{sub}|{aud}|{scope}".encode()
        return int(hashlib.sha256(key).hexdigest()[:8], 16) % 100

    def _selects_candidate(self, sub: str, aud: str, scope: str) -> bool:
        if self._rolled_back:
            return False
        if self.canary_buckets <= 0:
            return False
        if self.canary_buckets >= 100:
            return True
        return self._bucket(sub, aud, scope) < self.canary_buckets

    def evaluate(
        self, *, sub: str, aud: str, scope: str, ttl: timedelta
    ) -> PolicyDecision:
        if self._selects_candidate(sub, aud, scope):
            decision = self.candidate.evaluate(sub=sub, aud=aud, scope=scope, ttl=ttl)
            if not decision.allowed:
                self._candidate_denials += 1
                if self._candidate_denials >= self.rollback_after_denials:
                    self._rolled_back = True
            return decision
        return self.stable.evaluate(sub=sub, aud=aud, scope=scope, ttl=ttl)
