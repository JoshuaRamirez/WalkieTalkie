"""Sybil deterrence v0 (Phase 3 Track A A1).

Closes the "identity issuance quotas" half of A1 ("Sybil Deterrence")
plus a v0 take on "reputation hygiene and decay controls":

- "Identity issuance quotas." — :class:`SybilDeterrence` enforces two
  independent sliding-window quotas on identity issuance:
  - a per-issuer quota (how many identities a single issuer can mint
    in a window), and
  - a per-tenant quota (how many identities can be minted across all
    issuers within a single trust domain in a window).
  Both default-deny on saturation, with distinct
  :class:`DenyReason` codes so operators can tell apart "this issuer
  is going wild" from "this whole tenant is flooding admission".

- "Reputation hygiene and decay controls." — :class:`IssuerReputation`
  tracks a small score per ``(issuer_iss, issuer_kid)`` that decays
  toward zero with time. The deterrence gate's
  :attr:`SybilDeterrence.min_reputation` floor refuses to admit
  issuance from issuers whose reputation has decayed below the
  threshold. Operators raise an issuer's score after successful
  admissions and let it bleed off naturally; a misbehaving issuer's
  score is bumped down explicitly via :meth:`IssuerReputation.penalize`.

Out of scope for v0
-------------------
- "Attestation burden tuning". The plan's expected mechanism is a
  proof-of-work or hardware-attestation cost dial; the v0 substrate
  doesn't pretend to mint identities, so wiring an attestation gate
  belongs in the higher-level identity-issuance flow.
- Distributed/cluster-wide quota state. v0 :class:`SybilDeterrence`
  keeps in-process counters; operators wanting cluster-wide
  consistency should swap in a Redis / etcd backend behind the
  :class:`SybilLedger` ABC.
- Reputation transferability across rotations. v0 reputation is
  keyed on ``(issuer_iss, issuer_kid)``; rotating ``kid`` resets to
  the operator-supplied initial score.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from audit_query import trust_domain_of
from deny_reason import DenyReason
from verify_envelope import KID_RE, SPIFFE_ID_RE


class SybilDeterrenceError(ValueError):
    """Raised when deterrence inputs violate v0 invariants."""


@dataclass(frozen=True)
class IssuanceRecord:
    """One identity-issuance attempt observed at the gate."""

    issuer_iss: str
    issuer_kid: str
    minted_iss: str
    at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_iss, str) or not SPIFFE_ID_RE.match(self.issuer_iss):
            raise SybilDeterrenceError(
                f"invalid issuer_iss: {self.issuer_iss!r}"
            )
        if not isinstance(self.issuer_kid, str) or not KID_RE.match(self.issuer_kid):
            raise SybilDeterrenceError(
                f"invalid issuer_kid: {self.issuer_kid!r}"
            )
        if not isinstance(self.minted_iss, str) or not SPIFFE_ID_RE.match(self.minted_iss):
            raise SybilDeterrenceError(
                f"invalid minted_iss: {self.minted_iss!r}"
            )
        if not isinstance(self.at, datetime) or self.at.tzinfo is None:
            raise SybilDeterrenceError(
                "at must be a timezone-aware datetime"
            )


class SybilLedger(ABC):
    """Ledger ABC. ``record`` is fire-and-forget; ``count_*`` window-counts."""

    @abstractmethod
    def record(self, record: IssuanceRecord) -> None:
        ...

    @abstractmethod
    def count_for_issuer(
        self, issuer_iss: str, issuer_kid: str, *, since: datetime
    ) -> int:
        ...

    @abstractmethod
    def count_for_tenant(self, trust_domain: str, *, since: datetime) -> int:
        ...


@dataclass
class InMemorySybilLedger(SybilLedger):
    """Bounded in-process ledger.

    Stores recent :class:`IssuanceRecord` entries in a deque trimmed
    on every call to either of the count methods (so the working set
    stays bounded by the active retention window the caller queries).
    """

    retention: timedelta = timedelta(hours=24)
    _events: deque[IssuanceRecord] = field(default_factory=deque)

    def _trim(self, now: datetime) -> None:
        cutoff = now.astimezone(UTC) - self.retention
        while self._events and self._events[0].at < cutoff:
            self._events.popleft()

    def record(self, record: IssuanceRecord) -> None:
        # Use the record's own timestamp to trim — preserves the
        # invariant that count queries return everything in-window
        # without depending on a separate "now".
        self._events.append(record)
        self._trim(record.at)

    def count_for_issuer(
        self, issuer_iss: str, issuer_kid: str, *, since: datetime
    ) -> int:
        cutoff = since.astimezone(UTC)
        return sum(
            1
            for r in self._events
            if r.issuer_iss == issuer_iss
            and r.issuer_kid == issuer_kid
            and r.at >= cutoff
        )

    def count_for_tenant(self, trust_domain: str, *, since: datetime) -> int:
        cutoff = since.astimezone(UTC)
        return sum(
            1
            for r in self._events
            if trust_domain_of(r.issuer_iss) == trust_domain and r.at >= cutoff
        )


@dataclass
class IssuerReputation:
    """Per-issuer reputation with time-based decay.

    The score is a unitless integer; operators choose what counts as
    "good" by tuning :attr:`SybilDeterrence.min_reputation`. Every
    :meth:`current_score` call applies one decay step per elapsed
    :attr:`decay_interval` since the score was last touched.
    """

    initial_score: int = 50
    decay_per_interval: int = 1
    decay_interval: timedelta = timedelta(hours=1)
    floor: int = 0
    ceiling: int = 100
    _scores: dict[tuple[str, str], tuple[int, datetime]] = field(default_factory=dict)

    def _decay(self, score: int, last_touched: datetime, now: datetime) -> int:
        elapsed = now.astimezone(UTC) - last_touched.astimezone(UTC)
        if elapsed <= timedelta(0):
            return score
        steps = int(elapsed / self.decay_interval)
        if steps <= 0:
            return score
        new_score = score - steps * self.decay_per_interval
        return max(self.floor, new_score)

    def _key(self, issuer_iss: str, issuer_kid: str) -> tuple[str, str]:
        if not isinstance(issuer_iss, str) or not SPIFFE_ID_RE.match(issuer_iss):
            raise SybilDeterrenceError(f"invalid issuer_iss: {issuer_iss!r}")
        if not isinstance(issuer_kid, str) or not KID_RE.match(issuer_kid):
            raise SybilDeterrenceError(f"invalid issuer_kid: {issuer_kid!r}")
        return (issuer_iss, issuer_kid)

    def current_score(
        self, issuer_iss: str, issuer_kid: str, *, now: datetime
    ) -> int:
        key = self._key(issuer_iss, issuer_kid)
        entry = self._scores.get(key)
        if entry is None:
            self._scores[key] = (self.initial_score, now.astimezone(UTC))
            return self.initial_score
        score, last = entry
        return self._decay(score, last, now)

    def reward(
        self, issuer_iss: str, issuer_kid: str, *, amount: int, now: datetime
    ) -> int:
        if not isinstance(amount, int) or amount <= 0:
            raise SybilDeterrenceError(
                f"reward amount must be positive int: {amount!r}"
            )
        key = self._key(issuer_iss, issuer_kid)
        decayed = self.current_score(issuer_iss, issuer_kid, now=now)
        new_score = min(self.ceiling, decayed + amount)
        self._scores[key] = (new_score, now.astimezone(UTC))
        return new_score

    def penalize(
        self, issuer_iss: str, issuer_kid: str, *, amount: int, now: datetime
    ) -> int:
        if not isinstance(amount, int) or amount <= 0:
            raise SybilDeterrenceError(
                f"penalty amount must be positive int: {amount!r}"
            )
        key = self._key(issuer_iss, issuer_kid)
        decayed = self.current_score(issuer_iss, issuer_kid, now=now)
        new_score = max(self.floor, decayed - amount)
        self._scores[key] = (new_score, now.astimezone(UTC))
        return new_score


@dataclass(frozen=True)
class IssuanceDecision:
    allowed: bool
    reason: str
    reason_code: str = ""


@dataclass
class SybilDeterrence:
    """The Sybil-deterrence gate.

    Per :attr:`window`, an issuer may mint at most
    :attr:`max_per_issuer` identities; a whole trust domain may mint
    at most :attr:`max_per_tenant`. The issuer's reputation (looked up
    via :attr:`reputation`) must also be at or above
    :attr:`min_reputation`.

    :meth:`evaluate` is the read-only check; :meth:`record_admission`
    writes to the ledger after the caller decides the admission was
    in fact granted. Splitting check and record lets callers compose
    deterrence with other gates without spurious counter increments.
    """

    ledger: SybilLedger
    reputation: IssuerReputation
    window: timedelta = timedelta(hours=1)
    max_per_issuer: int = 100
    max_per_tenant: int = 1000
    min_reputation: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.window, timedelta) or self.window <= timedelta(0):
            raise SybilDeterrenceError("window must be a positive timedelta")
        for name, value in (
            ("max_per_issuer", self.max_per_issuer),
            ("max_per_tenant", self.max_per_tenant),
        ):
            if not isinstance(value, int) or value < 0:
                raise SybilDeterrenceError(
                    f"{name} must be a non-negative int: {value!r}"
                )
        if not isinstance(self.min_reputation, int):
            raise SybilDeterrenceError(
                f"min_reputation must be an int: {self.min_reputation!r}"
            )

    def evaluate(
        self,
        *,
        issuer_iss: str,
        issuer_kid: str,
        now: datetime,
    ) -> IssuanceDecision:
        score = self.reputation.current_score(
            issuer_iss, issuer_kid, now=now
        )
        if score < self.min_reputation:
            return IssuanceDecision(
                allowed=False,
                reason=(
                    f"issuer reputation {score} below floor "
                    f"{self.min_reputation}"
                ),
                reason_code=DenyReason.SYBIL_REPUTATION_INSUFFICIENT.value,
            )

        since = now.astimezone(UTC) - self.window
        issuer_count = self.ledger.count_for_issuer(
            issuer_iss, issuer_kid, since=since
        )
        if issuer_count >= self.max_per_issuer:
            return IssuanceDecision(
                allowed=False,
                reason=(
                    f"issuer {issuer_iss!r}/{issuer_kid!r} has minted "
                    f"{issuer_count} identities in the last {self.window}"
                    f" (cap {self.max_per_issuer})"
                ),
                reason_code=DenyReason.SYBIL_ISSUER_QUOTA_EXCEEDED.value,
            )

        td = trust_domain_of(issuer_iss)
        if td:
            tenant_count = self.ledger.count_for_tenant(td, since=since)
            if tenant_count >= self.max_per_tenant:
                return IssuanceDecision(
                    allowed=False,
                    reason=(
                        f"tenant {td!r} has minted {tenant_count} identities "
                        f"in the last {self.window} (cap {self.max_per_tenant})"
                    ),
                    reason_code=DenyReason.SYBIL_TENANT_QUOTA_EXCEEDED.value,
                )

        return IssuanceDecision(allowed=True, reason="ok", reason_code="ok")

    def record_admission(
        self,
        *,
        issuer_iss: str,
        issuer_kid: str,
        minted_iss: str,
        at: datetime,
    ) -> None:
        self.ledger.record(
            IssuanceRecord(
                issuer_iss=issuer_iss,
                issuer_kid=issuer_kid,
                minted_iss=minted_iss,
                at=at,
            )
        )
