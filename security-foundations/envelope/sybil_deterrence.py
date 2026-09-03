"""Sybil deterrence v0 (Phase 3 Track A A1).

Closes the "identity issuance quotas" half of A1 ("Sybil Deterrence")
plus a v0 take on "reputation hygiene and decay controls" and the
leftover "attestation burden tuning" hook:

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

- "Attestation burden tuning." — optional :class:`AttestationBurden`
  on the gate is the leftover #106 hook: "verify this attestation
  proof has at least X work units." :meth:`AttestationBurden.verify`
  (and :meth:`SybilDeterrence.evaluate` when the hook is attached)
  fail closed on a missing, malformed, or under-threshold
  :class:`AttestationBurdenProof`. Integrity is a JCS+sha256 digest
  over ``typ`` / ``work_units`` / the issuer binding — a pin tests
  can recompute, not a mining loop and not hardware attestation.
  Callers that omit the hook are unchanged (quotas + reputation
  only). The substrate still does not mint identities.

Out of scope for v0
-------------------
- Production proof-of-work mining, TPM/HSM quotes, or an
  identity-issuance product. The leftover is the cost-dial
  verifier, not the flow that produces proofs.
- Distributed/cluster-wide quota state. v0 :class:`SybilDeterrence`
  keeps in-process counters; operators wanting cluster-wide
  consistency should swap in a Redis / etcd backend behind the
  :class:`SybilLedger` ABC.
- Reputation transferability across rotations. v0 reputation is
  keyed on ``(issuer_iss, issuer_kid)``; rotating ``kid`` resets to
  the operator-supplied initial score.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import jcs

from .audit_query import trust_domain_of
from .deny_reason import DenyReason
from .verify_envelope import HEX_SHA256_RE, KID_RE, SPIFFE_ID_RE

BURDEN_TYP = "wt-attestation-burden/v0"


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


def _burden_body(*, work_units: int, issuer_iss: str, issuer_kid: str) -> dict:
    return {
        "typ": BURDEN_TYP,
        "work_units": work_units,
        "issuer_iss": issuer_iss,
        "issuer_kid": issuer_kid,
    }


def _burden_integrity(*, work_units: int, issuer_iss: str, issuer_kid: str) -> str:
    return hashlib.sha256(
        jcs.canonicalize(
            _burden_body(
                work_units=work_units,
                issuer_iss=issuer_iss,
                issuer_kid=issuer_kid,
            )
        )
    ).hexdigest()


@dataclass(frozen=True)
class AttestationBurdenProof:
    """Structured v0 attestation-burden proof.

    Declares ``work_units`` and an integrity digest over the
    JCS-canonicalized body (``typ``, ``work_units``, issuer binding).
    This is not a mining loop and not hardware attestation — the
    issuance pipeline constructs the proof; the substrate verifies
    the claim and the digest.
    """

    work_units: int
    issuer_iss: str
    issuer_kid: str
    integrity: str

    def __post_init__(self) -> None:
        if not isinstance(self.work_units, int) or self.work_units < 0:
            raise SybilDeterrenceError(
                f"work_units must be a non-negative int: {self.work_units!r}"
            )
        if not isinstance(self.issuer_iss, str) or not SPIFFE_ID_RE.match(
            self.issuer_iss
        ):
            raise SybilDeterrenceError(f"invalid issuer_iss: {self.issuer_iss!r}")
        if not isinstance(self.issuer_kid, str) or not KID_RE.match(self.issuer_kid):
            raise SybilDeterrenceError(f"invalid issuer_kid: {self.issuer_kid!r}")
        if not isinstance(self.integrity, str) or not HEX_SHA256_RE.match(
            self.integrity
        ):
            raise SybilDeterrenceError(
                f"integrity must be hex sha256: {self.integrity!r}"
            )


def make_attestation_proof(
    *,
    work_units: int,
    issuer_iss: str,
    issuer_kid: str,
) -> AttestationBurdenProof:
    """Construct a well-formed proof. Not a miner — stamps the digest."""
    return AttestationBurdenProof(
        work_units=work_units,
        issuer_iss=issuer_iss,
        issuer_kid=issuer_kid,
        integrity=_burden_integrity(
            work_units=work_units,
            issuer_iss=issuer_iss,
            issuer_kid=issuer_kid,
        ),
    )


@dataclass(frozen=True)
class AttestationBurden:
    """Cost dial: a presented proof must declare at least ``min_work_units``.

    :meth:`verify` is the leftover hook — callable from the issuance
    pipeline on its own, and from :meth:`SybilDeterrence.evaluate`
    when this object is attached as :attr:`SybilDeterrence.burden`.
    Missing, malformed, or under-threshold proofs fail closed.
    """

    min_work_units: int

    def __post_init__(self) -> None:
        if not isinstance(self.min_work_units, int) or self.min_work_units < 0:
            raise SybilDeterrenceError(
                f"min_work_units must be a non-negative int: {self.min_work_units!r}"
            )

    def verify(
        self,
        proof: AttestationBurdenProof | None,
        *,
        issuer_iss: str,
        issuer_kid: str,
    ) -> IssuanceDecision:
        if proof is None or not isinstance(proof, AttestationBurdenProof):
            return IssuanceDecision(
                allowed=False,
                reason="attestation proof missing or not an AttestationBurdenProof",
                reason_code=DenyReason.SYBIL_ATTESTATION_PROOF_MALFORMED.value,
            )
        if proof.issuer_iss != issuer_iss or proof.issuer_kid != issuer_kid:
            return IssuanceDecision(
                allowed=False,
                reason=(
                    f"attestation proof bound to {proof.issuer_iss!r}/"
                    f"{proof.issuer_kid!r}, not {issuer_iss!r}/{issuer_kid!r}"
                ),
                reason_code=DenyReason.SYBIL_ATTESTATION_PROOF_MALFORMED.value,
            )
        expected = _burden_integrity(
            work_units=proof.work_units,
            issuer_iss=proof.issuer_iss,
            issuer_kid=proof.issuer_kid,
        )
        if proof.integrity != expected:
            return IssuanceDecision(
                allowed=False,
                reason="attestation proof integrity mismatch",
                reason_code=DenyReason.SYBIL_ATTESTATION_PROOF_MALFORMED.value,
            )
        if proof.work_units < self.min_work_units:
            return IssuanceDecision(
                allowed=False,
                reason=(
                    f"attestation proof work_units {proof.work_units} "
                    f"below min {self.min_work_units}"
                ),
                reason_code=DenyReason.SYBIL_ATTESTATION_BURDEN_INSUFFICIENT.value,
            )
        return IssuanceDecision(allowed=True, reason="ok", reason_code="ok")


@dataclass
class SybilDeterrence:
    """The Sybil-deterrence gate.

    Per :attr:`window`, an issuer may mint at most
    :attr:`max_per_issuer` identities; a whole trust domain may mint
    at most :attr:`max_per_tenant`. The issuer's reputation (looked up
    via :attr:`reputation`) must also be at or above
    :attr:`min_reputation`.

    Optional :attr:`burden` is the leftover #106 cost dial. When
    attached, :meth:`evaluate` requires a well-formed
    :class:`AttestationBurdenProof` whose declared work units meet
    :attr:`AttestationBurden.min_work_units`. Callers that omit the
    hook are unchanged.

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
    burden: AttestationBurden | None = None

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
        if self.burden is not None and not isinstance(self.burden, AttestationBurden):
            raise SybilDeterrenceError(
                f"burden must be AttestationBurden or None: {self.burden!r}"
            )

    def evaluate(
        self,
        *,
        issuer_iss: str,
        issuer_kid: str,
        now: datetime,
        attestation_proof: AttestationBurdenProof | None = None,
    ) -> IssuanceDecision:
        if self.burden is not None:
            burden_decision = self.burden.verify(
                attestation_proof,
                issuer_iss=issuer_iss,
                issuer_kid=issuer_kid,
            )
            if not burden_decision.allowed:
                return burden_decision

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
