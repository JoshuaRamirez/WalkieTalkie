"""Peer admission policy (Phase 5 Track A, D5.2). [RUNNABLE]

Closes the admission half of the vision's Layer A ("Identity, Trust,
and Admission"). Once a peer's SVID verifies (:func:`workload_ca.verify_svid`),
the mesh still has to decide *whether this identity is allowed to join
at all* — the vision's "peer admission policies: deny-by-default,
explicit allowlists by service identity and environment tier, cert
pinning for high-trust peers."

This is the fabric-scope realization of vision §8 criterion 1
("Unauthorized peer cannot join the mesh"). Admission runs AFTER SVID
verification (you cannot admit an identity you haven't authenticated)
and BEFORE any message is processed.

Model:

- :class:`AdmissionRule` — one allowlist entry: a SPIFFE id, the
  environment tier it may join (`prod` / `staging` / `dev` — free-form
  strings the operator defines), and an optional pinned public-key
  fingerprint. When a pin is set, the peer's SVID must present exactly
  that key ("cert pinning for high-trust peers").
- :class:`PeerAdmissionPolicy` — a closed tuple of rules. Anything not
  matched is denied (deny-by-default). Evaluation is first-match on
  `(spiffe_id, env_tier)`.
- :func:`admit_peer` — returns an :class:`AdmissionDecision`;
  :func:`require_admission` raises on denial.

The env tier is part of the key so the same identity can be admitted
to `staging` but not `prod` — the vision's "environment tier"
allowlisting. Cross-tier presentation (a prod-only identity showing up
on the staging mesh) is a distinct deny reason from an unknown
identity, so operators can tell "wrong place" from "not on the list."
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from deny_reason import DenyReason
from verify_envelope import SPIFFE_ID_RE


class PeerAdmissionError(ValueError):
    """Raised when admission inputs violate v0 invariants."""


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Stable hex sha256 over the raw Ed25519 public key.

    This is what a cert pin stores and what :func:`admit_peer`
    compares against, so a pinned peer must present the exact key the
    operator recorded."""
    return hashlib.sha256(public_key.public_bytes_raw()).hexdigest()


@dataclass(frozen=True)
class AdmissionRule:
    spiffe_id: str
    env_tier: str
    pinned_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.spiffe_id, str) or not SPIFFE_ID_RE.match(self.spiffe_id):
            raise PeerAdmissionError(f"invalid spiffe_id: {self.spiffe_id!r}")
        if not isinstance(self.env_tier, str) or not self.env_tier:
            raise PeerAdmissionError("env_tier must be a non-empty string")
        if self.pinned_fingerprint is not None:
            if (
                not isinstance(self.pinned_fingerprint, str)
                or len(self.pinned_fingerprint) != 64
            ):
                raise PeerAdmissionError(
                    f"pinned_fingerprint must be a hex sha256: "
                    f"{self.pinned_fingerprint!r}"
                )


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    reason: str
    reason_code: str = ""


@dataclass(frozen=True)
class PeerAdmissionPolicy:
    """Deny-by-default allowlist of admission rules.

    Rules evaluate in declaration order; the first rule whose
    `(spiffe_id, env_tier)` matches decides. No match ⇒ deny.
    """

    rules: tuple[AdmissionRule, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.rules, tuple):
            raise PeerAdmissionError("rules must be a tuple")
        seen: set[tuple[str, str]] = set()
        for index, rule in enumerate(self.rules):
            if not isinstance(rule, AdmissionRule):
                raise PeerAdmissionError(f"rules[{index}] must be an AdmissionRule")
            key = (rule.spiffe_id, rule.env_tier)
            if key in seen:
                raise PeerAdmissionError(
                    f"duplicate admission rule for {key!r}"
                )
            seen.add(key)

    def _rules_for_identity(self, spiffe_id: str) -> tuple[AdmissionRule, ...]:
        return tuple(r for r in self.rules if r.spiffe_id == spiffe_id)


def admit_peer(
    *,
    spiffe_id: str,
    env_tier: str,
    policy: PeerAdmissionPolicy,
    presented_key: Ed25519PublicKey | None = None,
) -> AdmissionDecision:
    """Decide whether a verified peer may join.

    ``spiffe_id`` MUST already be an authenticated identity (the SAN
    id returned by :func:`workload_ca.verify_svid`). ``presented_key``
    is the peer's SVID public key, required only when a matching rule
    carries a pin.

    Deny reasons:
    - No rule for this identity at all → ``ADMISSION_PEER_NOT_ALLOWED``.
    - Identity is allowlisted, but not for this env tier →
      ``ADMISSION_TIER_MISMATCH``.
    - Matching rule pins a key and the presented key differs (or is
      absent) → ``ADMISSION_CERT_PIN_MISMATCH``.
    """
    if not isinstance(spiffe_id, str) or not SPIFFE_ID_RE.match(spiffe_id):
        raise PeerAdmissionError(f"invalid spiffe_id: {spiffe_id!r}")
    if not isinstance(env_tier, str) or not env_tier:
        raise PeerAdmissionError("env_tier must be a non-empty string")

    identity_rules = policy._rules_for_identity(spiffe_id)
    if not identity_rules:
        return AdmissionDecision(
            allowed=False,
            reason=f"peer {spiffe_id!r} is not on the admission allowlist",
            reason_code=DenyReason.ADMISSION_PEER_NOT_ALLOWED.value,
        )

    for rule in identity_rules:
        if rule.env_tier != env_tier:
            continue
        # Matched (spiffe_id, env_tier). Enforce the pin if present.
        if rule.pinned_fingerprint is not None:
            if presented_key is None:
                return AdmissionDecision(
                    allowed=False,
                    reason=(
                        f"peer {spiffe_id!r} rule pins a key but no key was "
                        f"presented"
                    ),
                    reason_code=DenyReason.ADMISSION_CERT_PIN_MISMATCH.value,
                )
            presented_fp = public_key_fingerprint(presented_key)
            if presented_fp != rule.pinned_fingerprint:
                return AdmissionDecision(
                    allowed=False,
                    reason=(
                        f"peer {spiffe_id!r} presented key {presented_fp} "
                        f"does not match pin {rule.pinned_fingerprint}"
                    ),
                    reason_code=DenyReason.ADMISSION_CERT_PIN_MISMATCH.value,
                )
        return AdmissionDecision(allowed=True, reason="ok", reason_code="ok")

    # Identity is allowlisted, but not for this tier.
    return AdmissionDecision(
        allowed=False,
        reason=(
            f"peer {spiffe_id!r} is allowlisted but not for env tier "
            f"{env_tier!r}"
        ),
        reason_code=DenyReason.ADMISSION_TIER_MISMATCH.value,
    )


class PeerAdmissionDenied(ValueError):
    """Raised by :func:`require_admission` on denial."""

    def __init__(self, decision: AdmissionDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


def require_admission(
    *,
    spiffe_id: str,
    env_tier: str,
    policy: PeerAdmissionPolicy,
    presented_key: Ed25519PublicKey | None = None,
) -> AdmissionDecision:
    """Evaluate the policy and raise :class:`PeerAdmissionDenied` on deny."""
    decision = admit_peer(
        spiffe_id=spiffe_id,
        env_tier=env_tier,
        policy=policy,
        presented_key=presented_key,
    )
    if not decision.allowed:
        raise PeerAdmissionDenied(decision)
    return decision
