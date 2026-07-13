"""Delegation receipt v0 (Phase 2 Track A A1 + A2).

A :class:`DelegationReceipt` is a signed JWT-like artifact that records one
delegation hop. Each hop carries:

- ``chain_id``: stable across the entire chain.
- ``hop_index``: 0 for the root hop, +1 per subsequent hop.
- ``parent_jti``: the parent receipt's (or originating cap token's) ``jti``;
  empty for the root hop.
- ``delegator_iss`` / ``delegate_iss``: who is delegating to whom.
- ``scope`` / ``aud`` / ``iat`` / ``nbf`` / ``exp`` / ``jti``: mirror the
  capability-token semantics.

Wire format: ``<base64url(header)>.<base64url(payload)>.<base64url(signature)>``
(JWS Compact, no padding). Signature is EdDSA over the JCS-canonicalized
body with ``typ: "wt-delegation/v0"`` cross-protocol binding.

Non-escalation invariants (Phase 2 A2 acceptance criterion: "No test case
can produce broader privilege at child hop"):

- ``hop_index`` is exactly ``parent.hop_index + 1`` (or 0 if root).
- ``parent_jti`` matches ``parent.jti``.
- ``delegator_iss`` equals ``parent.sub`` (the parent's subject becomes the
  new delegator).
- ``scope`` is **identical** to the parent's scope. v0 takes the strict
  view; scope narrowing is a v1 extension.
- ``aud`` is identical to the parent's aud (audience continuity).
- ``[iat, exp]`` is contained within ``[parent.iat, parent.exp]`` (i.e.,
  the child window cannot extend past the parent's).
- ``hop_index`` is less than ``max_chain_depth`` (default 3).

Out of scope for v0
-------------------
- Scope narrowing / partial-order semantics. v0 requires identical scope.
- Multiple parents per hop (DAG-shaped chains).
- Receipt revocation lists (use TTL).
- Audit checkpoint emission. The validator's outcome is returnable; wiring
  a ``delegation.verify`` event is a follow-up that pairs with the rest of
  the Phase 2 checkpoint suite.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from deny_reason import DenyReason
from verify_envelope import (
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

DELEGATION_TYP = "wt-delegation/v0"


class DelegationError(EnvelopeVerificationError):
    """Raised when a delegation receipt fails verification.

    Subclasses :class:`EnvelopeVerificationError` so callers that already
    catch the envelope error don't need a separate branch.
    """


@dataclass(frozen=True)
class DelegationReceipt:
    chain_id: str
    hop_index: int
    parent_jti: str
    delegator_iss: str
    delegate_iss: str
    scope: str
    aud: str
    iat: int
    nbf: int
    exp: int
    jti: str
    delegator_kid: str = ""
    signature: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class ParentClaims:
    """Subset of a parent receipt or capability-token claim set used for
    non-escalation checks. Constructed by the caller from whichever
    artifact was the previous hop."""

    jti: str
    sub: str  # parent.sub = the workload now doing the delegating
    aud: str
    scope: str
    iat: int
    exp: int
    hop_index: int = -1  # -1 means "this is a cap token, not another receipt"


def parent_from_capability_claims(claims) -> ParentClaims:
    """Build a :class:`ParentClaims` from a
    :class:`capability_token.CapabilityClaims`."""
    return ParentClaims(
        jti=claims.jti,
        sub=claims.sub,
        aud=claims.aud,
        scope=claims.scope,
        iat=claims.iat,
        exp=claims.exp,
        hop_index=-1,
    )


def parent_from_receipt(receipt: DelegationReceipt) -> ParentClaims:
    return ParentClaims(
        jti=receipt.jti,
        sub=receipt.delegate_iss,
        aud=receipt.aud,
        scope=receipt.scope,
        iat=receipt.iat,
        exp=receipt.exp,
        hop_index=receipt.hop_index,
    )


def _body_for_signing(receipt: DelegationReceipt) -> bytes:
    body = {
        "typ": DELEGATION_TYP,
        "chain_id": receipt.chain_id,
        "hop_index": receipt.hop_index,
        "parent_jti": receipt.parent_jti,
        "delegator_iss": receipt.delegator_iss,
        "delegator_kid": receipt.delegator_kid,
        "delegate_iss": receipt.delegate_iss,
        "scope": receipt.scope,
        "aud": receipt.aud,
        "iat": receipt.iat,
        "nbf": receipt.nbf,
        "exp": receipt.exp,
        "jti": receipt.jti,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_receipt(
    receipt: DelegationReceipt, signing_key: Ed25519PrivateKey
) -> DelegationReceipt:
    sig = _b64u(signing_key.sign(_body_for_signing(receipt)))
    return dataclasses.replace(receipt, signature=sig)


def to_json(receipt: DelegationReceipt) -> bytes:
    return json.dumps(receipt.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> DelegationReceipt:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise DelegationError(
            "receipt is not valid JSON", reason=DenyReason.DELEGATION_MALFORMED
        ) from exc
    if not isinstance(obj, dict):
        raise DelegationError(
            "receipt JSON must be an object",
            reason=DenyReason.DELEGATION_MALFORMED,
        )
    required = {
        "chain_id", "hop_index", "parent_jti", "delegator_iss", "delegator_kid",
        "delegate_iss", "scope", "aud", "iat", "nbf", "exp", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise DelegationError(
            f"missing required fields: {','.join(missing)}",
            reason=DenyReason.DELEGATION_MALFORMED,
        )
    return DelegationReceipt(**{k: obj[k] for k in required})


def _malformed(msg: str) -> DelegationError:
    return DelegationError(msg, reason=DenyReason.DELEGATION_MALFORMED)


def _validate_shape(receipt: DelegationReceipt) -> None:
    if not isinstance(receipt.chain_id, str) or not UUID_V7_RE.match(receipt.chain_id):
        raise _malformed(f"chain_id must be UUIDv7: {receipt.chain_id!r}")
    if not isinstance(receipt.jti, str) or not UUID_V7_RE.match(receipt.jti):
        raise _malformed(f"jti must be UUIDv7: {receipt.jti!r}")
    if not isinstance(receipt.hop_index, int) or isinstance(receipt.hop_index, bool):
        raise _malformed("hop_index must be an integer")
    if receipt.hop_index < 0:
        raise _malformed(f"hop_index must be non-negative: {receipt.hop_index}")
    if not isinstance(receipt.delegator_iss, str) or not SPIFFE_ID_RE.match(receipt.delegator_iss):
        raise _malformed(f"invalid delegator_iss: {receipt.delegator_iss!r}")
    if not isinstance(receipt.delegate_iss, str) or not SPIFFE_ID_RE.match(receipt.delegate_iss):
        raise _malformed(f"invalid delegate_iss: {receipt.delegate_iss!r}")
    if not isinstance(receipt.aud, str) or not SPIFFE_ID_RE.match(receipt.aud):
        raise _malformed(f"invalid aud: {receipt.aud!r}")
    if not isinstance(receipt.scope, str) or not receipt.scope:
        raise _malformed("scope must be a non-empty string")
    if not isinstance(receipt.delegator_kid, str) or not KID_RE.match(receipt.delegator_kid):
        raise _malformed(f"invalid delegator_kid: {receipt.delegator_kid!r}")
    if not isinstance(receipt.parent_jti, str):
        raise _malformed("parent_jti must be a string")
    if receipt.parent_jti and not UUID_V7_RE.match(receipt.parent_jti):
        raise _malformed(f"parent_jti must be UUIDv7 when set: {receipt.parent_jti!r}")
    if receipt.hop_index == 0 and receipt.parent_jti:
        raise _malformed("root hop (hop_index=0) must have empty parent_jti")
    if receipt.hop_index > 0 and not receipt.parent_jti:
        raise _malformed("non-root hop must have non-empty parent_jti")
    for name, value in (("iat", receipt.iat), ("nbf", receipt.nbf), ("exp", receipt.exp)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _malformed(f"{name} must be a NumericDate (int)")


@dataclass(frozen=True)
class DelegationVerificationConfig:
    max_clock_skew: timedelta = field(default_factory=lambda: timedelta(seconds=60))
    max_receipt_ttl: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    max_chain_depth: int = 3  # hop_index < max_chain_depth


DEFAULT_DELEGATION_CONFIG = DelegationVerificationConfig()


def verify_receipt(
    receipt: DelegationReceipt,
    *,
    parent: ParentClaims | None,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    config: DelegationVerificationConfig = DEFAULT_DELEGATION_CONFIG,
) -> DelegationReceipt:
    """Verify shape + non-escalation + time window + signature.

    ``parent`` is ``None`` only for the root hop (``hop_index == 0``). For
    subsequent hops it MUST carry the previous hop's audience-relevant
    claims (build via :func:`parent_from_capability_claims` or
    :func:`parent_from_receipt`).
    """
    _validate_shape(receipt)

    if receipt.hop_index >= config.max_chain_depth:
        raise DelegationError(
            f"hop_index {receipt.hop_index} >= max_chain_depth {config.max_chain_depth}",
            reason=DenyReason.DELEGATION_DEPTH_EXCEEDED,
        )

    if receipt.hop_index == 0:
        if parent is not None:
            raise DelegationError(
                "root hop must not have a parent claims set",
                reason=DenyReason.DELEGATION_PARENT_MISMATCH,
            )
    else:
        if parent is None:
            raise DelegationError(
                "non-root hop requires parent claims",
                reason=DenyReason.DELEGATION_PARENT_MISMATCH,
            )
        if receipt.parent_jti != parent.jti:
            raise DelegationError(
                "parent_jti does not match the supplied parent",
                reason=DenyReason.DELEGATION_PARENT_MISMATCH,
            )
        if parent.hop_index >= 0 and receipt.hop_index != parent.hop_index + 1:
            raise DelegationError(
                f"hop_index {receipt.hop_index} != parent.hop_index + 1 "
                f"({parent.hop_index + 1})",
                reason=DenyReason.DELEGATION_PARENT_MISMATCH,
            )
        if receipt.delegator_iss != parent.sub:
            raise DelegationError(
                f"delegator_iss {receipt.delegator_iss!r} does not match "
                f"parent.sub {parent.sub!r}",
                reason=DenyReason.DELEGATION_PARENT_MISMATCH,
            )
        if receipt.scope != parent.scope:
            raise DelegationError(
                f"scope {receipt.scope!r} differs from parent.scope "
                f"{parent.scope!r} — v0 forbids scope narrowing/widening",
                reason=DenyReason.DELEGATION_SCOPE_ESCALATION,
            )
        if receipt.aud != parent.aud:
            raise DelegationError(
                f"aud {receipt.aud!r} differs from parent.aud {parent.aud!r}",
                reason=DenyReason.DELEGATION_AUDIENCE_DRIFT,
            )
        if receipt.iat < parent.iat or receipt.exp > parent.exp:
            raise DelegationError(
                "child validity window must be contained within parent's",
                reason=DenyReason.DELEGATION_TTL_ESCALATION,
            )

    if receipt.iat > receipt.nbf:
        raise DelegationError(
            "iat must be <= nbf", reason=DenyReason.DELEGATION_MALFORMED
        )
    nbf_dt = datetime.fromtimestamp(receipt.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(receipt.exp, tz=UTC)
    if exp_dt <= nbf_dt:
        raise DelegationError(
            "invalid validity window", reason=DenyReason.DELEGATION_EXPIRED
        )
    if exp_dt - nbf_dt > config.max_receipt_ttl:
        raise DelegationError(
            f"receipt ttl exceeds maximum {config.max_receipt_ttl}",
            reason=DenyReason.DELEGATION_EXPIRED,
        )
    if nbf_dt - current > config.max_clock_skew:
        raise DelegationError(
            "nbf in future beyond skew", reason=DenyReason.DELEGATION_EXPIRED
        )
    if current - exp_dt > config.max_clock_skew:
        raise DelegationError(
            "receipt expired", reason=DenyReason.DELEGATION_EXPIRED
        )

    if not receipt.signature:
        raise _malformed("receipt is unsigned")
    try:
        sig_bytes = decode_base64url(receipt.signature)
    except Exception as exc:
        raise _malformed("invalid signature encoding") from exc

    try:
        pem = issuer_lookup(receipt.delegator_iss, receipt.delegator_kid)
    except Exception as exc:
        raise DelegationError(
            f"unknown delegation issuer key: {exc}",
            reason=DenyReason.DELEGATION_UNKNOWN_ISSUER,
        ) from exc

    try:
        key = load_ed25519_public_key(pem)
    except Exception as exc:
        raise DelegationError(
            "invalid delegation issuer public key",
            reason=DenyReason.DELEGATION_UNKNOWN_ISSUER,
        ) from exc

    try:
        key.verify(sig_bytes, _body_for_signing(receipt))
    except InvalidSignature as exc:
        raise DelegationError(
            "signature invalid", reason=DenyReason.DELEGATION_SIGNATURE_INVALID
        ) from exc

    return receipt
