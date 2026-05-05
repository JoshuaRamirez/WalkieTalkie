"""Capability token v0 — RFC 7519 JWT with EdDSA (RFC 8037).

Wire format::

    <base64url(header)>.<base64url(payload)>.<base64url(signature)>

Header (all required, all checked)::

    {"alg": "EdDSA", "typ": "wt-cap+jwt", "kid": "<issuer kid>"}

Payload claims (all required)::

    iss   issuer SPIFFE ID
    sub   subject SPIFFE ID — must equal envelope.sender_spiffe_id
    aud   audience SPIFFE ID — must equal envelope.recipient_spiffe_id
    scope must equal envelope.purpose_of_use
    iat   NumericDate (seconds since epoch)
    nbf   NumericDate
    exp   NumericDate
    jti   UUIDv7 — consulted against an optional revocation list
    cnf   {"envelope_digest": "<hex sha256>"} — must equal
          envelope.payload_digest, binding the token to one specific payload

Signature is detached EdDSA over the ASCII bytes
``base64url(header) + "." + base64url(payload)`` (JWS standard).

Out of scope for v0
-------------------
- Token issuance API.
- ``resource`` claim and structured action/resource binding (deferred to v1).
- Proof-of-possession via ``cnf.jwk``. v0 is bearer; a leaked token grants the
  same authorization for at most ``max_capability_ttl`` (5 minutes by default).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from verify_envelope import (
    HEX_SHA256_RE,
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

if TYPE_CHECKING:
    from revocation_list import RevocationList

MAX_TOKEN_BYTES = 4096
EXPECTED_TYP = "wt-cap+jwt"
EXPECTED_ALG = "EdDSA"

_REQUIRED_CLAIMS = ("iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti", "cnf")


@dataclass(frozen=True)
class CapabilityClaims:
    iss: str
    sub: str
    aud: str
    scope: str
    iat: int
    nbf: int
    exp: int
    jti: str
    envelope_digest: str
    issuer_kid: str


def _err(reason: str) -> EnvelopeVerificationError:
    return EnvelopeVerificationError(f"capability token: {reason}")


def parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Parse a JWT into (header, payload, signing_input, signature_bytes).

    Enforces length cap, three segments, parseable base64url, parseable JSON
    objects. Does not verify the signature or any claim semantics.
    """
    if not isinstance(token, str) or not token:
        raise _err("missing token")
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise _err(f"exceeds max size of {MAX_TOKEN_BYTES} bytes")

    parts = token.split(".")
    if len(parts) != 3:
        raise _err("must have three base64url segments")

    header_b64, payload_b64, signature_b64 = parts
    try:
        header_bytes = decode_base64url(header_b64)
        payload_bytes = decode_base64url(payload_b64)
        signature_bytes = decode_base64url(signature_b64)
    except EnvelopeVerificationError as exc:
        raise _err("invalid base64url segment") from exc

    try:
        header = json.loads(header_bytes)
        payload = json.loads(payload_bytes)
    except (ValueError, TypeError) as exc:
        raise _err("segment is not valid JSON") from exc

    if not isinstance(header, dict):
        raise _err("header is not a JSON object")
    if not isinstance(payload, dict):
        raise _err("payload is not a JSON object")

    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    return header, payload, signing_input, signature_bytes


def _check_header(header: dict[str, Any]) -> str:
    alg = header.get("alg")
    typ = header.get("typ")
    kid = header.get("kid")
    if alg != EXPECTED_ALG:
        raise _err(f"alg must be {EXPECTED_ALG!r}")
    if typ != EXPECTED_TYP:
        raise _err(f"typ must be {EXPECTED_TYP!r}")
    if not isinstance(kid, str) or not KID_RE.match(kid):
        raise _err("invalid kid format")
    return kid


def _extract_claims(payload: dict[str, Any], *, issuer_kid: str) -> CapabilityClaims:
    missing = [c for c in _REQUIRED_CLAIMS if c not in payload]
    if missing:
        raise _err(f"missing required claims: {','.join(missing)}")

    iss = payload["iss"]
    sub = payload["sub"]
    aud = payload["aud"]
    scope = payload["scope"]
    iat = payload["iat"]
    nbf = payload["nbf"]
    exp = payload["exp"]
    jti = payload["jti"]
    cnf = payload["cnf"]

    if not isinstance(iss, str) or not SPIFFE_ID_RE.match(iss):
        raise _err("invalid iss format")
    if not isinstance(sub, str) or not SPIFFE_ID_RE.match(sub):
        raise _err("invalid sub format")
    if not isinstance(aud, str) or not SPIFFE_ID_RE.match(aud):
        raise _err("invalid aud format")
    if not isinstance(scope, str) or not scope:
        raise _err("scope must be a non-empty string")
    for name, value in (("iat", iat), ("nbf", nbf), ("exp", exp)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _err(f"{name} must be a NumericDate (int seconds since epoch)")
    if not isinstance(jti, str) or not UUID_V7_RE.match(jti):
        raise _err("jti must be UUIDv7")
    if not isinstance(cnf, dict) or "envelope_digest" not in cnf:
        raise _err("cnf.envelope_digest is required")
    envelope_digest = cnf["envelope_digest"]
    if not isinstance(envelope_digest, str) or not HEX_SHA256_RE.match(envelope_digest):
        raise _err("cnf.envelope_digest must be hex sha256")

    return CapabilityClaims(
        iss=iss,
        sub=sub,
        aud=aud,
        scope=scope,
        iat=iat,
        nbf=nbf,
        exp=exp,
        jti=jti,
        envelope_digest=envelope_digest,
        issuer_kid=issuer_kid,
    )


def verify_capability_token(
    token: str,
    *,
    envelope: dict[str, Any],
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta,
    max_capability_ttl: timedelta,
    revocation_list: RevocationList | None = None,
) -> CapabilityClaims:
    """Full validation. Raises EnvelopeVerificationError on any failure."""
    header, payload, signing_input, signature_bytes = parse_jwt(token)
    issuer_kid = _check_header(header)
    claims = _extract_claims(payload, issuer_kid=issuer_kid)

    if claims.sub != envelope["sender_spiffe_id"]:
        raise _err("sub does not match envelope sender")
    if claims.aud != envelope["recipient_spiffe_id"]:
        raise _err("aud does not match envelope recipient")
    if claims.scope != envelope["purpose_of_use"]:
        raise _err("scope does not match envelope purpose_of_use")
    if claims.envelope_digest != envelope["payload_digest"]:
        raise _err("cnf.envelope_digest does not match envelope payload_digest")

    if claims.iat > claims.nbf:
        raise _err("iat must be <= nbf")
    nbf_dt = datetime.fromtimestamp(claims.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(claims.exp, tz=UTC)
    if nbf_dt - current > max_clock_skew:
        raise _err("nbf in future beyond skew")
    if current - exp_dt > max_clock_skew:
        raise _err("token expired")
    if exp_dt <= nbf_dt:
        raise _err("invalid validity window")
    if exp_dt - nbf_dt > max_capability_ttl:
        raise _err("ttl exceeds maximum")

    pem = issuer_lookup(claims.iss, issuer_kid)
    issuer_key = load_ed25519_public_key(pem)
    try:
        issuer_key.verify(signature_bytes, signing_input)
    except InvalidSignature as exc:
        raise _err("signature invalid") from exc

    # Revocation is consulted last so we only ask the revocation list about
    # cryptographically valid tokens. Otherwise an attacker could probe the
    # list with forged jti values and learn which tokens have been revoked.
    if revocation_list is not None and revocation_list.is_revoked(claims.jti):
        raise _err("revoked")

    return claims
