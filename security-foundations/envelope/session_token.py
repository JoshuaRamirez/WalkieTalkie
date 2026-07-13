"""Session tokens for streaming + resume (Phase 2 Track E E2).

Closes E2 ("Streaming and Resume Controls"):

- "Session tokens with bounded lifetime and strict resume conditions."
- "Replay-safe resume identifiers."

A long-lived interaction (a streamed LLM response, a chunked RPC, a
multi-message tool dialog) is anchored by an EdDSA-signed
:class:`SessionToken`. The token carries a ``session_id`` that
remains stable across resumes plus a ``seq`` counter that strictly
increases each time the session is resumed. When the network blips
or the client disconnects, the client cannot replay the previous
token; instead it requests a new token whose ``parent_jti`` references
the previous one and whose ``seq`` is exactly one higher.

:func:`verify_session_token` validates a single token (shape, time
window, signature). :func:`verify_resume` additionally enforces the
chain rules so a resumed token cannot widen the original scope or
duplicate the previous sequence position. The chain's *cumulative*
lifetime is also capped — operators set ``max_session_lifetime`` to
bound how long a single session can stay alive across resumes.

Wire format mirrors the rest of the substrate: the body is a JCS-
canonicalized JSON object with ``typ="wt-session/v0"`` cross-protocol
binding; the signature is base64url-encoded EdDSA over that body.

Replay safety
-------------
Every :class:`SessionToken` has a unique :attr:`SessionToken.jti`. A
resumed token MUST carry the previous ``jti`` in ``parent_jti`` AND
increment ``seq``. Together those make replay detectable two ways:

- A replayed open-token reuses its own ``jti``, which the operator
  can store in a per-session set the same way :class:`InMemoryReplayCache`
  handles envelope nonces.
- A replayed resume-token has a ``seq`` that no longer strictly
  follows the most recently seen token for the session, so the
  validator's :class:`DenyReason.SESSION_RESUME_SEQUENCE_INVALID`
  catches it even without the operator running a separate cache.

Out of scope for v0
-------------------
- The session-wide replay cache itself. This module produces a
  ``jti`` and enforces sequence rules; the operator wires the
  per-session cache (typically a small in-memory set keyed by
  ``session_id``).
- Bidirectional streaming with separate token chains per direction.
  v0 takes a single chain; operators wanting per-direction chains
  compose two :class:`SessionToken` instances.
- Session-level data-classification labels. Compose with the B1
  primitive at the higher layer.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Callable
from dataclasses import dataclass
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

SESSION_TYP = "wt-session/v0"


class SessionError(EnvelopeVerificationError):
    """Raised when a session token fails verification."""


@dataclass(frozen=True)
class SessionToken:
    session_id: str   # UUIDv7 — stable across resumes
    seq: int          # monotonically increases per resume; 0 for open
    parent_jti: str   # previous token's jti; "" on the initial open
    iss: str          # issuing authority SPIFFE id
    iss_kid: str
    sub: str          # caller SPIFFE id
    aud: str          # recipient SPIFFE id
    scope: str
    iat: int
    nbf: int
    exp: int
    jti: str          # UUIDv7, unique per token
    signature: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _session_body(token: SessionToken) -> bytes:
    body = {
        "typ": SESSION_TYP,
        "session_id": token.session_id,
        "seq": token.seq,
        "parent_jti": token.parent_jti,
        "iss": token.iss,
        "iss_kid": token.iss_kid,
        "sub": token.sub,
        "aud": token.aud,
        "scope": token.scope,
        "iat": token.iat,
        "nbf": token.nbf,
        "exp": token.exp,
        "jti": token.jti,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_session(
    token: SessionToken, signing_key: Ed25519PrivateKey
) -> SessionToken:
    sig = _b64u(signing_key.sign(_session_body(token)))
    return dataclasses.replace(token, signature=sig)


def to_json(token: SessionToken) -> bytes:
    return json.dumps(token.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> SessionToken:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise SessionError(
            "session token is not valid JSON",
            reason=DenyReason.SESSION_MALFORMED,
        ) from exc
    if not isinstance(obj, dict):
        raise SessionError(
            "session token JSON must be an object",
            reason=DenyReason.SESSION_MALFORMED,
        )
    required = {
        "session_id", "seq", "parent_jti", "iss", "iss_kid", "sub",
        "aud", "scope", "iat", "nbf", "exp", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise SessionError(
            f"missing required fields: {','.join(missing)}",
            reason=DenyReason.SESSION_MALFORMED,
        )
    return SessionToken(**{k: obj[k] for k in required})


def _malformed(msg: str) -> SessionError:
    return SessionError(msg, reason=DenyReason.SESSION_MALFORMED)


def _validate_shape(token: SessionToken) -> None:
    if not isinstance(token.session_id, str) or not UUID_V7_RE.match(token.session_id):
        raise _malformed(f"session_id must be UUIDv7: {token.session_id!r}")
    if not isinstance(token.jti, str) or not UUID_V7_RE.match(token.jti):
        raise _malformed(f"jti must be UUIDv7: {token.jti!r}")
    if not isinstance(token.seq, int) or isinstance(token.seq, bool):
        raise _malformed("seq must be an integer")
    if token.seq < 0:
        raise _malformed(f"seq must be non-negative: {token.seq}")
    if not isinstance(token.parent_jti, str):
        raise _malformed("parent_jti must be a string")
    if token.parent_jti and not UUID_V7_RE.match(token.parent_jti):
        raise _malformed(
            f"parent_jti must be UUIDv7 when non-empty: {token.parent_jti!r}"
        )
    if token.seq == 0 and token.parent_jti:
        raise _malformed("open token (seq=0) must have empty parent_jti")
    if token.seq > 0 and not token.parent_jti:
        raise _malformed("resume token (seq>0) must have non-empty parent_jti")

    if not isinstance(token.iss, str) or not SPIFFE_ID_RE.match(token.iss):
        raise _malformed(f"invalid iss: {token.iss!r}")
    if not isinstance(token.iss_kid, str) or not KID_RE.match(token.iss_kid):
        raise _malformed(f"invalid iss_kid: {token.iss_kid!r}")
    if not isinstance(token.sub, str) or not SPIFFE_ID_RE.match(token.sub):
        raise _malformed(f"invalid sub: {token.sub!r}")
    if not isinstance(token.aud, str) or not SPIFFE_ID_RE.match(token.aud):
        raise _malformed(f"invalid aud: {token.aud!r}")
    if not isinstance(token.scope, str) or not token.scope:
        raise _malformed("scope must be a non-empty string")
    for name, value in (("iat", token.iat), ("nbf", token.nbf), ("exp", token.exp)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _malformed(f"{name} must be a NumericDate (int)")
    if not isinstance(token.signature, str) or not token.signature:
        raise _malformed("signature must be a non-empty string")


def verify_session_token(
    token: SessionToken,
    *,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_token_ttl: timedelta = timedelta(minutes=5),
) -> SessionToken:
    """Validate shape, time window, and signature.

    Does NOT enforce chain rules — call :func:`verify_resume` for
    resume tokens.
    """
    _validate_shape(token)

    if token.iat > token.nbf or token.nbf > token.exp:
        raise SessionError(
            f"invalid validity window: iat={token.iat}, nbf={token.nbf}, "
            f"exp={token.exp}",
            reason=DenyReason.SESSION_INVALID_VALIDITY_WINDOW,
        )
    ttl = timedelta(seconds=token.exp - token.nbf)
    if ttl > max_token_ttl:
        raise SessionError(
            f"session token TTL {ttl} exceeds maximum {max_token_ttl}",
            reason=DenyReason.SESSION_TTL_EXCEEDED,
        )

    nbf_dt = datetime.fromtimestamp(token.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(token.exp, tz=UTC)
    current_utc = current.astimezone(UTC)
    if current_utc + max_clock_skew < nbf_dt:
        raise SessionError(
            f"session not yet valid (nbf={nbf_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.SESSION_NOT_YET_VALID,
        )
    if current_utc - max_clock_skew > exp_dt:
        raise SessionError(
            f"session expired (exp={exp_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.SESSION_EXPIRED,
        )

    try:
        pem = issuer_lookup(token.iss, token.iss_kid)
    except EnvelopeVerificationError as exc:
        raise SessionError(
            f"unknown session issuer: iss={token.iss!r}, kid={token.iss_kid!r}",
            reason=DenyReason.SESSION_UNKNOWN_ISSUER,
        ) from exc

    public_key = load_ed25519_public_key(pem)
    try:
        sig_bytes = decode_base64url(token.signature)
    except EnvelopeVerificationError as exc:
        raise SessionError(
            "session signature is not valid base64url",
            reason=DenyReason.SESSION_SIGNATURE_INVALID,
        ) from exc
    try:
        public_key.verify(sig_bytes, _session_body(token))
    except InvalidSignature as exc:
        raise SessionError(
            "session signature failed verification",
            reason=DenyReason.SESSION_SIGNATURE_INVALID,
        ) from exc

    return token


def verify_resume(
    token: SessionToken,
    *,
    previous: SessionToken,
    session_opened_at: int,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_token_ttl: timedelta = timedelta(minutes=5),
    max_session_lifetime: timedelta = timedelta(hours=1),
) -> SessionToken:
    """Verify ``token`` as a resume of ``previous``.

    Enforces, in addition to :func:`verify_session_token`'s checks:

    - ``token.session_id == previous.session_id``
    - ``token.parent_jti == previous.jti``
    - ``token.seq == previous.seq + 1``
    - ``token.sub == previous.sub`` (no subject drift)
    - ``token.aud == previous.aud`` (no audience drift)
    - ``token.scope == previous.scope`` (no scope drift)
    - ``token.exp - session_opened_at <= max_session_lifetime``
    """
    # Cross-session rules first — these are the resume contract and
    # must hold regardless of whether the new token itself verifies.
    if token.session_id != previous.session_id:
        raise SessionError(
            f"session_id mismatch: token={token.session_id!r}, "
            f"previous={previous.session_id!r}",
            reason=DenyReason.SESSION_RESUME_SESSION_MISMATCH,
        )
    if token.parent_jti != previous.jti:
        raise SessionError(
            f"parent_jti mismatch: token.parent_jti={token.parent_jti!r}, "
            f"previous.jti={previous.jti!r}",
            reason=DenyReason.SESSION_RESUME_PARENT_MISMATCH,
        )
    if token.seq != previous.seq + 1:
        raise SessionError(
            f"resume seq must be previous.seq+1: token={token.seq}, "
            f"previous={previous.seq}",
            reason=DenyReason.SESSION_RESUME_SEQUENCE_INVALID,
        )
    if token.sub != previous.sub:
        raise SessionError(
            f"sub drift across resume: token={token.sub!r}, "
            f"previous={previous.sub!r}",
            reason=DenyReason.SESSION_RESUME_SUBJECT_DRIFT,
        )
    if token.aud != previous.aud:
        raise SessionError(
            f"aud drift across resume: token={token.aud!r}, "
            f"previous={previous.aud!r}",
            reason=DenyReason.SESSION_RESUME_AUDIENCE_DRIFT,
        )
    if token.scope != previous.scope:
        raise SessionError(
            f"scope drift across resume: token={token.scope!r}, "
            f"previous={previous.scope!r}",
            reason=DenyReason.SESSION_RESUME_SCOPE_DRIFT,
        )

    cumulative = timedelta(seconds=token.exp - session_opened_at)
    if cumulative > max_session_lifetime:
        raise SessionError(
            f"cumulative session lifetime {cumulative} exceeds "
            f"maximum {max_session_lifetime}",
            reason=DenyReason.SESSION_RESUME_LIFETIME_EXCEEDED,
        )

    verify_session_token(
        token,
        issuer_lookup=issuer_lookup,
        current=current,
        max_clock_skew=max_clock_skew,
        max_token_ttl=max_token_ttl,
    )
    return token
