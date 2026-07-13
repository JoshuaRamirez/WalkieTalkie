"""Signed safe-mode artifacts (Phase 3 D3.3, circle-back).

Phase 3 §3 D3.3 calls for "Signed state transition and recovery
attestation artifacts." The Phase 3 Track C v0 shipped the engine +
unsigned transition records; this module is the signing layer.

Two artifact shapes:

- :class:`SignedStateTransition` — emitted by the safe-mode runtime
  when a state change happens. Signed by a *broadcast* authority
  (operations / SRE / incident response) so external observers
  (audit pipeline, dashboards, cross-region replicas) can verify
  the record without trusting the emitter.

- :class:`SignedDowngradeApproval` — the input shape for
  :func:`verified_downgrade`. The Phase 3 v0
  :class:`safe_mode_engine.DowngradeApproval` is unsigned and the
  engine trusts it on faith. This module's
  :func:`verify_downgrade_approval` checks that the approval was
  signed by an issuer in a separate trust pool — operators that want
  the stricter contract route their downgrades through
  :func:`verified_downgrade` instead of the raw
  :meth:`SafeModeEngine.downgrade`.

Wire format mirrors the rest of the substrate: JCS-canonical body,
``typ`` cross-protocol binding, base64url-encoded EdDSA signature.
Issuer keys come from an :class:`IssuerTrustStore`-shaped lookup so
the same trust pool that issues capability tokens / reviewer
decisions / step-up attestations also handles safe-mode signatures.

Cross-protocol typ values:

- ``"wt-safe-mode-transition/v0"`` for :class:`SignedStateTransition`
- ``"wt-safe-mode-downgrade/v0"`` for :class:`SignedDowngradeApproval`

Out of scope for this circle-back
---------------------------------
- Multi-attester / quorum approvals. v0 takes a single signature.
- Replay caching of approval ``jti``. The engine doesn't allow
  re-running a downgrade once it's committed; if operators want
  belt-and-braces replay rejection, they can stash jtis like for
  envelope nonces.
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
from safe_mode_engine import (
    DowngradeApproval,
    SafeModeEngine,
    SafeModeEngineError,
    SafeModeState,
    StateTransition,
    TriggerCategory,
    TriggerKind,
)
from verify_envelope import (
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

TRANSITION_TYP = "wt-safe-mode-transition/v0"
DOWNGRADE_TYP = "wt-safe-mode-downgrade/v0"


class SignedSafeModeError(EnvelopeVerificationError):
    """Raised when a signed safe-mode artifact fails verification."""


# ---------------------------------------------------------------------
# SignedStateTransition
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class SignedStateTransition:
    """An attested state-change record."""

    from_state: SafeModeState
    to_state: SafeModeState
    transition_at: int          # NumericDate
    cause: str                  # "trigger" | "clear" | "downgrade"
    active_kinds: tuple[str, ...]  # TriggerKind values, sorted for determinism
    detail: str
    attester_iss: str
    attester_kid: str
    jti: str
    signature: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["active_kinds"] = list(self.active_kinds)
        d["from_state"] = self.from_state.value
        d["to_state"] = self.to_state.value
        return d


def _transition_body(rec: SignedStateTransition) -> bytes:
    body = {
        "typ": TRANSITION_TYP,
        "from_state": rec.from_state.value,
        "to_state": rec.to_state.value,
        "transition_at": rec.transition_at,
        "cause": rec.cause,
        "active_kinds": list(rec.active_kinds),
        "detail": rec.detail,
        "attester_iss": rec.attester_iss,
        "attester_kid": rec.attester_kid,
        "jti": rec.jti,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _malformed(msg: str) -> SignedSafeModeError:
    return SignedSafeModeError(
        msg, reason=DenyReason.SAFE_MODE_ARTIFACT_MALFORMED
    )


def from_transition(
    transition: StateTransition,
    *,
    attester_iss: str,
    attester_kid: str,
    jti: str,
) -> SignedStateTransition:
    """Build an unsigned :class:`SignedStateTransition` from the raw
    engine output. Pass to :func:`sign_transition` to populate
    ``signature``."""
    return SignedStateTransition(
        from_state=transition.from_state,
        to_state=transition.to_state,
        transition_at=int(transition.transition_at.astimezone(UTC).timestamp()),
        cause=transition.cause,
        active_kinds=tuple(sorted(k.value for k in transition.active_kinds)),
        detail=transition.detail,
        attester_iss=attester_iss,
        attester_kid=attester_kid,
        jti=jti,
    )


def sign_transition(
    rec: SignedStateTransition, signing_key: Ed25519PrivateKey
) -> SignedStateTransition:
    sig = _b64u(signing_key.sign(_transition_body(rec)))
    return dataclasses.replace(rec, signature=sig)


def _validate_transition_shape(rec: SignedStateTransition) -> None:
    if not isinstance(rec.from_state, SafeModeState):
        raise _malformed(f"from_state must be a SafeModeState: {rec.from_state!r}")
    if not isinstance(rec.to_state, SafeModeState):
        raise _malformed(f"to_state must be a SafeModeState: {rec.to_state!r}")
    if not isinstance(rec.transition_at, int) or isinstance(rec.transition_at, bool):
        raise _malformed("transition_at must be a NumericDate (int)")
    if rec.cause not in ("trigger", "clear", "downgrade"):
        raise _malformed(f"cause must be trigger/clear/downgrade: {rec.cause!r}")
    if not isinstance(rec.active_kinds, tuple):
        raise _malformed("active_kinds must be a tuple")
    for k in rec.active_kinds:
        if not isinstance(k, str):
            raise _malformed(f"active_kinds element must be string: {k!r}")
        try:
            TriggerKind(k)
        except ValueError as exc:
            raise _malformed(f"unknown TriggerKind: {k!r}") from exc
    if not isinstance(rec.detail, str):
        raise _malformed("detail must be a string")
    if not isinstance(rec.attester_iss, str) or not SPIFFE_ID_RE.match(rec.attester_iss):
        raise _malformed(f"invalid attester_iss: {rec.attester_iss!r}")
    if not isinstance(rec.attester_kid, str) or not KID_RE.match(rec.attester_kid):
        raise _malformed(f"invalid attester_kid: {rec.attester_kid!r}")
    if not isinstance(rec.jti, str) or not UUID_V7_RE.match(rec.jti):
        raise _malformed(f"jti must be UUIDv7: {rec.jti!r}")
    if not isinstance(rec.signature, str) or not rec.signature:
        raise _malformed("signature must be a non-empty string")


def verify_transition(
    rec: SignedStateTransition,
    *,
    issuer_lookup: Callable[[str, str], bytes],
) -> SignedStateTransition:
    """Validate shape + signature against the attester's pool.

    There is no time-window check — transitions are durable audit
    records. Callers that want freshness (e.g. only consider
    transitions newer than X) compare ``transition_at`` themselves.
    """
    _validate_transition_shape(rec)
    try:
        pem = issuer_lookup(rec.attester_iss, rec.attester_kid)
    except EnvelopeVerificationError as exc:
        raise SignedSafeModeError(
            f"unknown attester key: iss={rec.attester_iss!r}, "
            f"kid={rec.attester_kid!r}",
            reason=DenyReason.SAFE_MODE_ARTIFACT_UNKNOWN_ISSUER,
        ) from exc
    public_key = load_ed25519_public_key(pem)
    try:
        sig_bytes = decode_base64url(rec.signature)
    except EnvelopeVerificationError as exc:
        raise SignedSafeModeError(
            "transition signature is not valid base64url",
            reason=DenyReason.SAFE_MODE_ARTIFACT_SIGNATURE_INVALID,
        ) from exc
    try:
        public_key.verify(sig_bytes, _transition_body(rec))
    except InvalidSignature as exc:
        raise SignedSafeModeError(
            "transition signature failed verification",
            reason=DenyReason.SAFE_MODE_ARTIFACT_SIGNATURE_INVALID,
        ) from exc
    return rec


def transition_to_json(rec: SignedStateTransition) -> bytes:
    return json.dumps(rec.to_dict(), separators=(",", ":")).encode("utf-8")


def transition_from_json(data: bytes) -> SignedStateTransition:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise _malformed("transition is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise _malformed("transition JSON must be an object")
    required = {
        "from_state", "to_state", "transition_at", "cause", "active_kinds",
        "detail", "attester_iss", "attester_kid", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise _malformed(f"missing required fields: {','.join(missing)}")
    try:
        from_state = SafeModeState(obj["from_state"])
        to_state = SafeModeState(obj["to_state"])
    except ValueError as exc:
        raise _malformed(f"invalid state value: {exc}") from exc
    return SignedStateTransition(
        from_state=from_state,
        to_state=to_state,
        transition_at=obj["transition_at"],
        cause=obj["cause"],
        active_kinds=tuple(obj["active_kinds"]),
        detail=obj["detail"],
        attester_iss=obj["attester_iss"],
        attester_kid=obj["attester_kid"],
        jti=obj["jti"],
        signature=obj["signature"],
    )


# ---------------------------------------------------------------------
# SignedDowngradeApproval
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class SignedDowngradeApproval:
    """Signed approval to downgrade the safe-mode engine."""

    approver_iss: str
    approver_kid: str
    authority: TriggerCategory
    issued_at: int        # NumericDate
    nbf: int
    exp: int
    detail: str
    jti: str
    signature: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["authority"] = self.authority.value
        return d


def _approval_body(app: SignedDowngradeApproval) -> bytes:
    body = {
        "typ": DOWNGRADE_TYP,
        "approver_iss": app.approver_iss,
        "approver_kid": app.approver_kid,
        "authority": app.authority.value,
        "issued_at": app.issued_at,
        "nbf": app.nbf,
        "exp": app.exp,
        "detail": app.detail,
        "jti": app.jti,
    }
    return jcs.canonicalize(body)


def sign_downgrade_approval(
    app: SignedDowngradeApproval, signing_key: Ed25519PrivateKey
) -> SignedDowngradeApproval:
    sig = _b64u(signing_key.sign(_approval_body(app)))
    return dataclasses.replace(app, signature=sig)


def _validate_approval_shape(app: SignedDowngradeApproval) -> None:
    if not isinstance(app.approver_iss, str) or not SPIFFE_ID_RE.match(app.approver_iss):
        raise _malformed(f"invalid approver_iss: {app.approver_iss!r}")
    if not isinstance(app.approver_kid, str) or not KID_RE.match(app.approver_kid):
        raise _malformed(f"invalid approver_kid: {app.approver_kid!r}")
    if not isinstance(app.authority, TriggerCategory):
        raise _malformed(
            f"authority must be a TriggerCategory: {app.authority!r}"
        )
    for name, value in (
        ("issued_at", app.issued_at),
        ("nbf", app.nbf),
        ("exp", app.exp),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _malformed(f"{name} must be a NumericDate (int)")
    if app.issued_at > app.nbf or app.nbf > app.exp:
        raise _malformed(
            f"invalid validity window: issued_at={app.issued_at}, "
            f"nbf={app.nbf}, exp={app.exp}"
        )
    if not isinstance(app.detail, str):
        raise _malformed("detail must be a string")
    if not isinstance(app.jti, str) or not UUID_V7_RE.match(app.jti):
        raise _malformed(f"jti must be UUIDv7: {app.jti!r}")
    if not isinstance(app.signature, str) or not app.signature:
        raise _malformed("signature must be a non-empty string")


def verify_downgrade_approval(
    app: SignedDowngradeApproval,
    *,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_approval_ttl: timedelta = timedelta(hours=1),
) -> SignedDowngradeApproval:
    """Validate shape, time window, and signature.

    A successful return means the approval can be passed to
    :func:`verified_downgrade`. Callers that want to evaluate
    authority semantics directly (e.g. for dry-run / preview) call
    :class:`SafeModeEngine.downgrade` on a transient DowngradeApproval
    they construct from the verified record.
    """
    _validate_approval_shape(app)

    ttl = timedelta(seconds=app.exp - app.nbf)
    if ttl > max_approval_ttl:
        raise _malformed(
            f"approval TTL {ttl} exceeds maximum {max_approval_ttl}"
        )
    nbf_dt = datetime.fromtimestamp(app.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(app.exp, tz=UTC)
    current_utc = current.astimezone(UTC)
    if current_utc + max_clock_skew < nbf_dt:
        raise SignedSafeModeError(
            f"approval not yet valid (nbf={nbf_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.SAFE_MODE_ARTIFACT_EXPIRED,
        )
    if current_utc - max_clock_skew > exp_dt:
        raise SignedSafeModeError(
            f"approval expired (exp={exp_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.SAFE_MODE_ARTIFACT_EXPIRED,
        )

    try:
        pem = issuer_lookup(app.approver_iss, app.approver_kid)
    except EnvelopeVerificationError as exc:
        raise SignedSafeModeError(
            f"unknown approver key: iss={app.approver_iss!r}, "
            f"kid={app.approver_kid!r}",
            reason=DenyReason.SAFE_MODE_ARTIFACT_UNKNOWN_ISSUER,
        ) from exc
    public_key = load_ed25519_public_key(pem)
    try:
        sig_bytes = decode_base64url(app.signature)
    except EnvelopeVerificationError as exc:
        raise SignedSafeModeError(
            "approval signature is not valid base64url",
            reason=DenyReason.SAFE_MODE_ARTIFACT_SIGNATURE_INVALID,
        ) from exc
    try:
        public_key.verify(sig_bytes, _approval_body(app))
    except InvalidSignature as exc:
        raise SignedSafeModeError(
            "approval signature failed verification",
            reason=DenyReason.SAFE_MODE_ARTIFACT_SIGNATURE_INVALID,
        ) from exc
    return app


def verified_downgrade(
    engine: SafeModeEngine,
    *,
    to_state: SafeModeState,
    signed_approval: SignedDowngradeApproval,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_approval_ttl: timedelta = timedelta(hours=1),
) -> StateTransition:
    """End-to-end: verify the signed approval, then run the engine
    downgrade with a freshly-constructed plain
    :class:`DowngradeApproval`.

    The plain approval is constructed here from the verified record's
    fields; the engine's existing authority dominance / trigger-floor
    checks fire as usual. Authority spoofing is prevented by the
    signature check.
    """
    verify_downgrade_approval(
        signed_approval,
        issuer_lookup=issuer_lookup,
        current=current,
        max_clock_skew=max_clock_skew,
        max_approval_ttl=max_approval_ttl,
    )
    plain = DowngradeApproval(
        approver_iss=signed_approval.approver_iss,
        approver_kid=signed_approval.approver_kid,
        authority=signed_approval.authority,
        issued_at=datetime.fromtimestamp(signed_approval.issued_at, tz=UTC),
        detail=signed_approval.detail,
    )
    try:
        return engine.downgrade(to_state=to_state, approval=plain)
    except SafeModeEngineError:
        # The engine's own DenyReasons (SAFE_MODE_DOWNGRADE_*) cover
        # authority / floor failures; let them propagate as-is.
        raise


def approval_to_json(app: SignedDowngradeApproval) -> bytes:
    return json.dumps(app.to_dict(), separators=(",", ":")).encode("utf-8")


def approval_from_json(data: bytes) -> SignedDowngradeApproval:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise _malformed("approval is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise _malformed("approval JSON must be an object")
    required = {
        "approver_iss", "approver_kid", "authority", "issued_at", "nbf",
        "exp", "detail", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise _malformed(f"missing required fields: {','.join(missing)}")
    try:
        authority = TriggerCategory(obj["authority"])
    except ValueError as exc:
        raise _malformed(f"invalid authority: {obj['authority']!r}") from exc
    return SignedDowngradeApproval(
        approver_iss=obj["approver_iss"],
        approver_kid=obj["approver_kid"],
        authority=authority,
        issued_at=obj["issued_at"],
        nbf=obj["nbf"],
        exp=obj["exp"],
        detail=obj["detail"],
        jti=obj["jti"],
        signature=obj["signature"],
    )
