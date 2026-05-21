"""Recovery and re-admission v0 (Phase 3 Track D D3).

Closes D3 ("Recovery and Re-Admission"):

- "Quarantine policy." — :class:`QuarantineEntry` records that a
  specific workload (``workload_iss``) has been quarantined, why,
  and which kid is no longer trusted. The entry is pure data; the
  enforcement plumbing lives elsewhere (revocation ledger,
  admission gate). The entry plays the role of the "incident
  ticket" the rebuild flow attaches to.

- "Clean-room rebuild proof." — :class:`CleanRoomAttestation` is an
  EdDSA-signed JCS body with ``typ="wt-readmission/v0"`` cross-
  protocol binding. It carries the ``quarantine_id`` it covers, the
  rebuilt workload's ``new_kid``, the digest of the clean baseline
  the rebuild was performed from, and a time window. The signing
  authority is a separate trust pool (``IssuerTrustStore``-shaped
  lookup), so the workload being readmitted physically cannot sign
  its own re-admission.

- "Re-attestation and scoped monitoring period post rejoin." —
  :func:`verify_readmission` validates the attestation against the
  quarantine entry and returns a :class:`ReAdmissionGrant` carrying
  the post-rejoin ``monitoring_period``. The runtime applies extra
  scrutiny (e.g. lower budget ceiling, mandatory dual review on
  privileged calls) for that duration before treating the workload
  as fully trusted again.

A re-admitted workload MUST use a different kid than the one that
was quarantined. The verifier refuses
:class:`DenyReason.READMISSION_KID_REUSE` if the attestation's
``new_kid`` equals the quarantine entry's ``last_kid`` — that's the
basic "clean-state evidence" requirement: the old material is dead.

Out of scope for v0
-------------------
- Multi-attester / quorum re-admission. v0 takes a single
  :class:`CleanRoomAttestation`. Quorum is composed at a higher
  layer.
- Sealed / attested baseline integrity (TPM quotes, image
  signatures). v0 takes ``baseline_digest`` as opaque hex; how the
  operator computes it is upstream.
- Automatic monitoring-period enforcement. v0 returns the duration;
  runtimes wire it to budget controllers / step-up requirements.
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
    HEX_SHA256_RE,
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

READMISSION_TYP = "wt-readmission/v0"


class ReAdmissionError(EnvelopeVerificationError):
    """Raised when re-admission inputs violate v0 invariants."""


@dataclass(frozen=True)
class QuarantineEntry:
    quarantine_id: str
    workload_iss: str
    last_kid: str
    quarantined_at: datetime
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.quarantine_id, str) or not UUID_V7_RE.match(
            self.quarantine_id
        ):
            raise ReAdmissionError(
                f"quarantine_id must be UUIDv7: {self.quarantine_id!r}",
                reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
            )
        if not isinstance(self.workload_iss, str) or not SPIFFE_ID_RE.match(
            self.workload_iss
        ):
            raise ReAdmissionError(
                f"invalid workload_iss: {self.workload_iss!r}",
                reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
            )
        if not isinstance(self.last_kid, str) or not KID_RE.match(self.last_kid):
            raise ReAdmissionError(
                f"invalid last_kid: {self.last_kid!r}",
                reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
            )
        if (
            not isinstance(self.quarantined_at, datetime)
            or self.quarantined_at.tzinfo is None
        ):
            raise ReAdmissionError(
                "quarantined_at must be a timezone-aware datetime",
                reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
            )
        if not isinstance(self.reason, str) or not self.reason:
            raise ReAdmissionError(
                "reason must be a non-empty string",
                reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
            )


@dataclass(frozen=True)
class CleanRoomAttestation:
    """Signed proof that a workload was rebuilt from a clean baseline."""

    quarantine_id: str
    workload_iss: str
    new_kid: str
    baseline_digest: str
    attester_iss: str
    attester_kid: str
    iat: int
    nbf: int
    exp: int
    monitoring_period_seconds: int
    jti: str
    signature: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _body(att: CleanRoomAttestation) -> bytes:
    body = {
        "typ": READMISSION_TYP,
        "quarantine_id": att.quarantine_id,
        "workload_iss": att.workload_iss,
        "new_kid": att.new_kid,
        "baseline_digest": att.baseline_digest,
        "attester_iss": att.attester_iss,
        "attester_kid": att.attester_kid,
        "iat": att.iat,
        "nbf": att.nbf,
        "exp": att.exp,
        "monitoring_period_seconds": att.monitoring_period_seconds,
        "jti": att.jti,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_attestation(
    att: CleanRoomAttestation, signing_key: Ed25519PrivateKey
) -> CleanRoomAttestation:
    sig = _b64u(signing_key.sign(_body(att)))
    return dataclasses.replace(att, signature=sig)


def to_json(att: CleanRoomAttestation) -> bytes:
    return json.dumps(att.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> CleanRoomAttestation:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise ReAdmissionError(
            "attestation is not valid JSON",
            reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
        ) from exc
    if not isinstance(obj, dict):
        raise ReAdmissionError(
            "attestation JSON must be an object",
            reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
        )
    required = {
        "quarantine_id", "workload_iss", "new_kid", "baseline_digest",
        "attester_iss", "attester_kid", "iat", "nbf", "exp",
        "monitoring_period_seconds", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise ReAdmissionError(
            f"missing required fields: {','.join(missing)}",
            reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
        )
    return CleanRoomAttestation(**{k: obj[k] for k in required})


def _malformed(msg: str) -> ReAdmissionError:
    return ReAdmissionError(
        msg, reason=DenyReason.READMISSION_ATTESTATION_MALFORMED
    )


def _validate_shape(att: CleanRoomAttestation) -> None:
    if not isinstance(att.quarantine_id, str) or not UUID_V7_RE.match(
        att.quarantine_id
    ):
        raise _malformed(f"quarantine_id must be UUIDv7: {att.quarantine_id!r}")
    if not isinstance(att.workload_iss, str) or not SPIFFE_ID_RE.match(
        att.workload_iss
    ):
        raise _malformed(f"invalid workload_iss: {att.workload_iss!r}")
    if not isinstance(att.new_kid, str) or not KID_RE.match(att.new_kid):
        raise _malformed(f"invalid new_kid: {att.new_kid!r}")
    if not isinstance(att.baseline_digest, str) or not HEX_SHA256_RE.match(
        att.baseline_digest
    ):
        raise _malformed(
            f"baseline_digest must be hex sha256: {att.baseline_digest!r}"
        )
    if not isinstance(att.attester_iss, str) or not SPIFFE_ID_RE.match(
        att.attester_iss
    ):
        raise _malformed(f"invalid attester_iss: {att.attester_iss!r}")
    if not isinstance(att.attester_kid, str) or not KID_RE.match(att.attester_kid):
        raise _malformed(f"invalid attester_kid: {att.attester_kid!r}")
    if not isinstance(att.jti, str) or not UUID_V7_RE.match(att.jti):
        raise _malformed(f"jti must be UUIDv7: {att.jti!r}")
    for name, value in (("iat", att.iat), ("nbf", att.nbf), ("exp", att.exp)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _malformed(f"{name} must be a NumericDate (int)")
    if not isinstance(att.monitoring_period_seconds, int) or att.monitoring_period_seconds < 0:
        raise _malformed(
            f"monitoring_period_seconds must be non-negative int: "
            f"{att.monitoring_period_seconds!r}"
        )
    if not isinstance(att.signature, str) or not att.signature:
        raise _malformed("signature must be a non-empty string")


@dataclass(frozen=True)
class ReAdmissionGrant:
    workload_iss: str
    new_kid: str
    monitoring_period: timedelta
    baseline_digest: str
    granted_at: datetime


def verify_readmission(
    attestation: CleanRoomAttestation,
    *,
    quarantine: QuarantineEntry,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_attestation_ttl: timedelta = timedelta(hours=24),
) -> ReAdmissionGrant:
    """Validate the attestation and return the re-admission grant.

    Checks (in order, fail-fast):
    1. Shape (every field present, types correct).
    2. Bindings to the quarantine entry: ``quarantine_id``,
       ``workload_iss`` match. ``new_kid`` differs from
       ``quarantine.last_kid``.
    3. Time window: ``iat <= nbf <= exp``; ``[nbf, exp]`` covers
       ``current`` within ``max_clock_skew``; ``exp - nbf`` ≤
       ``max_attestation_ttl``.
    4. Signature via ``issuer_lookup`` (attester's pool).
    """
    _validate_shape(attestation)

    if attestation.quarantine_id != quarantine.quarantine_id:
        raise ReAdmissionError(
            f"attestation quarantine_id mismatch: att={attestation.quarantine_id!r}, "
            f"entry={quarantine.quarantine_id!r}",
            reason=DenyReason.READMISSION_ATTESTATION_MISMATCH,
        )
    if attestation.workload_iss != quarantine.workload_iss:
        raise ReAdmissionError(
            f"attestation workload_iss mismatch: att={attestation.workload_iss!r}, "
            f"entry={quarantine.workload_iss!r}",
            reason=DenyReason.READMISSION_ATTESTATION_MISMATCH,
        )
    if attestation.new_kid == quarantine.last_kid:
        raise ReAdmissionError(
            f"re-admission must use a new kid: attempted "
            f"reuse of {quarantine.last_kid!r}",
            reason=DenyReason.READMISSION_KID_REUSE,
        )

    if attestation.iat > attestation.nbf or attestation.nbf > attestation.exp:
        raise ReAdmissionError(
            f"invalid validity window: iat={attestation.iat}, "
            f"nbf={attestation.nbf}, exp={attestation.exp}",
            reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
        )
    ttl = timedelta(seconds=attestation.exp - attestation.nbf)
    if ttl > max_attestation_ttl:
        raise ReAdmissionError(
            f"attestation TTL {ttl} exceeds maximum {max_attestation_ttl}",
            reason=DenyReason.READMISSION_ATTESTATION_MALFORMED,
        )

    nbf_dt = datetime.fromtimestamp(attestation.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(attestation.exp, tz=UTC)
    current_utc = current.astimezone(UTC)
    if current_utc + max_clock_skew < nbf_dt:
        raise ReAdmissionError(
            f"attestation not yet valid (nbf={nbf_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.READMISSION_ATTESTATION_EXPIRED,
        )
    if current_utc - max_clock_skew > exp_dt:
        raise ReAdmissionError(
            f"attestation expired (exp={exp_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.READMISSION_ATTESTATION_EXPIRED,
        )

    try:
        pem = issuer_lookup(attestation.attester_iss, attestation.attester_kid)
    except EnvelopeVerificationError as exc:
        raise ReAdmissionError(
            f"unknown attester key: iss={attestation.attester_iss!r}, "
            f"kid={attestation.attester_kid!r}",
            reason=DenyReason.READMISSION_ATTESTATION_UNKNOWN_ISSUER,
        ) from exc

    public_key = load_ed25519_public_key(pem)
    try:
        sig_bytes = decode_base64url(attestation.signature)
    except EnvelopeVerificationError as exc:
        raise ReAdmissionError(
            "attestation signature is not valid base64url",
            reason=DenyReason.READMISSION_ATTESTATION_SIGNATURE_INVALID,
        ) from exc
    try:
        public_key.verify(sig_bytes, _body(attestation))
    except InvalidSignature as exc:
        raise ReAdmissionError(
            "attestation signature failed verification",
            reason=DenyReason.READMISSION_ATTESTATION_SIGNATURE_INVALID,
        ) from exc

    return ReAdmissionGrant(
        workload_iss=attestation.workload_iss,
        new_kid=attestation.new_kid,
        monitoring_period=timedelta(seconds=attestation.monitoring_period_seconds),
        baseline_digest=attestation.baseline_digest,
        granted_at=current_utc,
    )
