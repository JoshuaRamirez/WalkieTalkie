"""Reviewer workflow v0 (Phase 2 Track C C3).

Closes C3 ("Reviewer Workflow"):

- "Quarantined outputs route to human review queue." — a
  :class:`QuarantineRecord` captures everything a reviewer needs to
  decide on an artifact that the egress policy (Phase 2 Track C C2)
  flagged for review. The record is pure data; storage and routing
  are the operator's concern.
- "Signed reviewer decision record with expiration and scope." — a
  :class:`ReviewDecision` is an EdDSA-signed JCS-canonical record that
  binds (via ``record_digest``) to the exact quarantine entry it
  authorizes, carries a ``verdict`` (RELEASE / REJECT), and an
  ``[nbf, exp]`` window. :func:`verify_release_authorization`
  re-derives the record digest, validates shape + signature + window,
  and refuses anything other than a current, well-formed, RELEASE
  verdict bound to *this* record.

Wire format mirrors the rest of the substrate: the body is a JCS-
canonicalized JSON object with a ``typ`` cross-protocol binding
(``"wt-review/v0"``); the signature is base64url-encoded EdDSA over
that body. Issuer keys are looked up via the existing
:class:`issuer_trust_store.IssuerTrustStore` — reviewers are
issuers in a trust pool that is distinct from workload signers (same
defense-in-depth pattern that protects capability tokens).

Out of scope for v0
-------------------
- Multi-reviewer / N-of-M decisions. v0 takes a single
  :class:`ReviewDecision`; coordinating quorum is a higher-level
  concern.
- Per-decision scope narrowing (e.g. "release only the redacted
  variant"). v0 verdicts are coarse: RELEASE or REJECT on the
  artifact identified by ``record_digest``.
- Decision revocation lists. v0 uses a short TTL; the C3 acceptance
  criterion calls for "expiration and scope", both of which the v0
  ``ReviewDecision`` carries.
- Persistent quarantine queue / handoff protocol. The
  :class:`QuarantineRecord` is the queue entry shape; routing it to
  reviewers is the operator's responsibility.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from data_classification import DataClass
from deny_reason import DenyReason
from output_scanning import RiskLevel
from verify_envelope import (
    HEX_SHA256_RE,
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

REVIEW_TYP = "wt-review/v0"


class ReviewVerdict(StrEnum):
    RELEASE = "release"
    REJECT = "reject"


class ReviewError(EnvelopeVerificationError):
    """Raised when a review decision fails verification.

    Subclasses :class:`EnvelopeVerificationError` so callers that
    already handle the envelope error don't need a separate branch.
    """


@dataclass(frozen=True)
class QuarantineRecord:
    """One quarantine queue entry — pure data, no signature.

    The reviewer's decision binds to :attr:`record_digest`, so any
    mutation of any field invalidates every outstanding decision.
    """

    record_id: str
    artifact_digest: str
    risk: RiskLevel
    data_class: DataClass
    requested_at: str
    requester_iss: str
    purpose_of_use: str

    def __post_init__(self) -> None:
        if not isinstance(self.record_id, str) or not UUID_V7_RE.match(self.record_id):
            raise ValueError(f"record_id must be UUIDv7: {self.record_id!r}")
        if not isinstance(self.artifact_digest, str) or not HEX_SHA256_RE.match(
            self.artifact_digest
        ):
            raise ValueError(
                f"artifact_digest must be hex sha256: {self.artifact_digest!r}"
            )
        if not isinstance(self.risk, RiskLevel):
            raise ValueError(f"risk must be a RiskLevel: {self.risk!r}")
        if not isinstance(self.data_class, DataClass):
            raise ValueError(f"data_class must be a DataClass: {self.data_class!r}")
        if not isinstance(self.requested_at, str) or not self.requested_at:
            raise ValueError("requested_at must be a non-empty string")
        if not isinstance(self.requester_iss, str) or not SPIFFE_ID_RE.match(
            self.requester_iss
        ):
            raise ValueError(f"invalid requester_iss: {self.requester_iss!r}")
        if not isinstance(self.purpose_of_use, str) or not self.purpose_of_use:
            raise ValueError("purpose_of_use must be a non-empty string")

    @property
    def record_digest(self) -> str:
        """Stable hex sha256 over the record body.

        Used as the binding target on :class:`ReviewDecision`; any
        mutation of any field invalidates every outstanding decision.
        Bit-stable across processes (computed via JCS).
        """
        body = {
            "record_id": self.record_id,
            "artifact_digest": self.artifact_digest,
            "risk": self.risk.value,
            "data_class": self.data_class.value,
            "requested_at": self.requested_at,
            "requester_iss": self.requester_iss,
            "purpose_of_use": self.purpose_of_use,
        }
        return hashlib.sha256(jcs.canonicalize(body)).hexdigest()


@dataclass(frozen=True)
class ReviewDecision:
    """The signed verdict produced by a human reviewer."""

    record_digest: str
    verdict: ReviewVerdict
    reason: str
    reviewer_iss: str
    reviewer_kid: str
    iat: int
    nbf: int
    exp: int
    jti: str
    signature: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["verdict"] = self.verdict.value
        return d


def _body_for_signing(decision: ReviewDecision) -> bytes:
    body = {
        "typ": REVIEW_TYP,
        "record_digest": decision.record_digest,
        "verdict": decision.verdict.value,
        "reason": decision.reason,
        "reviewer_iss": decision.reviewer_iss,
        "reviewer_kid": decision.reviewer_kid,
        "iat": decision.iat,
        "nbf": decision.nbf,
        "exp": decision.exp,
        "jti": decision.jti,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_decision(
    decision: ReviewDecision, signing_key: Ed25519PrivateKey
) -> ReviewDecision:
    sig = _b64u(signing_key.sign(_body_for_signing(decision)))
    return dataclasses.replace(decision, signature=sig)


def to_json(decision: ReviewDecision) -> bytes:
    return json.dumps(decision.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> ReviewDecision:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise ReviewError(
            "review decision is not valid JSON",
            reason=DenyReason.REVIEW_MALFORMED,
        ) from exc
    if not isinstance(obj, dict):
        raise ReviewError(
            "review decision JSON must be an object",
            reason=DenyReason.REVIEW_MALFORMED,
        )
    required = {
        "record_digest", "verdict", "reason", "reviewer_iss", "reviewer_kid",
        "iat", "nbf", "exp", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise ReviewError(
            f"missing required fields: {','.join(missing)}",
            reason=DenyReason.REVIEW_MALFORMED,
        )
    verdict_raw = obj["verdict"]
    try:
        verdict = ReviewVerdict(verdict_raw)
    except ValueError as exc:
        raise ReviewError(
            f"invalid verdict: {verdict_raw!r}",
            reason=DenyReason.REVIEW_MALFORMED,
        ) from exc
    return ReviewDecision(
        record_digest=obj["record_digest"],
        verdict=verdict,
        reason=obj["reason"],
        reviewer_iss=obj["reviewer_iss"],
        reviewer_kid=obj["reviewer_kid"],
        iat=obj["iat"],
        nbf=obj["nbf"],
        exp=obj["exp"],
        jti=obj["jti"],
        signature=obj["signature"],
    )


def _malformed(msg: str) -> ReviewError:
    return ReviewError(msg, reason=DenyReason.REVIEW_MALFORMED)


def _validate_shape(decision: ReviewDecision) -> None:
    if not isinstance(decision.record_digest, str) or not HEX_SHA256_RE.match(
        decision.record_digest
    ):
        raise _malformed(
            f"record_digest must be hex sha256: {decision.record_digest!r}"
        )
    if not isinstance(decision.verdict, ReviewVerdict):
        raise _malformed(f"verdict must be a ReviewVerdict: {decision.verdict!r}")
    if not isinstance(decision.reason, str):
        raise _malformed("reason must be a string")
    if not isinstance(decision.reviewer_iss, str) or not SPIFFE_ID_RE.match(
        decision.reviewer_iss
    ):
        raise _malformed(f"invalid reviewer_iss: {decision.reviewer_iss!r}")
    if not isinstance(decision.reviewer_kid, str) or not KID_RE.match(
        decision.reviewer_kid
    ):
        raise _malformed(f"invalid reviewer_kid: {decision.reviewer_kid!r}")
    if not isinstance(decision.jti, str) or not UUID_V7_RE.match(decision.jti):
        raise _malformed(f"jti must be UUIDv7: {decision.jti!r}")
    for name, value in (
        ("iat", decision.iat),
        ("nbf", decision.nbf),
        ("exp", decision.exp),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _malformed(f"{name} must be a NumericDate (int)")
    if not isinstance(decision.signature, str) or not decision.signature:
        raise _malformed("signature must be a non-empty string")


def verify_decision(
    decision: ReviewDecision,
    *,
    record: QuarantineRecord,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_review_ttl: timedelta = timedelta(hours=24),
) -> ReviewDecision:
    """Validate shape, binding, time window, and signature.

    Does NOT check whether the verdict is RELEASE — that's
    :func:`verify_release_authorization`'s job. A caller that wants the
    plain "is this decision valid?" check (for audit, dashboarding,
    archiving a REJECT) goes through this entry point.
    """
    _validate_shape(decision)

    if decision.record_digest != record.record_digest:
        raise ReviewError(
            (
                f"record_digest mismatch: decision={decision.record_digest}, "
                f"record={record.record_digest}"
            ),
            reason=DenyReason.REVIEW_RECORD_MISMATCH,
        )

    if decision.iat > decision.nbf:
        raise ReviewError(
            f"iat ({decision.iat}) must be <= nbf ({decision.nbf})",
            reason=DenyReason.REVIEW_INVALID_VALIDITY_WINDOW,
        )
    if decision.nbf > decision.exp:
        raise ReviewError(
            f"nbf ({decision.nbf}) must be <= exp ({decision.exp})",
            reason=DenyReason.REVIEW_INVALID_VALIDITY_WINDOW,
        )
    ttl = timedelta(seconds=decision.exp - decision.nbf)
    if ttl > max_review_ttl:
        raise ReviewError(
            f"review TTL {ttl} exceeds maximum {max_review_ttl}",
            reason=DenyReason.REVIEW_TTL_EXCEEDED,
        )

    nbf_dt = datetime.fromtimestamp(decision.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(decision.exp, tz=UTC)
    current_utc = current.astimezone(UTC)
    if current_utc + max_clock_skew < nbf_dt:
        raise ReviewError(
            f"decision not yet valid (nbf={nbf_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.REVIEW_NOT_YET_VALID,
        )
    if current_utc - max_clock_skew > exp_dt:
        raise ReviewError(
            f"decision expired (exp={exp_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.REVIEW_EXPIRED,
        )

    try:
        pem = issuer_lookup(decision.reviewer_iss, decision.reviewer_kid)
    except EnvelopeVerificationError as exc:
        raise ReviewError(
            f"unknown reviewer key: iss={decision.reviewer_iss!r}, "
            f"kid={decision.reviewer_kid!r}",
            reason=DenyReason.REVIEW_UNKNOWN_ISSUER,
        ) from exc

    public_key = load_ed25519_public_key(pem)
    try:
        signature_bytes = decode_base64url(decision.signature)
    except EnvelopeVerificationError as exc:
        raise ReviewError(
            "signature is not valid base64url",
            reason=DenyReason.REVIEW_SIGNATURE_INVALID,
        ) from exc
    try:
        public_key.verify(signature_bytes, _body_for_signing(decision))
    except InvalidSignature as exc:
        raise ReviewError(
            "reviewer signature failed verification",
            reason=DenyReason.REVIEW_SIGNATURE_INVALID,
        ) from exc

    return decision


def verify_release_authorization(
    decision: ReviewDecision,
    *,
    record: QuarantineRecord,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_review_ttl: timedelta = timedelta(hours=24),
) -> ReviewDecision:
    """Verify the decision AND that it authorizes release.

    Equivalent to :func:`verify_decision` followed by a check that the
    verdict is :class:`ReviewVerdict.RELEASE`. A REJECT decision raises
    :class:`ReviewError` with reason :class:`DenyReason.REVIEW_REJECTED`
    — that's the "release path" check that downstream egress code calls
    before letting the artifact through.
    """
    verify_decision(
        decision,
        record=record,
        issuer_lookup=issuer_lookup,
        current=current,
        max_clock_skew=max_clock_skew,
        max_review_ttl=max_review_ttl,
    )
    if decision.verdict is not ReviewVerdict.RELEASE:
        raise ReviewError(
            f"reviewer rejected release (verdict={decision.verdict.value!r}): "
            f"{decision.reason}",
            reason=DenyReason.REVIEW_REJECTED,
        )
    return decision
