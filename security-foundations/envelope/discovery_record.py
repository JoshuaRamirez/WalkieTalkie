"""Discovery record integrity v0.

Closes Phase 1 Track A **A2** ("Discovery Record Integrity"):

- "Signed discovery records with expiry."
- "Anti-poisoning checks for stale/forged records."

A :class:`DiscoveryRecord` advertises a workload (``workload_iss``,
``workload_kid``, ``endpoints``) and is signed by a *discovery authority*
whose public key lives in an :class:`IssuerTrustStore` instance — typically
the one materialized from a verified :class:`bootstrap_bundle.BootstrapBundle`
(Phase 1 Track A A1). Time-window checks reject stale records; signature
checks against the trust store reject forged ones.

Endpoints are opaque transport-hint strings. v0 enforces only that they're
non-empty strings; the transport layer (out of scope here) defines the URI
grammar.

Out of scope for v0
-------------------
- Endpoint URI grammar / per-scheme validation.
- Discovery distribution / gossip (transport-coupled).
- Workload-side proof-of-control beyond what the discovery authority
  decides to encode (e.g., the authority might require a workload-signed
  inner blob in a future v1).
- Admission coupling — A3, separate slice.
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
from verify_envelope import (
    KID_RE,
    SPIFFE_ID_RE,
    decode_base64url,
    load_ed25519_public_key,
    parse_rfc3339,
)

DISCOVERY_TYP = "wt-discovery-record/v0"
DEFAULT_MAX_RECORD_TTL = timedelta(hours=1)
DEFAULT_CLOCK_SKEW = timedelta(seconds=60)


class DiscoveryRecordError(ValueError):
    """Raised when a discovery record fails verification."""


@dataclass(frozen=True)
class DiscoveryRecord:
    """A signed advertisement of a workload's identity + transport hints."""

    version: str
    workload_iss: str
    workload_kid: str
    endpoints: tuple[str, ...]
    issuer_iss: str
    issuer_kid: str
    issued_at: str
    expires_at: str
    signature: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["endpoints"] = list(self.endpoints)
        return d


def _body_for_signing(record: DiscoveryRecord) -> bytes:
    body = {
        "typ": DISCOVERY_TYP,
        "version": record.version,
        "workload_iss": record.workload_iss,
        "workload_kid": record.workload_kid,
        "endpoints": list(record.endpoints),
        "issuer_iss": record.issuer_iss,
        "issuer_kid": record.issuer_kid,
        "issued_at": record.issued_at,
        "expires_at": record.expires_at,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_record(record: DiscoveryRecord, signing_key: Ed25519PrivateKey) -> DiscoveryRecord:
    sig = _b64u(signing_key.sign(_body_for_signing(record)))
    return dataclasses.replace(record, signature=sig)


def to_json(record: DiscoveryRecord) -> bytes:
    return json.dumps(record.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> DiscoveryRecord:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise DiscoveryRecordError("record is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise DiscoveryRecordError("record JSON must be an object")
    required = {
        "version", "workload_iss", "workload_kid", "endpoints",
        "issuer_iss", "issuer_kid", "issued_at", "expires_at", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise DiscoveryRecordError(f"missing required fields: {','.join(missing)}")

    endpoints_raw = obj["endpoints"]
    if not isinstance(endpoints_raw, list):
        raise DiscoveryRecordError("endpoints must be a list")

    return DiscoveryRecord(
        version=obj["version"],
        workload_iss=obj["workload_iss"],
        workload_kid=obj["workload_kid"],
        endpoints=tuple(endpoints_raw),
        issuer_iss=obj["issuer_iss"],
        issuer_kid=obj["issuer_kid"],
        issued_at=obj["issued_at"],
        expires_at=obj["expires_at"],
        signature=obj["signature"],
    )


def _validate_shape(record: DiscoveryRecord) -> None:
    if record.version != "v0":
        raise DiscoveryRecordError(f"unsupported version: {record.version!r}")
    if not isinstance(record.workload_iss, str) or not SPIFFE_ID_RE.match(record.workload_iss):
        raise DiscoveryRecordError(f"invalid workload_iss: {record.workload_iss!r}")
    if not isinstance(record.workload_kid, str) or not KID_RE.match(record.workload_kid):
        raise DiscoveryRecordError(f"invalid workload_kid: {record.workload_kid!r}")
    if not isinstance(record.issuer_iss, str) or not SPIFFE_ID_RE.match(record.issuer_iss):
        raise DiscoveryRecordError(f"invalid issuer_iss: {record.issuer_iss!r}")
    if not isinstance(record.issuer_kid, str) or not KID_RE.match(record.issuer_kid):
        raise DiscoveryRecordError(f"invalid issuer_kid: {record.issuer_kid!r}")
    if not record.endpoints:
        raise DiscoveryRecordError("endpoints must be non-empty")
    for index, ep in enumerate(record.endpoints):
        if not isinstance(ep, str) or not ep:
            raise DiscoveryRecordError(f"endpoints[{index}] must be a non-empty string")


@dataclass(frozen=True)
class DiscoveryVerificationConfig:
    max_clock_skew: timedelta = field(default_factory=lambda: DEFAULT_CLOCK_SKEW)
    max_record_ttl: timedelta = field(default_factory=lambda: DEFAULT_MAX_RECORD_TTL)


DEFAULT_DISCOVERY_CONFIG = DiscoveryVerificationConfig()


def verify_record(
    record: DiscoveryRecord,
    *,
    issuer_lookup: Callable[[str, str], bytes],
    now: datetime | None = None,
    config: DiscoveryVerificationConfig = DEFAULT_DISCOVERY_CONFIG,
) -> DiscoveryRecord:
    """Verify shape + time-window + signature. Return the record on success.

    ``issuer_lookup`` is a callable mapping ``(iss, kid) -> PEM`` —
    typically an :class:`IssuerTrustStore` materialized from a verified
    bootstrap bundle.
    """
    _validate_shape(record)
    if not record.signature:
        raise DiscoveryRecordError("record is unsigned")

    try:
        issued_at = parse_rfc3339(record.issued_at)
        expires_at = parse_rfc3339(record.expires_at)
    except Exception as exc:
        raise DiscoveryRecordError(f"invalid timestamp: {exc}") from exc

    current = now.astimezone(UTC) if now is not None else datetime.now(UTC)

    if expires_at <= issued_at:
        raise DiscoveryRecordError("invalid validity window")
    if expires_at - issued_at > config.max_record_ttl:
        raise DiscoveryRecordError(
            f"record ttl exceeds maximum {config.max_record_ttl}"
        )
    if issued_at - current > config.max_clock_skew:
        raise DiscoveryRecordError("issued_at in future beyond skew")
    if current - expires_at > config.max_clock_skew:
        raise DiscoveryRecordError("record expired")

    try:
        sig_bytes = decode_base64url(record.signature)
    except Exception as exc:
        raise DiscoveryRecordError("invalid signature encoding") from exc

    try:
        pem = issuer_lookup(record.issuer_iss, record.issuer_kid)
    except Exception as exc:
        raise DiscoveryRecordError(f"unknown discovery issuer key: {exc}") from exc

    try:
        key = load_ed25519_public_key(pem)
    except Exception as exc:
        raise DiscoveryRecordError("invalid discovery issuer public key") from exc

    try:
        key.verify(sig_bytes, _body_for_signing(record))
    except InvalidSignature as exc:
        raise DiscoveryRecordError("signature invalid") from exc

    return record
