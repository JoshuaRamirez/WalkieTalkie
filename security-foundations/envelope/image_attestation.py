"""Image signature attestation (Phase 5 Track D, D5.6). [REFERENCE]

The vision's Layer E ("Runtime and Environment Hardening") calls for only
running workloads whose container image is a known, attested artifact.
This module is the substrate's cosign-style primitive for that check: a
detached Ed25519 signature over an image digest, plus a fail-fast verifier.

An :class:`ImageSignature` is a signed record binding a signer identity to
one image digest (an OCI ``sha256:<hex>`` content digest, carried here as
the bare 64-char hex). Verification answers a single question — *"is this
exact image digest signed by a signer whose key I trust?"* — and denies
with a stable :class:`DenyReason` on every other path.

Follows the substrate's signed-artifact pattern (see
``delegation_receipt.py``): a frozen dataclass with a ``typ``
cross-protocol binding, JCS-canonical body, ``sign_*`` / ``verify_*`` /
``from_json`` / ``to_json``, and issuer keys resolved through the same
``Callable[[str, str], bytes]`` (``IssuerTrustStore``) shape used
everywhere else.

ENFORCEMENT BOUNDARY (read this):
---------------------------------
This is **[REFERENCE]**. Verifying a signature proves the image digest was
attested; it does NOT stop a runtime from pulling and running an
*unattested* image. Admission control — refusing to schedule a workload
whose image lacks a verifying :class:`ImageSignature` — lives in the
deployment layer (an admission webhook, a runtime policy). The substrate
supplies the verifiable data model and the checker; the gate that calls
it before ``docker run`` is the operator's.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Callable
from dataclasses import dataclass

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from deny_reason import DenyReason
from verify_envelope import (
    HEX_SHA256_RE,
    KID_RE,
    SPIFFE_ID_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

IMAGE_SIG_TYP = "wt-image-sig/v0"


class ImageSignatureError(EnvelopeVerificationError):
    """Raised when an image signature fails verification.

    Subclasses :class:`EnvelopeVerificationError` so callers already
    catching the envelope error don't need a separate branch.
    """


@dataclass(frozen=True)
class ImageSignature:
    """A detached signature binding a signer to one image digest.

    - ``image_digest`` — the image's content digest as bare lowercase hex
      (the ``<hex>`` of an OCI ``sha256:<hex>`` descriptor).
    - ``signer_id`` — the SPIFFE id of the signer (a CI identity, a release
      key's workload id). Keyed with ``signer_kid`` into the trust store.
    - ``signer_kid`` — the signer's key id.
    - ``signature`` — base64url(EdDSA over the JCS-canonical body).
    """

    image_digest: str
    signer_id: str
    signer_kid: str
    signature: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _body_for_signing(sig: ImageSignature) -> bytes:
    body = {
        "typ": IMAGE_SIG_TYP,
        "image_digest": sig.image_digest,
        "signer_id": sig.signer_id,
        "signer_kid": sig.signer_kid,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_image_signature(
    sig: ImageSignature, signing_key: Ed25519PrivateKey
) -> ImageSignature:
    """Return a copy of ``sig`` with the signature populated."""
    signed = _b64u(signing_key.sign(_body_for_signing(sig)))
    return dataclasses.replace(sig, signature=signed)


def to_json(sig: ImageSignature) -> bytes:
    return json.dumps(sig.to_dict(), separators=(",", ":")).encode("utf-8")


def _malformed(msg: str) -> ImageSignatureError:
    return ImageSignatureError(msg, reason=DenyReason.IMAGE_SIG_MALFORMED)


def from_json(data: bytes) -> ImageSignature:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise _malformed("image signature is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise _malformed("image signature JSON must be an object")
    required = {"image_digest", "signer_id", "signer_kid", "signature"}
    missing = sorted(required - set(obj))
    if missing:
        raise _malformed(f"missing required fields: {','.join(missing)}")
    return ImageSignature(**{k: obj[k] for k in required})


def _validate_shape(sig: ImageSignature) -> None:
    if not isinstance(sig.image_digest, str) or not HEX_SHA256_RE.match(sig.image_digest):
        raise _malformed(f"image_digest must be lowercase sha256 hex: {sig.image_digest!r}")
    if not isinstance(sig.signer_id, str) or not SPIFFE_ID_RE.match(sig.signer_id):
        raise _malformed(f"invalid signer_id: {sig.signer_id!r}")
    if not isinstance(sig.signer_kid, str) or not KID_RE.match(sig.signer_kid):
        raise _malformed(f"invalid signer_kid: {sig.signer_kid!r}")


def verify_image_signature(
    sig: ImageSignature,
    *,
    expected_digest: str,
    issuer_lookup: Callable[[str, str], bytes],
) -> ImageSignature:
    """Verify shape → digest match → signer key → signature, fail-fast.

    ``expected_digest`` is the bare lowercase sha256 hex of the image the
    caller is about to run. Verification denies unless the signature
    covers *exactly* that digest and validates under a key the
    ``issuer_lookup`` resolves for ``(signer_id, signer_kid)``. Returns the
    signature on success; raises :class:`ImageSignatureError` otherwise.
    """
    _validate_shape(sig)

    if not isinstance(expected_digest, str) or not HEX_SHA256_RE.match(expected_digest):
        raise _malformed(f"expected_digest must be lowercase sha256 hex: {expected_digest!r}")
    if sig.image_digest != expected_digest:
        raise ImageSignatureError(
            f"signed digest {sig.image_digest!r} does not match expected "
            f"{expected_digest!r}",
            reason=DenyReason.IMAGE_SIG_DIGEST_MISMATCH,
        )

    if not sig.signature:
        raise _malformed("image signature is unsigned")
    try:
        sig_bytes = decode_base64url(sig.signature)
    except Exception as exc:
        raise _malformed("invalid signature encoding") from exc

    try:
        pem = issuer_lookup(sig.signer_id, sig.signer_kid)
    except Exception as exc:
        raise ImageSignatureError(
            f"unknown image signer key: {exc}",
            reason=DenyReason.IMAGE_SIG_UNKNOWN_SIGNER,
        ) from exc

    try:
        key = load_ed25519_public_key(pem)
    except Exception as exc:
        raise ImageSignatureError(
            "invalid image signer public key",
            reason=DenyReason.IMAGE_SIG_UNKNOWN_SIGNER,
        ) from exc

    try:
        key.verify(sig_bytes, _body_for_signing(sig))
    except InvalidSignature as exc:
        raise ImageSignatureError(
            "image signature invalid", reason=DenyReason.IMAGE_SIG_INVALID
        ) from exc

    return sig
