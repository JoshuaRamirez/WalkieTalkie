"""Bootstrap artifact validation v0.

Closes Phase 1 Track A **A1** ("Bootstrap Artifact Validation"):

- "Validate anchor set, environment identity, epoch metadata."
- "Enforce no-join on mismatch."
- "Add out-of-band re-seeding path for suspected compromise."

A :class:`BootstrapBundle` is a signed, monotonically-versioned envelope of
known-good ``(iss, kid) -> PEM`` anchors for a trust domain. The bundle is
verified against a root public key supplied **out of band** — that's the
"out-of-band re-seeding path." On verification the bundle materializes into
an :class:`IssuerTrustStore` so the rest of the stack (capability validator,
policy verifier, future discovery record verifier) consumes it through the
same interface every other trust source uses.

Out of scope for v0
-------------------
- TOFU / pinned-multiple-anchors seeding (real PKI bootstraps with multiple
  roots; v0 takes a single root PEM out-of-band).
- Anchor revocation lists (rotate the bundle epoch instead).
- Cross-domain federation (one bundle = one trust_domain).
- Discovery records themselves (Phase 1 Track A **A2**, separate slice).
"""

from __future__ import annotations

import base64
import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from issuer_trust_store import IssuerKey, IssuerTrustStore
from verify_envelope import (
    KID_RE,
    SPIFFE_ID_RE,
    decode_base64url,
    load_ed25519_public_key,
)

BOOTSTRAP_TYP = "wt-bootstrap-bundle/v0"
_TRUST_DOMAIN_RE = "^[a-zA-Z0-9._-]+$"


class BootstrapBundleError(ValueError):
    """Raised when a bootstrap bundle fails shape or signature verification."""


@dataclass(frozen=True)
class BootstrapAnchor:
    iss: str
    kid: str
    pem_b64: str  # base64url(PEM bytes) — embedded for portability

    def pem_bytes(self) -> bytes:
        try:
            return decode_base64url(self.pem_b64)
        except Exception as exc:
            raise BootstrapBundleError("invalid anchor pem_b64 encoding") from exc


@dataclass(frozen=True)
class BootstrapBundle:
    """Signed anchor set for one trust domain."""

    version: int
    trust_domain: str
    epoch: int
    anchors: tuple[BootstrapAnchor, ...]
    signature: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _body_for_signing(bundle: BootstrapBundle) -> bytes:
    body = {
        "typ": BOOTSTRAP_TYP,
        "version": bundle.version,
        "trust_domain": bundle.trust_domain,
        "epoch": bundle.epoch,
        "anchors": [
            {"iss": a.iss, "kid": a.kid, "pem_b64": a.pem_b64}
            for a in bundle.anchors
        ],
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_anchor_pem(pem_bytes: bytes) -> str:
    """Helper: encode a raw PEM blob to the ``pem_b64`` field's expected form."""
    return _b64u(pem_bytes)


def sign_bundle(bundle: BootstrapBundle, root_signing_key: Ed25519PrivateKey) -> BootstrapBundle:
    sig = _b64u(root_signing_key.sign(_body_for_signing(bundle)))
    return dataclasses.replace(bundle, signature=sig)


def to_json(bundle: BootstrapBundle) -> bytes:
    return json.dumps(bundle.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> BootstrapBundle:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise BootstrapBundleError("bundle is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise BootstrapBundleError("bundle JSON must be an object")
    required = {"version", "trust_domain", "epoch", "anchors", "signature"}
    missing = sorted(required - set(obj))
    if missing:
        raise BootstrapBundleError(f"missing required fields: {','.join(missing)}")
    anchors_raw = obj["anchors"]
    if not isinstance(anchors_raw, list):
        raise BootstrapBundleError("anchors must be a list")
    anchors: list[BootstrapAnchor] = []
    for index, a in enumerate(anchors_raw):
        if not isinstance(a, dict):
            raise BootstrapBundleError(f"anchors[{index}] must be an object")
        for field in ("iss", "kid", "pem_b64"):
            if field not in a or not isinstance(a[field], str):
                raise BootstrapBundleError(f"anchors[{index}].{field} missing or non-string")
        anchors.append(BootstrapAnchor(iss=a["iss"], kid=a["kid"], pem_b64=a["pem_b64"]))
    return BootstrapBundle(
        version=obj["version"],
        trust_domain=obj["trust_domain"],
        epoch=obj["epoch"],
        anchors=tuple(anchors),
        signature=obj["signature"],
    )


def _validate_shape(bundle: BootstrapBundle) -> None:
    import re

    if not isinstance(bundle.version, int) or isinstance(bundle.version, bool) or bundle.version < 1:
        raise BootstrapBundleError("version must be a positive integer")
    if not isinstance(bundle.epoch, int) or isinstance(bundle.epoch, bool) or bundle.epoch < 1:
        raise BootstrapBundleError("epoch must be a positive integer")
    if not isinstance(bundle.trust_domain, str) or not re.match(_TRUST_DOMAIN_RE, bundle.trust_domain):
        raise BootstrapBundleError(f"invalid trust_domain: {bundle.trust_domain!r}")
    if not bundle.anchors:
        raise BootstrapBundleError("anchors must be non-empty")
    seen: set[tuple[str, str]] = set()
    for index, anchor in enumerate(bundle.anchors):
        if not SPIFFE_ID_RE.match(anchor.iss):
            raise BootstrapBundleError(f"anchors[{index}].iss invalid: {anchor.iss!r}")
        if not KID_RE.match(anchor.kid):
            raise BootstrapBundleError(f"anchors[{index}].kid invalid: {anchor.kid!r}")
        if (anchor.iss, anchor.kid) in seen:
            raise BootstrapBundleError(
                f"anchors[{index}] duplicate (iss, kid): ({anchor.iss}, {anchor.kid})"
            )
        seen.add((anchor.iss, anchor.kid))
        # Parse the PEM eagerly so a corrupt anchor fails fast.
        try:
            load_ed25519_public_key(anchor.pem_bytes())
        except BootstrapBundleError:
            raise
        except Exception as exc:
            raise BootstrapBundleError(
                f"anchors[{index}] PEM is not a valid Ed25519 public key"
            ) from exc


def verify_bundle(
    bundle: BootstrapBundle,
    *,
    expected_root_pem: bytes,
    expected_trust_domain: str | None = None,
) -> IssuerTrustStore:
    """Verify shape + signature; return an :class:`IssuerTrustStore`.

    The root PEM must arrive **out-of-band** — that is the entire point of
    bootstrap-artifact validation. Optionally pin the trust domain so a
    bundle signed for some other mesh cannot be accepted by mistake.
    """
    _validate_shape(bundle)
    if expected_trust_domain is not None and expected_trust_domain != bundle.trust_domain:
        raise BootstrapBundleError(
            f"trust_domain mismatch: expected {expected_trust_domain!r}, "
            f"got {bundle.trust_domain!r}"
        )
    if not bundle.signature:
        raise BootstrapBundleError("bundle is unsigned")

    try:
        sig_bytes = decode_base64url(bundle.signature)
    except Exception as exc:
        raise BootstrapBundleError("invalid signature encoding") from exc

    try:
        root_key = load_ed25519_public_key(expected_root_pem)
    except Exception as exc:
        raise BootstrapBundleError("invalid root public key") from exc

    try:
        root_key.verify(sig_bytes, _body_for_signing(bundle))
    except InvalidSignature as exc:
        raise BootstrapBundleError("signature invalid") from exc

    keys: dict[tuple[str, str], IssuerKey] = {
        (a.iss, a.kid): IssuerKey(iss=a.iss, kid=a.kid, pem=a.pem_bytes())
        for a in bundle.anchors
    }
    return IssuerTrustStore(keys)


def write_bundle(bundle: BootstrapBundle, path: str | Path) -> None:
    Path(path).write_bytes(to_json(bundle))


def read_bundle(path: str | Path) -> BootstrapBundle:
    return from_json(Path(path).read_bytes())
