"""Signed policy bundles with anti-rollback.

Closes the first two sub-bullets of Phase 1 Track C C3 ("Policy Bundle
Hygiene"):

- "Signed policy bundles" — bundles are JCS-canonicalized and EdDSA-signed
  by a policy authority whose public key lives in an
  :class:`IssuerTrustStore` instance (distinct from the capability-issuer
  trust store, by operator convention — see security note below).
- "Anti-rollback version checks" — each bundle carries a monotonic
  ``version`` integer. :class:`FileBackedRollbackGuard` persists the
  highest version it has accepted; subsequent loads with a lower or equal
  version are rejected with ``PolicyBundleError``.

The third sub-bullet ("Canary + auto-rollback for policy releases") is
deferred to its own slice.

Security note
-------------
Reusing :class:`IssuerTrustStore` for policy keys is intentional — the
class is a generic ``(iss, kid) -> PEM`` Ed25519 lookup with manifest
loading, expiry, and path-traversal protection. The trust-separation
property is enforced by *which trust store instance* the caller passes:
the capability validator gets one ``IssuerTrustStore``, the policy
loader gets another, and operators MUST keep their PEMs in different
manifests so a capability-issuing key cannot sign a policy bundle (or
vice versa). Tests exist for the cap-side separation; the policy-side
separation is the operator's responsibility.

Out of scope for v0
-------------------
- Canary + auto-rollback (Phase 1 C3 third sub-bullet, separate slice).
- Bundle distribution / CDN (transport-coupled).
- Multiple concurrent policies (one bundle = one policy).
- Diff-based bundles (each bundle is a complete allowlist).
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from issuance_policy import AllowlistPolicy
from verify_envelope import (
    KID_RE,
    SPIFFE_ID_RE,
    decode_base64url,
    load_ed25519_public_key,
)

POLICY_BUNDLE_TYP = "wt-policy-bundle/v0"


class PolicyBundleError(ValueError):
    """Raised when a bundle fails verification, signature check, or rollback."""


@dataclass(frozen=True)
class PolicyBundle:
    """An :class:`AllowlistPolicy` rendered as a signed, versioned artifact."""

    version: int
    issuer_iss: str
    issuer_kid: str
    allowlist_grants: tuple[tuple[str, str, str], ...]
    max_ttl_seconds: int
    signature: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        # Tuples round-trip through JSON as lists; normalize for stable form.
        d["allowlist_grants"] = [list(g) for g in self.allowlist_grants]
        return d


def _body_for_signing(bundle: PolicyBundle) -> bytes:
    body = {
        "typ": POLICY_BUNDLE_TYP,
        "version": bundle.version,
        "issuer_iss": bundle.issuer_iss,
        "issuer_kid": bundle.issuer_kid,
        "allowlist_grants": [list(g) for g in bundle.allowlist_grants],
        "max_ttl_seconds": bundle.max_ttl_seconds,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_bundle(bundle: PolicyBundle, signing_key: Ed25519PrivateKey) -> PolicyBundle:
    """Return a copy of ``bundle`` with ``signature`` populated."""
    sig = _b64u(signing_key.sign(_body_for_signing(bundle)))
    return dataclasses.replace(bundle, signature=sig)


def to_json(bundle: PolicyBundle) -> bytes:
    return json.dumps(bundle.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> PolicyBundle:
    """Parse a JSON-encoded bundle (does not verify signature or contents)."""
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise PolicyBundleError("bundle is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise PolicyBundleError("bundle JSON must be an object")
    required = {
        "version", "issuer_iss", "issuer_kid", "allowlist_grants",
        "max_ttl_seconds", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise PolicyBundleError(f"missing required fields: {','.join(missing)}")
    grants_raw = obj["allowlist_grants"]
    if not isinstance(grants_raw, list):
        raise PolicyBundleError("allowlist_grants must be a list")
    grants: list[tuple[str, str, str]] = []
    for index, g in enumerate(grants_raw):
        if not isinstance(g, list) or len(g) != 3 or not all(isinstance(x, str) for x in g):
            raise PolicyBundleError(
                f"allowlist_grants[{index}] must be a 3-tuple of strings"
            )
        grants.append((g[0], g[1], g[2]))
    return PolicyBundle(
        version=obj["version"],
        issuer_iss=obj["issuer_iss"],
        issuer_kid=obj["issuer_kid"],
        allowlist_grants=tuple(grants),
        max_ttl_seconds=obj["max_ttl_seconds"],
        signature=obj["signature"],
    )


def _validate_bundle_shape(bundle: PolicyBundle) -> None:
    if not isinstance(bundle.version, int) or isinstance(bundle.version, bool) or bundle.version < 1:
        raise PolicyBundleError("version must be a positive integer")
    if not isinstance(bundle.issuer_iss, str) or not SPIFFE_ID_RE.match(bundle.issuer_iss):
        raise PolicyBundleError(f"invalid issuer_iss: {bundle.issuer_iss!r}")
    if not isinstance(bundle.issuer_kid, str) or not KID_RE.match(bundle.issuer_kid):
        raise PolicyBundleError(f"invalid issuer_kid: {bundle.issuer_kid!r}")
    if not isinstance(bundle.max_ttl_seconds, int) or bundle.max_ttl_seconds <= 0:
        raise PolicyBundleError("max_ttl_seconds must be a positive integer")
    # Per-grant SPIFFE-ID format check: sub and aud only. scope is free-form.
    for index, (sub, aud, scope) in enumerate(bundle.allowlist_grants):
        if not SPIFFE_ID_RE.match(sub):
            raise PolicyBundleError(f"allowlist_grants[{index}].sub invalid: {sub!r}")
        if not SPIFFE_ID_RE.match(aud):
            raise PolicyBundleError(f"allowlist_grants[{index}].aud invalid: {aud!r}")
        if not isinstance(scope, str) or not scope:
            raise PolicyBundleError(f"allowlist_grants[{index}].scope empty")


def verify_bundle(
    bundle: PolicyBundle,
    *,
    issuer_lookup: Callable[[str, str], bytes],
) -> AllowlistPolicy:
    """Verify shape + signature; return the realized :class:`AllowlistPolicy`.

    Does NOT check rollback. Compose with :class:`RollbackGuard` for the
    monotonic-version check.
    """
    _validate_bundle_shape(bundle)
    if not bundle.signature:
        raise PolicyBundleError("bundle is unsigned")
    try:
        sig_bytes = decode_base64url(bundle.signature)
    except Exception as exc:
        raise PolicyBundleError("invalid signature encoding") from exc

    try:
        pem = issuer_lookup(bundle.issuer_iss, bundle.issuer_kid)
    except Exception as exc:
        raise PolicyBundleError(f"unknown policy issuer key: {exc}") from exc

    try:
        key = load_ed25519_public_key(pem)
    except Exception as exc:
        raise PolicyBundleError("invalid policy issuer public key") from exc

    try:
        key.verify(sig_bytes, _body_for_signing(bundle))
    except InvalidSignature as exc:
        raise PolicyBundleError("signature invalid") from exc

    return AllowlistPolicy(
        allowed_grants=frozenset(bundle.allowlist_grants),
        max_ttl=timedelta(seconds=bundle.max_ttl_seconds),
    )


class RollbackGuard:
    """Tracks the highest accepted bundle version per ``issuer_iss``.

    ``accept(bundle)`` raises :class:`PolicyBundleError` if ``bundle.version``
    is not strictly greater than the last accepted version for the same
    issuer. On success it updates the stored high-water mark and returns.

    Anti-rollback is per-issuer because two distinct policy authorities can
    legitimately use overlapping integer version sequences.
    """

    def accept(self, bundle: PolicyBundle) -> None:
        last = self._get(bundle.issuer_iss)
        if last is not None and bundle.version <= last:
            raise PolicyBundleError(
                f"rollback: incoming version {bundle.version} <= last accepted {last} "
                f"for issuer {bundle.issuer_iss}"
            )
        self._put(bundle.issuer_iss, bundle.version)

    def _get(self, issuer_iss: str) -> int | None:
        raise NotImplementedError

    def _put(self, issuer_iss: str, version: int) -> None:
        raise NotImplementedError


class InMemoryRollbackGuard(RollbackGuard):
    def __init__(self) -> None:
        self._last: dict[str, int] = {}

    def _get(self, issuer_iss: str) -> int | None:
        return self._last.get(issuer_iss)

    def _put(self, issuer_iss: str, version: int) -> None:
        self._last[issuer_iss] = version


class FileBackedRollbackGuard(RollbackGuard):
    """Persists the highest accepted version per issuer to a JSON file.

    The file is read on every ``_get`` and rewritten on every ``_put`` so a
    fresh process picks up state from disk without coordination. v0 is
    single-process; cross-process concurrency is out of scope (operators
    should serialize bundle distribution).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        if not self._path.exists():
            self._path.write_text("{}")

    def _load(self) -> dict[str, int]:
        try:
            data = json.loads(self._path.read_text())
        except (ValueError, TypeError) as exc:
            raise PolicyBundleError(
                f"corrupt rollback-guard file: {self._path}"
            ) from exc
        if not isinstance(data, dict):
            raise PolicyBundleError(
                f"corrupt rollback-guard file (expected object): {self._path}"
            )
        return {k: int(v) for k, v in data.items()}

    def _get(self, issuer_iss: str) -> int | None:
        return self._load().get(issuer_iss)

    def _put(self, issuer_iss: str, version: int) -> None:
        data = self._load()
        data[issuer_iss] = version
        self._path.write_text(json.dumps(data, separators=(",", ":")))
