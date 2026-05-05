"""Trust store for capability-token issuer keys.

An ``IssuerTrustStore`` is a callable mapping ``(iss, kid) -> PEM bytes``. It
is deliberately a sibling of :class:`trust_store.FileSystemTrustStore` rather
than a subclass: envelope-signing keys and capability-issuing keys serve
different roles, and the type system should not allow them to be confused.

Construction is manifest-only. There is no ``from_directory`` loader because
``(iss, kid)`` has no natural single-file encoding.

Manifest schema::

    {
      "keys": [
        {
          "iss": "spiffe://mesh/cap-issuer-1",
          "kid": "issuer-kid-1",
          "pem_path": "issuer-1-key-1.pem",
          "not_after": "2027-01-01T00:00:00Z"  // optional
        }
      ]
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from deny_reason import DenyReason
from verify_envelope import (
    KID_RE,
    SPIFFE_ID_RE,
    EnvelopeVerificationError,
    parse_rfc3339,
)


@dataclass(frozen=True)
class IssuerKey:
    iss: str
    kid: str
    pem: bytes
    not_after: datetime | None = None


class IssuerTrustStore:
    def __init__(self, keys: dict[tuple[str, str], IssuerKey]) -> None:
        self._keys = keys

    @classmethod
    def from_manifest(cls, path: str | Path) -> IssuerTrustStore:
        manifest_path = Path(path)
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict) or "keys" not in manifest:
            raise ValueError(f"manifest missing 'keys' array: {manifest_path}")
        entries = manifest["keys"]
        if not isinstance(entries, list):
            raise ValueError(f"manifest 'keys' must be an array: {manifest_path}")

        base = manifest_path.parent.resolve()
        keys: dict[tuple[str, str], IssuerKey] = {}
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"manifest entry {index} is not an object")
            for required in ("iss", "kid", "pem_path"):
                if required not in entry:
                    raise ValueError(f"manifest entry {index} missing field: {required}")
            iss = entry["iss"]
            kid = entry["kid"]
            if not isinstance(iss, str) or not SPIFFE_ID_RE.match(iss):
                raise ValueError(f"manifest entry {index} invalid iss: {iss!r}")
            if not isinstance(kid, str) or not KID_RE.match(kid):
                raise ValueError(f"manifest entry {index} invalid kid: {kid!r}")
            pem_path = (base / entry["pem_path"]).resolve()
            if not pem_path.is_relative_to(base):
                raise ValueError(
                    f"manifest entry ({iss}, {kid}) pem_path escapes manifest directory: "
                    f"{entry['pem_path']}"
                )
            if not pem_path.is_file():
                raise ValueError(
                    f"manifest entry ({iss}, {kid}) pem_path not found: {pem_path}"
                )
            pem_bytes = pem_path.read_bytes()
            cls._parse_or_raise(pem_bytes, source=str(pem_path))
            not_after: datetime | None = None
            if "not_after" in entry:
                try:
                    not_after = parse_rfc3339(entry["not_after"])
                except EnvelopeVerificationError as exc:
                    raise ValueError(
                        f"manifest entry ({iss}, {kid}) has invalid not_after: "
                        f"{entry['not_after']}"
                    ) from exc
            key = (iss, kid)
            if key in keys:
                raise ValueError(f"duplicate (iss, kid) in manifest: ({iss}, {kid})")
            keys[key] = IssuerKey(iss=iss, kid=kid, pem=pem_bytes, not_after=not_after)
        return cls(keys)

    @staticmethod
    def _parse_or_raise(pem_bytes: bytes, *, source: str) -> None:
        try:
            key = serialization.load_pem_public_key(pem_bytes)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"unparseable PEM in issuer trust store: {source}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"non-Ed25519 PEM in issuer trust store: {source}")

    def __call__(self, iss: str, kid: str) -> bytes:
        entry = self._keys.get((iss, kid))
        if entry is None:
            raise EnvelopeVerificationError(
                f"unknown issuer key: iss={iss}, kid={kid}",
                reason=DenyReason.UNKNOWN_ISSUER_KEY,
            )
        if entry.not_after is not None and datetime.now(UTC) > entry.not_after:
            raise EnvelopeVerificationError(
                f"issuer key expired: iss={iss}, kid={kid}",
                reason=DenyReason.ISSUER_KEY_EXPIRED,
            )
        return entry.pem
