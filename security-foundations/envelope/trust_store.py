"""Reference trust store for the envelope verifier.

A ``FileSystemTrustStore`` is a callable mapping ``kid -> PEM bytes`` that
matches the ``key_lookup`` contract of :func:`verify_envelope.verify_envelope`.
Two loaders are provided:

* :py:meth:`FileSystemTrustStore.from_directory` — every ``<kid>.pem`` file in
  a directory is treated as a trusted key.
* :py:meth:`FileSystemTrustStore.from_manifest` — a JSON manifest assigns
  ``kid`` and optional ``not_after`` to PEM files, supporting expiring keys.

Both loaders eagerly parse PEMs via ``cryptography.serialization`` so an
unparseable key is rejected at load time, not at verification time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from verify_envelope import EnvelopeVerificationError, parse_rfc3339


@dataclass(frozen=True)
class TrustedKey:
    kid: str
    pem: bytes
    not_after: datetime | None = None


class FileSystemTrustStore:
    def __init__(self, keys: dict[str, TrustedKey]) -> None:
        self._keys = keys

    @classmethod
    def from_directory(cls, path: str | Path) -> FileSystemTrustStore:
        directory = Path(path)
        if not directory.is_dir():
            raise ValueError(f"trust store directory not found: {directory}")
        keys: dict[str, TrustedKey] = {}
        for pem_file in sorted(directory.glob("*.pem")):
            kid = pem_file.stem
            pem_bytes = pem_file.read_bytes()
            cls._parse_or_raise(pem_bytes, source=str(pem_file))
            if kid in keys:
                raise ValueError(f"duplicate kid in trust store: {kid}")
            keys[kid] = TrustedKey(kid=kid, pem=pem_bytes)
        return cls(keys)

    @classmethod
    def from_manifest(cls, path: str | Path) -> FileSystemTrustStore:
        manifest_path = Path(path)
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict) or "keys" not in manifest:
            raise ValueError(f"manifest missing 'keys' array: {manifest_path}")
        entries = manifest["keys"]
        if not isinstance(entries, list):
            raise ValueError(f"manifest 'keys' must be an array: {manifest_path}")

        base = manifest_path.parent.resolve()
        keys: dict[str, TrustedKey] = {}
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"manifest entry {index} is not an object")
            for required in ("kid", "pem_path"):
                if required not in entry:
                    raise ValueError(f"manifest entry {index} missing field: {required}")
            kid = entry["kid"]
            pem_path = (base / entry["pem_path"]).resolve()
            if not pem_path.is_relative_to(base):
                raise ValueError(
                    f"manifest entry {kid} pem_path escapes manifest directory: {entry['pem_path']}"
                )
            if not pem_path.is_file():
                raise ValueError(f"manifest entry {kid} pem_path not found: {pem_path}")
            pem_bytes = pem_path.read_bytes()
            cls._parse_or_raise(pem_bytes, source=str(pem_path))
            not_after: datetime | None = None
            if "not_after" in entry:
                try:
                    not_after = parse_rfc3339(entry["not_after"])
                except EnvelopeVerificationError as exc:
                    raise ValueError(
                        f"manifest entry {kid} has invalid not_after: {entry['not_after']}"
                    ) from exc
            if kid in keys:
                raise ValueError(f"duplicate kid in manifest: {kid}")
            keys[kid] = TrustedKey(kid=kid, pem=pem_bytes, not_after=not_after)
        return cls(keys)

    @staticmethod
    def _parse_or_raise(pem_bytes: bytes, *, source: str) -> None:
        try:
            key = serialization.load_pem_public_key(pem_bytes)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"unparseable PEM in trust store: {source}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"non-Ed25519 PEM in trust store: {source}")

    def __call__(self, kid: str) -> bytes:
        entry = self._keys.get(kid)
        if entry is None:
            raise EnvelopeVerificationError(f"unknown kid: {kid}")
        if entry.not_after is not None and datetime.now(UTC) > entry.not_after:
            raise EnvelopeVerificationError(f"key expired: {kid}")
        return entry.pem
