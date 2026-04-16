"""Reference envelope verification utilities for Phase 0 bootstrap."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


UUID_V7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SPIFFE_ID_RE = re.compile(r"^spiffe://[a-zA-Z0-9._/-]+$")
NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{16,256}$")
HEX_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

ALLOWED_ALGORITHMS = {"Ed25519"}


class EnvelopeVerificationError(ValueError):
    """Raised when envelope verification fails."""


@dataclass(frozen=True)
class VerificationConfig:
    max_clock_skew: timedelta = timedelta(seconds=60)
    max_envelope_ttl: timedelta = timedelta(minutes=5)


class ReplayCache:
    """Minimal replay cache interface."""

    def seen(self, sender: str, nonce: str) -> bool:
        raise NotImplementedError

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        raise NotImplementedError

    def mark_if_new(self, sender: str, nonce: str, ttl: timedelta) -> bool:
        """Atomically mark nonce as seen when possible.

        Returns True if nonce was new and is now reserved, False if replayed.
        """
        if self.seen(sender, nonce):
            return False
        self.mark(sender, nonce, ttl)
        return True


class InMemoryReplayCache(ReplayCache):
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def _purge(self, now: datetime) -> None:
        expired = [k for k, v in self._entries.items() if v <= now]
        for key in expired:
            del self._entries[key]

    def seen(self, sender: str, nonce: str) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge(now)
            return (sender, nonce) in self._entries

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._entries[(sender, nonce)] = now + ttl

    def mark_if_new(self, sender: str, nonce: str, ttl: timedelta) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge(now)
            key = (sender, nonce)
            if key in self._entries:
                return False
            self._entries[key] = now + ttl
            return True


class SQLiteReplayCache(ReplayCache):
    """SQLite-backed replay cache for cross-process nonce replay protection."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    sender TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (sender, nonce)
                )
                """
            )

    @staticmethod
    def _now_epoch() -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _purge(self, conn: sqlite3.Connection) -> None:
        conn.execute("DELETE FROM replay_nonces WHERE expires_at <= ?", (self._now_epoch(),))

    def seen(self, sender: str, nonce: str) -> bool:
        with self._connect() as conn:
            self._purge(conn)
            row = conn.execute(
                "SELECT 1 FROM replay_nonces WHERE sender = ? AND nonce = ?",
                (sender, nonce),
            ).fetchone()
            return row is not None

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        expires_at = self._now_epoch() + max(0, int(ttl.total_seconds()))
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO replay_nonces(sender, nonce, expires_at) VALUES (?, ?, ?)",
                (sender, nonce, expires_at),
            )

    def mark_if_new(self, sender: str, nonce: str, ttl: timedelta) -> bool:
        expires_at = self._now_epoch() + max(0, int(ttl.total_seconds()))
        with self._connect() as conn:
            self._purge(conn)
            cur = conn.execute(
                "INSERT OR IGNORE INTO replay_nonces(sender, nonce, expires_at) VALUES (?, ?, ?)",
                (sender, nonce, expires_at),
            )
            return cur.rowcount == 1


def _parse_rfc3339(value: str) -> datetime:
    candidate = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise EnvelopeVerificationError("invalid timestamp format") from exc
    if dt.tzinfo is None:
        raise EnvelopeVerificationError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def canonicalize_envelope_for_signing(envelope: dict[str, Any]) -> bytes:
    if "signature" not in envelope:
        raise EnvelopeVerificationError("missing signature")
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    return _canonical_json(unsigned)


def _decode_base64url(signature: str) -> bytes:
    if not isinstance(signature, str) or not signature:
        raise EnvelopeVerificationError("signature must be non-empty base64url")
    padded = signature + ("=" * ((4 - len(signature) % 4) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise EnvelopeVerificationError("invalid signature encoding") from exc


def _verify_ed25519_signature(signing_input: bytes, signature: str, public_key_pem: bytes) -> bool:
    sig_bytes = _decode_base64url(signature)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        message_path = tmp / "message.bin"
        sig_path = tmp / "signature.bin"
        key_path = tmp / "public.pem"

        message_path.write_bytes(signing_input)
        sig_path.write_bytes(sig_bytes)
        key_path.write_bytes(public_key_pem)

        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(sig_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    return result.returncode == 0


def _validate_static_fields(envelope: dict[str, Any]) -> None:
    if envelope["version"] != "v0":
        raise EnvelopeVerificationError("unsupported version")

    if not UUID_V7_RE.match(envelope["message_id"]):
        raise EnvelopeVerificationError("message_id must be UUIDv7")

    if not SPIFFE_ID_RE.match(envelope["sender_spiffe_id"]):
        raise EnvelopeVerificationError("invalid sender_spiffe_id")

    if not SPIFFE_ID_RE.match(envelope["recipient_spiffe_id"]):
        raise EnvelopeVerificationError("invalid recipient_spiffe_id")

    if not NONCE_RE.match(envelope["nonce"]):
        raise EnvelopeVerificationError("invalid nonce format")

    if not HEX_SHA256_RE.match(envelope["payload_digest"]):
        raise EnvelopeVerificationError("payload_digest must be hex sha256")

    if envelope["alg"] not in ALLOWED_ALGORITHMS:
        raise EnvelopeVerificationError("algorithm not allowed")


def verify_envelope(
    envelope: dict[str, Any],
    *,
    key_lookup: Callable[[str], bytes],
    replay_cache: ReplayCache,
    config: VerificationConfig = VerificationConfig(),
    now: datetime | None = None,
) -> None:
    required = {
        "version",
        "message_id",
        "sender_spiffe_id",
        "recipient_spiffe_id",
        "issued_at",
        "expires_at",
        "nonce",
        "capability_token",
        "purpose_of_use",
        "kid",
        "alg",
        "payload",
        "payload_digest",
        "signature",
    }

    missing = sorted(required - set(envelope))
    if missing:
        raise EnvelopeVerificationError(f"missing required fields: {','.join(missing)}")

    _validate_static_fields(envelope)

    issued_at = _parse_rfc3339(envelope["issued_at"])
    expires_at = _parse_rfc3339(envelope["expires_at"])
    current = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)

    if issued_at - current > config.max_clock_skew:
        raise EnvelopeVerificationError("issued_at in future beyond skew")
    if current - expires_at > config.max_clock_skew:
        raise EnvelopeVerificationError("envelope expired")
    if expires_at <= issued_at:
        raise EnvelopeVerificationError("invalid validity window")
    if expires_at - issued_at > config.max_envelope_ttl:
        raise EnvelopeVerificationError("envelope ttl exceeds maximum")

    computed_digest = _digest_payload(envelope["payload"])
    if computed_digest != envelope["payload_digest"]:
        raise EnvelopeVerificationError("payload digest mismatch")

    signing_input = canonicalize_envelope_for_signing(envelope)
    public_key_pem = key_lookup(envelope["kid"])

    if envelope["alg"] == "Ed25519" and not _verify_ed25519_signature(
        signing_input,
        envelope["signature"],
        public_key_pem,
    ):
        raise EnvelopeVerificationError("signature invalid")

    sender = envelope["sender_spiffe_id"]
    nonce = envelope["nonce"]
    ttl = max(expires_at - current, timedelta(seconds=0))
    if not replay_cache.mark_if_new(sender, nonce, ttl):
        raise EnvelopeVerificationError("replay detected")
