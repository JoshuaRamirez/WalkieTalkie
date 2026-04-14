"""Reference envelope verification utilities for Phase 0 bootstrap."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


ALLOWED_ALGORITHMS = {"HS256"}


class EnvelopeVerificationError(ValueError):
    """Raised when envelope verification fails."""


@dataclass(frozen=True)
class VerificationConfig:
    max_clock_skew: timedelta = timedelta(seconds=60)


class ReplayCache:
    """Minimal replay cache interface."""

    def seen(self, sender: str, nonce: str) -> bool:
        raise NotImplementedError

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        raise NotImplementedError


class InMemoryReplayCache(ReplayCache):
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], datetime] = {}

    def _purge(self, now: datetime) -> None:
        expired = [k for k, v in self._entries.items() if v <= now]
        for key in expired:
            del self._entries[key]

    def seen(self, sender: str, nonce: str) -> bool:
        now = datetime.now(timezone.utc)
        self._purge(now)
        return (sender, nonce) in self._entries

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        now = datetime.now(timezone.utc)
        self._entries[(sender, nonce)] = now + ttl


def _parse_rfc3339(value: str) -> datetime:
    candidate = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(candidate)
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


def _verify_hs256_signature(signing_input: bytes, signature: str, secret: bytes) -> bool:
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(encoded, signature)


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

    if envelope["version"] != "v0":
        raise EnvelopeVerificationError("unsupported version")

    alg = envelope["alg"]
    if alg not in ALLOWED_ALGORITHMS:
        raise EnvelopeVerificationError("algorithm not allowed")

    issued_at = _parse_rfc3339(envelope["issued_at"])
    expires_at = _parse_rfc3339(envelope["expires_at"])
    current = now.astimezone(timezone.utc) if now else datetime.now(timezone.utc)

    if issued_at - current > config.max_clock_skew:
        raise EnvelopeVerificationError("issued_at in future beyond skew")
    if current - expires_at > config.max_clock_skew:
        raise EnvelopeVerificationError("envelope expired")
    if expires_at <= issued_at:
        raise EnvelopeVerificationError("invalid validity window")

    sender = envelope["sender_spiffe_id"]
    nonce = envelope["nonce"]
    if replay_cache.seen(sender, nonce):
        raise EnvelopeVerificationError("replay detected")

    computed_digest = _digest_payload(envelope["payload"])
    if computed_digest != envelope["payload_digest"]:
        raise EnvelopeVerificationError("payload digest mismatch")

    signing_input = canonicalize_envelope_for_signing(envelope)

    kid = envelope["kid"]
    secret = key_lookup(kid)
    if alg == "HS256" and not _verify_hs256_signature(signing_input, envelope["signature"], secret):
        raise EnvelopeVerificationError("signature invalid")

    ttl = max(expires_at - current, timedelta(seconds=0))
    replay_cache.mark(sender, nonce, ttl)
