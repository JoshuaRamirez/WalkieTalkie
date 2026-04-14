import base64
import hashlib
import hmac
import json
import unittest
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from datetime import datetime, timedelta, timezone

from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    canonicalize_envelope_for_signing,
    verify_envelope,
)


def digest_payload(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def sign(envelope, secret):
    signing_input = canonicalize_envelope_for_signing(envelope)
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


class VerifyEnvelopeTests(unittest.TestCase):
    def _valid_envelope(self):
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
        envelope = {
            "version": "v0",
            "message_id": "123e4567-e89b-12d3-a456-426614174000",
            "sender_spiffe_id": "spiffe://mesh/ns-a/service-a",
            "recipient_spiffe_id": "spiffe://mesh/ns-b/service-b",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "nonce": "nonce-000000000001",
            "capability_token": "cap-token-1",
            "purpose_of_use": "invoke_tool",
            "kid": "dev-kid-1",
            "alg": "HS256",
            "payload": {"tool": "ping", "args": {"target": "node-1"}},
        }
        envelope["payload_digest"] = digest_payload(envelope["payload"])
        envelope["signature"] = ""
        envelope["signature"] = sign(envelope, b"super-secret")
        return envelope, now

    def test_valid_envelope_passes(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()

        verify_envelope(
            envelope,
            key_lookup=lambda kid: b"super-secret",
            replay_cache=replay_cache,
            now=now,
        )

    def test_tampered_payload_fails(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "node-2"

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: b"super-secret",
                replay_cache=InMemoryReplayCache(),
                now=now,
            )

    def test_replay_fails(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()

        verify_envelope(
            envelope,
            key_lookup=lambda kid: b"super-secret",
            replay_cache=replay_cache,
            now=now,
        )

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: b"super-secret",
                replay_cache=replay_cache,
                now=now,
            )

    def test_disallowed_algorithm_fails(self):
        envelope, now = self._valid_envelope()
        envelope["alg"] = "none"

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: b"super-secret",
                replay_cache=InMemoryReplayCache(),
                now=now,
            )


if __name__ == "__main__":
    unittest.main()
