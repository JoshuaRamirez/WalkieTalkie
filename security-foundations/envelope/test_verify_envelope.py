import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    SQLiteReplayCache,
    canonicalize_envelope_for_signing,
    verify_envelope,
)


def digest_payload(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def generate_ed25519_keypair():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        priv = tmp_path / "private.pem"
        pub = tmp_path / "public.pem"

        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv)], check=True)
        subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True)

        return priv.read_bytes(), pub.read_bytes()


def sign(signing_input: bytes, private_key_pem: bytes):
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        message = tmp_path / "message.bin"
        signature = tmp_path / "signature.bin"
        priv = tmp_path / "private.pem"

        message.write_bytes(signing_input)
        priv.write_bytes(private_key_pem)

        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(priv),
                "-rawin",
                "-in",
                str(message),
                "-out",
                str(signature),
            ],
            check=True,
        )

        return base64.urlsafe_b64encode(signature.read_bytes()).rstrip(b"=").decode("ascii")


class VerifyEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key_pem, cls.public_key_pem = generate_ed25519_keypair()

    def _valid_envelope(self):
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)
        envelope = {
            "version": "v0",
            "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
            "sender_spiffe_id": "spiffe://mesh/ns-a/service-a",
            "recipient_spiffe_id": "spiffe://mesh/ns-b/service-b",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "nonce": "nonce-000000000001",
            "capability_token": "cap-token-1",
            "purpose_of_use": "invoke_tool",
            "kid": "dev-kid-1",
            "alg": "Ed25519",
            "payload": {"tool": "ping", "args": {"target": "node-1"}},
        }
        envelope["payload_digest"] = digest_payload(envelope["payload"])
        envelope["signature"] = ""
        signing_input = canonicalize_envelope_for_signing(envelope)
        envelope["signature"] = sign(signing_input, self.private_key_pem)
        return envelope, now

    def test_valid_envelope_passes(self):
        envelope, now = self._valid_envelope()

        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.public_key_pem,
            replay_cache=InMemoryReplayCache(),
            now=now,
        )

    def test_tampered_payload_fails(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "node-2"

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.public_key_pem,
                replay_cache=InMemoryReplayCache(),
                now=now,
            )

    def test_replay_fails(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()

        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.public_key_pem,
            replay_cache=replay_cache,
            now=now,
        )

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.public_key_pem,
                replay_cache=replay_cache,
                now=now,
            )

    def test_sqlite_replay_cache_detects_replay_across_instances(self):
        envelope, now = self._valid_envelope()
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(pathlib.Path(tmp) / "replay.db")
            cache_a = SQLiteReplayCache(db_path)
            cache_b = SQLiteReplayCache(db_path)

            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.public_key_pem,
                replay_cache=cache_a,
                now=now,
            )

            with self.assertRaises(EnvelopeVerificationError):
                verify_envelope(
                    envelope,
                    key_lookup=lambda kid: self.public_key_pem,
                    replay_cache=cache_b,
                    now=now,
                )

    def test_invalid_signature_does_not_reserve_nonce(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()

        invalid = dict(envelope)
        invalid["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                invalid,
                key_lookup=lambda kid: self.public_key_pem,
                replay_cache=replay_cache,
                now=now,
            )

        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.public_key_pem,
            replay_cache=replay_cache,
            now=now,
        )

    def test_disallowed_algorithm_fails(self):
        envelope, now = self._valid_envelope()
        envelope["alg"] = "HS256"

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.public_key_pem,
                replay_cache=InMemoryReplayCache(),
                now=now,
            )

    def test_uuid_v7_required(self):
        envelope, now = self._valid_envelope()
        envelope["message_id"] = "123e4567-e89b-12d3-a456-426614174000"

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.public_key_pem,
                replay_cache=InMemoryReplayCache(),
                now=now,
            )


if __name__ == "__main__":
    unittest.main()
