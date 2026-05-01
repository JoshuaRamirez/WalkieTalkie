import base64
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from trust_store import FileSystemTrustStore
from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    SQLiteReplayCache,
    _digest_payload,
    canonicalize_envelope_for_signing,
    verify_envelope,
)


def generate_ed25519_keypair():
    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def sign(signing_input: bytes, private_key_pem: bytes):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(private_key, Ed25519PrivateKey)
    return base64.urlsafe_b64encode(private_key.sign(signing_input)).rstrip(b"=").decode("ascii")


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
        envelope["payload_digest"] = _digest_payload(envelope["payload"])
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
        invalid["signature"] = "A" * 86

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

    def test_non_ed25519_key_rejected(self):
        envelope, now = self._valid_envelope()
        rsa_key = generate_rsa_private_key(public_exponent=65537, key_size=2048)
        rsa_pub_pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: rsa_pub_pem,
                replay_cache=InMemoryReplayCache(),
                now=now,
            )

    def test_verify_with_filesystem_trust_store(self):
        envelope, now = self._valid_envelope()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "dev-kid-1.pem").write_bytes(self.public_key_pem)
            store = FileSystemTrustStore.from_directory(tmp_path)
            verify_envelope(
                envelope,
                key_lookup=store,
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

    def test_invalid_kid_format_rejected(self):
        for bad_kid in ("", "../etc/passwd", "kid with space", "a" * 200, "kid\n"):
            with self.subTest(bad_kid=bad_kid):
                envelope, now = self._valid_envelope()
                envelope["kid"] = bad_kid
                with self.assertRaises(EnvelopeVerificationError):
                    verify_envelope(
                        envelope,
                        key_lookup=lambda kid: self.public_key_pem,
                        replay_cache=InMemoryReplayCache(),
                        now=now,
                    )


class CanonicalizationSemanticsTests(unittest.TestCase):
    def test_int_and_float_collide_under_jcs(self):
        self.assertEqual(_digest_payload({"a": 1.0}), _digest_payload({"a": 1}))

    def test_unicode_normalization_is_not_applied(self):
        precomposed = "caf\u00e9"
        decomposed = "cafe\u0301"
        self.assertNotEqual(
            _digest_payload({"k": precomposed}),
            _digest_payload({"k": decomposed}),
        )


if __name__ == "__main__":
    unittest.main()
