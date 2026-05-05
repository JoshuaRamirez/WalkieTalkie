import base64
import pathlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import InMemoryAuditSink, verify_chain
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


def mint_capability_token(
    *,
    issuer_priv_pem: bytes,
    issuer_kid: str,
    iss: str,
    sub: str,
    aud: str,
    scope: str,
    payload_digest: str,
    now: datetime,
    ttl_seconds: int = 240,
) -> str:
    """Test helper that wraps CapabilityIssuer for fixture-style use."""
    from capability_issuer import CapabilityIssuer

    issuer_priv = serialization.load_pem_private_key(issuer_priv_pem, password=None)
    assert isinstance(issuer_priv, Ed25519PrivateKey)
    issuer = CapabilityIssuer(
        iss=iss,
        kid=issuer_kid,
        signing_key=issuer_priv,
        default_ttl=timedelta(seconds=ttl_seconds),
        clock_skew=timedelta(seconds=30),
    )
    return issuer.issue(
        sub=sub,
        aud=aud,
        scope=scope,
        envelope_digest=payload_digest,
        jti="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2",
        now=now,
    )


_ISSUER_IDENTITY = "spiffe://mesh/cap-issuer-1"
_ISSUER_KID = "issuer-kid-1"
_SENDER = "spiffe://mesh/ns-a/service-a"
_RECIPIENT = "spiffe://mesh/ns-b/service-b"
_PURPOSE = "invoke_tool"


class VerifyEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer_priv_pem, cls.signer_pub_pem = generate_ed25519_keypair()
        cls.issuer_priv_pem, cls.issuer_pub_pem = generate_ed25519_keypair()

    def issuer_lookup(self, iss, kid):
        if (iss, kid) != (_ISSUER_IDENTITY, _ISSUER_KID):
            raise EnvelopeVerificationError(f"unknown issuer key: iss={iss}, kid={kid}")
        return self.issuer_pub_pem

    def _valid_envelope(self):
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        envelope = {
            "version": "v0",
            "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
            "sender_spiffe_id": _SENDER,
            "recipient_spiffe_id": _RECIPIENT,
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "nonce": "nonce-000000000001",
            "purpose_of_use": _PURPOSE,
            "kid": "dev-kid-1",
            "alg": "Ed25519",
            "payload": {"tool": "ping", "args": {"target": "node-1"}},
        }
        envelope["payload_digest"] = _digest_payload(envelope["payload"])
        envelope["capability_token"] = mint_capability_token(
            issuer_priv_pem=self.issuer_priv_pem,
            issuer_kid=_ISSUER_KID,
            iss=_ISSUER_IDENTITY,
            sub=_SENDER,
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest=envelope["payload_digest"],
            now=now,
        )
        envelope["signature"] = ""
        signing_input = canonicalize_envelope_for_signing(envelope)
        envelope["signature"] = sign(signing_input, self.signer_priv_pem)
        return envelope, now

    def _verify(self, envelope, now, *, replay_cache=None, key_lookup=None, issuer_lookup=None):
        verify_envelope(
            envelope,
            key_lookup=key_lookup or (lambda kid: self.signer_pub_pem),
            issuer_lookup=issuer_lookup or self.issuer_lookup,
            replay_cache=replay_cache or InMemoryReplayCache(),
            now=now,
        )

    def test_valid_envelope_passes(self):
        envelope, now = self._valid_envelope()
        self._verify(envelope, now)

    def test_tampered_payload_fails(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "node-2"
        with self.assertRaises(EnvelopeVerificationError):
            self._verify(envelope, now)

    def test_replay_fails(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()
        self._verify(envelope, now, replay_cache=replay_cache)
        with self.assertRaises(EnvelopeVerificationError):
            self._verify(envelope, now, replay_cache=replay_cache)

    def test_sqlite_replay_cache_detects_replay_across_instances(self):
        envelope, now = self._valid_envelope()
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(pathlib.Path(tmp) / "replay.db")
            cache_a = SQLiteReplayCache(db_path)
            cache_b = SQLiteReplayCache(db_path)
            self._verify(envelope, now, replay_cache=cache_a)
            with self.assertRaises(EnvelopeVerificationError):
                self._verify(envelope, now, replay_cache=cache_b)

    def test_invalid_signature_does_not_reserve_nonce(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()

        invalid = dict(envelope)
        invalid["signature"] = "A" * 86

        with self.assertRaises(EnvelopeVerificationError):
            self._verify(invalid, now, replay_cache=replay_cache)

        # Original valid envelope must still pass after the failed attempt;
        # asserts the nonce was NOT reserved.
        self._verify(envelope, now, replay_cache=replay_cache)

    def test_capability_failure_does_not_reserve_nonce(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()

        # Mutate the token after envelope is signed; envelope sig still
        # valid but cap validation fails.
        bad = dict(envelope)
        bad["capability_token"] = bad["capability_token"][:-4] + "XXXX"
        # Re-sign envelope with the mutated token (so envelope signature
        # passes and we definitely fail at capability validation, not earlier).
        unsigned = {k: v for k, v in bad.items() if k != "signature"}
        bad["signature"] = sign(
            canonicalize_envelope_for_signing({**unsigned, "signature": ""}),
            self.signer_priv_pem,
        )
        with self.assertRaises(EnvelopeVerificationError):
            self._verify(bad, now, replay_cache=replay_cache)

        # Original valid envelope must still pass — nonce wasn't reserved.
        self._verify(envelope, now, replay_cache=replay_cache)

    def test_envelope_signing_key_cannot_sign_capability(self):
        # Mint a token signed by the envelope-signing private key. The
        # IssuerTrustStore (here: a stub) only knows the real issuer key,
        # so the (iss=cap-issuer, kid=dev-kid-1) lookup must miss.
        envelope, now = self._valid_envelope()
        rogue_token = mint_capability_token(
            issuer_priv_pem=self.signer_priv_pem,
            issuer_kid="dev-kid-1",
            iss=_ISSUER_IDENTITY,
            sub=_SENDER,
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest=envelope["payload_digest"],
            now=now,
        )
        envelope["capability_token"] = rogue_token
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        envelope["signature"] = sign(
            canonicalize_envelope_for_signing({**unsigned, "signature": ""}),
            self.signer_priv_pem,
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "unknown issuer key"):
            self._verify(envelope, now)

    def test_disallowed_algorithm_fails(self):
        envelope, now = self._valid_envelope()
        envelope["alg"] = "HS256"
        with self.assertRaises(EnvelopeVerificationError):
            self._verify(envelope, now)

    def test_non_ed25519_key_rejected(self):
        envelope, now = self._valid_envelope()
        rsa_key = generate_rsa_private_key(public_exponent=65537, key_size=2048)
        rsa_pub_pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaises(EnvelopeVerificationError):
            self._verify(envelope, now, key_lookup=lambda kid: rsa_pub_pem)

    def test_verify_with_filesystem_trust_store(self):
        envelope, now = self._valid_envelope()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "dev-kid-1.pem").write_bytes(self.signer_pub_pem)
            store = FileSystemTrustStore.from_directory(tmp_path)
            self._verify(envelope, now, key_lookup=store)

    def test_uuid_v7_required(self):
        envelope, now = self._valid_envelope()
        envelope["message_id"] = "123e4567-e89b-12d3-a456-426614174000"
        with self.assertRaises(EnvelopeVerificationError):
            self._verify(envelope, now)

    def test_invalid_kid_format_rejected(self):
        for bad_kid in ("", "../etc/passwd", "kid with space", "a" * 200, "kid\n"):
            with self.subTest(bad_kid=bad_kid):
                envelope, now = self._valid_envelope()
                envelope["kid"] = bad_kid
                with self.assertRaises(EnvelopeVerificationError):
                    self._verify(envelope, now)

    def test_capability_wrong_sub_rejected(self):
        envelope, now = self._valid_envelope()
        envelope["capability_token"] = mint_capability_token(
            issuer_priv_pem=self.issuer_priv_pem,
            issuer_kid=_ISSUER_KID,
            iss=_ISSUER_IDENTITY,
            sub="spiffe://mesh/ns-x/service-x",
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest=envelope["payload_digest"],
            now=now,
        )
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        envelope["signature"] = sign(
            canonicalize_envelope_for_signing({**unsigned, "signature": ""}),
            self.signer_priv_pem,
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "sub does not match"):
            self._verify(envelope, now)

    def test_capability_wrong_envelope_digest_rejected(self):
        envelope, now = self._valid_envelope()
        envelope["capability_token"] = mint_capability_token(
            issuer_priv_pem=self.issuer_priv_pem,
            issuer_kid=_ISSUER_KID,
            iss=_ISSUER_IDENTITY,
            sub=_SENDER,
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest="0" * 64,
            now=now,
        )
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        envelope["signature"] = sign(
            canonicalize_envelope_for_signing({**unsigned, "signature": ""}),
            self.signer_priv_pem,
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "envelope_digest does not match"):
            self._verify(envelope, now)

    def test_audit_sink_records_allow_event_on_success(self):
        envelope, now = self._valid_envelope()
        sink = InMemoryAuditSink()
        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.signer_pub_pem,
            issuer_lookup=self.issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            now=now,
            audit_sink=sink,
        )
        self.assertEqual(len(sink.events), 1)
        event = sink.events[0]
        self.assertEqual(event.event_type, "envelope.verify")
        self.assertEqual(event.outcome, "allow")
        self.assertEqual(event.reason, "ok")
        self.assertEqual(event.message_id, envelope["message_id"])
        self.assertEqual(event.sender, _SENDER)
        self.assertEqual(event.recipient, _RECIPIENT)
        self.assertEqual(event.envelope_kid, "dev-kid-1")
        self.assertEqual(event.issuer_iss, _ISSUER_IDENTITY)
        self.assertEqual(event.issuer_kid, _ISSUER_KID)

    def test_audit_sink_records_deny_event_on_failure(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "tampered"
        sink = InMemoryAuditSink()
        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.signer_pub_pem,
                issuer_lookup=self.issuer_lookup,
                replay_cache=InMemoryReplayCache(),
                now=now,
                audit_sink=sink,
            )
        self.assertEqual(len(sink.events), 1)
        event = sink.events[0]
        self.assertEqual(event.outcome, "deny")
        self.assertEqual(event.reason, "payload digest mismatch")
        self.assertEqual(event.message_id, envelope["message_id"])

    def test_audit_chain_holds_across_verifications(self):
        envelope, now = self._valid_envelope()
        sink = InMemoryAuditSink()

        # One success, one tampered failure, one success — each must chain.
        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.signer_pub_pem,
            issuer_lookup=self.issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            now=now,
            audit_sink=sink,
        )

        bad = dict(envelope)
        bad["payload"] = {"tool": "ping", "args": {"target": "tampered"}}
        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                bad,
                key_lookup=lambda kid: self.signer_pub_pem,
                issuer_lookup=self.issuer_lookup,
                replay_cache=InMemoryReplayCache(),
                now=now,
                audit_sink=sink,
            )

        envelope2, _ = self._valid_envelope()
        envelope2["nonce"] = "nonce-000000000002"
        envelope2["message_id"] = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c3"
        envelope2["payload_digest"] = _digest_payload(envelope2["payload"])
        envelope2["capability_token"] = mint_capability_token(
            issuer_priv_pem=self.issuer_priv_pem,
            issuer_kid=_ISSUER_KID,
            iss=_ISSUER_IDENTITY,
            sub=_SENDER,
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest=envelope2["payload_digest"],
            now=now,
        )
        unsigned = {k: v for k, v in envelope2.items() if k != "signature"}
        envelope2["signature"] = sign(
            canonicalize_envelope_for_signing({**unsigned, "signature": ""}),
            self.signer_priv_pem,
        )
        verify_envelope(
            envelope2,
            key_lookup=lambda kid: self.signer_pub_pem,
            issuer_lookup=self.issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            now=now,
            audit_sink=sink,
        )

        self.assertEqual(len(sink.events), 3)
        self.assertEqual([e.outcome for e in sink.events], ["allow", "deny", "allow"])
        verify_chain(sink.events)

    def test_envelope_with_revoked_token_rejected(self):
        from revocation_list import InMemoryRevocationList

        envelope, now = self._valid_envelope()
        # mint_capability_token bakes this jti into the cap token.
        rl = InMemoryRevocationList(["0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2"])
        with self.assertRaisesRegex(EnvelopeVerificationError, "revoked"):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.signer_pub_pem,
                issuer_lookup=self.issuer_lookup,
                replay_cache=InMemoryReplayCache(),
                now=now,
                revocation_list=rl,
            )

    def test_envelope_revocation_failure_does_not_reserve_nonce(self):
        from revocation_list import InMemoryRevocationList

        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()
        rl = InMemoryRevocationList(["0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2"])

        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.signer_pub_pem,
                issuer_lookup=self.issuer_lookup,
                replay_cache=replay_cache,
                now=now,
                revocation_list=rl,
            )

        # Same envelope must still verify when revocation is dropped — proves
        # the nonce was NOT reserved during the revoked attempt.
        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.signer_pub_pem,
            issuer_lookup=self.issuer_lookup,
            replay_cache=replay_cache,
            now=now,
        )


class CanonicalizationSemanticsTests(unittest.TestCase):
    def test_int_and_float_collide_under_jcs(self):
        self.assertEqual(_digest_payload({"a": 1.0}), _digest_payload({"a": 1}))

    def test_unicode_normalization_is_not_applied(self):
        precomposed = "café"
        decomposed = "café"
        self.assertNotEqual(
            _digest_payload({"k": precomposed}),
            _digest_payload({"k": decomposed}),
        )


if __name__ == "__main__":
    unittest.main()
