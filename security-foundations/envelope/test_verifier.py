import base64
import json
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import InMemoryAuditSink
from verifier import VerificationResult, Verifier
from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    _digest_payload,
    canonicalize_envelope_for_signing,
)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ed25519_keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


_ISSUER = "spiffe://mesh/cap-issuer-1"
_ISSUER_KID = "issuer-kid-1"
_SENDER = "spiffe://mesh/ns-a/service-a"
_RECIPIENT = "spiffe://mesh/ns-b/service-b"
_PURPOSE = "invoke_tool"


def _mint_token(issuer_priv_pem: bytes, payload_digest: str, now: datetime) -> str:
    issuer = serialization.load_pem_private_key(issuer_priv_pem, password=None)
    assert isinstance(issuer, Ed25519PrivateKey)
    header = {"alg": "EdDSA", "typ": "wt-cap+jwt", "kid": _ISSUER_KID}
    epoch = int(now.timestamp())
    payload = {
        "iss": _ISSUER,
        "sub": _SENDER,
        "aud": _RECIPIENT,
        "scope": _PURPOSE,
        "iat": epoch - 30,
        "nbf": epoch - 30,
        "exp": epoch + 240,
        "jti": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2",
        "cnf": {"envelope_digest": payload_digest},
    }
    h = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64u(issuer.sign((h + "." + p).encode("ascii")))
    return f"{h}.{p}.{sig}"


def _sign_envelope(envelope: dict, signer_priv_pem: bytes) -> dict:
    signer = serialization.load_pem_private_key(signer_priv_pem, password=None)
    assert isinstance(signer, Ed25519PrivateKey)
    envelope["signature"] = ""
    signing_input = canonicalize_envelope_for_signing(envelope)
    envelope["signature"] = _b64u(signer.sign(signing_input))
    return envelope


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer_priv, cls.signer_pub = _ed25519_keypair()
        cls.issuer_priv, cls.issuer_pub = _ed25519_keypair()

    def _issuer_lookup(self, iss, kid):
        if (iss, kid) != (_ISSUER, _ISSUER_KID):
            raise EnvelopeVerificationError(f"unknown issuer key: iss={iss}, kid={kid}")
        return self.issuer_pub

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
        envelope["capability_token"] = _mint_token(
            self.issuer_priv, envelope["payload_digest"], now
        )
        _sign_envelope(envelope, self.signer_priv)
        return envelope, now

    def _make_verifier(self, *, audit_sink=None) -> Verifier:
        return Verifier(
            key_lookup=lambda kid: self.signer_pub,
            issuer_lookup=self._issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            audit_sink=audit_sink,
        )

    def test_verify_returns_claims_on_success(self):
        envelope, now = self._valid_envelope()
        verifier = self._make_verifier()
        claims = verifier.verify(envelope, now=now)
        self.assertEqual(claims.iss, _ISSUER)
        self.assertEqual(claims.sub, _SENDER)
        self.assertEqual(claims.scope, _PURPOSE)
        self.assertEqual(claims.issuer_kid, _ISSUER_KID)

    def test_verify_raises_on_failure(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "tampered"
        verifier = self._make_verifier()
        with self.assertRaisesRegex(EnvelopeVerificationError, "payload digest"):
            verifier.verify(envelope, now=now)

    def test_try_verify_returns_ok_result(self):
        envelope, now = self._valid_envelope()
        verifier = self._make_verifier()
        result = verifier.try_verify(envelope, now=now)
        self.assertIsInstance(result, VerificationResult)
        self.assertTrue(result.ok)
        self.assertEqual(result.reason, "ok")
        self.assertIsNotNone(result.claims)
        self.assertEqual(result.claims.scope, _PURPOSE)

    def test_try_verify_returns_deny_with_reason(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "tampered"
        verifier = self._make_verifier()
        result = verifier.try_verify(envelope, now=now)
        self.assertFalse(result.ok)
        self.assertIn("payload digest", result.reason)
        self.assertIsNone(result.claims)

    def test_audit_sink_attached_to_verifier_records_events(self):
        sink = InMemoryAuditSink()
        verifier = self._make_verifier(audit_sink=sink)
        envelope, now = self._valid_envelope()
        verifier.verify(envelope, now=now)
        self.assertEqual(len(sink.events), 1)
        self.assertEqual(sink.events[0].outcome, "allow")

    def test_replay_state_shared_across_calls(self):
        envelope, now = self._valid_envelope()
        verifier = self._make_verifier()
        verifier.verify(envelope, now=now)
        with self.assertRaisesRegex(EnvelopeVerificationError, "replay"):
            verifier.verify(envelope, now=now)


if __name__ == "__main__":
    unittest.main()
