"""Tests for the deterministic-error-contract surface.

Phase 1 Track B B3 acceptance criterion: "Security-deny responses are
machine-readable and auditable. No ambiguous errors that could cause insecure
fallback." This file pins:

- Every ``EnvelopeVerificationError`` raised by the verification path carries
  a non-empty ``reason_code`` (i.e., a :class:`DenyReason` value).
- ``DenyReason`` values are unique snake_case identifiers — no two enum members
  share a string form.
- The audit event for a denied verify_envelope call carries the matching
  ``reason_code``.
"""

import json
import pathlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import InMemoryAuditSink
from capability_token import verify_capability_token
from deny_reason import DenyReason
from issuer_trust_store import IssuerTrustStore
from revocation_list import InMemoryRevocationList
from trust_store import FileSystemTrustStore
from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    _digest_payload,
    canonicalize_envelope_for_signing,
    verify_envelope,
)


class DenyReasonEnumTests(unittest.TestCase):
    def test_values_are_unique(self):
        values = [r.value for r in DenyReason]
        self.assertEqual(len(values), len(set(values)))

    def test_values_are_snake_case_lowercase(self):
        for r in DenyReason:
            self.assertEqual(r.value, r.value.lower())
            self.assertNotIn(" ", r.value)
            self.assertNotIn("-", r.value)

    def test_str_round_trip(self):
        # StrEnum: each value behaves as its string form.
        self.assertEqual(str(DenyReason.REPLAY_DETECTED), "replay_detected")


class ExceptionContractTests(unittest.TestCase):
    def test_default_reason_is_none(self):
        exc = EnvelopeVerificationError("legacy error")
        self.assertIsNone(exc.reason)
        self.assertEqual(exc.reason_code, "")

    def test_explicit_reason_round_trips(self):
        exc = EnvelopeVerificationError("x", reason=DenyReason.SIGNATURE_INVALID)
        self.assertIs(exc.reason, DenyReason.SIGNATURE_INVALID)
        self.assertEqual(exc.reason_code, "signature_invalid")


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


def _b64u(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_ISSUER = "spiffe://mesh/cap-issuer-1"
_ISSUER_KID = "issuer-kid-1"
_SENDER = "spiffe://mesh/ns-a/service-a"
_RECIPIENT = "spiffe://mesh/ns-b/service-b"
_PURPOSE = "invoke_tool"


def _mint_token(
    issuer_priv_pem: bytes,
    payload_digest: str,
    now: datetime,
    *,
    payload_overrides: dict | None = None,
) -> str:
    issuer_priv = serialization.load_pem_private_key(issuer_priv_pem, password=None)
    assert isinstance(issuer_priv, Ed25519PrivateKey)
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
    if payload_overrides:
        payload = {**payload, **payload_overrides}
    h = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64u(issuer_priv.sign((h + "." + p).encode("ascii")))
    return f"{h}.{p}.{sig}"


def _sign_envelope(envelope: dict, signer_priv_pem: bytes) -> dict:
    signer = serialization.load_pem_private_key(signer_priv_pem, password=None)
    assert isinstance(signer, Ed25519PrivateKey)
    envelope["signature"] = ""
    signing_input = canonicalize_envelope_for_signing(envelope)
    envelope["signature"] = _b64u(signer.sign(signing_input))
    return envelope


class CapabilityTokenReasonCodeTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _ed25519_keypair()
        self.envelope = {
            "sender_spiffe_id": _SENDER,
            "recipient_spiffe_id": _RECIPIENT,
            "purpose_of_use": _PURPOSE,
            "payload_digest": "94fabd33a2221b6d3986e8d5ba98d75a91dcdad9b978ac7ea70bbc996fb2bb45",
        }
        self.now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)

    def _verify(self, token: str, **kwargs) -> None:
        verify_capability_token(
            token,
            envelope=self.envelope,
            issuer_lookup=lambda iss, kid: self.pem,
            current=self.now,
            max_clock_skew=timedelta(seconds=60),
            max_capability_ttl=timedelta(minutes=5),
            **kwargs,
        )

    def _expect_reason(self, expected: DenyReason, fn) -> None:
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            fn()
        self.assertEqual(ctx.exception.reason, expected)
        self.assertEqual(ctx.exception.reason_code, expected.value)

    def test_oversized_token(self):
        self._expect_reason(DenyReason.CAP_OVERSIZED, lambda: self._verify("a" * 9999))

    def test_three_segments_required(self):
        self._expect_reason(DenyReason.CAP_MALFORMED, lambda: self._verify("a.b"))

    def test_wrong_alg(self):
        token = _mint_token(self.priv, self.envelope["payload_digest"], self.now)
        # Replace the header's alg by remixing — easier to just hand-build.
        bad_header = {"alg": "none", "typ": "wt-cap+jwt", "kid": _ISSUER_KID}
        h = _b64u(json.dumps(bad_header, separators=(",", ":")).encode())
        _, p, _ = token.split(".")
        sig = _b64u(b"\x00" * 64)
        self._expect_reason(
            DenyReason.CAP_WRONG_ALG, lambda: self._verify(f"{h}.{p}.{sig}")
        )

    def test_sub_mismatch(self):
        token = _mint_token(
            self.priv, self.envelope["payload_digest"], self.now,
            payload_overrides={"sub": "spiffe://mesh/ns-z/other"},
        )
        self._expect_reason(DenyReason.CAP_SUB_MISMATCH, lambda: self._verify(token))

    def test_digest_mismatch(self):
        token = _mint_token(self.priv, "0" * 64, self.now)
        self._expect_reason(DenyReason.CAP_DIGEST_MISMATCH, lambda: self._verify(token))

    def test_revoked(self):
        token = _mint_token(self.priv, self.envelope["payload_digest"], self.now)
        rl = InMemoryRevocationList(["0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2"])
        self._expect_reason(
            DenyReason.CAP_REVOKED,
            lambda: self._verify(token, revocation_list=rl),
        )


class EnvelopeReasonCodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer_priv, cls.signer_pub = _ed25519_keypair()
        cls.issuer_priv, cls.issuer_pub = _ed25519_keypair()

    def _issuer_lookup(self, iss, kid):
        if (iss, kid) != (_ISSUER, _ISSUER_KID):
            raise EnvelopeVerificationError(
                f"unknown issuer key: iss={iss}, kid={kid}",
                reason=DenyReason.UNKNOWN_ISSUER_KEY,
            )
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

    def _verify(self, envelope, now, **kwargs):
        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.signer_pub,
            issuer_lookup=self._issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            now=now,
            **kwargs,
        )

    def test_payload_digest_mismatch_reason(self):
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "tampered"
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            self._verify(envelope, now)
        self.assertIs(ctx.exception.reason, DenyReason.PAYLOAD_DIGEST_MISMATCH)

    def test_disallowed_algorithm_reason(self):
        envelope, now = self._valid_envelope()
        envelope["alg"] = "HS256"
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            self._verify(envelope, now)
        self.assertIs(ctx.exception.reason, DenyReason.DISALLOWED_ALGORITHM)

    def test_replay_reason(self):
        envelope, now = self._valid_envelope()
        replay_cache = InMemoryReplayCache()
        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.signer_pub,
            issuer_lookup=self._issuer_lookup,
            replay_cache=replay_cache,
            now=now,
        )
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.signer_pub,
                issuer_lookup=self._issuer_lookup,
                replay_cache=replay_cache,
                now=now,
            )
        self.assertIs(ctx.exception.reason, DenyReason.REPLAY_DETECTED)

    def test_audit_event_carries_reason_code_on_deny(self):
        # Pre-cap deny: only envelope.verify is emitted.
        envelope, now = self._valid_envelope()
        envelope["payload"]["args"]["target"] = "tampered"
        sink = InMemoryAuditSink()
        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope,
                key_lookup=lambda kid: self.signer_pub,
                issuer_lookup=self._issuer_lookup,
                replay_cache=InMemoryReplayCache(),
                now=now,
                audit_sink=sink,
            )
        self.assertEqual(len(sink.events), 1)
        self.assertEqual(sink.events[0].event_type, "envelope.verify")
        self.assertEqual(sink.events[0].outcome, "deny")
        self.assertEqual(
            sink.events[0].reason_code, DenyReason.PAYLOAD_DIGEST_MISMATCH.value
        )
        self.assertEqual(sink.events[0].artifact_version, "envelope/v0")

    def test_audit_event_reason_code_on_allow(self):
        envelope, now = self._valid_envelope()
        sink = InMemoryAuditSink()
        verify_envelope(
            envelope,
            key_lookup=lambda kid: self.signer_pub,
            issuer_lookup=self._issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            now=now,
            audit_sink=sink,
        )
        # Successful verify emits cap.verify allow then envelope.verify allow.
        self.assertEqual([e.event_type for e in sink.events], ["capability.verify", "envelope.verify"])
        self.assertEqual([e.reason_code for e in sink.events], ["ok", "ok"])
        self.assertEqual(sink.events[0].artifact_version, "wt-cap+jwt")
        self.assertEqual(sink.events[1].artifact_version, "envelope/v0")

    def test_unknown_issuer_kid_reason(self):
        envelope, now = self._valid_envelope()
        # Mint a token with an iss the lookup doesn't know.
        envelope["capability_token"] = _mint_token(
            self.issuer_priv,
            envelope["payload_digest"],
            now,
            payload_overrides={"iss": "spiffe://mesh/cap-issuer-other"},
        )
        _sign_envelope(envelope, self.signer_priv)
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            self._verify(envelope, now)
        self.assertIs(ctx.exception.reason, DenyReason.UNKNOWN_ISSUER_KEY)


class TrustStoreReasonCodeTests(unittest.TestCase):
    def test_filesystem_unknown_kid_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            priv, pub = _ed25519_keypair()
            (tmp_path / "kid-1.pem").write_bytes(pub)
            store = FileSystemTrustStore.from_directory(tmp_path)
            with self.assertRaises(EnvelopeVerificationError) as ctx:
                store("missing")
            self.assertIs(ctx.exception.reason, DenyReason.UNKNOWN_KID)

    def test_issuer_unknown_kid_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            priv, pub = _ed25519_keypair()
            (tmp_path / "k.pem").write_bytes(pub)
            manifest = tmp_path / "manifest.json"
            manifest.write_text(
                json.dumps({"keys": [{"iss": _ISSUER, "kid": _ISSUER_KID, "pem_path": "k.pem"}]})
            )
            store = IssuerTrustStore.from_manifest(manifest)
            with self.assertRaises(EnvelopeVerificationError) as ctx:
                store("spiffe://mesh/other", "x")
            self.assertIs(ctx.exception.reason, DenyReason.UNKNOWN_ISSUER_KEY)


if __name__ == "__main__":
    unittest.main()
