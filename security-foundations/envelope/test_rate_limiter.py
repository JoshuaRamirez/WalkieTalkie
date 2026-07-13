"""Tests for identity-aware rate limiting (Phase 1 D1.5)."""

import base64
import json
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from rate_limiter import (
    IdentityRateLimiter,
    RateLimitedVerifier,
    RateLimitExceededError,
)
from verifier import VerificationResult, Verifier
from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    _digest_payload,
    canonicalize_envelope_for_signing,
)

_SENDER_A = "spiffe://mesh.example/ns-a/svc"
_SENDER_B = "spiffe://mesh.example/ns-b/svc"
_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)


class IdentityRateLimiterConstructionTests(unittest.TestCase):
    def test_zero_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            IdentityRateLimiter(limit=0)

    def test_zero_window_rejected(self):
        with self.assertRaisesRegex(ValueError, "window"):
            IdentityRateLimiter(limit=1, window=timedelta(0))

    def test_override_with_zero_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "override limit"):
            IdentityRateLimiter(limit=10, overrides={_SENDER_A: 0})

    def test_override_with_empty_identity_rejected(self):
        with self.assertRaisesRegex(ValueError, "override identity"):
            IdentityRateLimiter(limit=10, overrides={"": 5})


class IdentityRateLimiterBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.limiter = IdentityRateLimiter(
            limit=3, window=timedelta(seconds=60)
        )

    def test_under_limit_allowed(self):
        for i in range(3):
            d = self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
            self.assertTrue(d.allowed)
            self.assertEqual(d.retry_after_seconds, 0)

    def test_over_limit_throttled(self):
        for i in range(3):
            self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
        d = self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=3))
        self.assertFalse(d.allowed)
        self.assertIn("rate limit exceeded", d.reason)
        self.assertGreater(d.retry_after_seconds, 0)

    def test_sliding_window_re_admits_once_oldest_expires(self):
        for i in range(3):
            self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
        # 61 seconds later the first request has aged out.
        d = self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=61))
        self.assertTrue(d.allowed)

    def test_per_identity_isolation(self):
        for i in range(3):
            self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
        # Sender B is still under its own limit.
        d = self.limiter.check(_SENDER_B, now=_NOW + timedelta(seconds=3))
        self.assertTrue(d.allowed)

    def test_override_raises_per_identity_limit(self):
        limiter = IdentityRateLimiter(
            limit=3, window=timedelta(seconds=60), overrides={_SENDER_A: 10}
        )
        for i in range(10):
            d = limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
            self.assertTrue(d.allowed)
        d = limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=10))
        self.assertFalse(d.allowed)

    def test_override_does_not_affect_other_identities(self):
        limiter = IdentityRateLimiter(
            limit=3, window=timedelta(seconds=60), overrides={_SENDER_A: 100}
        )
        for i in range(3):
            limiter.check(_SENDER_B, now=_NOW + timedelta(seconds=i))
        d = limiter.check(_SENDER_B, now=_NOW + timedelta(seconds=3))
        self.assertFalse(d.allowed)

    def test_reset_drops_bucket(self):
        for i in range(3):
            self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
        self.limiter.reset([_SENDER_A])
        d = self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=3))
        self.assertTrue(d.allowed)

    def test_reset_all_drops_every_bucket(self):
        for i in range(3):
            self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=i))
            self.limiter.check(_SENDER_B, now=_NOW + timedelta(seconds=i))
        self.limiter.reset()
        self.assertTrue(self.limiter.check(_SENDER_A, now=_NOW + timedelta(seconds=4)).allowed)
        self.assertTrue(self.limiter.check(_SENDER_B, now=_NOW + timedelta(seconds=4)).allowed)


# --- Integration: RateLimitedVerifier wraps a real Verifier ---

_ISSUER = "spiffe://mesh.example/cap-issuer-1"
_ISSUER_KID = "issuer-kid-1"
_RECIPIENT = "spiffe://mesh.example/ns-b/svc"
_PURPOSE = "invoke_tool"


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


def _mint_token(issuer_priv_pem: bytes, payload_digest: str, now: datetime) -> str:
    priv = serialization.load_pem_private_key(issuer_priv_pem, password=None)
    assert isinstance(priv, Ed25519PrivateKey)
    header = {"alg": "EdDSA", "typ": "wt-cap+jwt", "kid": _ISSUER_KID}
    epoch = int(now.timestamp())
    payload = {
        "iss": _ISSUER,
        "sub": _SENDER_A,
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
    sig = _b64u(priv.sign((h + "." + p).encode("ascii")))
    return f"{h}.{p}.{sig}"


def _sign_envelope(envelope: dict, signer_priv_pem: bytes) -> dict:
    signer = serialization.load_pem_private_key(signer_priv_pem, password=None)
    assert isinstance(signer, Ed25519PrivateKey)
    envelope["signature"] = ""
    signing_input = canonicalize_envelope_for_signing(envelope)
    envelope["signature"] = _b64u(signer.sign(signing_input))
    return envelope


class RateLimitedVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer_priv, cls.signer_pub = _ed25519_keypair()
        cls.issuer_priv, cls.issuer_pub = _ed25519_keypair()

    def _issuer_lookup(self, iss, kid):
        if (iss, kid) != (_ISSUER, _ISSUER_KID):
            raise EnvelopeVerificationError(f"unknown ({iss}, {kid})")
        return self.issuer_pub

    def _envelope(self, nonce: str = "nonce-000000000001") -> dict:
        envelope = {
            "version": "v0",
            "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
            "sender_spiffe_id": _SENDER_A,
            "recipient_spiffe_id": _RECIPIENT,
            "issued_at": _NOW.isoformat().replace("+00:00", "Z"),
            "expires_at": (_NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "nonce": nonce,
            "purpose_of_use": _PURPOSE,
            "kid": "dev-kid-1",
            "alg": "Ed25519",
            "payload": {"tool": "ping", "args": {"target": "node-1"}},
        }
        envelope["payload_digest"] = _digest_payload(envelope["payload"])
        envelope["capability_token"] = _mint_token(
            self.issuer_priv, envelope["payload_digest"], _NOW
        )
        _sign_envelope(envelope, self.signer_priv)
        return envelope

    def _make_verifier(self) -> Verifier:
        return Verifier(
            key_lookup=lambda kid: self.signer_pub,
            issuer_lookup=self._issuer_lookup,
            replay_cache=InMemoryReplayCache(),
        )

    def test_authentic_throttle(self):
        # Two successful verifies on a limit-1 window: the second is throttled
        # at the rate limiter, *after* the inner verifier has authenticated it
        # (and consumed the replay slot).
        rl_verifier = RateLimitedVerifier(
            inner=self._make_verifier(),
            limiter=IdentityRateLimiter(limit=1, window=timedelta(minutes=5)),
        )
        env = self._envelope()
        rl_verifier.verify(env, now=_NOW)
        env2 = self._envelope(nonce="nonce-000000000002")
        with self.assertRaises(RateLimitExceededError) as ctx:
            rl_verifier.verify(env2, now=_NOW)
        self.assertEqual(ctx.exception.decision.identity, _SENDER_A)

    def test_try_verify_returns_rate_limit_reason(self):
        rl_verifier = RateLimitedVerifier(
            inner=self._make_verifier(),
            limiter=IdentityRateLimiter(limit=1, window=timedelta(minutes=5)),
        )
        env = self._envelope()
        first = rl_verifier.try_verify(env, now=_NOW)
        self.assertTrue(first.ok)

        env2 = self._envelope(nonce="nonce-000000000002")
        second = rl_verifier.try_verify(env2, now=_NOW)
        self.assertIsInstance(second, VerificationResult)
        self.assertFalse(second.ok)
        self.assertIn("rate limit exceeded", second.reason)

    def test_rate_limit_error_is_envelope_verification_error(self):
        # Callers that catch EnvelopeVerificationError also catch
        # RateLimitExceededError without special-casing.
        rl_verifier = RateLimitedVerifier(
            inner=self._make_verifier(),
            limiter=IdentityRateLimiter(limit=1, window=timedelta(minutes=5)),
        )
        rl_verifier.verify(self._envelope(), now=_NOW)
        env2 = self._envelope(nonce="nonce-000000000002")
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            rl_verifier.verify(env2, now=_NOW)
        self.assertEqual(ctx.exception.reason_code, "rate_limited")

    def test_forged_signature_does_not_burn_victims_allowance(self):
        # Hardening: rate limiter MUST run after signature verification so an
        # attacker cannot DoS a workload by sending envelopes that *claim* the
        # victim's sender_spiffe_id but fail signature.
        rl_verifier = RateLimitedVerifier(
            inner=self._make_verifier(),
            limiter=IdentityRateLimiter(limit=1, window=timedelta(minutes=5)),
        )
        env = self._envelope()
        # Tamper with the signature: still claims sender=_SENDER_A but signature
        # is invalid. The inner verifier rejects → limiter never sees the call.
        env["signature"] = "A" * 86  # well-formed base64url, wrong bytes
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            rl_verifier.verify(env, now=_NOW)
        self.assertNotEqual(ctx.exception.reason_code, "rate_limited")

        # The legitimate sender's allowance is intact — a real envelope from
        # _SENDER_A should still succeed.
        legit = self._envelope(nonce="nonce-000000000099")
        rl_verifier.verify(legit, now=_NOW)


if __name__ == "__main__":
    unittest.main()
