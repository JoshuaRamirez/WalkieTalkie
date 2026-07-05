"""Tests for peer admission (Phase 5 Track A A3)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from peer_admission import (
    AdmissionRule,
    PeerAdmissionDenied,
    PeerAdmissionError,
    PeerAdmissionPolicy,
    admit_peer,
    public_key_fingerprint,
    require_admission,
)

_PROD_PEER = "spiffe://mesh.example/ns-a/agent-1"
_UNKNOWN_PEER = "spiffe://mesh.example/ns-z/stranger"


class RuleValidationTests(unittest.TestCase):
    def test_invalid_spiffe_rejected(self):
        with self.assertRaisesRegex(PeerAdmissionError, "spiffe_id"):
            AdmissionRule(spiffe_id="nope", env_tier="prod")

    def test_empty_tier_rejected(self):
        with self.assertRaisesRegex(PeerAdmissionError, "env_tier"):
            AdmissionRule(spiffe_id=_PROD_PEER, env_tier="")

    def test_bad_pin_rejected(self):
        with self.assertRaisesRegex(PeerAdmissionError, "pinned_fingerprint"):
            AdmissionRule(
                spiffe_id=_PROD_PEER, env_tier="prod", pinned_fingerprint="short"
            )


class PolicyValidationTests(unittest.TestCase):
    def test_duplicate_rule_rejected(self):
        rule = AdmissionRule(spiffe_id=_PROD_PEER, env_tier="prod")
        with self.assertRaisesRegex(PeerAdmissionError, "duplicate"):
            PeerAdmissionPolicy(rules=(rule, rule))

    def test_same_identity_different_tiers_allowed(self):
        # Not a duplicate — different env tier.
        PeerAdmissionPolicy(
            rules=(
                AdmissionRule(spiffe_id=_PROD_PEER, env_tier="prod"),
                AdmissionRule(spiffe_id=_PROD_PEER, env_tier="staging"),
            )
        )


class AdmissionTests(unittest.TestCase):
    def _policy(self):
        return PeerAdmissionPolicy(
            rules=(AdmissionRule(spiffe_id=_PROD_PEER, env_tier="prod"),)
        )

    def test_deny_by_default(self):
        decision = admit_peer(
            spiffe_id=_UNKNOWN_PEER, env_tier="prod", policy=self._policy()
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "admission_peer_not_allowed")

    def test_allowlisted_peer_admitted(self):
        decision = admit_peer(
            spiffe_id=_PROD_PEER, env_tier="prod", policy=self._policy()
        )
        self.assertTrue(decision.allowed)

    def test_tier_mismatch_denied(self):
        # Allowlisted for prod, presenting on staging.
        decision = admit_peer(
            spiffe_id=_PROD_PEER, env_tier="staging", policy=self._policy()
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "admission_tier_mismatch")


class CertPinningTests(unittest.TestCase):
    def _pinned_policy(self, key):
        return PeerAdmissionPolicy(
            rules=(
                AdmissionRule(
                    spiffe_id=_PROD_PEER,
                    env_tier="prod",
                    pinned_fingerprint=public_key_fingerprint(key.public_key()),
                ),
            )
        )

    def test_pinned_peer_with_matching_key_admitted(self):
        key = Ed25519PrivateKey.generate()
        decision = admit_peer(
            spiffe_id=_PROD_PEER,
            env_tier="prod",
            policy=self._pinned_policy(key),
            presented_key=key.public_key(),
        )
        self.assertTrue(decision.allowed)

    def test_pinned_peer_with_wrong_key_denied(self):
        pinned = Ed25519PrivateKey.generate()
        wrong = Ed25519PrivateKey.generate()
        decision = admit_peer(
            spiffe_id=_PROD_PEER,
            env_tier="prod",
            policy=self._pinned_policy(pinned),
            presented_key=wrong.public_key(),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "admission_cert_pin_mismatch")

    def test_pinned_peer_with_no_key_denied(self):
        pinned = Ed25519PrivateKey.generate()
        decision = admit_peer(
            spiffe_id=_PROD_PEER,
            env_tier="prod",
            policy=self._pinned_policy(pinned),
            presented_key=None,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "admission_cert_pin_mismatch")


class RequireAdmissionTests(unittest.TestCase):
    def test_allow_returns_decision(self):
        policy = PeerAdmissionPolicy(
            rules=(AdmissionRule(spiffe_id=_PROD_PEER, env_tier="prod"),)
        )
        d = require_admission(spiffe_id=_PROD_PEER, env_tier="prod", policy=policy)
        self.assertTrue(d.allowed)

    def test_deny_raises(self):
        policy = PeerAdmissionPolicy(rules=())
        with self.assertRaises(PeerAdmissionDenied) as ctx:
            require_admission(spiffe_id=_PROD_PEER, env_tier="prod", policy=policy)
        self.assertEqual(
            ctx.exception.decision.reason_code, "admission_peer_not_allowed"
        )


if __name__ == "__main__":
    unittest.main()
