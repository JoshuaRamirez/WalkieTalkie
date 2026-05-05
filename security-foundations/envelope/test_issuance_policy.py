"""Tests for issuance policy primitives.

Covers Phase 1 Track C C1 acceptance — both the policy-evaluation surface
itself (this file) and its integration with CapabilityIssuer (the
new test classes in test_capability_issuer.py).
"""

import pathlib
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from issuance_policy import (
    AllowAllPolicy,
    AllowlistPolicy,
    PolicyDecision,
)

_SUB = "spiffe://mesh/ns-a/service-a"
_AUD = "spiffe://mesh/ns-b/service-b"
_SCOPE = "invoke_tool"


class AllowAllPolicyTests(unittest.TestCase):
    def test_always_allows(self):
        decision = AllowAllPolicy().evaluate(
            sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(hours=24)
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "permissive")


class AllowlistPolicyTests(unittest.TestCase):
    def test_allows_listed_grant(self):
        policy = AllowlistPolicy(
            allowed_grants=frozenset({(_SUB, _AUD, _SCOPE)}),
            max_ttl=timedelta(minutes=5),
        )
        decision = policy.evaluate(
            sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(minutes=4)
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "ok")

    def test_denies_unlisted_grant(self):
        policy = AllowlistPolicy(
            allowed_grants=frozenset({(_SUB, _AUD, _SCOPE)}),
        )
        for sub, aud, scope in [
            ("spiffe://mesh/ns-x/svc", _AUD, _SCOPE),  # wrong sub
            (_SUB, "spiffe://mesh/ns-x/svc", _SCOPE),  # wrong aud
            (_SUB, _AUD, "different_scope"),           # wrong scope
        ]:
            with self.subTest(sub=sub, aud=aud, scope=scope):
                d = policy.evaluate(sub=sub, aud=aud, scope=scope, ttl=timedelta(minutes=1))
                self.assertFalse(d.allowed)
                self.assertIn("not in allowlist", d.reason)

    def test_denies_ttl_above_cap(self):
        policy = AllowlistPolicy(
            allowed_grants=frozenset({(_SUB, _AUD, _SCOPE)}),
            max_ttl=timedelta(minutes=5),
        )
        decision = policy.evaluate(
            sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(minutes=6)
        )
        self.assertFalse(decision.allowed)
        self.assertIn("exceeds policy max", decision.reason)

    def test_allows_ttl_at_cap(self):
        policy = AllowlistPolicy(
            allowed_grants=frozenset({(_SUB, _AUD, _SCOPE)}),
            max_ttl=timedelta(minutes=5),
        )
        decision = policy.evaluate(
            sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(minutes=5)
        )
        self.assertTrue(decision.allowed)

    def test_zero_max_ttl_rejected_at_construction(self):
        with self.assertRaisesRegex(ValueError, "max_ttl"):
            AllowlistPolicy(
                allowed_grants=frozenset({(_SUB, _AUD, _SCOPE)}),
                max_ttl=timedelta(0),
            )

    def test_default_max_ttl_is_five_minutes(self):
        policy = AllowlistPolicy(allowed_grants=frozenset({(_SUB, _AUD, _SCOPE)}))
        # 5 min = 300 s. Sanity-check the default by asserting an exact-edge
        # ttl passes and a 1s-over ttl fails.
        ok = policy.evaluate(sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(minutes=5))
        self.assertTrue(ok.allowed)
        bad = policy.evaluate(sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(minutes=5, seconds=1))
        self.assertFalse(bad.allowed)


class PolicyDecisionTests(unittest.TestCase):
    def test_is_frozen(self):
        from dataclasses import FrozenInstanceError

        d = PolicyDecision(allowed=True, reason="ok")
        with self.assertRaises(FrozenInstanceError):
            d.allowed = False  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
