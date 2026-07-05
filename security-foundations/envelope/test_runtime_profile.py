"""Tests for runtime trust tiers (Phase 5 Track D D1)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from runtime_profile import (
    EgressPolicy,
    RuntimeProfile,
    RuntimeProfileError,
    TrustTier,
    limited_trust_profile,
    standard_profile,
    strict_profile,
)


class ProfileValidationTests(unittest.TestCase):
    def test_non_tier_rejected(self):
        with self.assertRaisesRegex(RuntimeProfileError, "tier"):
            RuntimeProfile(tier="strict")  # type: ignore[arg-type]

    def test_non_frozenset_syscalls_rejected(self):
        with self.assertRaisesRegex(RuntimeProfileError, "allowed_syscalls"):
            RuntimeProfile(
                tier=TrustTier.STRICT,
                allowed_syscalls={"read"},  # type: ignore[arg-type]
            )

    def test_empty_syscall_name_rejected(self):
        with self.assertRaisesRegex(RuntimeProfileError, "non-empty"):
            RuntimeProfile(
                tier=TrustTier.STRICT, allowed_syscalls=frozenset({""})
            )

    def test_allowlist_egress_requires_hosts(self):
        with self.assertRaisesRegex(RuntimeProfileError, "non-empty egress_allowlist"):
            RuntimeProfile(tier=TrustTier.STANDARD, egress=EgressPolicy.ALLOWLIST)

    def test_allowlist_only_when_allowlist_egress(self):
        with self.assertRaisesRegex(RuntimeProfileError, "only meaningful"):
            RuntimeProfile(
                tier=TrustTier.STRICT,
                egress=EgressPolicy.DENY_ALL,
                egress_allowlist=frozenset({"api.example"}),
            )


class BuiltinProfileTests(unittest.TestCase):
    def test_strict_denies_egress_and_has_minimal_writable(self):
        p = strict_profile()
        self.assertEqual(p.tier, TrustTier.STRICT)
        self.assertEqual(p.egress, EgressPolicy.DENY_ALL)
        self.assertEqual(p.writable_paths, frozenset({"/tmp"}))
        self.assertIn("read", p.allowed_syscalls)

    def test_standard_uses_egress_allowlist(self):
        p = standard_profile(egress_allowlist=frozenset({"api.internal"}))
        self.assertEqual(p.tier, TrustTier.STANDARD)
        self.assertEqual(p.egress, EgressPolicy.ALLOWLIST)
        self.assertIn("api.internal", p.egress_allowlist)
        # Broader syscall set than strict.
        self.assertIn("connect", p.allowed_syscalls)

    def test_limited_trust_denies_egress_and_writable(self):
        p = limited_trust_profile(allowed_syscalls=frozenset({"getpid"}))
        self.assertEqual(p.tier, TrustTier.LIMITED_TRUST)
        self.assertEqual(p.egress, EgressPolicy.DENY_ALL)
        self.assertEqual(p.writable_paths, frozenset())
        self.assertIn("getpid", p.allowed_syscalls)
        # Base syscalls still present.
        self.assertIn("read", p.allowed_syscalls)

    def test_secret_scopes_propagate(self):
        p = strict_profile(secret_scopes=frozenset({"db/readonly"}))
        self.assertIn("db/readonly", p.secret_scopes)

    def test_profiles_are_frozen(self):
        from dataclasses import FrozenInstanceError
        p = strict_profile()
        with self.assertRaises(FrozenInstanceError):
            p.egress = EgressPolicy.ALLOW_ALL  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
