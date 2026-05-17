"""Tests for canary policy releases (Phase 1 Track C C3)."""

import pathlib
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from canary_policy import CanaryPolicy
from issuance_policy import (
    AllowAllPolicy,
    AllowlistPolicy,
    IssuancePolicy,
    PolicyDecision,
)

_SUB = "spiffe://mesh.example/ns-a/svc"
_AUD = "spiffe://mesh.example/ns-b/svc"
_SCOPE = "invoke_tool"


class _LabelingPolicy(IssuancePolicy):
    """Always-allow policy that tags its decisions with a label so tests can
    tell which side of the canary handled a given evaluate()."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.calls = 0

    def evaluate(
        self, *, sub: str, aud: str, scope: str, ttl: timedelta
    ) -> PolicyDecision:
        self.calls += 1
        return PolicyDecision(allowed=True, reason=self.label)


class _StrictPolicy(IssuancePolicy):
    """Always-deny policy used to drive the auto-rollback path."""

    def evaluate(
        self, *, sub: str, aud: str, scope: str, ttl: timedelta
    ) -> PolicyDecision:
        return PolicyDecision(allowed=False, reason="strict candidate denied")


class ConstructionTests(unittest.TestCase):
    def test_canary_buckets_out_of_range_rejected(self):
        with self.assertRaisesRegex(ValueError, "canary_buckets"):
            CanaryPolicy(
                stable=AllowAllPolicy(),
                candidate=AllowAllPolicy(),
                canary_buckets=-1,
            )
        with self.assertRaisesRegex(ValueError, "canary_buckets"):
            CanaryPolicy(
                stable=AllowAllPolicy(),
                candidate=AllowAllPolicy(),
                canary_buckets=101,
            )

    def test_zero_rollback_threshold_rejected(self):
        with self.assertRaisesRegex(ValueError, "rollback_after_denials"):
            CanaryPolicy(
                stable=AllowAllPolicy(),
                candidate=AllowAllPolicy(),
                rollback_after_denials=0,
            )


class TrafficSplitTests(unittest.TestCase):
    def test_zero_percent_routes_all_to_stable(self):
        stable = _LabelingPolicy("stable")
        candidate = _LabelingPolicy("candidate")
        canary = CanaryPolicy(stable=stable, candidate=candidate, canary_buckets=0)
        for i in range(200):
            d = canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
            self.assertEqual(d.reason, "stable")
        self.assertEqual(candidate.calls, 0)

    def test_hundred_percent_routes_all_to_candidate(self):
        stable = _LabelingPolicy("stable")
        candidate = _LabelingPolicy("candidate")
        canary = CanaryPolicy(stable=stable, candidate=candidate, canary_buckets=100)
        for i in range(200):
            d = canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
            self.assertEqual(d.reason, "candidate")
        self.assertEqual(stable.calls, 0)

    def test_fifty_percent_split_is_approximately_balanced(self):
        # The bucket function is deterministic per (sub, aud, scope), so we
        # need to vary at least one of them. Use a 1000-row sample.
        stable = _LabelingPolicy("stable")
        candidate = _LabelingPolicy("candidate")
        canary = CanaryPolicy(stable=stable, candidate=candidate, canary_buckets=50)
        for i in range(1000):
            canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
        # sha256-based bucketing should be within a generous tolerance.
        self.assertAlmostEqual(candidate.calls / 1000.0, 0.5, delta=0.05)

    def test_split_is_deterministic_per_grant(self):
        stable = _LabelingPolicy("stable")
        candidate = _LabelingPolicy("candidate")
        canary = CanaryPolicy(stable=stable, candidate=candidate, canary_buckets=50)
        # Same (sub, aud, scope) MUST land on the same side every call until
        # canary_buckets changes — that's what makes a percentage ramp safe.
        first = canary.evaluate(sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60))
        for _ in range(20):
            again = canary.evaluate(sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60))
            self.assertEqual(again.reason, first.reason)


class AutoRollbackTests(unittest.TestCase):
    def test_rollback_after_threshold_denials(self):
        stable = _LabelingPolicy("stable")
        candidate = _StrictPolicy()
        canary = CanaryPolicy(
            stable=stable,
            candidate=candidate,
            canary_buckets=100,
            rollback_after_denials=3,
        )
        # First 3 grants hit the candidate and are denied.
        for i in range(3):
            d = canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
            self.assertFalse(d.allowed)
            self.assertEqual(d.reason, "strict candidate denied")
        self.assertTrue(canary.rolled_back)
        self.assertEqual(canary.candidate_denials, 3)

        # Subsequent calls bypass the candidate even at 100% canary.
        d = canary.evaluate(sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60))
        self.assertEqual(d.reason, "stable")

    def test_no_rollback_when_candidate_allows(self):
        stable = _LabelingPolicy("stable")
        candidate = _LabelingPolicy("candidate")
        canary = CanaryPolicy(
            stable=stable,
            candidate=candidate,
            canary_buckets=100,
            rollback_after_denials=3,
        )
        for i in range(20):
            canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
        self.assertFalse(canary.rolled_back)
        self.assertEqual(canary.candidate_denials, 0)

    def test_rollback_is_sticky(self):
        stable = _LabelingPolicy("stable")
        # Candidate denies once at the threshold, then "fixes itself" — but
        # rollback is sticky for the lifetime of the CanaryPolicy.
        class FlakyCandidate(IssuancePolicy):
            def __init__(self):
                self.deny_count = 0

            def evaluate(self, *, sub, aud, scope, ttl):
                if self.deny_count < 2:
                    self.deny_count += 1
                    return PolicyDecision(allowed=False, reason="flake")
                return PolicyDecision(allowed=True, reason="recovered")

        canary = CanaryPolicy(
            stable=stable,
            candidate=FlakyCandidate(),
            canary_buckets=100,
            rollback_after_denials=2,
        )
        for i in range(2):
            canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
        self.assertTrue(canary.rolled_back)
        d = canary.evaluate(
            sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
        )
        # Sticky rollback: even though the candidate would now allow, we go
        # to stable.
        self.assertEqual(d.reason, "stable")

    def test_denials_from_stable_do_not_trigger_rollback(self):
        # Candidate is well-behaved; stable denies. The canary's rollback
        # counter ONLY tracks the candidate.
        stable = AllowlistPolicy(allowed_grants=frozenset())  # always denies
        candidate = _LabelingPolicy("candidate")
        canary = CanaryPolicy(
            stable=stable,
            candidate=candidate,
            canary_buckets=10,  # 90% of grants land on stable
            rollback_after_denials=1,
        )
        for i in range(50):
            canary.evaluate(
                sub=f"{_SUB}-{i}", aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
            )
        self.assertFalse(canary.rolled_back)
        self.assertEqual(canary.candidate_denials, 0)


if __name__ == "__main__":
    unittest.main()
