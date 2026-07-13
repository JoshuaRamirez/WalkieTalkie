"""Tests for discovery propagation integrity (Phase 3 Track A A3)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from discovery_propagation import (
    DiscoveryAdmissionGate,
    DiscoveryPropagationError,
    InMemoryDiscoveryFreshnessTracker,
    InMemoryDiscoveryPropagationLimiter,
)
from discovery_record import DiscoveryRecord

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_WORKLOAD_ISS = "spiffe://mesh.example/ns-a/agent-1"
_WORKLOAD_KID = "workload-kid-1"
_ISSUER_ISS = "spiffe://mesh.example/ns-iss/discovery-1"
_ISSUER_KID = "issuer-kid-1"


def _record(*, issued_at: datetime = _NOW, workload_iss: str = _WORKLOAD_ISS) -> DiscoveryRecord:
    return DiscoveryRecord(
        version="v0",
        workload_iss=workload_iss,
        workload_kid=_WORKLOAD_KID,
        endpoints=("tls://example.test:443",),
        issuer_iss=_ISSUER_ISS,
        issuer_kid=_ISSUER_KID,
        issued_at=issued_at.isoformat().replace("+00:00", "Z"),
        expires_at=(issued_at + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        signature="placeholder",
    )


class FreshnessTests(unittest.TestCase):
    def test_first_record_allowed(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        decision = tracker.check(_record())
        self.assertTrue(decision.allowed)

    def test_strictly_newer_record_allowed_after_commit(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        r1 = _record(issued_at=_NOW)
        tracker.commit(r1)
        r2 = _record(issued_at=_NOW + timedelta(minutes=5))
        self.assertTrue(tracker.check(r2).allowed)

    def test_rewound_record_rejected(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        newer = _record(issued_at=_NOW)
        tracker.commit(newer)
        older = _record(issued_at=_NOW - timedelta(minutes=10))
        decision = tracker.check(older)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "discovery_rewound")

    def test_replayed_same_timestamp_rejected(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        tracker.commit(_record())
        # Same issued_at again — must not be allowed (strict
        # monotonicity prevents replay of the same record).
        decision = tracker.check(_record())
        self.assertEqual(decision.reason_code, "discovery_rewound")

    def test_per_workload_pins_are_independent(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        tracker.commit(_record(workload_iss=_WORKLOAD_ISS))
        other = _record(workload_iss="spiffe://mesh.example/ns-b/agent-2")
        # Different workload — independent pin.
        self.assertTrue(tracker.check(other).allowed)

    def test_commit_is_idempotent_for_lower_timestamps(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        tracker.commit(_record(issued_at=_NOW))
        # Out-of-order admission of an older record (e.g. via race)
        # must not lower the pin.
        tracker.commit(_record(issued_at=_NOW - timedelta(minutes=10)))
        decision = tracker.check(_record(issued_at=_NOW - timedelta(minutes=5)))
        self.assertEqual(decision.reason_code, "discovery_rewound")

    def test_evict_drops_old_pins(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        tracker.commit(_record(issued_at=_NOW - timedelta(days=2)))
        tracker.commit(
            _record(
                workload_iss="spiffe://mesh.example/ns-c/agent-3",
                issued_at=_NOW,
            )
        )
        evicted = tracker.evict_older_than(_NOW - timedelta(days=1))
        self.assertEqual(evicted, 1)

    def test_unparseable_issued_at_rejected(self):
        tracker = InMemoryDiscoveryFreshnessTracker()
        bad = DiscoveryRecord(
            version="v0",
            workload_iss=_WORKLOAD_ISS,
            workload_kid=_WORKLOAD_KID,
            endpoints=("tls://x:443",),
            issuer_iss=_ISSUER_ISS,
            issuer_kid=_ISSUER_KID,
            issued_at="not-rfc3339",
            expires_at="2026-04-14T13:00:00Z",
            signature="placeholder",
        )
        with self.assertRaises(DiscoveryPropagationError):
            tracker.check(bad)


class RateLimitTests(unittest.TestCase):
    def test_first_republish_allowed(self):
        limiter = InMemoryDiscoveryPropagationLimiter()
        self.assertTrue(limiter.check(_record(), at=_NOW).allowed)

    def test_within_window_rejected(self):
        limiter = InMemoryDiscoveryPropagationLimiter(
            window=timedelta(seconds=60), max_per_window=1
        )
        limiter.commit(_record(), at=_NOW)
        # Another republish 30s later — rate-limited.
        decision = limiter.check(_record(), at=_NOW + timedelta(seconds=30))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "discovery_rate_limited")

    def test_after_window_allowed(self):
        limiter = InMemoryDiscoveryPropagationLimiter(
            window=timedelta(seconds=60), max_per_window=1
        )
        limiter.commit(_record(), at=_NOW)
        decision = limiter.check(_record(), at=_NOW + timedelta(seconds=90))
        self.assertTrue(decision.allowed)

    def test_per_workload_independent(self):
        limiter = InMemoryDiscoveryPropagationLimiter(
            window=timedelta(seconds=60), max_per_window=1
        )
        limiter.commit(_record(workload_iss=_WORKLOAD_ISS), at=_NOW)
        other = _record(workload_iss="spiffe://mesh.example/ns-b/agent-2")
        decision = limiter.check(other, at=_NOW + timedelta(seconds=5))
        self.assertTrue(decision.allowed)

    def test_max_per_window_higher_allows_burst(self):
        limiter = InMemoryDiscoveryPropagationLimiter(
            window=timedelta(seconds=60), max_per_window=3
        )
        for delta in (0, 10, 20):
            limiter.commit(_record(), at=_NOW + timedelta(seconds=delta))
        # 4th in window — rejected.
        decision = limiter.check(_record(), at=_NOW + timedelta(seconds=30))
        self.assertFalse(decision.allowed)

    def test_invalid_config_rejected(self):
        with self.assertRaises(DiscoveryPropagationError):
            InMemoryDiscoveryPropagationLimiter(window=timedelta(0))
        with self.assertRaises(DiscoveryPropagationError):
            InMemoryDiscoveryPropagationLimiter(max_per_window=0)

    def test_naive_at_rejected(self):
        limiter = InMemoryDiscoveryPropagationLimiter()
        with self.assertRaises(DiscoveryPropagationError):
            limiter.check(_record(), at=datetime(2026, 4, 14, 12))


class AdmissionGateTests(unittest.TestCase):
    def _gate(self):
        return DiscoveryAdmissionGate(
            freshness=InMemoryDiscoveryFreshnessTracker(),
            limiter=InMemoryDiscoveryPropagationLimiter(
                window=timedelta(seconds=60), max_per_window=1
            ),
        )

    def test_happy_path_admits_and_pins(self):
        gate = self._gate()
        decision = gate.admit(_record(), at=_NOW)
        self.assertTrue(decision.allowed)
        # Same record again — both freshness and limiter would reject;
        # freshness runs first.
        again = gate.admit(_record(), at=_NOW + timedelta(seconds=120))
        self.assertEqual(again.reason_code, "discovery_rewound")

    def test_rate_limit_runs_after_freshness(self):
        gate = self._gate()
        # First commit pins the freshness baseline.
        first = _record(issued_at=_NOW)
        self.assertTrue(gate.admit(first, at=_NOW).allowed)
        # Now propose a fresher record but within the rate-limit
        # window. Freshness passes; rate-limit catches it.
        fresher = _record(issued_at=_NOW + timedelta(seconds=10))
        decision = gate.admit(fresher, at=_NOW + timedelta(seconds=10))
        self.assertEqual(decision.reason_code, "discovery_rate_limited")

    def test_failed_admit_does_not_advance_pins(self):
        gate = self._gate()
        # Two commits in quick succession: the second hits the rate
        # limit. After that, a third record with a timestamp between
        # the two should still pass freshness because the rate-
        # limited middle attempt did not advance the pin.
        first = _record(issued_at=_NOW)
        self.assertTrue(gate.admit(first, at=_NOW).allowed)
        middle = _record(issued_at=_NOW + timedelta(seconds=10))
        self.assertFalse(gate.admit(middle, at=_NOW + timedelta(seconds=10)).allowed)
        third = _record(issued_at=_NOW + timedelta(seconds=5))
        # 5s after first, which is strictly later than the pinned _NOW.
        # The rate-limit window is 60s though; second admit attempt
        # still within window.
        decision = gate.evaluate(third, at=_NOW + timedelta(seconds=90))
        self.assertTrue(decision.allowed)


if __name__ == "__main__":
    unittest.main()
