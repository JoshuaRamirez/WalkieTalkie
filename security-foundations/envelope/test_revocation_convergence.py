"""Tests for revocation convergence (Phase 3 Track D D2)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from revocation_convergence import (
    ConvergenceSnapshot,
    InMemoryConvergenceTracker,
    RevocationBroadcast,
    RevocationConvergenceError,
    SLOPolicy,
    SLOStatus,
    evaluate_slo,
    pending_broadcasts,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_JTI = "01900000-0000-7000-8000-aaaaaaaaaaa1"
_OTHER_JTI = "01900000-0000-7000-8000-aaaaaaaaaaa2"


def _broadcast(
    *,
    fast_path: bool = False,
    nodes: tuple[str, ...] = ("n1", "n2", "n3", "n4"),
) -> RevocationBroadcast:
    return RevocationBroadcast(
        jti=_JTI,
        issued_at=_NOW,
        fast_path=fast_path,
        reason="key compromised",
        expected_nodes=frozenset(nodes),
    )


def _policy(*, target: float = 0.75) -> SLOPolicy:
    return SLOPolicy(
        target_coverage=target,
        normal_deadline=timedelta(minutes=5),
        fast_path_deadline=timedelta(seconds=30),
    )


class BroadcastValidationTests(unittest.TestCase):
    def test_empty_expected_nodes_rejected(self):
        with self.assertRaisesRegex(RevocationConvergenceError, "expected_nodes"):
            RevocationBroadcast(
                jti=_JTI,
                issued_at=_NOW,
                fast_path=False,
                reason="x",
                expected_nodes=frozenset(),
            )

    def test_naive_issued_at_rejected(self):
        with self.assertRaisesRegex(RevocationConvergenceError, "timezone-aware"):
            RevocationBroadcast(
                jti=_JTI,
                issued_at=datetime(2026, 4, 14, 12),
                fast_path=False,
                reason="x",
                expected_nodes=frozenset({"n1"}),
            )

    def test_bad_jti_rejected(self):
        with self.assertRaisesRegex(RevocationConvergenceError, "jti"):
            RevocationBroadcast(
                jti="not-uuid",
                issued_at=_NOW,
                fast_path=False,
                reason="x",
                expected_nodes=frozenset({"n1"}),
            )


class TrackerTests(unittest.TestCase):
    def test_register_and_ack(self):
        tracker = InMemoryConvergenceTracker()
        tracker.register_broadcast(_broadcast())
        tracker.record_ack(_JTI, "n1", at=_NOW + timedelta(seconds=5))
        acks = tracker.acks_for(_JTI)
        self.assertEqual(len(acks), 1)
        self.assertIn("n1", acks)

    def test_duplicate_register_rejected(self):
        tracker = InMemoryConvergenceTracker()
        tracker.register_broadcast(_broadcast())
        with self.assertRaisesRegex(RevocationConvergenceError, "already registered"):
            tracker.register_broadcast(_broadcast())

    def test_ack_for_unknown_jti_rejected(self):
        tracker = InMemoryConvergenceTracker()
        with self.assertRaisesRegex(RevocationConvergenceError, "no broadcast"):
            tracker.record_ack(_JTI, "n1", at=_NOW)

    def test_ack_from_unexpected_node_rejected(self):
        tracker = InMemoryConvergenceTracker()
        tracker.register_broadcast(_broadcast(nodes=("n1", "n2")))
        with self.assertRaisesRegex(
            RevocationConvergenceError, "not in the expected_nodes"
        ):
            tracker.record_ack(_JTI, "n9", at=_NOW)

    def test_re_ack_keeps_earliest_timestamp(self):
        tracker = InMemoryConvergenceTracker()
        tracker.register_broadcast(_broadcast())
        tracker.record_ack(_JTI, "n1", at=_NOW + timedelta(seconds=10))
        tracker.record_ack(_JTI, "n1", at=_NOW + timedelta(seconds=20))
        acks = tracker.acks_for(_JTI)
        self.assertEqual(acks["n1"], (_NOW + timedelta(seconds=10)).astimezone(UTC))


class SLOEvaluationTests(unittest.TestCase):
    def _populated_tracker(self, n_acks: int, *, fast_path: bool = False, base_delta_s: int = 0):
        tracker = InMemoryConvergenceTracker()
        broadcast = _broadcast(fast_path=fast_path)
        tracker.register_broadcast(broadcast)
        nodes = sorted(broadcast.expected_nodes)
        for i, node in enumerate(nodes[:n_acks]):
            tracker.record_ack(
                _JTI, node, at=_NOW + timedelta(seconds=base_delta_s + i)
            )
        return tracker

    def test_pending_before_deadline(self):
        tracker = self._populated_tracker(2)  # 2/4 = 50% < 75% target
        snap = evaluate_slo(
            tracker=tracker, jti=_JTI, policy=_policy(), now=_NOW + timedelta(seconds=10)
        )
        self.assertIsInstance(snap, ConvergenceSnapshot)
        self.assertEqual(snap.status, SLOStatus.PENDING)
        self.assertAlmostEqual(snap.coverage, 0.5)
        self.assertIsNone(snap.time_to_target)

    def test_meeting_when_target_reached_in_time(self):
        tracker = self._populated_tracker(3)  # 3/4 = 75% meets target
        snap = evaluate_slo(
            tracker=tracker, jti=_JTI, policy=_policy(), now=_NOW + timedelta(seconds=10)
        )
        self.assertEqual(snap.status, SLOStatus.MEETING)
        self.assertEqual(snap.acks_received, 3)
        self.assertEqual(snap.acks_expected, 4)
        self.assertIsNotNone(snap.time_to_target)

    def test_missed_when_deadline_passes_without_target(self):
        tracker = self._populated_tracker(1)  # 1/4 = 25%
        snap = evaluate_slo(
            tracker=tracker, jti=_JTI, policy=_policy(), now=_NOW + timedelta(minutes=10)
        )
        self.assertEqual(snap.status, SLOStatus.MISSED)

    def test_fast_path_uses_tighter_deadline(self):
        tracker = self._populated_tracker(1, fast_path=True)  # 1/4 = 25%
        # 60 seconds elapsed — fast_path_deadline is 30s, so MISSED.
        snap = evaluate_slo(
            tracker=tracker, jti=_JTI, policy=_policy(), now=_NOW + timedelta(seconds=60)
        )
        self.assertEqual(snap.status, SLOStatus.MISSED)
        self.assertEqual(snap.deadline, timedelta(seconds=30))

    def test_normal_path_still_pending_at_60s(self):
        tracker = self._populated_tracker(1, fast_path=False)
        snap = evaluate_slo(
            tracker=tracker, jti=_JTI, policy=_policy(), now=_NOW + timedelta(seconds=60)
        )
        self.assertEqual(snap.status, SLOStatus.PENDING)

    def test_late_full_convergence_marked_missed(self):
        # Target hit eventually but after the deadline.
        tracker = self._populated_tracker(3, base_delta_s=400)
        # Acks at 400, 401, 402 seconds — well after the 5-minute
        # (300s) normal deadline.
        snap = evaluate_slo(
            tracker=tracker,
            jti=_JTI,
            policy=_policy(),
            now=_NOW + timedelta(seconds=500),
        )
        self.assertEqual(snap.status, SLOStatus.MISSED)


class PendingBroadcastsTests(unittest.TestCase):
    def test_pending_broadcasts_skips_meeting(self):
        tracker = InMemoryConvergenceTracker()
        ok = RevocationBroadcast(
            jti=_JTI,
            issued_at=_NOW,
            fast_path=False,
            reason="met",
            expected_nodes=frozenset({"n1", "n2"}),
        )
        bad = RevocationBroadcast(
            jti=_OTHER_JTI,
            issued_at=_NOW,
            fast_path=True,
            reason="missed",
            expected_nodes=frozenset({"n1", "n2"}),
        )
        tracker.register_broadcast(ok)
        tracker.register_broadcast(bad)
        # ok meets 100% target via 2 acks.
        tracker.record_ack(_JTI, "n1", at=_NOW + timedelta(seconds=1))
        tracker.record_ack(_JTI, "n2", at=_NOW + timedelta(seconds=2))
        # bad: no acks, fast-path deadline passes.
        result = pending_broadcasts(
            tracker,
            jtis=(_JTI, _OTHER_JTI),
            policy=_policy(target=1.0),
            now=_NOW + timedelta(seconds=60),
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].jti, _OTHER_JTI)
        self.assertEqual(result[0].status, SLOStatus.MISSED)


class SLOPolicyValidationTests(unittest.TestCase):
    def test_target_outside_range_rejected(self):
        with self.assertRaisesRegex(RevocationConvergenceError, "target_coverage"):
            SLOPolicy(
                target_coverage=1.5,
                normal_deadline=timedelta(seconds=10),
                fast_path_deadline=timedelta(seconds=5),
            )

    def test_zero_deadline_rejected(self):
        with self.assertRaisesRegex(RevocationConvergenceError, "deadline"):
            SLOPolicy(
                target_coverage=0.9,
                normal_deadline=timedelta(0),
                fast_path_deadline=timedelta(seconds=5),
            )


if __name__ == "__main__":
    unittest.main()
