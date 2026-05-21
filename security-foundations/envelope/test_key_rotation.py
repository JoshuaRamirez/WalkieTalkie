"""Tests for key rotation drills (Phase 3 Track D D1)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from key_rotation import (
    KeyRotationError,
    KeyRotationPlan,
    RotationPhase,
    RotationRegistry,
    accepted_kids,
    build_plan,
    current_phase,
    require_accepted_kid,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_SUB = "spiffe://mesh.example/ns-a/agent-1"
_OLD = "kid-old"
_NEW = "kid-new"


def _plan(**overrides) -> KeyRotationPlan:
    kwargs = dict(
        subject_iss=_SUB,
        old_kid=_OLD,
        new_kid=_NEW,
        overlap_start=_NOW,
        cutover_at=_NOW + timedelta(hours=1),
        overlap_end=_NOW + timedelta(hours=2),
    )
    kwargs.update(overrides)
    return build_plan(**kwargs)


class PlanValidationTests(unittest.TestCase):
    def test_old_equals_new_rejected(self):
        with self.assertRaisesRegex(KeyRotationError, "differ"):
            _plan(new_kid=_OLD)

    def test_invalid_kid_rejected(self):
        with self.assertRaisesRegex(KeyRotationError, "new_kid"):
            _plan(new_kid="bad kid")

    def test_cutover_before_overlap_start_rejected(self):
        with self.assertRaisesRegex(KeyRotationError, "cutover_at"):
            _plan(cutover_at=_NOW - timedelta(minutes=1))

    def test_overlap_end_before_cutover_rejected(self):
        with self.assertRaisesRegex(KeyRotationError, "overlap_end"):
            _plan(overlap_end=_NOW + timedelta(minutes=30))


class PhaseTests(unittest.TestCase):
    def test_pre_overlap(self):
        plan = _plan()
        self.assertEqual(
            current_phase(plan, now=_NOW - timedelta(minutes=1)),
            RotationPhase.PRE_OVERLAP,
        )

    def test_overlap(self):
        plan = _plan()
        self.assertEqual(
            current_phase(plan, now=_NOW + timedelta(minutes=30)),
            RotationPhase.OVERLAP,
        )

    def test_post_cutover(self):
        plan = _plan()
        self.assertEqual(
            current_phase(plan, now=_NOW + timedelta(minutes=90)),
            RotationPhase.POST_CUTOVER,
        )

    def test_complete(self):
        plan = _plan()
        self.assertEqual(
            current_phase(plan, now=_NOW + timedelta(hours=3)),
            RotationPhase.COMPLETE,
        )


class AcceptedKidsTests(unittest.TestCase):
    def test_pre_overlap_only_old(self):
        plan = _plan()
        self.assertEqual(
            accepted_kids(plan, now=_NOW - timedelta(minutes=1)),
            frozenset({_OLD}),
        )

    def test_overlap_accepts_both(self):
        plan = _plan()
        self.assertEqual(
            accepted_kids(plan, now=_NOW + timedelta(minutes=30)),
            frozenset({_OLD, _NEW}),
        )

    def test_post_cutover_still_accepts_both(self):
        plan = _plan()
        self.assertEqual(
            accepted_kids(plan, now=_NOW + timedelta(minutes=90)),
            frozenset({_OLD, _NEW}),
        )

    def test_complete_only_new(self):
        plan = _plan()
        self.assertEqual(
            accepted_kids(plan, now=_NOW + timedelta(hours=3)),
            frozenset({_NEW}),
        )


class RegistryTests(unittest.TestCase):
    def test_register_and_query(self):
        reg = RotationRegistry()
        reg.register(_plan())
        self.assertTrue(reg.is_accepted(_SUB, _OLD, now=_NOW))
        self.assertTrue(
            reg.is_accepted(_SUB, _NEW, now=_NOW + timedelta(minutes=30))
        )

    def test_conflicting_plan_rejected(self):
        reg = RotationRegistry()
        reg.register(_plan())
        # Same subject, overlapping window, shared old_kid → conflict.
        with self.assertRaisesRegex(KeyRotationError, "conflicting"):
            reg.register(
                _plan(
                    new_kid="kid-other",
                    overlap_start=_NOW + timedelta(minutes=30),
                )
            )

    def test_non_conflicting_plan_admitted(self):
        reg = RotationRegistry()
        reg.register(_plan())
        # Same subject, but the new plan's window is entirely AFTER
        # the first plan's overlap_end → no conflict.
        reg.register(
            _plan(
                old_kid=_NEW,
                new_kid="kid-newer",
                overlap_start=_NOW + timedelta(hours=3),
                cutover_at=_NOW + timedelta(hours=4),
                overlap_end=_NOW + timedelta(hours=5),
            )
        )
        # At the second-plan's overlap, both kid-new and kid-newer
        # are accepted.
        self.assertTrue(
            reg.is_accepted(_SUB, "kid-newer", now=_NOW + timedelta(hours=3, minutes=30))
        )

    def test_different_subject_does_not_conflict(self):
        reg = RotationRegistry()
        reg.register(_plan())
        other_sub = "spiffe://mesh.example/ns-b/agent-2"
        reg.register(_plan(subject_iss=other_sub))
        # Both registered; same kid name fine across distinct subjects.
        self.assertTrue(reg.is_accepted(_SUB, _OLD, now=_NOW))
        self.assertTrue(reg.is_accepted(other_sub, _OLD, now=_NOW))

    def test_evict_completed_drops_aged_plans(self):
        reg = RotationRegistry()
        reg.register(_plan())
        evicted = reg.evict_completed(now=_NOW + timedelta(hours=3))
        self.assertEqual(evicted, 1)
        self.assertFalse(
            reg.is_accepted(_SUB, _NEW, now=_NOW + timedelta(hours=3))
        )

    def test_snapshot_returns_current_plans(self):
        reg = RotationRegistry()
        plan = _plan()
        reg.register(plan)
        self.assertEqual(reg.snapshot(), (plan,))


class RequireAcceptedKidTests(unittest.TestCase):
    def test_accepted_kid_passes(self):
        reg = RotationRegistry()
        reg.register(_plan())
        # Doesn't raise.
        require_accepted_kid(
            reg, subject_iss=_SUB, kid=_OLD, now=_NOW + timedelta(minutes=30)
        )

    def test_unknown_kid_raises_with_code(self):
        reg = RotationRegistry()
        reg.register(_plan())
        with self.assertRaisesRegex(KeyRotationError, "rotation_kid_not_accepted"):
            require_accepted_kid(
                reg, subject_iss=_SUB, kid="kid-unknown",
                now=_NOW + timedelta(minutes=30),
            )

    def test_post_complete_old_kid_no_longer_accepted(self):
        reg = RotationRegistry()
        reg.register(_plan())
        # After overlap_end, only new_kid accepted.
        with self.assertRaisesRegex(KeyRotationError, "rotation_kid_not_accepted"):
            require_accepted_kid(
                reg, subject_iss=_SUB, kid=_OLD,
                now=_NOW + timedelta(hours=3),
            )


if __name__ == "__main__":
    unittest.main()
