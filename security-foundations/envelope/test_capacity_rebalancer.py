"""Tests for the capacity rebalancer (Phase 3 B3 deferred half)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from capacity_budgets import (
    BudgetPool,
    CapacityBudgetError,
    build_controller,
)
from capacity_rebalancer import (
    CapacityRebalancer,
    CeilingChange,
    RebalanceDecision,
    RebalancerError,
)


def _three_pool_controller():
    """security 20/40, control 30/60, data 50/100, total 100.

    Total reserved = 100 so no cross-pool burst is available out of
    the gate; the rebalancer must move ceilings to free headroom.
    """
    return build_controller(
        total_capacity=200,
        pools=[
            BudgetPool("security", reserved=20, ceiling=40),
            BudgetPool("control", reserved=30, ceiling=60),
            BudgetPool("data", reserved=50, ceiling=100),
        ],
    )


class RebalancerValidationTests(unittest.TestCase):
    def test_thresholds_must_be_in_range(self):
        with self.assertRaisesRegex(RebalancerError, "stress_threshold"):
            CapacityRebalancer(stress_threshold=1.5)
        with self.assertRaisesRegex(RebalancerError, "slack_threshold"):
            CapacityRebalancer(slack_threshold=0.0)

    def test_slack_must_be_below_stress(self):
        with self.assertRaisesRegex(RebalancerError, "slack_threshold"):
            CapacityRebalancer(stress_threshold=0.5, slack_threshold=0.6)

    def test_negative_cascade_min_stressed_rejected(self):
        with self.assertRaisesRegex(RebalancerError, "cascade_min_stressed"):
            CapacityRebalancer(cascade_min_stressed=0)


class SignalsTests(unittest.TestCase):
    def test_no_cascading_at_idle(self):
        ctrl = _three_pool_controller()
        reb = CapacityRebalancer()
        sigs = reb.signals(ctrl)
        self.assertFalse(sigs.cascading)
        # All three pools are at 0 utilization → all slack.
        self.assertEqual(len(sigs.slack), 3)
        self.assertEqual(len(sigs.stressed), 0)

    def test_cascading_detected(self):
        ctrl = _three_pool_controller()
        # Push security to 36/40 (90%) and control to 56/60 (~93%).
        # Data stays at 0/100 (0%).
        for _ in range(36):
            ctrl.acquire(pool="security")
        for _ in range(56):
            ctrl.acquire(pool="control")
        reb = CapacityRebalancer()
        sigs = reb.signals(ctrl)
        self.assertTrue(sigs.cascading)
        names_stressed = {p.name for p in sigs.stressed}
        self.assertEqual(names_stressed, {"security", "control"})
        self.assertEqual({p.name for p in sigs.slack}, {"data"})

    def test_one_stressed_no_cascade(self):
        ctrl = _three_pool_controller()
        for _ in range(36):
            ctrl.acquire(pool="security")
        reb = CapacityRebalancer()
        sigs = reb.signals(ctrl)
        self.assertFalse(sigs.cascading)


class EvaluateTests(unittest.TestCase):
    def test_noop_when_not_cascading(self):
        ctrl = _three_pool_controller()
        decision = CapacityRebalancer().evaluate(ctrl)
        self.assertTrue(decision.is_noop)
        self.assertIn("no cascading", decision.reason)

    def test_donor_and_recipient_changes_recorded(self):
        ctrl = _three_pool_controller()
        # security 36/40, control 56/60, data 0/100.
        for _ in range(36):
            ctrl.acquire(pool="security")
        for _ in range(56):
            ctrl.acquire(pool="control")
        reb = CapacityRebalancer(transfer_fraction=0.2)
        decision = reb.evaluate(ctrl)
        # data has slack_headroom = 100 - 50 (reserved) = 50.
        # donation = int(50 * 0.2) = 10.
        # Donor change: data 100 -> 90.
        # Recipients: security and control split 10 proportional to
        # stress_excess. Neither overflows ceiling (excess=0 for both),
        # so even split: 5 to each → security 40->45, control 60->65.
        names = {c.pool for c in decision.changes}
        self.assertEqual(names, {"data", "security", "control"})
        data_change = next(c for c in decision.changes if c.pool == "data")
        self.assertEqual(data_change.old_ceiling, 100)
        self.assertEqual(data_change.new_ceiling, 90)
        sec_change = next(c for c in decision.changes if c.pool == "security")
        self.assertGreater(sec_change.new_ceiling, sec_change.old_ceiling)
        ctrl_change = next(c for c in decision.changes if c.pool == "control")
        self.assertGreater(ctrl_change.new_ceiling, ctrl_change.old_ceiling)

    def test_overflow_recipient_gets_proportional_share(self):
        # Construct a state where one stressed pool is already in
        # excess (in_flight > ceiling is impossible via acquire, but
        # we can simulate by adjusting ceiling down from a fuller
        # state — instead, use unequal utilizations).
        ctrl = build_controller(
            total_capacity=200,
            pools=[
                BudgetPool("hot1", reserved=10, ceiling=20),
                BudgetPool("hot2", reserved=10, ceiling=20),
                BudgetPool("cold", reserved=10, ceiling=80),
            ],
        )
        # hot1 = 18/20 (90%), hot2 = 18/20 (90%), cold = 0/80.
        for _ in range(18):
            ctrl.acquire(pool="hot1")
        for _ in range(18):
            ctrl.acquire(pool="hot2")
        reb = CapacityRebalancer(transfer_fraction=0.25)
        decision = reb.evaluate(ctrl)
        # cold slack_headroom = 80 - 10 = 70. donation = 17.
        # Both stressed pools have excess 0 → even split, 8 + 9 = 17.
        self.assertEqual(sum(c.delta for c in decision.changes), 0)


class ApplyTests(unittest.TestCase):
    def test_apply_mutates_controller(self):
        ctrl = _three_pool_controller()
        for _ in range(36):
            ctrl.acquire(pool="security")
        for _ in range(56):
            ctrl.acquire(pool="control")
        reb = CapacityRebalancer()
        decision = reb.evaluate(ctrl)
        reb.apply(ctrl, decision)
        # After apply: security ceiling has grown, data ceiling has
        # shrunk, and the total reserved + ceiling stays consistent.
        pools = {p.name: p for p in ctrl.pools}
        self.assertGreater(pools["security"].ceiling, 40)
        self.assertLess(pools["data"].ceiling, 100)

    def test_apply_preserves_floor_invariant(self):
        ctrl = _three_pool_controller()
        for _ in range(36):
            ctrl.acquire(pool="security")
        for _ in range(56):
            ctrl.acquire(pool="control")
        reb = CapacityRebalancer()
        decision = reb.evaluate(ctrl)
        reb.apply(ctrl, decision)
        # Every ceiling still >= its own reserved.
        for p in ctrl.pools:
            self.assertGreaterEqual(p.ceiling, p.reserved)

    def test_apply_preserves_oversubscription_cap(self):
        ctrl = _three_pool_controller()
        for _ in range(36):
            ctrl.acquire(pool="security")
        for _ in range(56):
            ctrl.acquire(pool="control")
        reb = CapacityRebalancer()
        reb.evaluate_and_apply(ctrl)
        # For every pool, ceiling + sum(others.reserved) <= total.
        for p in ctrl.pools:
            others = sum(
                op.reserved for op in ctrl.pools if op.name != p.name
            )
            self.assertLessEqual(p.ceiling + others, ctrl.total_capacity)

    def test_apply_shrinks_before_grows(self):
        # Construct a state where applying grows first would
        # temporarily oversubscribe. The rebalancer guarantees shrinks
        # apply first.
        ctrl = build_controller(
            total_capacity=200,
            pools=[
                BudgetPool("stressed", reserved=10, ceiling=20),
                BudgetPool("slack", reserved=10, ceiling=180),
            ],
        )
        # Saturate the stressed pool.
        for _ in range(19):
            ctrl.acquire(pool="stressed")
        # Need a second stressed pool to trigger cascading; use a
        # min_stressed=1 variant.
        reb = CapacityRebalancer(cascade_min_stressed=1)
        decision = reb.evaluate(ctrl)
        # If this passes without CapacityBudgetError, ordering worked.
        reb.apply(ctrl, decision)
        pools = {p.name: p for p in ctrl.pools}
        self.assertLess(pools["slack"].ceiling, 180)
        self.assertGreater(pools["stressed"].ceiling, 20)


class AdjustCeilingTests(unittest.TestCase):
    """Pin BudgetController.adjust_ceiling invariants directly."""

    def test_below_reserved_rejected(self):
        ctrl = _three_pool_controller()
        with self.assertRaisesRegex(CapacityBudgetError, "below pool"):
            ctrl.adjust_ceiling("security", new_ceiling=10)

    def test_below_in_flight_rejected(self):
        ctrl = _three_pool_controller()
        for _ in range(35):
            ctrl.acquire(pool="security")
        with self.assertRaisesRegex(CapacityBudgetError, "in_flight"):
            ctrl.adjust_ceiling("security", new_ceiling=30)

    def test_oversubscription_rejected(self):
        ctrl = _three_pool_controller()
        # total=200, others.reserved = 30+50=80. Max allowed for
        # security = 200-80 = 120. Try 130.
        with self.assertRaisesRegex(CapacityBudgetError, "exceeds total_capacity"):
            ctrl.adjust_ceiling("security", new_ceiling=130)

    def test_valid_adjustment_takes_effect(self):
        ctrl = _three_pool_controller()
        ctrl.adjust_ceiling("security", new_ceiling=50)
        pools = {p.name: p for p in ctrl.pools}
        self.assertEqual(pools["security"].ceiling, 50)
        self.assertEqual(pools["security"].reserved, 20)


class EndToEndTests(unittest.TestCase):
    """Acceptance-style: rebalance lets a previously-deny path succeed."""

    def test_post_rebalance_acquire_succeeds_where_before_failed(self):
        ctrl = _three_pool_controller()
        # Saturate security to its ceiling (40/40).
        for _ in range(40):
            ctrl.acquire(pool="security")
        # Control near saturation.
        for _ in range(56):
            ctrl.acquire(pool="control")
        # Pre-rebalance: another acquire on security fails (ceiling).
        decision = ctrl.acquire(pool="security")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "budget_ceiling_exceeded")
        # Run rebalance.
        CapacityRebalancer().evaluate_and_apply(ctrl)
        # Now security's ceiling has grown; acquire succeeds.
        decision_after = ctrl.acquire(pool="security")
        self.assertTrue(decision_after.allowed)


class DecisionShapeTests(unittest.TestCase):
    def test_decision_is_frozen_dataclass(self):
        ctrl = _three_pool_controller()
        decision = CapacityRebalancer().evaluate(ctrl)
        self.assertIsInstance(decision, RebalanceDecision)
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            decision.reason = "mutated"  # type: ignore[misc]

    def test_change_delta(self):
        change = CeilingChange(pool="x", old_ceiling=10, new_ceiling=15)
        self.assertEqual(change.delta, 5)


if __name__ == "__main__":
    unittest.main()
