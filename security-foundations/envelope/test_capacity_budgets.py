"""Tests for capacity budgets (Phase 3 Track B B1/B2 + B3 tenant half)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from capacity_budgets import (
    BudgetController,
    BudgetPool,
    CapacityBudgetError,
    TenantBudget,
    build_controller,
)


class PoolValidationTests(unittest.TestCase):
    def test_empty_name_rejected(self):
        with self.assertRaisesRegex(CapacityBudgetError, "name"):
            BudgetPool(name="", reserved=0, ceiling=0)

    def test_negative_reserved_rejected(self):
        with self.assertRaisesRegex(CapacityBudgetError, "reserved"):
            BudgetPool(name="x", reserved=-1, ceiling=0)

    def test_ceiling_below_reserved_rejected(self):
        with self.assertRaisesRegex(CapacityBudgetError, "ceiling"):
            BudgetPool(name="x", reserved=10, ceiling=5)


class ControllerValidationTests(unittest.TestCase):
    def test_duplicate_pool_rejected(self):
        with self.assertRaisesRegex(CapacityBudgetError, "duplicate pool"):
            BudgetController(
                total_capacity=100,
                pools=(
                    BudgetPool("p", 10, 20),
                    BudgetPool("p", 5, 10),
                ),
            )

    def test_reserved_sum_over_total_rejected(self):
        with self.assertRaisesRegex(CapacityBudgetError, "exceeds total_capacity"):
            BudgetController(
                total_capacity=10,
                pools=(BudgetPool("a", 6, 6), BudgetPool("b", 5, 5)),
            )

    def test_tenant_budget_unknown_pool_rejected(self):
        with self.assertRaisesRegex(CapacityBudgetError, "unknown pool"):
            BudgetController(
                total_capacity=10,
                pools=(BudgetPool("a", 5, 5),),
                tenant_budgets=(
                    TenantBudget(pool="b", tenant="t1", reserve=1, burst=2),
                ),
            )


class FloorGuardTests(unittest.TestCase):
    """The Track B acceptance criterion: data-plane flood cannot
    starve security-critical services."""

    def _three_pool_controller(self) -> BudgetController:
        return build_controller(
            total_capacity=100,
            pools=[
                BudgetPool("security", reserved=20, ceiling=40),
                BudgetPool("control", reserved=30, ceiling=60),
                BudgetPool("data", reserved=50, ceiling=100),
            ],
        )

    def test_data_plane_cannot_consume_security_floor(self):
        ctrl = self._three_pool_controller()
        # Data-plane has reserved=50, ceiling=100. The cross-pool
        # cap is 100 - (security.reserved + control.reserved) = 50.
        # So data-plane can only acquire up to 50 in total despite
        # its own ceiling=100.
        first = ctrl.acquire(pool="data", cost=50)
        self.assertTrue(first.allowed)
        # Even though data's own ceiling is 100, the next request
        # would dip into security's reserved floor.
        second = ctrl.acquire(pool="data", cost=1)
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason_code, "budget_floor_guard")

    def test_security_pool_always_has_its_floor(self):
        ctrl = self._three_pool_controller()
        # Even after data fills its allotment, security can still
        # acquire up to its reserved=20.
        ctrl.acquire(pool="data", cost=50)
        decision = ctrl.acquire(pool="security", cost=20)
        self.assertTrue(decision.allowed)

    def test_pool_can_burst_into_idle_capacity(self):
        # No other pool reserved → pool's own ceiling is the only
        # ceiling.
        ctrl = build_controller(
            total_capacity=100,
            pools=[BudgetPool("only", reserved=10, ceiling=80)],
        )
        decision = ctrl.acquire(pool="only", cost=80)
        self.assertTrue(decision.allowed)

    def test_unknown_pool_rejected(self):
        ctrl = self._three_pool_controller()
        decision = ctrl.acquire(pool="nope")
        self.assertEqual(decision.reason_code, "budget_pool_unknown")

    def test_release_restores_capacity(self):
        ctrl = self._three_pool_controller()
        ctrl.acquire(pool="data", cost=50)
        # Now blocked.
        self.assertFalse(ctrl.acquire(pool="data", cost=1).allowed)
        # Release 30; should be able to acquire up to 30 more.
        ctrl.release(pool="data", cost=30)
        self.assertTrue(ctrl.acquire(pool="data", cost=30).allowed)


class CeilingTests(unittest.TestCase):
    def test_ceiling_enforced_independently_of_floor(self):
        # Single pool — ceiling lower than reserved-sum guard, so
        # ceiling fires first.
        ctrl = build_controller(
            total_capacity=200,
            pools=[BudgetPool("only", reserved=10, ceiling=50)],
        )
        ctrl.acquire(pool="only", cost=50)
        decision = ctrl.acquire(pool="only", cost=1)
        self.assertEqual(decision.reason_code, "budget_ceiling_exceeded")


class WorkTokenTests(unittest.TestCase):
    def test_high_cost_request_burns_ceiling_faster(self):
        # Mirrors B2's "work-token / equivalent throttles for
        # abuse-heavy identities" — expensive calls cost more, so
        # a flood of expensive calls hits the ceiling faster than
        # a flood of cheap calls.
        ctrl = build_controller(
            total_capacity=100,
            pools=[BudgetPool("p", reserved=10, ceiling=10)],
        )
        self.assertTrue(ctrl.acquire(pool="p", cost=8).allowed)
        # Cheap call still fits.
        self.assertTrue(ctrl.acquire(pool="p", cost=2).allowed)
        # No more room.
        self.assertFalse(ctrl.acquire(pool="p", cost=1).allowed)

    def test_zero_cost_rejected(self):
        ctrl = build_controller(
            total_capacity=10,
            pools=[BudgetPool("p", reserved=0, ceiling=10)],
        )
        with self.assertRaisesRegex(CapacityBudgetError, "cost"):
            ctrl.acquire(pool="p", cost=0)


class TenantFairnessTests(unittest.TestCase):
    def test_tenant_burst_caps_per_tenant_usage(self):
        ctrl = build_controller(
            total_capacity=100,
            pools=[BudgetPool("p", reserved=10, ceiling=100)],
            tenant_budgets=[
                TenantBudget(pool="p", tenant="t-noisy", reserve=10, burst=20),
            ],
        )
        # Noisy tenant can hit burst=20 but no more.
        self.assertTrue(ctrl.acquire(pool="p", tenant="t-noisy", cost=20).allowed)
        decision = ctrl.acquire(pool="p", tenant="t-noisy", cost=1)
        self.assertEqual(decision.reason_code, "budget_tenant_burst_exceeded")

    def test_other_tenant_unaffected(self):
        ctrl = build_controller(
            total_capacity=100,
            pools=[BudgetPool("p", reserved=10, ceiling=100)],
            tenant_budgets=[
                TenantBudget(pool="p", tenant="t-noisy", reserve=10, burst=20),
                TenantBudget(pool="p", tenant="t-quiet", reserve=10, burst=20),
            ],
        )
        # Saturate noisy tenant.
        ctrl.acquire(pool="p", tenant="t-noisy", cost=20)
        # Quiet tenant can still acquire up to their own burst.
        self.assertTrue(ctrl.acquire(pool="p", tenant="t-quiet", cost=15).allowed)

    def test_tenant_release_restores_budget(self):
        ctrl = build_controller(
            total_capacity=100,
            pools=[BudgetPool("p", reserved=10, ceiling=100)],
            tenant_budgets=[
                TenantBudget(pool="p", tenant="t1", reserve=5, burst=10),
            ],
        )
        ctrl.acquire(pool="p", tenant="t1", cost=10)
        ctrl.release(pool="p", tenant="t1", cost=5)
        self.assertTrue(ctrl.acquire(pool="p", tenant="t1", cost=5).allowed)


class SnapshotTests(unittest.TestCase):
    def test_snapshot_reflects_in_flight(self):
        ctrl = build_controller(
            total_capacity=100,
            pools=[
                BudgetPool("a", 10, 50),
                BudgetPool("b", 10, 50),
            ],
        )
        ctrl.acquire(pool="a", cost=15)
        ctrl.acquire(pool="b", cost=5)
        snap = ctrl.snapshot()
        self.assertEqual(snap.get("a"), 15)
        self.assertEqual(snap.get("b"), 5)


if __name__ == "__main__":
    unittest.main()
