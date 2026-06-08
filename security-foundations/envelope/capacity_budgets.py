"""Capacity budgets v0 (Phase 3 Track B B1 + B2 + partial B3).

Closes B1 ("Resource Budget Partitioning") and B2 ("Anti-Amplification
Controls") at the in-process primitive level, plus the per-tenant
half of B3 ("Fairness Controller"):

- "Separate pools for control-plane and data-plane." —
  :class:`BudgetController` admits requests against named
  :class:`BudgetPool` records. Operators define one pool per
  workload class (e.g. ``security-critical``, ``control-plane``,
  ``data-plane``) and route each subsystem's :meth:`acquire` calls
  to the appropriate pool.
- "Security-critical services get non-preemptible floor." — every
  :class:`BudgetPool` carries a ``reserved`` allocation that is
  always held aside from the cross-pool total. Even when a
  security-critical pool is idle, no other pool can burst into its
  reserved capacity. That's what makes the floor non-preemptible
  and is the invariant behind the Track B acceptance criterion:
  "Data-plane flood cannot starve revocation/authZ/policy services."
- "Bounded expensive verification paths" + "Work-token / equivalent
  throttles for abuse-heavy identities." — every :meth:`acquire`
  takes a ``cost`` parameter. Operators charge expensive routes a
  higher cost so that abuse-heavy identities burn ceiling capacity
  faster. The cost API is the work-token equivalent.
- "Tenant reserve pools and burst ceilings." — :class:`TenantBudget`
  records carry per-(pool, tenant) ``reserve`` and ``burst``
  allowances. A tenant flooding a pool stops at their personal
  ``burst`` ceiling, so cascading data-plane abuse from one tenant
  can't drain the whole pool's burst headroom.

Out of scope for v0
-------------------
- "Automatic rebalance on cascading throttle detection." That's a
  reactive controller on top of this primitive. v0 exposes
  consumption snapshots (:meth:`BudgetController.snapshot`) so a
  follow-up rebalancer can read them and adjust budgets.
- Distributed enforcement across cluster nodes. The controller is
  in-process; operators wanting cluster-wide consistency place a
  central admission service behind this primitive or back it with
  a distributed counter store.
- Pre-emption / cancellation. v0 only refuses NEW acquisitions; it
  doesn't take running work away.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from dataclasses import replace as _dc_replace

from deny_reason import DenyReason


class CapacityBudgetError(ValueError):
    """Raised when budget inputs violate v0 invariants."""


@dataclass(frozen=True)
class BudgetPool:
    name: str
    reserved: int   # always-available capacity, even when idle
    ceiling: int    # max capacity (incl. burst above reserved)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise CapacityBudgetError("name must be a non-empty string")
        if not isinstance(self.reserved, int) or self.reserved < 0:
            raise CapacityBudgetError(
                f"reserved must be a non-negative int: {self.reserved!r}"
            )
        if not isinstance(self.ceiling, int) or self.ceiling < self.reserved:
            raise CapacityBudgetError(
                f"ceiling ({self.ceiling}) must be >= reserved ({self.reserved})"
            )


@dataclass(frozen=True)
class TenantBudget:
    pool: str
    tenant: str
    reserve: int
    burst: int

    def __post_init__(self) -> None:
        if not isinstance(self.pool, str) or not self.pool:
            raise CapacityBudgetError("pool must be a non-empty string")
        if not isinstance(self.tenant, str) or not self.tenant:
            raise CapacityBudgetError("tenant must be a non-empty string")
        if not isinstance(self.reserve, int) or self.reserve < 0:
            raise CapacityBudgetError(
                f"reserve must be a non-negative int: {self.reserve!r}"
            )
        if not isinstance(self.burst, int) or self.burst < self.reserve:
            raise CapacityBudgetError(
                f"burst ({self.burst}) must be >= reserve ({self.reserve})"
            )


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str
    reason_code: str = ""


@dataclass
class BudgetController:
    total_capacity: int
    pools: tuple[BudgetPool, ...]
    tenant_budgets: tuple[TenantBudget, ...] = field(default_factory=tuple)
    _in_flight_pool: dict[str, int] = field(default_factory=dict)
    _in_flight_tenant: dict[tuple[str, str], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.total_capacity, int) or self.total_capacity < 0:
            raise CapacityBudgetError(
                f"total_capacity must be non-negative int: {self.total_capacity!r}"
            )
        if not isinstance(self.pools, tuple):
            raise CapacityBudgetError("pools must be a tuple")
        seen_pool: set[str] = set()
        for index, p in enumerate(self.pools):
            if not isinstance(p, BudgetPool):
                raise CapacityBudgetError(
                    f"pools[{index}] must be a BudgetPool"
                )
            if p.name in seen_pool:
                raise CapacityBudgetError(f"duplicate pool name: {p.name!r}")
            seen_pool.add(p.name)

        reserved_sum = sum(p.reserved for p in self.pools)
        if reserved_sum > self.total_capacity:
            raise CapacityBudgetError(
                f"sum of pool reserved ({reserved_sum}) exceeds "
                f"total_capacity ({self.total_capacity})"
            )

        if not isinstance(self.tenant_budgets, tuple):
            raise CapacityBudgetError("tenant_budgets must be a tuple")
        seen_tb: set[tuple[str, str]] = set()
        for index, tb in enumerate(self.tenant_budgets):
            if not isinstance(tb, TenantBudget):
                raise CapacityBudgetError(
                    f"tenant_budgets[{index}] must be a TenantBudget"
                )
            if tb.pool not in seen_pool:
                raise CapacityBudgetError(
                    f"tenant_budgets[{index}] references unknown pool "
                    f"{tb.pool!r}"
                )
            key = (tb.pool, tb.tenant)
            if key in seen_tb:
                raise CapacityBudgetError(
                    f"duplicate tenant_budget: {key!r}"
                )
            seen_tb.add(key)

    # ----- helpers -----

    def _pool_by_name(self, name: str) -> BudgetPool | None:
        for p in self.pools:
            if p.name == name:
                return p
        return None

    def _tenant_budget(self, pool: str, tenant: str) -> TenantBudget | None:
        for tb in self.tenant_budgets:
            if tb.pool == pool and tb.tenant == tenant:
                return tb
        return None

    # ----- API -----

    def acquire(
        self,
        *,
        pool: str,
        cost: int = 1,
        tenant: str | None = None,
    ) -> BudgetDecision:
        if not isinstance(cost, int) or cost < 1:
            raise CapacityBudgetError(
                f"cost must be a positive int: {cost!r}"
            )

        p = self._pool_by_name(pool)
        if p is None:
            return BudgetDecision(
                allowed=False,
                reason=f"unknown pool: {pool!r}",
                reason_code=DenyReason.BUDGET_POOL_UNKNOWN.value,
            )

        current_pool = self._in_flight_pool.get(pool, 0)
        if current_pool + cost > p.ceiling:
            return BudgetDecision(
                allowed=False,
                reason=(
                    f"pool {pool!r} ceiling exceeded: "
                    f"in_flight={current_pool}, cost={cost}, ceiling={p.ceiling}"
                ),
                reason_code=DenyReason.BUDGET_CEILING_EXCEEDED.value,
            )

        # Non-preemptible floor: this pool may burst above its
        # ``reserved`` only into capacity that is NOT another pool's
        # reserved. Even if other pools are idle, their reserved is
        # held aside.
        if current_pool + cost > p.reserved:
            others_reserved = sum(
                op.reserved for op in self.pools if op.name != pool
            )
            max_for_pool = self.total_capacity - others_reserved
            if current_pool + cost > max_for_pool:
                return BudgetDecision(
                    allowed=False,
                    reason=(
                        f"granting cost={cost} to pool {pool!r} would "
                        f"violate other pools' reserved floors "
                        f"({current_pool}+{cost} > "
                        f"total_capacity({self.total_capacity})"
                        f"-other_reserved({others_reserved}))"
                    ),
                    reason_code=DenyReason.BUDGET_FLOOR_GUARD.value,
                )

        # Per-tenant burst check (only when a tenant is supplied AND
        # an explicit TenantBudget exists for that (pool, tenant)).
        tb_key: tuple[str, str] | None = None
        if tenant is not None:
            tb = self._tenant_budget(pool, tenant)
            if tb is not None:
                current_tenant = self._in_flight_tenant.get((pool, tenant), 0)
                if current_tenant + cost > tb.burst:
                    return BudgetDecision(
                        allowed=False,
                        reason=(
                            f"tenant {tenant!r} burst exceeded in pool "
                            f"{pool!r}: in_flight={current_tenant}, "
                            f"cost={cost}, burst={tb.burst}"
                        ),
                        reason_code=(
                            DenyReason.BUDGET_TENANT_BURST_EXCEEDED.value
                        ),
                    )
                tb_key = (pool, tenant)

        self._in_flight_pool[pool] = current_pool + cost
        if tb_key is not None:
            self._in_flight_tenant[tb_key] = (
                self._in_flight_tenant.get(tb_key, 0) + cost
            )
        return BudgetDecision(allowed=True, reason="ok", reason_code="ok")

    def release(
        self,
        *,
        pool: str,
        cost: int = 1,
        tenant: str | None = None,
    ) -> None:
        if not isinstance(cost, int) or cost < 1:
            raise CapacityBudgetError(
                f"cost must be a positive int: {cost!r}"
            )
        p = self._pool_by_name(pool)
        if p is None:
            raise CapacityBudgetError(f"unknown pool: {pool!r}")
        current = self._in_flight_pool.get(pool, 0)
        if cost > current:
            raise CapacityBudgetError(
                f"release of cost={cost} exceeds pool {pool!r} "
                f"in_flight={current}"
            )
        self._in_flight_pool[pool] = current - cost

        if tenant is not None:
            tb = self._tenant_budget(pool, tenant)
            if tb is not None:
                key = (pool, tenant)
                ct = self._in_flight_tenant.get(key, 0)
                if cost > ct:
                    raise CapacityBudgetError(
                        f"release of cost={cost} exceeds tenant "
                        f"{tenant!r} in pool {pool!r} in_flight={ct}"
                    )
                self._in_flight_tenant[key] = ct - cost

    def snapshot(self) -> dict[str, int]:
        """Return a copy of current pool consumption.

        Operators in a follow-up rebalancer read this to detect
        cascading throttling and trigger capacity reallocation.
        """
        return dict(self._in_flight_pool)

    def tenant_snapshot(self) -> dict[tuple[str, str], int]:
        return dict(self._in_flight_tenant)

    def adjust_ceiling(self, pool: str, new_ceiling: int) -> None:
        """Replace ``pool``'s ceiling with ``new_ceiling`` in place.

        Preserves ``reserved`` and any in-flight counters. Raises
        :class:`CapacityBudgetError` if:
        - ``pool`` is unknown
        - ``new_ceiling < pool.reserved`` (would violate this pool's
          own floor guarantee)
        - ``new_ceiling`` plus the sum of OTHER pools' reserved would
          exceed ``total_capacity`` (would oversubscribe the system)
        - ``new_ceiling`` is below the pool's current in-flight count
          (would create an illegally-overcommitted controller; the
          rebalancer should drain first)

        The rebalancer in :mod:`capacity_rebalancer` is the
        intended caller; direct operators should normally use it
        rather than mutating ceilings ad hoc.
        """
        if not isinstance(new_ceiling, int) or new_ceiling < 0:
            raise CapacityBudgetError(
                f"new_ceiling must be a non-negative int: {new_ceiling!r}"
            )
        existing = self._pool_by_name(pool)
        if existing is None:
            raise CapacityBudgetError(f"unknown pool: {pool!r}")
        if new_ceiling < existing.reserved:
            raise CapacityBudgetError(
                f"new_ceiling ({new_ceiling}) below pool {pool!r} "
                f"reserved ({existing.reserved})"
            )
        in_flight = self._in_flight_pool.get(pool, 0)
        if new_ceiling < in_flight:
            raise CapacityBudgetError(
                f"new_ceiling ({new_ceiling}) below pool {pool!r} "
                f"current in_flight ({in_flight}); drain first"
            )
        others_reserved = sum(
            p.reserved for p in self.pools if p.name != pool
        )
        if new_ceiling + others_reserved > self.total_capacity:
            raise CapacityBudgetError(
                f"new_ceiling ({new_ceiling}) + other pools' reserved "
                f"({others_reserved}) exceeds total_capacity "
                f"({self.total_capacity})"
            )
        # Replace the BudgetPool entry in the pools tuple.
        new_pools: list[BudgetPool] = []
        for p in self.pools:
            if p.name == pool:
                new_pools.append(_dc_replace(p, ceiling=new_ceiling))
            else:
                new_pools.append(p)
        self.pools = tuple(new_pools)


def build_controller(
    *,
    total_capacity: int,
    pools: Iterable[BudgetPool],
    tenant_budgets: Iterable[TenantBudget] = (),
) -> BudgetController:
    """Convenience constructor that materializes iterables into tuples."""
    return BudgetController(
        total_capacity=total_capacity,
        pools=tuple(pools),
        tenant_budgets=tuple(tenant_budgets),
    )
