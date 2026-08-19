"""Automatic capacity rebalancer v0 (Phase 3 B3).

Phase 3 Track B B3 calls for "Automatic rebalance on cascading
throttle detection." The capacity-budgets v0 shipped
:meth:`BudgetController.snapshot` / :meth:`tenant_snapshot` as the
read-only surface for live consumption. This module is the
reactive controller on top of those snapshots.

How it works
------------
:class:`CapacityRebalancer` reads a :class:`BudgetController`'s
snapshots, classifies **pools** and (when configured)
**tenants** as ``stressed`` (utilization at or above
``stress_threshold``) or ``slack`` (at or below
``slack_threshold``), and reports whether each half is
*cascading*: at least ``cascade_min_stressed`` units stressed
AND at least one slack unit to draw from.

When cascading, the rebalancer drafts a :class:`RebalanceDecision`:
take ``transfer_fraction`` of each slack unit's unused-headroom
and donate it to the stressed units in proportion to their
excess demand.

- Pools: headroom is ``ceiling - max(reserved, in_flight)``.
  Donations are constrained so the donor's NEW ceiling never
  falls below its ``reserved`` floor or its current in-flight
  count, and recipient ceilings stay under the cross-pool
  oversubscription cap.
- Tenants: headroom is ``burst - max(reserve, in_flight)``,
  read from :meth:`BudgetController.tenant_snapshot`. Donations
  are constrained so the donor's NEW burst never falls below
  that tenant's ``reserve`` or current in-flight. Reserved
  stays put; only burst headroom moves. Callers that never
  configure ``tenant_budgets`` see an empty tenant half
  (no-op).

The decision is *advisory* by default. :meth:`apply` mutates the
controller in place via :meth:`BudgetController.adjust_ceiling`
and :meth:`BudgetController.adjust_tenant_burst`, so operators
can run a planning loop (``evaluate`` -> review -> ``apply``)
or just call :meth:`evaluate_and_apply` directly.

Invariants preserved on every apply
-----------------------------------
- Non-preemptible floor: a pool's ceiling never falls below its own
  ``reserved``.
- Cross-pool oversubscription cap:
  ``ceiling + sum(other_pools.reserved) <= total_capacity``.
- No retroactive overcommit: a pool's ceiling never falls below the
  pool's current in-flight (operators must drain first if they want
  a deeper shrink).
- Tenant burst floor: a tenant's burst never falls below that
  tenant's ``reserve``.
- Tenant no-retroactive-overcommit: a tenant's burst never falls
  below that tenant's current in-flight.
- ``burst >= reserve`` remains the :class:`TenantBudget` invariant.

These are the same invariants
:meth:`BudgetController.adjust_ceiling` and
:meth:`BudgetController.adjust_tenant_burst` enforce; the
rebalancer just calls into them.

Out of scope for v0
-------------------
- Predictive / forecasting models. v0 reacts to current snapshots
  only.
- Reserved redistribution. Reserved is treated as a permanent
  declaration of intent; only burst headroom (the gap between
  reserved and ceiling, or reserve and burst) moves.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from .capacity_budgets import BudgetController, CapacityBudgetError

K = TypeVar("K")


class RebalancerError(ValueError):
    """Raised when rebalancer inputs violate v0 invariants."""


@dataclass(frozen=True)
class PoolUtilization:
    name: str
    in_flight: int
    ceiling: int
    reserved: int

    @property
    def utilization(self) -> float:
        if self.ceiling <= 0:
            return 0.0
        return self.in_flight / self.ceiling

    @property
    def slack_headroom(self) -> int:
        """How much ceiling can be removed without dropping below
        ``max(reserved, in_flight)`` — the donor-side budget."""
        floor = max(self.reserved, self.in_flight)
        return max(0, self.ceiling - floor)

    @property
    def stress_excess(self) -> int:
        """How much ceiling the pool is short relative to demand. Used
        as the share key when distributing donations among stressed
        pools."""
        return max(0, self.in_flight - self.ceiling)


@dataclass(frozen=True)
class TenantUtilization:
    pool: str
    tenant: str
    in_flight: int
    burst: int
    reserve: int

    @property
    def utilization(self) -> float:
        if self.burst <= 0:
            return 0.0
        return self.in_flight / self.burst

    @property
    def slack_headroom(self) -> int:
        """How much burst can be removed without dropping below
        ``max(reserve, in_flight)`` — the donor-side budget."""
        floor = max(self.reserve, self.in_flight)
        return max(0, self.burst - floor)

    @property
    def stress_excess(self) -> int:
        """How much burst the tenant is short relative to demand. Used
        as the share key when distributing donations among stressed
        tenants."""
        return max(0, self.in_flight - self.burst)


@dataclass(frozen=True)
class RebalanceSignals:
    stressed: tuple[PoolUtilization, ...]
    slack: tuple[PoolUtilization, ...]
    cascading: bool
    tenant_stressed: tuple[TenantUtilization, ...] = ()
    tenant_slack: tuple[TenantUtilization, ...] = ()
    tenant_cascading: bool = False


@dataclass(frozen=True)
class CeilingChange:
    pool: str
    old_ceiling: int
    new_ceiling: int

    @property
    def delta(self) -> int:
        return self.new_ceiling - self.old_ceiling


@dataclass(frozen=True)
class BurstChange:
    pool: str
    tenant: str
    old_burst: int
    new_burst: int

    @property
    def delta(self) -> int:
        return self.new_burst - self.old_burst


@dataclass(frozen=True)
class RebalanceDecision:
    signals: RebalanceSignals
    changes: tuple[CeilingChange, ...]
    reason: str
    tenant_changes: tuple[BurstChange, ...] = ()

    @property
    def is_noop(self) -> bool:
        return not self.changes and not self.tenant_changes


def _allocate_transfer(
    slack_items: Sequence[tuple[K, int]],
    stressed_items: Sequence[tuple[K, int]],
    transfer_fraction: float,
) -> tuple[dict[K, int], dict[K, int], int]:
    """Share ``transfer_fraction`` of slack headroom across stressed items.

    ``slack_items`` is ``(key, slack_headroom)``; ``stressed_items``
    is ``(key, stress_excess)``. Returns
    ``(donors, recipients, total_donation)``. Empty when nothing
    is transferable. Recipients share proportionally by
    ``stress_excess``, or evenly when every excess is 0.
    """
    donors: dict[K, int] = {}
    total_donation = 0
    for key, headroom in slack_items:
        donation = int(headroom * transfer_fraction)
        if donation > 0:
            donors[key] = donation
            total_donation += donation
    if total_donation == 0:
        return {}, {}, 0

    recipients: dict[K, int] = {}
    excess_total = sum(excess for _, excess in stressed_items)
    if excess_total > 0:
        allocated = 0
        for key, excess in stressed_items:
            share = int(total_donation * excess / excess_total)
            if share > 0:
                recipients[key] = share
                allocated += share
        remainder = total_donation - allocated
        if remainder > 0 and stressed_items:
            top_key = max(stressed_items, key=lambda item: item[1])[0]
            recipients[top_key] = recipients.get(top_key, 0) + remainder
    else:
        per = total_donation // len(stressed_items)
        rem = total_donation - per * len(stressed_items)
        for i, (key, _) in enumerate(stressed_items):
            share = per + (1 if i < rem else 0)
            if share > 0:
                recipients[key] = share
    return donors, recipients, total_donation


@dataclass
class CapacityRebalancer:
    """Reactive controller atop :class:`BudgetController`."""

    stress_threshold: float = 0.85
    slack_threshold: float = 0.30
    cascade_min_stressed: int = 2
    transfer_fraction: float = 0.20

    def __post_init__(self) -> None:
        for name, value in (
            ("stress_threshold", self.stress_threshold),
            ("slack_threshold", self.slack_threshold),
            ("transfer_fraction", self.transfer_fraction),
        ):
            if not isinstance(value, (int, float)):
                raise RebalancerError(
                    f"{name} must be a number: {value!r}"
                )
            if not (0.0 < value <= 1.0):
                raise RebalancerError(
                    f"{name} must be in (0, 1]: {value!r}"
                )
        if self.slack_threshold >= self.stress_threshold:
            raise RebalancerError(
                f"slack_threshold ({self.slack_threshold}) must be "
                f"< stress_threshold ({self.stress_threshold})"
            )
        if not isinstance(self.cascade_min_stressed, int) or self.cascade_min_stressed < 1:
            raise RebalancerError(
                f"cascade_min_stressed must be a positive int: "
                f"{self.cascade_min_stressed!r}"
            )

    # ------- read paths -------

    def signals(self, controller: BudgetController) -> RebalanceSignals:
        snap = controller.snapshot()
        stressed: list[PoolUtilization] = []
        slack: list[PoolUtilization] = []
        for pool in controller.pools:
            util = PoolUtilization(
                name=pool.name,
                in_flight=snap.get(pool.name, 0),
                ceiling=pool.ceiling,
                reserved=pool.reserved,
            )
            if util.utilization >= self.stress_threshold:
                stressed.append(util)
            elif util.utilization <= self.slack_threshold:
                slack.append(util)
        cascading = (
            len(stressed) >= self.cascade_min_stressed and len(slack) >= 1
        )

        tenant_snap = controller.tenant_snapshot()
        tenant_stressed: list[TenantUtilization] = []
        tenant_slack: list[TenantUtilization] = []
        for tb in controller.tenant_budgets:
            t_util = TenantUtilization(
                pool=tb.pool,
                tenant=tb.tenant,
                in_flight=tenant_snap.get((tb.pool, tb.tenant), 0),
                burst=tb.burst,
                reserve=tb.reserve,
            )
            if t_util.utilization >= self.stress_threshold:
                tenant_stressed.append(t_util)
            elif t_util.utilization <= self.slack_threshold:
                tenant_slack.append(t_util)
        tenant_cascading = (
            len(tenant_stressed) >= self.cascade_min_stressed
            and len(tenant_slack) >= 1
        )
        return RebalanceSignals(
            stressed=tuple(stressed),
            slack=tuple(slack),
            cascading=cascading,
            tenant_stressed=tuple(tenant_stressed),
            tenant_slack=tuple(tenant_slack),
            tenant_cascading=tenant_cascading,
        )

    def evaluate(self, controller: BudgetController) -> RebalanceDecision:
        sigs = self.signals(controller)
        pool_changes, pool_reason, pool_donation = self._evaluate_pools(
            controller, sigs
        )
        tenant_changes, tenant_reason, tenant_donation = (
            self._evaluate_tenants(controller, sigs)
        )

        if not pool_changes and not tenant_changes:
            if not sigs.cascading and not sigs.tenant_cascading:
                reason = "no cascading throttle detected"
            elif pool_reason and not tenant_reason:
                reason = pool_reason
            elif tenant_reason and not pool_reason:
                reason = tenant_reason
            else:
                reason = (
                    pool_reason
                    or tenant_reason
                    or (
                        "cascading detected but ceilings already balanced "
                        "against floor / oversubscription caps"
                    )
                )
            return RebalanceDecision(
                signals=sigs,
                changes=(),
                tenant_changes=(),
                reason=reason,
            )

        parts: list[str] = []
        if pool_changes:
            parts.append(
                pool_reason
                or (
                    f"cascading throttle: {len(sigs.stressed)} stressed, "
                    f"{len(sigs.slack)} slack; redistributed "
                    f"{pool_donation} units of ceiling headroom"
                )
            )
        if tenant_changes:
            parts.append(
                tenant_reason
                or (
                    f"cascading tenant stress: "
                    f"{len(sigs.tenant_stressed)} stressed, "
                    f"{len(sigs.tenant_slack)} slack; redistributed "
                    f"{tenant_donation} units of burst headroom"
                )
            )
        return RebalanceDecision(
            signals=sigs,
            changes=pool_changes,
            tenant_changes=tenant_changes,
            reason="; ".join(parts),
        )

    def _evaluate_pools(
        self, controller: BudgetController, sigs: RebalanceSignals
    ) -> tuple[tuple[CeilingChange, ...], str | None, int]:
        if not sigs.cascading:
            return (), None, 0

        donors, recipients, total_donation = _allocate_transfer(
            [(s.name, s.slack_headroom) for s in sigs.slack],
            [(p.name, p.stress_excess) for p in sigs.stressed],
            self.transfer_fraction,
        )
        if total_donation == 0:
            return (), "slack pools have no transferable headroom", 0

        changes: list[CeilingChange] = []
        snap = controller.snapshot()
        for name, donation in donors.items():
            pool = _pool_by_name(controller, name)
            new_ceiling = pool.ceiling - donation
            # Defensive lower bound: never below max(reserved, in_flight).
            new_ceiling = max(new_ceiling, pool.reserved, snap.get(name, 0))
            if new_ceiling != pool.ceiling:
                changes.append(
                    CeilingChange(
                        pool=name,
                        old_ceiling=pool.ceiling,
                        new_ceiling=new_ceiling,
                    )
                )
        others_reserved_excluding = {
            p.name: sum(
                op.reserved for op in controller.pools if op.name != p.name
            )
            for p in controller.pools
        }
        for name, share in recipients.items():
            pool = _pool_by_name(controller, name)
            max_for_pool = (
                controller.total_capacity - others_reserved_excluding[name]
            )
            new_ceiling = min(pool.ceiling + share, max_for_pool)
            if new_ceiling != pool.ceiling:
                changes.append(
                    CeilingChange(
                        pool=name,
                        old_ceiling=pool.ceiling,
                        new_ceiling=new_ceiling,
                    )
                )

        if not changes:
            return (
                (),
                (
                    "cascading detected but ceilings already balanced "
                    "against floor / oversubscription caps"
                ),
                total_donation,
            )
        return (
            tuple(changes),
            (
                f"cascading throttle: {len(sigs.stressed)} stressed, "
                f"{len(sigs.slack)} slack; redistributed "
                f"{total_donation} units of ceiling headroom"
            ),
            total_donation,
        )

    def _evaluate_tenants(
        self, controller: BudgetController, sigs: RebalanceSignals
    ) -> tuple[tuple[BurstChange, ...], str | None, int]:
        if not sigs.tenant_cascading:
            return (), None, 0

        donors, recipients, total_donation = _allocate_transfer(
            [
                ((s.pool, s.tenant), s.slack_headroom)
                for s in sigs.tenant_slack
            ],
            [
                ((p.pool, p.tenant), p.stress_excess)
                for p in sigs.tenant_stressed
            ],
            self.transfer_fraction,
        )
        if total_donation == 0:
            return (), "slack tenants have no transferable headroom", 0

        tenant_snap = controller.tenant_snapshot()
        changes: list[BurstChange] = []
        for (pool, tenant), donation in donors.items():
            tb = _tenant_budget_by_key(controller, pool, tenant)
            new_burst = tb.burst - donation
            new_burst = max(
                new_burst,
                tb.reserve,
                tenant_snap.get((pool, tenant), 0),
            )
            if new_burst != tb.burst:
                changes.append(
                    BurstChange(
                        pool=pool,
                        tenant=tenant,
                        old_burst=tb.burst,
                        new_burst=new_burst,
                    )
                )
        for (pool, tenant), share in recipients.items():
            tb = _tenant_budget_by_key(controller, pool, tenant)
            new_burst = tb.burst + share
            if new_burst != tb.burst:
                changes.append(
                    BurstChange(
                        pool=pool,
                        tenant=tenant,
                        old_burst=tb.burst,
                        new_burst=new_burst,
                    )
                )

        if not changes:
            return (
                (),
                (
                    "cascading tenant stress detected but bursts "
                    "already balanced against reserve / in-flight floors"
                ),
                total_donation,
            )
        return (
            tuple(changes),
            (
                f"cascading tenant stress: "
                f"{len(sigs.tenant_stressed)} stressed, "
                f"{len(sigs.tenant_slack)} slack; redistributed "
                f"{total_donation} units of burst headroom"
            ),
            total_donation,
        )

    # ------- write paths -------

    def apply(
        self, controller: BudgetController, decision: RebalanceDecision
    ) -> None:
        """Apply ``decision`` to ``controller``.

        Donor reductions are applied BEFORE recipient increases so
        the cross-pool oversubscription guard in
        :meth:`BudgetController.adjust_ceiling` sees the most-relaxed
        intermediate state. Tenant burst shrinks apply before grows
        for the same reason (even though tenant burst has no
        cross-tenant cap). If any single change is rejected by the
        controller's invariants, the partial state is left as-is and
        the underlying :class:`CapacityBudgetError` is re-raised —
        operators investigating a transient state should consult
        :meth:`BudgetController.snapshot` /
        :meth:`BudgetController.tenant_snapshot` to see what landed.
        """
        shrinks = [c for c in decision.changes if c.delta < 0]
        grows = [c for c in decision.changes if c.delta > 0]
        for change in (*shrinks, *grows):
            controller.adjust_ceiling(change.pool, change.new_ceiling)

        tenant_shrinks = [c for c in decision.tenant_changes if c.delta < 0]
        tenant_grows = [c for c in decision.tenant_changes if c.delta > 0]
        for change in (*tenant_shrinks, *tenant_grows):
            controller.adjust_tenant_burst(
                change.pool, change.tenant, change.new_burst
            )

    def evaluate_and_apply(
        self, controller: BudgetController
    ) -> RebalanceDecision:
        decision = self.evaluate(controller)
        if not decision.is_noop:
            self.apply(controller, decision)
        return decision


def _pool_by_name(controller: BudgetController, name: str):
    for p in controller.pools:
        if p.name == name:
            return p
    raise CapacityBudgetError(f"unknown pool: {name!r}")


def _tenant_budget_by_key(controller: BudgetController, pool: str, tenant: str):
    for tb in controller.tenant_budgets:
        if tb.pool == pool and tb.tenant == tenant:
            return tb
    raise CapacityBudgetError(f"unknown tenant_budget: {(pool, tenant)!r}")
