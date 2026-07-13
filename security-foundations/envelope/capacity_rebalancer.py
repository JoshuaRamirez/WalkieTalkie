"""Automatic capacity rebalancer v0 (Phase 3 B3 deferred half).

Phase 3 Track B B3 calls for "Automatic rebalance on cascading
throttle detection." The capacity-budgets v0 (PR #43) shipped
:meth:`BudgetController.snapshot` / :meth:`tenant_snapshot` as the
read-only surface for live consumption, with the reactive
controller documented as deferred. This module is that controller.

How it works
------------
:class:`CapacityRebalancer` reads a :class:`BudgetController`'s
snapshot, classifies pools as ``stressed`` (utilization at or above
``stress_threshold``) or ``slack`` (at or below ``slack_threshold``),
and reports whether the system is *cascading*: at least
``cascade_min_stressed`` pools stressed AND at least one slack pool
to draw from.

When cascading, the rebalancer drafts a :class:`RebalanceDecision`:
take ``transfer_fraction`` of each slack pool's unused-headroom
(``ceiling - max(reserved, in_flight)``) and donate it to the
stressed pools in proportion to their excess demand. Donations are
constrained so the donor's NEW ceiling never falls below its
``reserved`` floor or its current in-flight count.

The decision is *advisory* by default. :meth:`apply` mutates the
controller in place via :meth:`BudgetController.adjust_ceiling`, so
operators can run a planning loop (``evaluate`` -> review ->
``apply``) or just call :meth:`evaluate_and_apply` directly.

Invariants preserved on every apply
-----------------------------------
- Non-preemptible floor: a pool's ceiling never falls below its own
  ``reserved``.
- Cross-pool oversubscription cap:
  ``ceiling + sum(other_pools.reserved) <= total_capacity``.
- No retroactive overcommit: a pool's ceiling never falls below the
  pool's current in-flight (operators must drain first if they want
  a deeper shrink).

These are the same invariants :meth:`BudgetController.adjust_ceiling`
enforces; the rebalancer just calls into it.

Out of scope for v0
-------------------
- Tenant-level rebalancing. v0 only adjusts pool ceilings. Tenant
  burst caps stay where the operator set them; a follow-up can
  extend the same heuristic to ``TenantBudget.burst``.
- Predictive / forecasting models. v0 reacts to current snapshots
  only.
- Reserved redistribution. Reserved is treated as a permanent
  declaration of intent; only burst headroom (the gap between
  reserved and ceiling) moves.
"""

from __future__ import annotations

from dataclasses import dataclass

from capacity_budgets import BudgetController, CapacityBudgetError


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
class RebalanceSignals:
    stressed: tuple[PoolUtilization, ...]
    slack: tuple[PoolUtilization, ...]
    cascading: bool


@dataclass(frozen=True)
class CeilingChange:
    pool: str
    old_ceiling: int
    new_ceiling: int

    @property
    def delta(self) -> int:
        return self.new_ceiling - self.old_ceiling


@dataclass(frozen=True)
class RebalanceDecision:
    signals: RebalanceSignals
    changes: tuple[CeilingChange, ...]
    reason: str

    @property
    def is_noop(self) -> bool:
        return not self.changes


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
        return RebalanceSignals(
            stressed=tuple(stressed),
            slack=tuple(slack),
            cascading=cascading,
        )

    def evaluate(self, controller: BudgetController) -> RebalanceDecision:
        sigs = self.signals(controller)
        if not sigs.cascading:
            return RebalanceDecision(
                signals=sigs,
                changes=(),
                reason="no cascading throttle detected",
            )

        # Donor side: take transfer_fraction of each slack pool's
        # headroom (rounded down so we never over-transfer).
        donors: dict[str, int] = {}
        total_donation = 0
        for s in sigs.slack:
            donation = int(s.slack_headroom * self.transfer_fraction)
            if donation > 0:
                donors[s.name] = donation
                total_donation += donation
        if total_donation == 0:
            return RebalanceDecision(
                signals=sigs,
                changes=(),
                reason="slack pools have no transferable headroom",
            )

        # Recipient side: share by stress_excess; fall back to equal
        # split when all stressed pools are at ceiling without overflow.
        excess_total = sum(p.stress_excess for p in sigs.stressed)
        recipients: dict[str, int] = {}
        if excess_total > 0:
            # Proportional share.
            allocated = 0
            for p in sigs.stressed:
                share = int(total_donation * p.stress_excess / excess_total)
                if share > 0:
                    recipients[p.name] = share
                    allocated += share
            # Distribute rounding remainder to the most-stressed pool.
            remainder = total_donation - allocated
            if remainder > 0 and sigs.stressed:
                top = max(sigs.stressed, key=lambda p: p.stress_excess)
                recipients[top.name] = recipients.get(top.name, 0) + remainder
        else:
            # Even split.
            per = total_donation // len(sigs.stressed)
            rem = total_donation - per * len(sigs.stressed)
            for i, p in enumerate(sigs.stressed):
                share = per + (1 if i < rem else 0)
                if share > 0:
                    recipients[p.name] = share

        # Build the change list (donors first, then recipients).
        changes: list[CeilingChange] = []
        # Donors: ceiling -= donation
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
        # Recipients: ceiling += share, subject to the cross-pool cap.
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
            return RebalanceDecision(
                signals=sigs,
                changes=(),
                reason=(
                    "cascading detected but ceilings already balanced "
                    "against floor / oversubscription caps"
                ),
            )
        return RebalanceDecision(
            signals=sigs,
            changes=tuple(changes),
            reason=(
                f"cascading throttle: {len(sigs.stressed)} stressed, "
                f"{len(sigs.slack)} slack; redistributed "
                f"{total_donation} units of ceiling headroom"
            ),
        )

    # ------- write paths -------

    def apply(
        self, controller: BudgetController, decision: RebalanceDecision
    ) -> None:
        """Apply ``decision`` to ``controller``.

        Donor reductions are applied BEFORE recipient increases so
        the cross-pool oversubscription guard in
        :meth:`BudgetController.adjust_ceiling` sees the most-relaxed
        intermediate state. If any single change is rejected by the
        controller's invariants, the partial state is left as-is and
        the underlying :class:`CapacityBudgetError` is re-raised —
        operators investigating a transient state should consult
        :meth:`BudgetController.snapshot` to see what landed.
        """
        # Order: shrinks first, then grows.
        shrinks = [c for c in decision.changes if c.delta < 0]
        grows = [c for c in decision.changes if c.delta > 0]
        for change in (*shrinks, *grows):
            controller.adjust_ceiling(change.pool, change.new_ceiling)

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
