"""Eclipse resistance v0 (Phase 3 Track A A2).

Closes the "neighbor diversity rules" half of A2 ("Eclipse
Resistance"):

- "Neighbor diversity rules." — :func:`select_neighbors` is a
  greedy diversity-aware selector. Given a pool of
  :class:`NeighborCandidate` records and a :class:`DiversityRule`,
  it picks up to ``target_count`` neighbors while capping how many
  can come from any single trust domain (``max_per_trust_domain``)
  and reporting whether the final set hits the minimum spread
  (``min_distinct_trust_domains``).

  This implements the Phase 3 Track A acceptance criterion at the
  primitive level: "Simulated Sybil clusters cannot dominate peer
  view beyond tolerated threshold." A flood of candidates from one
  trust domain cannot occupy more than the configured per-domain
  cap, no matter how many candidates that domain submits.

Out of scope for v0
-------------------
- "Independent peer sampling paths." That's a multi-process / network
  topology concern — pull peers from two separate gossip layers, then
  ask :func:`select_neighbors` to combine them. v0 takes the combined
  candidate pool as input.
- "Routing anomaly detection." Detecting impossible-neighbor sets and
  trust-domain surges is its own slice; this module returns selection
  diagnostics so a downstream detector can read them.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from audit_query import trust_domain_of
from verify_envelope import KID_RE, SPIFFE_ID_RE


class EclipseResistanceError(ValueError):
    """Raised when selection inputs violate v0 invariants."""


@dataclass(frozen=True)
class NeighborCandidate:
    """One peer being considered for the neighbor set."""

    peer_iss: str
    peer_kid: str
    last_seen: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.peer_iss, str) or not SPIFFE_ID_RE.match(self.peer_iss):
            raise EclipseResistanceError(
                f"invalid peer_iss: {self.peer_iss!r}"
            )
        if not isinstance(self.peer_kid, str) or not KID_RE.match(self.peer_kid):
            raise EclipseResistanceError(
                f"invalid peer_kid: {self.peer_kid!r}"
            )
        if not isinstance(self.last_seen, datetime) or self.last_seen.tzinfo is None:
            raise EclipseResistanceError(
                "last_seen must be a timezone-aware datetime"
            )

    @property
    def trust_domain(self) -> str:
        return trust_domain_of(self.peer_iss) or ""


@dataclass(frozen=True)
class DiversityRule:
    target_count: int
    max_per_trust_domain: int
    min_distinct_trust_domains: int = 1

    def __post_init__(self) -> None:
        for name, value in (
            ("target_count", self.target_count),
            ("max_per_trust_domain", self.max_per_trust_domain),
            ("min_distinct_trust_domains", self.min_distinct_trust_domains),
        ):
            if not isinstance(value, int) or value < 1:
                raise EclipseResistanceError(
                    f"{name} must be a positive int: {value!r}"
                )
        if self.max_per_trust_domain > self.target_count:
            # Not strictly broken, just nonsensical — the cap can't
            # bind. Permit but operators should know.
            pass
        if (
            self.min_distinct_trust_domains
            > self.target_count
        ):
            raise EclipseResistanceError(
                "min_distinct_trust_domains cannot exceed target_count"
            )


@dataclass(frozen=True)
class RejectedCandidate:
    candidate: NeighborCandidate
    reason_code: str


@dataclass(frozen=True)
class NeighborSelection:
    selected: tuple[NeighborCandidate, ...]
    rejected: tuple[RejectedCandidate, ...] = field(default_factory=tuple)
    diversity_shortfall: bool = False
    target_shortfall: bool = False

    @property
    def trust_domain_count(self) -> int:
        return len({c.trust_domain for c in self.selected if c.trust_domain})

    @property
    def per_trust_domain(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for cand in self.selected:
            if cand.trust_domain:
                c[cand.trust_domain] += 1
        return dict(c)


def select_neighbors(
    candidates: Iterable[NeighborCandidate],
    *,
    rule: DiversityRule,
) -> NeighborSelection:
    """Pick up to ``rule.target_count`` neighbors with bounded TD share.

    Algorithm (deterministic):

    1. Order candidates by ``last_seen`` descending (freshness first),
       breaking ties on ``peer_iss`` for determinism. Operators who
       want a different ranking pre-sort the input.
    2. Walk the ordered list, admitting a candidate iff its trust
       domain currently holds fewer than ``rule.max_per_trust_domain``
       slots. Otherwise reject with
       ``reason_code="diversity_per_domain_cap"``.
    3. Stop when ``target_count`` is met or candidates are exhausted.
    4. Set ``target_shortfall=True`` if fewer than ``target_count``
       were admitted; ``diversity_shortfall=True`` if fewer than
       ``rule.min_distinct_trust_domains`` distinct trust domains
       appear in the final set.

    A candidate with an empty trust domain (a SPIFFE id with no
    parseable authority host) is treated as a distinct singleton
    "" bucket; this keeps Sybil pressure visible rather than hidden.
    """
    cands_list = list(candidates)
    for index, cand in enumerate(cands_list):
        if not isinstance(cand, NeighborCandidate):
            raise EclipseResistanceError(
                f"candidates[{index}] must be a NeighborCandidate"
            )

    ordered = sorted(
        cands_list,
        key=lambda c: (-c.last_seen.timestamp(), c.peer_iss),
    )

    selected: list[NeighborCandidate] = []
    rejected: list[RejectedCandidate] = []
    per_td: Counter[str] = Counter()

    for cand in ordered:
        if len(selected) >= rule.target_count:
            rejected.append(
                RejectedCandidate(
                    candidate=cand,
                    reason_code="diversity_target_reached",
                )
            )
            continue

        td = cand.trust_domain
        if per_td[td] >= rule.max_per_trust_domain:
            rejected.append(
                RejectedCandidate(
                    candidate=cand,
                    reason_code="diversity_per_domain_cap",
                )
            )
            continue

        selected.append(cand)
        per_td[td] += 1

    distinct = len({c.trust_domain for c in selected if c.trust_domain})
    return NeighborSelection(
        selected=tuple(selected),
        rejected=tuple(rejected),
        diversity_shortfall=distinct < rule.min_distinct_trust_domains,
        target_shortfall=len(selected) < rule.target_count,
    )


# ---------------------------------------------------------------------
# Surge-rate anomaly detector (lightweight pair to the diversity
# selector). Spots a sudden flood of new peers from one trust domain
# inside a sliding window.
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class TrustDomainSurge:
    """Anomaly: too many new candidates from one trust domain too fast."""

    trust_domain: str
    count: int
    window_start: datetime
    window_end: datetime


def detect_trust_domain_surges(
    candidates: Iterable[NeighborCandidate],
    *,
    window_end: datetime,
    window: datetime | None = None,  # kept for future symmetry
    window_start: datetime,
    surge_threshold: int,
) -> tuple[TrustDomainSurge, ...]:
    """Return any trust domain that posted ``surge_threshold`` or more
    candidates with ``last_seen`` inside ``[window_start, window_end]``.

    A surge alone is not a denial — it's a signal for the operator to
    investigate. Pair this with the per-domain cap in
    :func:`select_neighbors` for the actual eclipse-resistance gate.
    """
    if not isinstance(surge_threshold, int) or surge_threshold < 1:
        raise EclipseResistanceError(
            f"surge_threshold must be a positive int: {surge_threshold!r}"
        )
    if window_start.tzinfo is None or window_end.tzinfo is None:
        raise EclipseResistanceError(
            "window_start and window_end must be timezone-aware"
        )
    start_utc = window_start.astimezone(UTC)
    end_utc = window_end.astimezone(UTC)
    if start_utc > end_utc:
        raise EclipseResistanceError(
            "window_start must be <= window_end"
        )

    per_td: Counter[str] = Counter()
    for cand in candidates:
        if not isinstance(cand, NeighborCandidate):
            raise EclipseResistanceError("candidates must be NeighborCandidate")
        last = cand.last_seen.astimezone(UTC)
        if start_utc <= last <= end_utc and cand.trust_domain:
            per_td[cand.trust_domain] += 1

    return tuple(
        TrustDomainSurge(
            trust_domain=td,
            count=count,
            window_start=start_utc,
            window_end=end_utc,
        )
        for td, count in sorted(per_td.items())
        if count >= surge_threshold
    )
