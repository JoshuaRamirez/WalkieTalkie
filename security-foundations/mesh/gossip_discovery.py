"""Gossip-driven discovery + admission (Phase 6 Track B, D6.4). [RUNNABLE]

Membership (D6.3) answers *"who is reachable"*. Admission (Phase 5
`peer_admission`) answers *"who is allowed"*. This module composes them:
a node learns peers by **gossip** (not a shared config file), and every
learned peer must still pass the deny-by-default admission policy before
it becomes **routable**.

The security invariant this preserves at network scope: **discovery is
not authorization.** A node can *appear* in the gossip view — it can even
be alive and reachable — and still be denied a place in the routing
table. Only the intersection of *reachable* (gossip says ALIVE) and
*allowed* (admission policy permits its `(spiffe_id, env_tier)`) is
routable. This is vision §8.1 ("unauthorized peer cannot join") enforced
against gossiped membership.

Why self-asserted tier can't escalate: admission is a deny-by-default
allowlist keyed on the exact `(spiffe_id, env_tier)` pair. A peer that
claims a tier other than the one the policy allow-lists for its identity
simply matches no rule and is denied. And the identity itself
(`spiffe_id`) is not self-asserted on the wire — it is proven by the
peer's SVID at the mTLS handshake (D6.1). So gossip can introduce a peer,
but it cannot grant one authority.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from membership import SwimMembership
from peer_admission import PeerAdmissionPolicy, admit_peer


@dataclass
class GossipDiscovery:
    """Couples a :class:`SwimMembership` view to a
    :class:`PeerAdmissionPolicy`.

    ``membership`` must use each node's **SPIFFE id** as its ``node_id`` so
    admission keys line up. ``peer_tier`` resolves a peer's env tier from a
    trusted source (a verified discovery record in production; a fixture in
    tests) — returning ``None`` for an unknown peer, which denies by
    default.
    """

    membership: SwimMembership
    admission: PeerAdmissionPolicy
    peer_tier: Callable[[str], str | None]

    def join(self) -> None:
        self.membership.join()

    def tick(self) -> None:
        self.membership.tick()

    def alive_ids(self) -> set[str]:
        """Reachable peers (gossip liveness) — NOT the same as routable."""
        return self.membership.alive_ids()

    def routable_peers(self) -> set[str]:
        """Peers that are both reachable AND admitted. The routing table
        (D6.5) draws only from this set."""
        out: set[str] = set()
        for pid in self.membership.alive_ids():
            tier = self.peer_tier(pid)
            if tier is None:
                continue  # unknown identity → deny by default
            if admit_peer(spiffe_id=pid, env_tier=tier, policy=self.admission).allowed:
                out.add(pid)
        return out

    def is_routable(self, spiffe_id: str) -> bool:
        return spiffe_id in self.routable_peers()
