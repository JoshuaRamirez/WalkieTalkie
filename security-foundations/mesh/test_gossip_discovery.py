"""Tests for gossip-driven discovery + admission (Phase 6 Track B D6.4)."""

import unittest

from envelope.peer_admission import AdmissionRule, PeerAdmissionPolicy
from mesh.gossip_discovery import GossipDiscovery
from mesh.membership import SwimMembership
from mesh.transport import InMemoryTransport, Switchboard

_A = "spiffe://mesh.local/a"
_B = "spiffe://mesh.local/b"
_ROGUE = "spiffe://mesh.local/rogue"
_TIER = "prod"

# Policy admits A and B at tier "prod"; the rogue is on nobody's allowlist.
_POLICY = PeerAdmissionPolicy(
    rules=(
        AdmissionRule(spiffe_id=_A, env_tier=_TIER),
        AdmissionRule(spiffe_id=_B, env_tier=_TIER),
    )
)

def _fabric(*, admission=None, peer_tier=None):
    """A, B, and a rogue all gossip into one cluster (all seeded to A).

    Pass ``admission`` (and optionally ``peer_tier``) to attach the
    leftover #104 membership gate. Omitting it keeps the original
    reachability-only table so routing-layer deny can be pinned on its
    own.
    """
    sb = Switchboard()
    ids = [_A, _B, _ROGUE]
    mem = {}
    extra = {}
    if admission is not None:
        extra["admission"] = admission
        extra["peer_tier"] = peer_tier if peer_tier is not None else (lambda _p: _TIER)
    for i in ids:
        seeds = [] if i == _A else [_A]
        mem[i] = SwimMembership(
            i, InMemoryTransport(i, sb), seeds=seeds, **extra
        )
    return ids, mem

def _converge(mem, ids, rounds=25):
    for m in mem.values():
        m.join()
    for _ in range(rounds):
        for i in ids:
            mem[i].tick()

class GossipAdmissionTests(unittest.TestCase):
    def test_reachable_rogue_is_not_routable(self):
        ids, mem = _fabric(admission=_POLICY)
        _converge(mem, ids)
        disc_a = GossipDiscovery(
            membership=mem[_A], admission=_POLICY, peer_tier=lambda _p: _TIER
        )
        # Membership gate attached: the unadmitted rogue never enters the
        # table (leftover #104). Routing deny-by-default still holds.
        self.assertNotIn(_ROGUE, disc_a.alive_ids())
        self.assertNotIn(_ROGUE, mem[_A].members)
        self.assertNotIn(_ROGUE, mem[_B].members)
        self.assertIn(_B, disc_a.alive_ids())
        self.assertEqual(disc_a.routable_peers(), {_B})
        self.assertFalse(disc_a.is_routable(_ROGUE))
        self.assertTrue(disc_a.is_routable(_B))

    def test_unknown_tier_denies_by_default(self):
        ids, mem = _fabric()
        _converge(mem, ids)
        # peer_tier returns None for B → its identity can't be resolved to a
        # tier, so admission can't match a rule → not routable.
        disc = GossipDiscovery(
            membership=mem[_A], admission=_POLICY,
            peer_tier=lambda p: None if p == _B else _TIER,
        )
        self.assertIn(_B, disc.alive_ids())
        self.assertNotIn(_B, disc.routable_peers())

    def test_self_asserted_wrong_tier_cannot_escalate(self):
        ids, mem = _fabric()
        _converge(mem, ids)
        # B claims tier "root" (not the "prod" the policy allow-lists for it)
        # → no matching rule → denied. Self-asserted tier can't escalate.
        disc = GossipDiscovery(
            membership=mem[_A], admission=_POLICY,
            peer_tier=lambda p: "root" if p == _B else _TIER,
        )
        self.assertIn(_B, disc.alive_ids())
        self.assertNotIn(_B, disc.routable_peers())

if __name__ == "__main__":
    unittest.main()
