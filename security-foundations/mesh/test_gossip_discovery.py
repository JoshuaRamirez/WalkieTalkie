"""Tests for gossip-driven discovery + admission (Phase 6 Track B D6.4)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "envelope"))

from gossip_discovery import GossipDiscovery
from membership import SwimMembership
from peer_admission import AdmissionRule, PeerAdmissionPolicy
from transport import InMemoryTransport, Switchboard

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


def _fabric():
    """A, B, and a rogue all gossip into one cluster (all seeded to A)."""
    sb = Switchboard()
    ids = [_A, _B, _ROGUE]
    mem = {}
    for i in ids:
        seeds = [] if i == _A else [_A]
        mem[i] = SwimMembership(i, InMemoryTransport(i, sb), seeds=seeds)
    return ids, mem


def _converge(mem, ids, rounds=25):
    for m in mem.values():
        m.join()
    for _ in range(rounds):
        for i in ids:
            mem[i].tick()


class GossipAdmissionTests(unittest.TestCase):
    def test_reachable_rogue_is_not_routable(self):
        ids, mem = _fabric()
        _converge(mem, ids)
        # From A's perspective, everyone (incl. the rogue) is reachable...
        disc_a = GossipDiscovery(
            membership=mem[_A], admission=_POLICY, peer_tier=lambda _p: _TIER
        )
        self.assertIn(_ROGUE, disc_a.alive_ids())
        self.assertIn(_B, disc_a.alive_ids())
        # ...but only the admitted peer is ROUTABLE. Discovery != authorization.
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
