"""Tests for the gossip membership protocol (Phase 6 Track B D6.3)."""

import json
import unittest

from envelope.peer_admission import AdmissionRule, PeerAdmissionPolicy
from mesh.membership import Member, MemberState, SwimMembership, _supersedes
from mesh.transport import (
    Frame,
    InMemoryTransport,
    Switchboard,
    Transport,
    TransportError,
)

_A = "spiffe://mesh.local/a"
_B = "spiffe://mesh.local/b"
_C = "spiffe://mesh.local/c"
_ROGUE = "spiffe://mesh.local/rogue"
_TIER = "prod"

_POLICY_AB = PeerAdmissionPolicy(
    rules=(
        AdmissionRule(spiffe_id=_A, env_tier=_TIER),
        AdmissionRule(spiffe_id=_B, env_tier=_TIER),
    )
)
_POLICY_ABC = PeerAdmissionPolicy(
    rules=(
        AdmissionRule(spiffe_id=_A, env_tier=_TIER),
        AdmissionRule(spiffe_id=_B, env_tier=_TIER),
        AdmissionRule(spiffe_id=_C, env_tier=_TIER),
    )
)


class _QueueTransport(Transport):
    """Hands the node a fixed list of payloads, then goes quiet."""

    def __init__(self, payloads, *, address="node-a"):
        self._addr = address
        self._queue = [p if isinstance(p, bytes) else json.dumps(p).encode("utf-8") for p in payloads]
        self.sent: list[tuple[str, bytes]] = []

    @property
    def address(self) -> str:
        return self._addr

    def send(self, dest, payload):
        self.sent.append((dest, payload))

    def receive(self):
        if not self._queue:
            return None
        return Frame("peer-1", self._queue.pop(0))

    def close(self):
        pass


def _cluster(n, *, seed_all_to_first=True):
    """n nodes over one switchboard. Node 0 is the seed; nodes 1..n-1 are
    seeded ONLY with node 0, so the rest must be discovered by gossip."""
    sb = Switchboard()
    ids = [f"n{i}" for i in range(n)]
    transports = {i: InMemoryTransport(i, sb) for i in ids}
    mem = {}
    mem[ids[0]] = SwimMembership(ids[0], transports[ids[0]], seeds=[])
    for i in ids[1:]:
        seeds = [ids[0]] if seed_all_to_first else []
        mem[i] = SwimMembership(i, transports[i], seeds=seeds)
    return ids, mem

def _run(mem, ids, rounds):
    for m in mem.values():
        m.join()
    for _ in range(rounds):
        for i in ids:
            if i in mem:
                mem[i].tick()

class ConvergenceTests(unittest.TestCase):
    def test_cluster_converges_via_gossip(self):
        ids, mem = _cluster(4)
        _run(mem, ids, rounds=25)
        # Every node learns every OTHER node as ALIVE — including the two
        # it was never seeded with (discovered purely by gossip).
        for i in ids:
            self.assertEqual(
                mem[i].alive_ids(), set(ids) - {i},
                f"{i} view: {mem[i].alive_ids()}",
            )

class FailureDetectionTests(unittest.TestCase):
    def test_downed_node_is_detected_dead(self):
        ids, mem = _cluster(4)
        _run(mem, ids, rounds=25)
        self.assertEqual(mem["n0"].state_of("n2"), MemberState.ALIVE)

        # Kill n2: stop ticking it. Others keep probing but never hear back;
        # nobody refutes, so suspicion escalates to DEAD and gossip spreads it.
        dead = mem.pop("n2")  # noqa: F841 - removed from the tick loop
        for _ in range(25):
            for i in ids:
                if i in mem:
                    mem[i].tick()

        for i in ("n0", "n1", "n3"):
            self.assertEqual(
                mem[i].state_of("n2"), MemberState.DEAD,
                f"{i} still sees n2 as {mem[i].state_of('n2')}",
            )

    def test_live_cluster_has_no_false_positives(self):
        ids, mem = _cluster(4)
        _run(mem, ids, rounds=40)
        # Nobody is wrongly suspected/killed while everyone keeps ticking.
        for i in ids:
            for j in set(ids) - {i}:
                self.assertEqual(mem[i].state_of(j), MemberState.ALIVE)

class RefutationTests(unittest.TestCase):
    def test_node_refutes_suspicion_about_itself(self):
        sb = Switchboard()
        m = SwimMembership("me", InMemoryTransport("me", sb), seeds=[])
        self.assertEqual(m.incarnation, 0)
        # Incoming gossip claims "me" is suspect at incarnation 0.
        m._merge([["me", 0, "suspect"]])
        # I out-incarnate the rumor so my ALIVE supersedes it everywhere.
        self.assertEqual(m.incarnation, 1)

class PrecedenceTests(unittest.TestCase):
    def test_alive_refutes_only_newer_incarnation(self):
        self.assertTrue(_supersedes(MemberState.ALIVE, 2, MemberState.SUSPECT, 1))
        self.assertFalse(_supersedes(MemberState.ALIVE, 1, MemberState.SUSPECT, 1))

    def test_suspect_overrides_equal_incarnation_alive(self):
        self.assertTrue(_supersedes(MemberState.SUSPECT, 1, MemberState.ALIVE, 1))
        self.assertFalse(_supersedes(MemberState.SUSPECT, 1, MemberState.SUSPECT, 1))

    def test_dead_overrides_equal_incarnation_non_dead(self):
        self.assertTrue(_supersedes(MemberState.DEAD, 0, MemberState.SUSPECT, 0))
        self.assertFalse(_supersedes(MemberState.DEAD, 0, MemberState.DEAD, 0))

    def test_member_dataclass_defaults(self):
        m = Member("x", 0, MemberState.ALIVE)
        self.assertEqual(m.ticks_since_heard, 0)


class AdmissionGateTests(unittest.TestCase):
    """Leftover #104: optional admission gate on the members table."""

    def test_unadmitted_gossiped_id_does_not_enter_table(self):
        sb = Switchboard()
        node = SwimMembership(
            _A, InMemoryTransport(_A, sb),
            admission=_POLICY_AB, peer_tier=lambda _p: _TIER,
        )
        node._merge([[_ROGUE, 0, "alive"], [_B, 0, "alive"]])
        self.assertNotIn(_ROGUE, node.members)
        self.assertNotIn(_ROGUE, node.alive_ids())
        self.assertIn(_B, node.members)
        # Unadmitted ids are not re-gossiped: _digest is not truncated,
        # they simply never entered the table.
        digest_ids = {row[0] for row in node._digest()}
        self.assertNotIn(_ROGUE, digest_ids)
        self.assertIn(_B, digest_ids)
        self.assertIn(_A, digest_ids)

    def test_unadmitted_sender_does_not_enter_via_mark_heard(self):
        sb = Switchboard()
        node = SwimMembership(
            _A, InMemoryTransport(_A, sb),
            admission=_POLICY_AB, peer_tier=lambda _p: _TIER,
        )
        node._mark_heard(_ROGUE)
        self.assertNotIn(_ROGUE, node.members)
        node._mark_heard(_B)
        self.assertIn(_B, node.members)

    def test_admitted_peers_still_converge(self):
        sb = Switchboard()
        ids = [_A, _B, _C]
        mem = {}
        for i in ids:
            seeds = [] if i == _A else [_A]
            mem[i] = SwimMembership(
                i, InMemoryTransport(i, sb), seeds=seeds,
                admission=_POLICY_ABC, peer_tier=lambda _p: _TIER,
            )
        for m in mem.values():
            m.join()
        for _ in range(25):
            for i in ids:
                mem[i].tick()
        for i in ids:
            self.assertEqual(
                mem[i].alive_ids(), set(ids) - {i},
                f"{i} view: {mem[i].alive_ids()}",
            )

    def test_no_admission_callers_still_learn_any_id(self):
        sb = Switchboard()
        node = SwimMembership("n0", InMemoryTransport("n0", sb))
        node._merge([["stranger", 0, "alive"]])
        node._mark_heard("other")
        self.assertIn("stranger", node.members)
        self.assertIn("other", node.members)

    def test_operator_seeds_are_retained(self):
        sb = Switchboard()
        node = SwimMembership(
            _A, InMemoryTransport(_A, sb), seeds=[_ROGUE],
            admission=_POLICY_AB, peer_tier=lambda _p: _TIER,
        )
        self.assertIn(_ROGUE, node.members)
        # State updates for a seed still apply; the gate does not evict.
        node._merge([[_ROGUE, 1, "suspect"]])
        self.assertEqual(node.state_of(_ROGUE), MemberState.SUSPECT)
        self.assertEqual(node.members[_ROGUE].incarnation, 1)
        node._mark_heard(_ROGUE)
        self.assertEqual(node.state_of(_ROGUE), MemberState.ALIVE)

    def test_unknown_tier_and_wrong_tier_deny_new_entries(self):
        sb = Switchboard()
        unknown = SwimMembership(
            _A, InMemoryTransport(_A, sb),
            admission=_POLICY_AB, peer_tier=lambda _p: None,
        )
        unknown._merge([[_B, 0, "alive"]])
        self.assertNotIn(_B, unknown.members)

        wrong = SwimMembership(
            _A, InMemoryTransport(_A, sb),
            admission=_POLICY_AB, peer_tier=lambda _p: "root",
        )
        wrong._merge([[_B, 0, "alive"]])
        self.assertNotIn(_B, wrong.members)

    def test_invalid_spiffe_fails_closed(self):
        sb = Switchboard()
        node = SwimMembership(
            _A, InMemoryTransport(_A, sb),
            admission=_POLICY_AB, peer_tier=lambda _p: _TIER,
        )
        node._merge([["not-a-spiffe", 0, "alive"]])
        self.assertNotIn("not-a-spiffe", node.members)

    def test_admission_and_peer_tier_must_be_paired(self):
        sb = Switchboard()
        transport = InMemoryTransport("n0", sb)
        with self.assertRaises(TransportError):
            SwimMembership("n0", transport, admission=_POLICY_AB)
        with self.assertRaises(TransportError):
            SwimMembership("n0", transport, peer_tier=lambda _p: _TIER)

    def test_malformed_frames_still_skipped_with_gate(self):
        transport = _QueueTransport([b"123", b"{{{", {"from": ["p"], "gossip": []}])
        node = SwimMembership(
            _A, transport,
            admission=_POLICY_AB, peer_tier=lambda _p: _TIER,
        )
        node.tick()  # must not raise
        self.assertEqual(node.members, {})

    def test_well_formed_admitted_gossip_still_merges_with_gate(self):
        msg = {
            "from": _B,
            "type": "ping",
            "gossip": [[_B, 0, "alive"], [_ROGUE, 0, "alive"]],
        }
        transport = _QueueTransport([msg])
        node = SwimMembership(
            _A, transport,
            admission=_POLICY_AB, peer_tier=lambda _p: _TIER,
        )
        node.tick()
        self.assertIn(_B, node.alive_ids())
        self.assertNotIn(_ROGUE, node.members)
        self.assertTrue(any(dest == _B for dest, _ in transport.sent))


if __name__ == "__main__":
    unittest.main()
