"""Tests for the gossip membership protocol (Phase 6 Track B D6.3)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from membership import Member, MemberState, SwimMembership, _supersedes
from transport import InMemoryTransport, Switchboard


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


if __name__ == "__main__":
    unittest.main()
