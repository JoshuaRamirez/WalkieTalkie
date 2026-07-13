"""Tests for routing + multi-hop forwarding (Phase 6 Track C D6.5)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from routing import RoutedMessage, Router

# Linear topology A — B — C. B is the only path between A and C.
_A, _B, _C = "node-a", "node-b", "node-c"
_NEXT = {
    _A: {_B: _B, _C: _B},   # A reaches C via B
    _B: {_A: _A, _C: _C},   # B is directly connected to both
    _C: {_A: _B, _B: _B},   # C reaches A via B
}


def _router(node, *, routable=lambda _n: True):
    return Router(node, next_hop=lambda d: _NEXT[node].get(d), is_routable=routable)


class MultiHopTests(unittest.TestCase):
    def test_message_reaches_far_node_via_intermediary(self):
        a, b, c = _router(_A), _router(_B), _router(_C)
        routed = a.originate(_C, b"signed-envelope-bytes", msg_id="m1")

        # A sends to next hop B; B forwards toward C.
        dec_b = b.handle(routed)
        self.assertEqual(dec_b.action, "forward")
        self.assertEqual(dec_b.next_hop, _C)
        self.assertEqual(dec_b.forwarded.ttl, routed.ttl - 1)

        # C is the destination — it delivers the ORIGINAL payload intact.
        dec_c = c.handle(dec_b.forwarded)
        self.assertEqual(dec_c.action, "deliver")
        self.assertEqual(dec_c.payload, b"signed-envelope-bytes")


class LoopSafetyTests(unittest.TestCase):
    def test_duplicate_message_id_is_dropped(self):
        b = _router(_B)
        routed = RoutedMessage(dest=_C, ttl=8, msg_id="dup", payload=b"x")
        first = b.handle(routed)
        self.assertEqual(first.action, "forward")
        # The same id arriving again (a loop) is dropped, not re-forwarded.
        second = b.handle(routed)
        self.assertEqual(second.action, "drop")
        self.assertEqual(second.reason, "duplicate")

    def test_ttl_exhaustion_drops(self):
        b = _router(_B)
        routed = RoutedMessage(dest=_C, ttl=1, msg_id="ttl", payload=b"x")
        dec = b.handle(routed)
        self.assertEqual(dec.action, "drop")
        self.assertEqual(dec.reason, "ttl_exhausted")


class DenyByDefaultForwardingTests(unittest.TestCase):
    def test_forward_denied_to_unadmitted_next_hop(self):
        # B knows the route to C but is NOT allowed to route to C.
        b = _router(_B, routable=lambda n: n != _C)
        routed = RoutedMessage(dest=_C, ttl=8, msg_id="deny", payload=b"x")
        dec = b.handle(routed)
        self.assertEqual(dec.action, "drop")
        self.assertEqual(dec.reason, "next_hop_not_admitted")

    def test_no_route_drops(self):
        b = Router(_B, next_hop=lambda d: None, is_routable=lambda n: True)
        routed = RoutedMessage(dest="node-x", ttl=8, msg_id="nr", payload=b"x")
        dec = b.handle(routed)
        self.assertEqual(dec.action, "drop")
        self.assertEqual(dec.reason, "no_route")


class SerializationTests(unittest.TestCase):
    def test_routed_message_json_round_trip(self):
        m = RoutedMessage(dest=_C, ttl=5, msg_id="s1", payload=b"\x00\x01binary")
        back = RoutedMessage.from_json(m.to_json())
        self.assertEqual(back, m)


if __name__ == "__main__":
    unittest.main()
