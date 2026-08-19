"""Peer-controlled frames must not crash the node (Phase 6 Tracks B + C).

Both mesh decoders read bytes a peer chose. Nothing has authenticated the
*contents* at this point — mTLS authenticates the channel, and the signed
envelope inside is verified later, but the routing envelope and the gossip
digest are parsed first, in the clear, to decide where the bytes go.

That makes a malformed frame an ordinary input, not an internal error. Two
distinct contracts, because the two call sites differ:

- :meth:`RoutedMessage.from_json` is called by a *relay* on ``frame.payload``
  (see ``test_mtls_multihop``, which the docs name as the integration
  starting point). A bad frame must raise ``TransportError`` — the mesh's
  own error type — never a raw ``KeyError`` / ``ValueError`` / base64 error
  that the relay loop has no reason to catch.
- :meth:`SwimMembership.tick` drains a queue in a background loop. A bad
  frame must be *skipped*, because raising would stop failure detection for
  the whole cluster: one peer sending ``123`` would freeze every other
  node's view of who is alive.

Before this suite, 8 of 11 gossip cases and 6 of 9 routing cases crashed.
Two routing cases were worse than a crash — ``dest`` of any type and
non-base64 ``payload_b64`` were silently *accepted*.
"""

import json
import unittest

from mesh.membership import MAX_NODE_ID_LEN, MemberState, SwimMembership
from mesh.routing import RoutedMessage
from mesh.transport import Frame, Transport, TransportError


class _ReplayTransport(Transport):
    """Hands the node a fixed list of frames, then goes quiet."""

    def __init__(self, payloads, *, address="node-a"):
        self._addr = address
        self._queue = [Frame("peer-1", p) for p in payloads]
        self.sent: list[tuple[str, bytes]] = []

    @property
    def address(self) -> str:
        return self._addr

    def send(self, dest, payload):
        self.sent.append((dest, payload))

    def receive(self):
        return self._queue.pop(0) if self._queue else None

    def close(self):
        pass

def _encode(obj) -> bytes:
    return obj if isinstance(obj, bytes) else json.dumps(obj).encode("utf-8")

class GossipFrameTests(unittest.TestCase):
    """A malformed gossip frame is skipped; the tick survives."""

    MALFORMED = [
        ("message is an int", b"123"),
        ("message is a list", b"[]"),
        ("message is a string", b'"hello"'),
        ("message is null", b"null"),
        ("message is not JSON", b"{{{"),
        ("gossip is an int", {"from": "p", "gossip": 5}),
        ("gossip is a string", {"from": "p", "gossip": "xx"}),
        ("gossip entry is a dict", {"from": "p", "gossip": [{"a": 1}]}),
        ("gossip entry too short", {"from": "p", "gossip": [["p", 0]]}),
        ("gossip node id unhashable", {"from": "p", "gossip": [[["x"], 0, "alive"]]}),
        ("gossip node id is an int", {"from": "p", "gossip": [[7, 0, "alive"]]}),
        ("from is a list", {"from": ["p"], "gossip": []}),
        ("from is a dict", {"from": {}, "gossip": []}),
        ("from is an int", {"from": 7, "gossip": []}),
    ]

    def test_malformed_frames_do_not_kill_the_tick(self):
        for label, raw in self.MALFORMED:
            with self.subTest(case=label):
                node = SwimMembership("node-a", _ReplayTransport([_encode(raw)]))
                node.tick()  # must not raise

    def test_malformed_frame_does_not_stop_later_frames(self):
        """One bad sender must not deny service to every peer behind it."""
        good = {"from": "peer-good", "type": "ping", "gossip": [["peer-good", 0, "alive"]]}
        transport = _ReplayTransport([b"123", _encode(good)])
        node = SwimMembership("node-a", transport)
        node.tick()
        self.assertIn("peer-good", node.alive_ids())

    def test_oversized_gossiped_node_id_is_dropped(self):
        """A gossiped id is stored *and re-gossiped*, so it must be bounded."""
        huge = "x" * (MAX_NODE_ID_LEN + 1)
        msg = {"from": "peer-1", "gossip": [[huge, 0, "alive"]]}
        node = SwimMembership("node-a", _ReplayTransport([_encode(msg)]))
        node.tick()
        self.assertNotIn(huge, node.alive_ids())

    def test_oversized_sender_is_dropped(self):
        """``from`` is stored by ``_mark_heard`` — same bound as a gossiped id.

        Bounding only the gossip digest would leave the cheaper injection
        path open: one frame whose ``from`` is unbounded lands in ``members``
        and is then re-gossiped to every peer.
        """
        huge = "y" * (MAX_NODE_ID_LEN + 1)
        msg = {"from": huge, "gossip": []}
        node = SwimMembership("node-a", _ReplayTransport([_encode(msg)]))
        node.tick()
        self.assertNotIn(huge, node.alive_ids())
        self.assertNotIn(huge, node.members)

    def test_well_formed_gossip_still_merges(self):
        """The hardening must not have narrowed the accept path."""
        msg = {
            "from": "peer-1",
            "type": "ping",
            "gossip": [["peer-1", 0, "alive"], ["peer-2", 3, "suspect"]],
        }
        transport = _ReplayTransport([_encode(msg)])
        node = SwimMembership("node-a", transport)
        node.tick()
        self.assertIn("peer-1", node.alive_ids())
        self.assertEqual(node.members["peer-2"].state, MemberState.SUSPECT)
        self.assertEqual(node.members["peer-2"].incarnation, 3)
        # A ping is acked back to the sender.
        self.assertTrue(any(dest == "peer-1" for dest, _ in transport.sent))

class RoutedMessageDecodeTests(unittest.TestCase):
    """A malformed routed frame denies as TransportError, never a raw error."""

    MALFORMED = [
        ("not JSON", b"{{{"),
        ("not an object", b"[]"),
        ("null", b"null"),
        ("missing dest", {"ttl": 3, "msg_id": "m", "payload_b64": ""}),
        ("missing ttl", {"dest": "d", "msg_id": "m", "payload_b64": ""}),
        ("missing payload_b64", {"dest": "d", "ttl": 3, "msg_id": "m"}),
        ("ttl is a string", {"dest": "d", "ttl": "abc", "msg_id": "m", "payload_b64": ""}),
        ("ttl is null", {"dest": "d", "ttl": None, "msg_id": "m", "payload_b64": ""}),
        ("ttl is a bool", {"dest": "d", "ttl": True, "msg_id": "m", "payload_b64": ""}),
        ("ttl is negative", {"dest": "d", "ttl": -1, "msg_id": "m", "payload_b64": ""}),
        ("dest is a list", {"dest": [], "ttl": 3, "msg_id": "m", "payload_b64": ""}),
        ("dest is empty", {"dest": "", "ttl": 3, "msg_id": "m", "payload_b64": ""}),
        ("msg_id is an int", {"dest": "d", "ttl": 3, "msg_id": 5, "payload_b64": ""}),
        ("payload_b64 is an int", {"dest": "d", "ttl": 3, "msg_id": "m", "payload_b64": 5}),
        ("payload_b64 is not base64",
         {"dest": "d", "ttl": 3, "msg_id": "m", "payload_b64": "!!!!"}),
    ]

    def test_malformed_frames_raise_transport_error(self):
        for label, raw in self.MALFORMED:
            with self.subTest(case=label):
                with self.assertRaises(TransportError):
                    RoutedMessage.from_json(_encode(raw))

    def test_oversized_identifiers_are_rejected(self):
        """A relay records msg_ids in its seen-set — unbounded id, unbounded set."""
        for field in ("dest", "msg_id"):
            with self.subTest(field=field):
                obj = {"dest": "d", "ttl": 3, "msg_id": "m", "payload_b64": ""}
                obj[field] = "x" * 300
                with self.assertRaises(TransportError):
                    RoutedMessage.from_json(_encode(obj))

    def test_non_base64_payload_is_rejected_not_silently_decoded(self):
        """``b64decode`` without ``validate=True`` discards junk characters.

        That is worse than crashing: a corrupted or crafted payload would
        decode to *something* and be forwarded as if intact.
        """
        obj = {"dest": "d", "ttl": 3, "msg_id": "m", "payload_b64": "YWJ$%^jZA=="}
        with self.assertRaises(TransportError):
            RoutedMessage.from_json(_encode(obj))

    def test_round_trip_survives_binary_payload(self):
        """The accept path is unchanged, including non-UTF-8 payload bytes."""
        original = RoutedMessage(dest="node-c", ttl=5, msg_id="m1", payload=b"\x00\xff\x01")
        decoded = RoutedMessage.from_json(original.to_json())
        self.assertEqual(decoded, original)

    def test_bytearray_payload_is_snapshotted(self):
        """``frozen=True`` freezes the binding, not the buffer behind it.

        A mutable payload could be changed *after* the routing decision was
        made on it, so the forwarded frame would not be the one authorized.
        Applies to ``Frame`` for the same reason.
        """
        buf = bytearray(b"original")
        routed = RoutedMessage(dest="node-c", ttl=5, msg_id="m1", payload=buf)
        frame = Frame("peer-1", buf)
        buf[:] = b"tampered"
        self.assertEqual(routed.payload, b"original")
        self.assertEqual(frame.payload, b"original")
        self.assertIsInstance(routed.payload, bytes)
        self.assertIsInstance(frame.payload, bytes)

    def test_direct_construction_validates_too(self):
        """``from_json`` delegates type checks to ``__post_init__``.

        Pinning it here keeps that delegation honest — an in-process caller
        building a RoutedMessage by hand gets the same contract as the wire.
        """
        for kwargs in (
            {"dest": 5, "ttl": 3, "msg_id": "m", "payload": b""},
            {"dest": "d", "ttl": "3", "msg_id": "m", "payload": b""},
            {"dest": "d", "ttl": 3, "msg_id": "", "payload": b""},
            {"dest": "d", "ttl": 3, "msg_id": "m", "payload": "not-bytes"},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(TransportError):
                    RoutedMessage(**kwargs)

if __name__ == "__main__":
    unittest.main()
