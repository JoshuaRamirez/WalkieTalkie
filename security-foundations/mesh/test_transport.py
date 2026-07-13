"""Tests for the mesh transport (Phase 5 Track C C1)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from transport import (
    Frame,
    InMemoryTransport,
    Switchboard,
    TransportError,
)


class FrameTests(unittest.TestCase):
    def test_empty_source_rejected(self):
        with self.assertRaisesRegex(TransportError, "source"):
            Frame(source="", payload=b"x")

    def test_non_bytes_payload_rejected(self):
        with self.assertRaisesRegex(TransportError, "payload"):
            Frame(source="a", payload="not-bytes")  # type: ignore[arg-type]


class SwitchboardTests(unittest.TestCase):
    def test_duplicate_registration_rejected(self):
        sb = Switchboard()
        sb.register("node-a")
        with self.assertRaisesRegex(TransportError, "already registered"):
            sb.register("node-a")

    def test_deliver_to_unknown_dest_rejected(self):
        sb = Switchboard()
        with self.assertRaisesRegex(TransportError, "unknown destination"):
            sb.deliver(dest="ghost", frame=Frame(source="a", payload=b"x"))

    def test_drain_empty_returns_none(self):
        sb = Switchboard()
        sb.register("node-a")
        self.assertIsNone(sb.drain_one("node-a"))


class InMemoryTransportTests(unittest.TestCase):
    def test_send_and_receive(self):
        sb = Switchboard()
        a = InMemoryTransport("node-a", sb)
        b = InMemoryTransport("node-b", sb)
        a.send("node-b", b"hello")
        frame = b.receive()
        self.assertIsNotNone(frame)
        self.assertEqual(frame.source, "node-a")
        self.assertEqual(frame.payload, b"hello")

    def test_fifo_order(self):
        sb = Switchboard()
        a = InMemoryTransport("node-a", sb)
        b = InMemoryTransport("node-b", sb)
        a.send("node-b", b"first")
        a.send("node-b", b"second")
        self.assertEqual(b.receive().payload, b"first")
        self.assertEqual(b.receive().payload, b"second")
        self.assertIsNone(b.receive())

    def test_address_property(self):
        sb = Switchboard()
        a = InMemoryTransport("node-a", sb)
        self.assertEqual(a.address, "node-a")

    def test_send_to_unregistered_rejected(self):
        sb = Switchboard()
        a = InMemoryTransport("node-a", sb)
        with self.assertRaisesRegex(TransportError, "unknown destination"):
            a.send("node-nowhere", b"x")

    def test_isolation_between_mailboxes(self):
        sb = Switchboard()
        a = InMemoryTransport("node-a", sb)
        b = InMemoryTransport("node-b", sb)
        a.send("node-b", b"for-b")
        # a's own inbox is empty; the message went to b.
        self.assertIsNone(a.receive())
        self.assertEqual(b.receive().payload, b"for-b")


if __name__ == "__main__":
    unittest.main()
