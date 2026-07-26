"""Tests for the mesh transport (Phase 5 Track C C1)."""

import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from socket_transport import LocalSocketTransport
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


class LocalSocketBindTests(unittest.TestCase):
    """The plain socket transport's bind interface is configurable so peers
    on other machines can connect; the default is unchanged."""

    @staticmethod
    def _drain(t, tries=60):
        for _ in range(tries):
            f = t.receive()
            if f is not None:
                return f
            time.sleep(0.02)
        return None

    def test_default_advertises_loopback(self):
        t = LocalSocketTransport("a")
        try:
            self.assertTrue(t.address.startswith("127.0.0.1:"))
        finally:
            t.close()

    def test_wildcard_bind_advertises_dialable_host_and_round_trips(self):
        server = LocalSocketTransport("server", bind_host="0.0.0.0", advertise_host="127.0.0.1")
        client = LocalSocketTransport("client")
        try:
            self.assertTrue(server.address.startswith("127.0.0.1:"))
            self.assertNotIn("0.0.0.0", server.address)
            client.send(server.address, b"cross-interface")
            frame = self._drain(server)
            self.assertIsNotNone(frame)
            self.assertEqual(frame.payload, b"cross-interface")
        finally:
            client.close()
            server.close()

    def test_empty_bind_host_rejected(self):
        with self.assertRaises(TransportError):
            LocalSocketTransport("a", bind_host="")


if __name__ == "__main__":
    unittest.main()
