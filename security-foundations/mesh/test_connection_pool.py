"""Tests for the pooled connection transport (Phase 6 Track D D6.7)."""

import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from connection_pool import PooledSocketTransport
from transport import TransportError


def _await(t, want, tries=100):
    got = []
    for _ in range(tries):
        f = t.receive()
        if f is not None:
            got.append(f)
            if len(got) >= want:
                return got
        else:
            time.sleep(0.02)
    return got


class ConnectionReuseTests(unittest.TestCase):
    def test_many_frames_over_one_connection(self):
        a = PooledSocketTransport("a")
        b = PooledSocketTransport("b")
        try:
            for i in range(50):
                a.send(b.address, f"msg-{i}".encode())
            got = _await(b, 50)
            self.assertEqual(len(got), 50)
            self.assertEqual({f.payload for f in got},
                             {f"msg-{i}".encode() for i in range(50)})
            # 50 frames, but the pool reused ONE connection.
            self.assertEqual(b.accepted_connections, 1)
            self.assertEqual(a.open_connections(), 1)
        finally:
            a.close()
            b.close()


class ReconnectTests(unittest.TestCase):
    def test_recovers_after_dropped_connection(self):
        a = PooledSocketTransport("a", backoff_base=0.01)
        b = PooledSocketTransport("b")
        try:
            a.send(b.address, b"before")
            self.assertEqual(len(_await(b, 1)), 1)

            # Simulate a dropped link: kill the pooled socket out from under
            # the sender. The next send must transparently reconnect.
            with a._out_lock:
                sock = a._out[b.address]
            sock.close()

            a.send(b.address, b"after")
            got = _await(b, 1)
            self.assertEqual(len(got), 1)
            self.assertEqual(got[0].payload, b"after")
            # A second inbound connection was accepted (the reconnect).
            self.assertGreaterEqual(b.accepted_connections, 2)
        finally:
            a.close()
            b.close()


class BoundedPoolTests(unittest.TestCase):
    def test_lru_eviction_beyond_max_connections(self):
        a = PooledSocketTransport("a", max_connections=2)
        peers = [PooledSocketTransport(f"p{i}") for i in range(3)]
        try:
            for p in peers:
                a.send(p.address, b"hi")
            # Pool is capped at 2; the least-recently-used (peers[0]) was
            # evicted, so at most 2 outbound connections remain open.
            self.assertEqual(a.open_connections(), 2)
        finally:
            a.close()
            for p in peers:
                p.close()


class ValidationTests(unittest.TestCase):
    def test_bad_dest_raises(self):
        a = PooledSocketTransport("a")
        try:
            with self.assertRaises(TransportError):
                a.send("not-an-address", b"x")
        finally:
            a.close()

    def test_send_to_dead_peer_raises_after_retries(self):
        a = PooledSocketTransport("a", connect_retries=2, backoff_base=0.01)
        try:
            with self.assertRaises(TransportError):
                a.send("127.0.0.1:1", b"nobody home")  # port 1: no listener
        finally:
            a.close()


if __name__ == "__main__":
    unittest.main()
