"""Tests for the mTLS transport (Phase 6 Track A D6.1)."""

import time
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from envelope.workload_ca import WorkloadCA
from mesh.tls_transport import TlsSocketTransport, mint_identity
from mesh.transport import TransportError

_NOW = datetime.now(UTC)

def _ca(trust_domain="mesh.local"):
    return WorkloadCA(trust_domain=trust_domain, root_key=Ed25519PrivateKey.generate())

def _await_frame(t, tries=60):
    for _ in range(tries):
        f = t.receive()
        if f is not None:
            return f
        time.sleep(0.02)
    return None

class MutualTlsTests(unittest.TestCase):
    def test_valid_peers_exchange_frame_over_mtls(self):
        ca = _ca()
        a = TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/a"))
        b = TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/b"))
        try:
            a.send(b.address, b"hello over tls")
            frame = _await_frame(b)
            self.assertIsNotNone(frame)
            self.assertEqual(frame.payload, b"hello over tls")
            # source is the peer's TLS-VERIFIED SPIFFE id, not a raw address.
            self.assertEqual(frame.source, "spiffe://mesh.local/a")
        finally:
            a.close()
            b.close()

    def test_peer_from_untrusted_ca_cannot_handshake(self):
        good_ca = _ca()
        evil_ca = _ca()  # different root the good node does not trust
        server = TlsSocketTransport(mint_identity(good_ca, "spiffe://mesh.local/server"))
        impostor = TlsSocketTransport(mint_identity(evil_ca, "spiffe://mesh.local/impostor"))
        try:
            # The impostor's SVID chains to a root the server doesn't trust,
            # so the mTLS handshake fails and send raises — the bytes never
            # reach the envelope layer.
            with self.assertRaises(TransportError):
                impostor.send(server.address, b"let me in")
            self.assertIsNone(_await_frame(server, tries=10))
        finally:
            server.close()
            impostor.close()

    def test_expired_svid_rejected_by_substrate_check(self):
        ca = _ca()
        a = TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/a"))
        # Receiver's clock is 2h ahead: the sender's 1h SVID is expired from
        # its point of view, so verify_svid drops it even though TLS (system
        # clock) accepted the still-valid cert.
        future = datetime.now(UTC) + timedelta(hours=2)
        b = TlsSocketTransport(
            mint_identity(ca, "spiffe://mesh.local/b"), now_fn=lambda: future
        )
        try:
            try:
                a.send(b.address, b"too late")
            except TransportError:
                pass  # send may see the receiver drop mid-stream
            self.assertIsNone(_await_frame(b, tries=15))
        finally:
            a.close()
            b.close()

    def test_context_manager_closes(self):
        ca = _ca()
        with TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/x")) as t:
            self.assertTrue(t.address.startswith("127.0.0.1:"))
            self.assertEqual(t.spiffe_id, "spiffe://mesh.local/x")

class ConfigurableBindTests(unittest.TestCase):
    """The bind interface is configurable so peers on other machines can
    connect. The default is unchanged, and widening the bind interface does
    not touch identity: the mTLS handshake still binds identity to the SVID."""

    def test_default_binds_and_advertises_loopback(self):
        ca = _ca()
        # No new args -> loopback bind + loopback advertise, exactly as before.
        with TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/d")) as t:
            self.assertTrue(t.address.startswith("127.0.0.1:"))

    def test_wildcard_bind_advertises_dialable_host_and_round_trips(self):
        ca = _ca()
        # Server binds ALL interfaces (reachable from other machines) but
        # advertises a *dialable* host; on a real LAN advertise_host is the
        # host's routable IP. 127.0.0.1 stands in so the test runs on one box.
        server = TlsSocketTransport(
            mint_identity(ca, "spiffe://mesh.local/server"),
            bind_host="0.0.0.0",
            advertise_host="127.0.0.1",
        )
        client = TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/client"))
        try:
            # The advertised address is the dialable host, never the wildcard.
            self.assertTrue(server.address.startswith("127.0.0.1:"))
            self.assertNotIn("0.0.0.0", server.address)
            # A peer dials the advertised address; the mTLS round trip and the
            # identity binding are unaffected by the wider bind interface.
            client.send(server.address, b"cross-interface hello")
            frame = _await_frame(server)
            self.assertIsNotNone(frame)
            self.assertEqual(frame.payload, b"cross-interface hello")
            self.assertEqual(frame.source, "spiffe://mesh.local/client")
        finally:
            client.close()
            server.close()

    def test_empty_bind_host_rejected(self):
        ca = _ca()
        with self.assertRaises(TransportError):
            TlsSocketTransport(mint_identity(ca, "spiffe://mesh.local/x"), bind_host="")

if __name__ == "__main__":
    unittest.main()
