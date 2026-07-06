"""Tests for the mTLS transport (Phase 6 Track A D6.1)."""

import pathlib
import sys
import time
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "envelope"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tls_transport import TlsSocketTransport, mint_identity
from transport import TransportError
from workload_ca import WorkloadCA

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


if __name__ == "__main__":
    unittest.main()
