"""Two-node signed round trip over mTLS (Phase 6 Track A D6.2). [RUNNABLE]

The two security layers composed, end to end:

- **Channel (Layer A):** the bytes cross a mutual TLS 1.3 connection;
  each side proves possession of a CA-issued SVID at handshake.
- **Message (Layer B):** the payload is a signed envelope the receiver
  verifies independently (signature + window + replay + capability).

This re-runs the Phase 5 signed round trip (`test_mesh_round_trip`) over
`TlsSocketTransport` instead of the bare socket. The same envelope
verifies after crossing the encrypted, mutually-authenticated channel —
proving (a) the node/message layer is transport-blind and (b) the two
layers agree on identity: the TLS-verified peer SPIFFE id equals the
envelope's signed sender.
"""

import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "envelope"))
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "integrations" / "mcp")
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from envelope_adapter import envelope_from_json, envelope_to_json

# Reuse the Phase 5 signed-envelope fixture verbatim.
from test_mesh_round_trip import _A, _A_KID, _B, _B_KID, _NOW, _Fabric
from tls_transport import TlsSocketTransport, mint_identity
from transport import TransportError
from verify_envelope import verify_envelope
from workload_ca import WorkloadCA

# The envelope SPIFFE ids live in trust domain "mesh.example"; the TLS CA
# must mint SVIDs in the SAME domain so channel identity == message identity.
_TRUST_DOMAIN = "mesh.example"


def _await(t, tries=80):
    for _ in range(tries):
        f = t.receive()
        if f is not None:
            return f
        time.sleep(0.02)
    return None


class MtlsRoundTripTests(unittest.TestCase):
    def test_signed_round_trip_over_mtls_two_layers_agree(self):
        fab = _Fabric()
        ca = WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key=Ed25519PrivateKey.generate())
        a_tls = TlsSocketTransport(mint_identity(ca, _A))
        b_tls = TlsSocketTransport(mint_identity(ca, _B))
        try:
            # A -> B: signed request over the encrypted, mutually-authed channel.
            req = fab.build_signed_envelope(
                sender=_A, sender_kid=_A_KID, recipient=_B, signing_key=fab.a_priv,
                method="read_file",
                message_id="01900000-0000-7000-8000-f00000000001",
                nonce="mtls-nonce-req-0001",
            )
            a_tls.send(b_tls.address, envelope_to_json(req))
            frame = _await(b_tls)
            self.assertIsNotNone(frame)
            # Channel layer: TLS-verified peer id.
            self.assertEqual(frame.source, _A)
            # Message layer: envelope verifies independently.
            claims = verify_envelope(
                envelope_from_json(frame.payload),
                key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                replay_cache=fab.b_replay, now=_NOW, audit_sink=fab.b_audit,
            )
            self.assertEqual(claims.sub, _A)
            # The two layers agree on WHO the peer is.
            self.assertEqual(frame.source, claims.sub)

            # B -> A: signed reply crosses back and re-verifies.
            reply = fab.build_signed_envelope(
                sender=_B, sender_kid=_B_KID, recipient=_A, signing_key=fab.b_priv,
                result={"ok": True},
                message_id="01900000-0000-7000-8000-f00000000002",
                nonce="mtls-nonce-rep-0001",
            )
            b_tls.send(a_tls.address, envelope_to_json(reply))
            back = _await(a_tls)
            self.assertIsNotNone(back)
            self.assertEqual(back.source, _B)
            rclaims = verify_envelope(
                envelope_from_json(back.payload),
                key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                replay_cache=fab.a_replay, now=_NOW, audit_sink=fab.a_audit,
            )
            self.assertEqual(rclaims.sub, _B)
        finally:
            a_tls.close()
            b_tls.close()

    def test_unauthenticated_peer_cannot_deliver_over_mtls(self):
        fab = _Fabric()
        good_ca = WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key=Ed25519PrivateKey.generate())
        evil_ca = WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key=Ed25519PrivateKey.generate())
        b_tls = TlsSocketTransport(mint_identity(good_ca, _B))
        # Impostor has a syntactically valid _A SVID, but from a root B does
        # not trust — the mTLS handshake fails before any envelope is seen.
        impostor = TlsSocketTransport(mint_identity(evil_ca, _A))
        try:
            req = fab.build_signed_envelope(
                sender=_A, sender_kid=_A_KID, recipient=_B, signing_key=fab.a_priv,
                method="read_file",
                message_id="01900000-0000-7000-8000-f00000000003",
                nonce="mtls-nonce-evil-0001",
            )
            with self.assertRaises(TransportError):
                impostor.send(b_tls.address, envelope_to_json(req))
            self.assertIsNone(_await(b_tls, tries=10))
        finally:
            b_tls.close()
            impostor.close()


if __name__ == "__main__":
    unittest.main()
