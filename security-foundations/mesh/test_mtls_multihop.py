"""3-node multi-hop secure round trip (Phase 6 Track C D6.6). [RUNNABLE]

The whole Phase 6 stack composed: a signed envelope travels A → B → C
where A and C are NOT directly connected, each hop is its own mutually-
authenticated TLS 1.3 connection, and the forwarder B cannot forge or
impersonate.

The load-bearing insight this proves: at a forwarding hop, **channel
identity and message identity legitimately differ**. C's TLS peer is B
(the relay), but the signed envelope inside names A as sender and C as
recipient. Security rests on the envelope, so B can move the bytes
without being able to make C accept them *as if from B* — and if B
tampers with the opaque payload, C's envelope verification fails.
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
from routing import RoutedMessage, Router
from test_mesh_round_trip import _A, _A_KID, _B, _B_KID, _NOW, _Fabric
from tls_transport import TlsSocketTransport, mint_identity
from verify_envelope import EnvelopeVerificationError, verify_envelope
from workload_ca import WorkloadCA

_RELAY = "spiffe://mesh.example/ns-relay/relay"
_DOMAIN = "mesh.example"


class _RelayNode:
    """Ties a TLS transport to a Router: drains inbound frames, and either
    delivers (this node is the destination) or forwards to the next hop."""

    def __init__(self, node_id, transport, router, addr_of):
        self.node_id = node_id
        self.transport = transport
        self.router = router
        self.addr_of = addr_of
        self.delivered = []

    def originate(self, dest, payload, msg_id):
        routed = self.router.originate(dest, payload, msg_id=msg_id)
        first = self.router._next_hop(dest)
        self.transport.send(self.addr_of[first], routed.to_json())

    def pump(self):
        while True:
            frame = self.transport.receive()
            if frame is None:
                return
            routed = RoutedMessage.from_json(frame.payload)
            dec = self.router.handle(routed)
            if dec.action == "deliver":
                self.delivered.append(dec.payload)
            elif dec.action == "forward":
                self.transport.send(self.addr_of[dec.next_hop], dec.forwarded.to_json())


def _pump_until(nodes, node, count, tries=100):
    for _ in range(tries):
        for n in nodes:
            n.pump()
        if len(node.delivered) >= count:
            return
        time.sleep(0.02)


class MultiHopRoundTripTests(unittest.TestCase):
    def _wire(self):
        fab = _Fabric()
        ca = WorkloadCA(trust_domain=_DOMAIN, root_key=Ed25519PrivateKey.generate())
        a_t = TlsSocketTransport(mint_identity(ca, _A))
        b_t = TlsSocketTransport(mint_identity(ca, _RELAY))
        c_t = TlsSocketTransport(mint_identity(ca, _B))
        addr_of = {_A: a_t.address, _RELAY: b_t.address, _B: c_t.address}
        routable = lambda _n: True  # noqa: E731 - admission covered in B2/C1
        # Routing: A reaches C(_B) via the relay; C reaches A via the relay.
        a = _RelayNode(_A, a_t, Router(
            _A, next_hop=lambda d: {_B: _RELAY}.get(d), is_routable=routable), addr_of)
        b = _RelayNode(_RELAY, b_t, Router(
            _RELAY, next_hop=lambda d: {_A: _A, _B: _B}.get(d), is_routable=routable), addr_of)
        c = _RelayNode(_B, c_t, Router(
            _B, next_hop=lambda d: {_A: _RELAY}.get(d), is_routable=routable), addr_of)
        return fab, (a, b, c)

    def test_signed_envelope_reaches_far_node_through_relay(self):
        fab, (a, b, c) = self._wire()
        try:
            env = fab.build_signed_envelope(
                sender=_A, sender_kid=_A_KID, recipient=_B, signing_key=fab.a_priv,
                method="read_file",
                message_id="01900000-0000-7000-8000-c00000000001",
                nonce="multihop-nonce-0001",
            )
            a.originate(_B, envelope_to_json(env), "mh-1")
            _pump_until((a, b, c), c, 1)

            self.assertEqual(len(c.delivered), 1)
            # C verifies A's signature end-to-end — even though C's TLS peer
            # on the final hop was the relay, not A.
            claims = verify_envelope(
                envelope_from_json(c.delivered[0]),
                key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                replay_cache=fab.b_replay, now=_NOW, audit_sink=fab.b_audit,
            )
            self.assertEqual(claims.sub, _A)

            # Reply C -> A back through the relay, re-verified at A.
            reply = fab.build_signed_envelope(
                sender=_B, sender_kid=_B_KID, recipient=_A, signing_key=fab.b_priv,
                result={"ok": True},
                message_id="01900000-0000-7000-8000-c00000000002",
                nonce="multihop-nonce-0002",
            )
            c.originate(_A, envelope_to_json(reply), "mh-2")
            _pump_until((a, b, c), a, 1)
            self.assertEqual(len(a.delivered), 1)
            rclaims = verify_envelope(
                envelope_from_json(a.delivered[0]),
                key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                replay_cache=fab.a_replay, now=_NOW, audit_sink=fab.a_audit,
            )
            self.assertEqual(rclaims.sub, _B)
        finally:
            for n in (a, b, c):
                n.transport.close()

    def test_relay_tampering_breaks_envelope_verification(self):
        fab, (a, b, c) = self._wire()
        try:
            env = fab.build_signed_envelope(
                sender=_A, sender_kid=_A_KID, recipient=_B, signing_key=fab.a_priv,
                method="read_file",
                message_id="01900000-0000-7000-8000-c00000000003",
                nonce="multihop-nonce-0003",
            )
            # Deliver a relay-tampered payload straight to C's router: the
            # forwarder flipped the envelope's payload after A signed it.
            good = envelope_from_json(envelope_to_json(env))
            good["payload"] = {"jsonrpc": "2.0", "method": "exec_sql",
                               "params": {"q": "DROP TABLE users"}, "id": 1}
            tampered = RoutedMessage(
                dest=_B, ttl=8, msg_id="mh-tamper",
                payload=envelope_to_json(good),
            )
            dec = c.router.handle(tampered)
            self.assertEqual(dec.action, "deliver")
            with self.assertRaises(EnvelopeVerificationError):
                verify_envelope(
                    envelope_from_json(dec.payload),
                    key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                    replay_cache=fab.b_replay, now=_NOW,
                )
        finally:
            for n in (a, b, c):
                n.transport.close()


if __name__ == "__main__":
    unittest.main()
