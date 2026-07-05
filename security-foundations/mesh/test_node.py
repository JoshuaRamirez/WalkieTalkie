"""Tests for the mesh node (Phase 5 Track C C2)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "envelope")
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from discovery_record import DiscoveryRecord, sign_record
from eclipse_resistance import DiversityRule
from node import MeshNode, MeshNodeError
from peer_admission import AdmissionRule, PeerAdmissionPolicy
from transport import InMemoryTransport, Switchboard
from verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_ISSUER_ISS = "spiffe://mesh.example/ns-disco/authority-1"
_ISSUER_KID = "disco-kid-1"
_PEER_ISS = "spiffe://mesh.example/ns-b/agent-2"
_PEER_KID = "peer-kid-1"
_SELF = "spiffe://mesh.example/ns-a/agent-1"


def _issuer_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _signed_record(issuer_priv, *, peer=_PEER_ISS, endpoints=("mesh-addr-b",)):
    rec = DiscoveryRecord(
        version="v0",
        workload_iss=peer,
        workload_kid=_PEER_KID,
        endpoints=endpoints,
        issuer_iss=_ISSUER_ISS,
        issuer_kid=_ISSUER_KID,
        issued_at="2026-04-14T12:00:00Z",
        expires_at="2026-04-14T12:30:00Z",
    )
    return sign_record(rec, issuer_priv)


def _node(*, admission_rules, switchboard, address="mesh-addr-a", issuer_pem=None):
    def _lookup(iss, kid):
        if (iss, kid) == (_ISSUER_ISS, _ISSUER_KID) and issuer_pem is not None:
            return issuer_pem
        raise EnvelopeVerificationError(f"unknown issuer {iss!r}/{kid!r}")

    return MeshNode(
        spiffe_id=_SELF,
        env_tier="prod",
        transport=InMemoryTransport(address, switchboard),
        issuer_lookup=_lookup,
        admission_policy=PeerAdmissionPolicy(rules=tuple(admission_rules)),
        routing_rule=DiversityRule(
            target_count=8, max_per_trust_domain=4, min_distinct_trust_domains=1
        ),
    )


class ConstructionTests(unittest.TestCase):
    def test_bad_transport_rejected(self):
        with self.assertRaisesRegex(MeshNodeError, "transport"):
            MeshNode(
                spiffe_id=_SELF,
                env_tier="prod",
                transport="not-a-transport",  # type: ignore[arg-type]
                issuer_lookup=lambda i, k: b"",
                admission_policy=PeerAdmissionPolicy(rules=()),
                routing_rule=DiversityRule(
                    target_count=1, max_per_trust_domain=1
                ),
            )


class LearnPeerTests(unittest.TestCase):
    def test_verified_admitted_peer_is_learned(self):
        priv, pem = _issuer_keypair()
        sb = Switchboard()
        node = _node(
            admission_rules=[AdmissionRule(spiffe_id=_PEER_ISS, env_tier="prod")],
            switchboard=sb,
            issuer_pem=pem,
        )
        result = node.learn_peer(_signed_record(priv), now=_NOW)
        self.assertTrue(result.admitted)
        self.assertIsNotNone(node.known_peer(_PEER_ISS))
        self.assertEqual(node.known_peer(_PEER_ISS).transport_address, "mesh-addr-b")

    def test_bad_signature_not_learned(self):
        priv, pem = _issuer_keypair()
        wrong_priv, _ = _issuer_keypair()
        sb = Switchboard()
        node = _node(
            admission_rules=[AdmissionRule(spiffe_id=_PEER_ISS, env_tier="prod")],
            switchboard=sb,
            issuer_pem=pem,
        )
        # Record signed by a DIFFERENT issuer key than the trust store
        # hands back → verification fails.
        result = node.learn_peer(_signed_record(wrong_priv), now=_NOW)
        self.assertFalse(result.admitted)
        self.assertIsNone(node.known_peer(_PEER_ISS))

    def test_verified_but_unadmitted_peer_rejected(self):
        # Authenticates fine, but not on the admission allowlist.
        priv, pem = _issuer_keypair()
        sb = Switchboard()
        node = _node(admission_rules=[], switchboard=sb, issuer_pem=pem)
        result = node.learn_peer(_signed_record(priv), now=_NOW)
        self.assertFalse(result.admitted)
        self.assertEqual(result.reason_code, "admission_peer_not_allowed")
        self.assertIsNone(node.known_peer(_PEER_ISS))

    def test_empty_endpoints_rejected_at_verification(self):
        # A discovery record with no endpoints fails the record's own
        # shape validation during verify_record (discovery_malformed),
        # which is stronger than the node's belt-and-braces guard —
        # the peer is never learned either way.
        priv, pem = _issuer_keypair()
        sb = Switchboard()
        node = _node(
            admission_rules=[AdmissionRule(spiffe_id=_PEER_ISS, env_tier="prod")],
            switchboard=sb,
            issuer_pem=pem,
        )
        result = node.learn_peer(
            _signed_record(priv, endpoints=()), now=_NOW
        )
        self.assertFalse(result.admitted)
        self.assertIsNone(node.known_peer(_PEER_ISS))


class RoutingTests(unittest.TestCase):
    def test_routing_table_contains_learned_peer(self):
        priv, pem = _issuer_keypair()
        sb = Switchboard()
        node = _node(
            admission_rules=[AdmissionRule(spiffe_id=_PEER_ISS, env_tier="prod")],
            switchboard=sb,
            issuer_pem=pem,
        )
        node.learn_peer(_signed_record(priv), now=_NOW)
        table = node.routing_table()
        self.assertEqual([p.spiffe_id for p in table], [_PEER_ISS])


class SendTests(unittest.TestCase):
    def test_send_to_admitted_peer_delivers(self):
        priv, pem = _issuer_keypair()
        sb = Switchboard()
        node_a = _node(
            admission_rules=[AdmissionRule(spiffe_id=_PEER_ISS, env_tier="prod")],
            switchboard=sb,
            address="mesh-addr-a",
            issuer_pem=pem,
        )
        # Register B's transport endpoint so delivery has a mailbox.
        b_transport = InMemoryTransport("mesh-addr-b", sb)
        node_a.learn_peer(_signed_record(priv), now=_NOW)
        node_a.send_to(_PEER_ISS, b"signed-envelope-bytes")
        frame = b_transport.receive()
        self.assertIsNotNone(frame)
        self.assertEqual(frame.payload, b"signed-envelope-bytes")

    def test_send_to_unknown_peer_raises(self):
        _priv, pem = _issuer_keypair()
        sb = Switchboard()
        node = _node(admission_rules=[], switchboard=sb, issuer_pem=pem)
        with self.assertRaisesRegex(MeshNodeError, "unknown/unadmitted"):
            node.send_to(_PEER_ISS, b"x")


if __name__ == "__main__":
    unittest.main()
