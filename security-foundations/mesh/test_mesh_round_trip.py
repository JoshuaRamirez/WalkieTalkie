"""Two-node mesh round trip (Phase 5 Track C C3, D5.5). [RUNNABLE]

THE fabric-works-as-a-system proof. Two authenticated mesh nodes
discover and admit each other, then a signed envelope crosses the
transport between them, is verified by the full substrate stack on
the receiving end, answered with a signed reply, and re-verified by
the original sender. Both nodes' audit chains hash-validate.

This is vision §8 re-proven at *mesh* scope (Phase 4 proved it at
single-host scope):
- §8.1 unauthorized peer cannot join — an unadmitted node's traffic
  has nowhere to route (`send_to` raises) and its envelope would fail
  verification anyway.
- §8.2 tampered/replayed message rejected — `verify_envelope` runs on
  every inbound frame; the replay cache is per-node.
- §8.6 full forensic trace — both nodes accumulate hash-chained audit
  events that `verify_chain` validates.

There are two transports under test: `InMemoryTransport` (deterministic,
for the full crypto round trip) and the real `LocalSocketTransport`
(loopback TCP, proving transport-agnosticism — the node code is
identical either way).
"""

import hashlib
import pathlib
import sys
import time
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "envelope")
)
sys.path.insert(
    0,
    str(
        pathlib.Path(__file__).resolve().parent.parent / "integrations" / "mcp"
    ),
)

import jcs
from audit import InMemoryAuditSink, verify_chain
from capability_issuer import CapabilityIssuer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from discovery_record import DiscoveryRecord, sign_record
from eclipse_resistance import DiversityRule
from envelope_adapter import (
    EnvelopeFields,
    MCPRequest,
    MCPResponse,
    build_envelope,
    envelope_from_json,
    envelope_to_json,
    mcp_request_to_payload,
    mcp_response_to_payload,
    sign_envelope,
)
from node import MeshNode, MeshNodeError
from peer_admission import AdmissionRule, PeerAdmissionPolicy
from socket_transport import LocalSocketTransport
from transport import InMemoryTransport, Switchboard
from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    verify_envelope,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_A = "spiffe://mesh.example/ns-a/agent-a"
_A_KID = "kid-a"
_B = "spiffe://mesh.example/ns-b/agent-b"
_B_KID = "kid-b"
_ISSUER = "spiffe://mesh.example/ns-iss/issuer-1"
_ISSUER_KID = "issuer-kid-1"


def _pem(priv):
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class _Fabric:
    """Wires two full mesh nodes over a shared in-memory switchboard."""

    def __init__(self):
        self.a_priv = Ed25519PrivateKey.generate()
        self.b_priv = Ed25519PrivateKey.generate()
        self.issuer_priv = Ed25519PrivateKey.generate()

        self._key_pems = {_A_KID: _pem(self.a_priv), _B_KID: _pem(self.b_priv)}
        self._issuer_pems = {(_ISSUER, _ISSUER_KID): _pem(self.issuer_priv)}

        self.a_audit = InMemoryAuditSink()
        self.b_audit = InMemoryAuditSink()
        self.a_replay = InMemoryReplayCache()
        self.b_replay = InMemoryReplayCache()

        self.issuer = CapabilityIssuer(
            iss=_ISSUER,
            kid=_ISSUER_KID,
            signing_key=self.issuer_priv,
            default_ttl=timedelta(minutes=5),
            clock_skew=timedelta(seconds=30),
        )

        self.switchboard = Switchboard()
        rule = DiversityRule(
            target_count=8, max_per_trust_domain=4, min_distinct_trust_domains=1
        )
        admit_both = PeerAdmissionPolicy(
            rules=(
                AdmissionRule(spiffe_id=_A, env_tier="prod"),
                AdmissionRule(spiffe_id=_B, env_tier="prod"),
            )
        )
        self.node_a = MeshNode(
            spiffe_id=_A,
            env_tier="prod",
            transport=InMemoryTransport("mesh-a", self.switchboard),
            issuer_lookup=self._issuer_lookup,
            admission_policy=admit_both,
            routing_rule=rule,
        )
        self.node_b = MeshNode(
            spiffe_id=_B,
            env_tier="prod",
            transport=InMemoryTransport("mesh-b", self.switchboard),
            issuer_lookup=self._issuer_lookup,
            admission_policy=admit_both,
            routing_rule=rule,
        )

    def _key_lookup(self, kid):
        pem = self._key_pems.get(kid)
        if pem is None:
            raise EnvelopeVerificationError(f"unknown kid {kid!r}")
        return pem

    def _issuer_lookup(self, iss, kid):
        pem = self._issuer_pems.get((iss, kid))
        if pem is None:
            raise EnvelopeVerificationError(f"unknown issuer {iss!r}/{kid!r}")
        return pem

    def discovery_record(self, *, peer, kid, endpoint):
        rec = DiscoveryRecord(
            version="v0",
            workload_iss=peer,
            workload_kid=kid,
            endpoints=(endpoint,),
            issuer_iss=_ISSUER,
            issuer_kid=_ISSUER_KID,
            issued_at="2026-04-14T12:00:00Z",
            expires_at="2026-04-14T12:30:00Z",
        )
        return sign_record(rec, self.issuer_priv)

    def build_signed_envelope(
        self, *, sender, sender_kid, recipient, signing_key,
        method=None, result=None, message_id, nonce,
    ):
        if method is not None:
            payload = mcp_request_to_payload(
                MCPRequest(method=method, params={"path": "/etc/motd"}, id=1)
            )
        else:
            payload = mcp_response_to_payload(MCPResponse(id=1, result=result))
        digest = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
        cap = self.issuer.issue(
            sub=sender, aud=recipient, scope="invoke_tool",
            envelope_digest=digest, now=_NOW,
        )
        fields = EnvelopeFields(
            sender_spiffe_id=sender,
            recipient_spiffe_id=recipient,
            purpose_of_use="invoke_tool",
            kid=sender_kid,
            capability_token=cap,
            message_id=message_id,
            nonce=nonce,
            issued_at=_NOW,
            ttl=timedelta(minutes=5),
        )
        return sign_envelope(build_envelope(payload=payload, fields=fields), signing_key)


class RoundTripTests(unittest.TestCase):
    def test_two_node_signed_round_trip(self):
        fab = _Fabric()

        # 1. Mutual discovery + admission.
        rec_b = fab.discovery_record(peer=_B, kid=_B_KID, endpoint="mesh-b")
        rec_a = fab.discovery_record(peer=_A, kid=_A_KID, endpoint="mesh-a")
        self.assertTrue(fab.node_a.learn_peer(rec_b, now=_NOW).admitted)
        self.assertTrue(fab.node_b.learn_peer(rec_a, now=_NOW).admitted)

        # 2. A sends a signed request to B over the mesh.
        req_env = fab.build_signed_envelope(
            sender=_A, sender_kid=_A_KID, recipient=_B, signing_key=fab.a_priv,
            method="read_file",
            message_id="01900000-0000-7000-8000-aaaaaaaaaaa1",
            nonce="a-to-b-nonce-0001",
        )
        fab.node_a.send_to(_B, envelope_to_json(req_env))

        # 3. B receives, runs the FULL substrate stack on the payload.
        frame = fab.node_b.receive()
        self.assertIsNotNone(frame)
        inbound = envelope_from_json(frame.payload)
        claims = verify_envelope(
            inbound,
            key_lookup=fab._key_lookup,
            issuer_lookup=fab._issuer_lookup,
            replay_cache=fab.b_replay,
            now=_NOW,
            audit_sink=fab.b_audit,
        )
        self.assertEqual(claims.sub, _A)
        self.assertEqual(claims.aud, _B)

        # 4. B replies with a signed envelope.
        reply_env = fab.build_signed_envelope(
            sender=_B, sender_kid=_B_KID, recipient=_A, signing_key=fab.b_priv,
            result={"contents": "ok"},
            message_id="01900000-0000-7000-8000-bbbbbbbbbbb1",
            nonce="b-to-a-nonce-0001",
        )
        fab.node_b.send_to(_A, envelope_to_json(reply_env))

        # 5. A receives and re-verifies the reply independently.
        reply_frame = fab.node_a.receive()
        self.assertIsNotNone(reply_frame)
        reply_inbound = envelope_from_json(reply_frame.payload)
        reply_claims = verify_envelope(
            reply_inbound,
            key_lookup=fab._key_lookup,
            issuer_lookup=fab._issuer_lookup,
            replay_cache=fab.a_replay,
            now=_NOW,
            audit_sink=fab.a_audit,
        )
        self.assertEqual(reply_claims.sub, _B)

        # 6. Both nodes' audit chains validate.
        verify_chain(fab.a_audit.events)
        verify_chain(fab.b_audit.events)
        self.assertTrue(fab.a_audit.events)
        self.assertTrue(fab.b_audit.events)

    def test_unadmitted_peer_has_nowhere_to_route(self):
        # Vision §8.1 at mesh scope: a node that hasn't admitted B
        # cannot send to it.
        fab = _Fabric()
        lonely = MeshNode(
            spiffe_id=_A,
            env_tier="prod",
            transport=InMemoryTransport("mesh-lonely", fab.switchboard),
            issuer_lookup=fab._issuer_lookup,
            admission_policy=PeerAdmissionPolicy(rules=()),  # admits nobody
            routing_rule=DiversityRule(target_count=8, max_per_trust_domain=4),
        )
        rec_b = fab.discovery_record(peer=_B, kid=_B_KID, endpoint="mesh-b")
        result = lonely.learn_peer(rec_b, now=_NOW)
        self.assertFalse(result.admitted)
        with self.assertRaises(MeshNodeError):
            lonely.send_to(_B, b"envelope-bytes")

    def test_replayed_envelope_rejected_at_receiver(self):
        # Vision §8.2 at mesh scope: the same nonce twice is caught by
        # the receiver's replay cache.
        fab = _Fabric()
        rec_b = fab.discovery_record(peer=_B, kid=_B_KID, endpoint="mesh-b")
        fab.node_a.learn_peer(rec_b, now=_NOW)
        env = fab.build_signed_envelope(
            sender=_A, sender_kid=_A_KID, recipient=_B, signing_key=fab.a_priv,
            method="read_file",
            message_id="01900000-0000-7000-8000-ccccccccccc1",
            nonce="replay-nonce-0001",
        )
        raw = envelope_to_json(env)
        fab.node_a.send_to(_B, raw)
        fab.node_a.send_to(_B, raw)  # same bytes twice
        # First verifies.
        f1 = fab.node_b.receive()
        verify_envelope(
            envelope_from_json(f1.payload),
            key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
            replay_cache=fab.b_replay, now=_NOW, audit_sink=fab.b_audit,
        )
        # Second is a replay.
        f2 = fab.node_b.receive()
        with self.assertRaises(EnvelopeVerificationError):
            verify_envelope(
                envelope_from_json(f2.payload),
                key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                replay_cache=fab.b_replay, now=_NOW, audit_sink=fab.b_audit,
            )


class LocalSocketTransportTests(unittest.TestCase):
    def _await_frame(self, transport, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            frame = transport.receive()
            if frame is not None:
                return frame
            time.sleep(0.01)
        return None

    def test_real_socket_round_trip(self):
        # Proves transport-agnosticism: real TCP on loopback carries a
        # frame between two endpoints implementing the same ABC.
        a = LocalSocketTransport("node-a")
        b = LocalSocketTransport("node-b")
        try:
            a.send(b.address, b"hello-over-tcp")
            frame = self._await_frame(b)
            self.assertIsNotNone(frame)
            self.assertEqual(frame.payload, b"hello-over-tcp")
            # And back.
            b.send(a.address, b"reply-over-tcp")
            reply = self._await_frame(a)
            self.assertEqual(reply.payload, b"reply-over-tcp")
        finally:
            a.close()
            b.close()

    def test_signed_envelope_over_real_socket(self):
        # The same signed envelope that verifies in-memory also
        # verifies after crossing a real socket — the wire is inert.
        fab = _Fabric()
        a = LocalSocketTransport("node-a")
        b = LocalSocketTransport("node-b")
        try:
            env = fab.build_signed_envelope(
                sender=_A, sender_kid=_A_KID, recipient=_B,
                signing_key=fab.a_priv, method="read_file",
                message_id="01900000-0000-7000-8000-ddddddddddd1",
                nonce="socket-nonce-0001",
            )
            a.send(b.address, envelope_to_json(env))
            frame = self._await_frame(b)
            self.assertIsNotNone(frame)
            claims = verify_envelope(
                envelope_from_json(frame.payload),
                key_lookup=fab._key_lookup, issuer_lookup=fab._issuer_lookup,
                replay_cache=fab.b_replay, now=_NOW, audit_sink=fab.b_audit,
            )
            self.assertEqual(claims.sub, _A)
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main()
