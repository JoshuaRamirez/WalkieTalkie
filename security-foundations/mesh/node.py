"""Mesh node: authenticated discovery + routing + admission (Phase 5
Track C, D5.4). [RUNNABLE]

The vision's §5 overlay mesh node. A :class:`MeshNode` is one
authenticated participant. It:

1. **Learns peers** from signed :class:`discovery_record.DiscoveryRecord`
   advertisements — verifying the record's signature/window against a
   trusted issuer (`verify_record`) before believing anything in it.
2. **Admits** each verified peer through a
   :class:`peer_admission.PeerAdmissionPolicy` (deny-by-default). A
   peer that verifies cryptographically but isn't on the admission
   allowlist is rejected — authentication is not authorization.
3. **Routes** with diversity: the routing table is selected via
   `eclipse_resistance.select_neighbors`, so no single trust domain
   can dominate a node's peer view (vision §5 Sybil/eclipse defense).
4. **Sends** signed envelope bytes to an admitted peer over the
   pluggable :class:`transport.Transport`, looking up the peer's
   transport address from its discovery record's endpoints.

This slice wires the node's control plane (who do I know, who may I
talk to, how do I reach them). The full data-plane round trip —
send a signed envelope, receive it, run the complete substrate
verification stack, reply — is the C3 proof.

A peer's transport address is taken from the first endpoint in its
(verified) discovery record. The mesh treats endpoints as untrusted
routing hints authenticated by the record signature: a tampered
endpoint invalidates the signature, so you cannot be redirected to an
attacker's address without breaking discovery verification.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from discovery_record import DiscoveryRecord, verify_record
from eclipse_resistance import (
    DiversityRule,
    NeighborCandidate,
    select_neighbors,
)
from peer_admission import PeerAdmissionPolicy, admit_peer
from transport import Frame, Transport


class MeshNodeError(ValueError):
    """Raised when mesh-node inputs violate v0 invariants."""


@dataclass(frozen=True)
class Peer:
    """An admitted peer in this node's routing table."""

    spiffe_id: str
    kid: str
    transport_address: str
    learned_at: datetime


@dataclass(frozen=True)
class LearnResult:
    admitted: bool
    reason: str
    reason_code: str = ""
    peer: Peer | None = None


@dataclass
class MeshNode:
    """One authenticated participant in the mesh.

    ``issuer_lookup`` verifies discovery-record signatures (typically
    an ``IssuerTrustStore`` from a verified bootstrap bundle).
    ``admission_policy`` gates which verified peers may join.
    ``env_tier`` is this node's environment tier, passed to admission.
    ``transport`` moves bytes. ``routing_rule`` bounds per-trust-domain
    peer share for eclipse resistance.
    """

    spiffe_id: str
    env_tier: str
    transport: Transport
    issuer_lookup: Callable[[str, str], bytes]
    admission_policy: PeerAdmissionPolicy
    routing_rule: DiversityRule
    _peers: dict[str, Peer] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.spiffe_id, str) or not self.spiffe_id:
            raise MeshNodeError("spiffe_id must be a non-empty string")
        if not isinstance(self.env_tier, str) or not self.env_tier:
            raise MeshNodeError("env_tier must be a non-empty string")
        if not isinstance(self.transport, Transport):
            raise MeshNodeError("transport must be a Transport")
        if not isinstance(self.routing_rule, DiversityRule):
            raise MeshNodeError("routing_rule must be a DiversityRule")

    # ----- control plane -----

    def learn_peer(
        self, record: DiscoveryRecord, *, now: datetime
    ) -> LearnResult:
        """Verify a discovery record, admit the peer, add it to the
        routing table. Returns a :class:`LearnResult`.

        Order (fail-fast): verify signature/window → admit → record.
        A verification failure or admission denial leaves the routing
        table untouched.
        """
        # 1. Authenticate the advertisement.
        try:
            verify_record(record, issuer_lookup=self.issuer_lookup, now=now)
        except Exception as exc:  # noqa: BLE001 — surface any verify failure
            return LearnResult(
                admitted=False,
                reason=f"discovery verification failed: {exc}",
                reason_code=getattr(getattr(exc, "reason", None), "value", "")
                or "discovery_verify_failed",
            )

        if not record.endpoints:
            return LearnResult(
                admitted=False,
                reason="verified discovery record carries no endpoints",
                reason_code="discovery_no_endpoints",
            )

        # 2. Authorize the peer (authentication != authorization).
        decision = admit_peer(
            spiffe_id=record.workload_iss,
            env_tier=self.env_tier,
            policy=self.admission_policy,
        )
        if not decision.allowed:
            return LearnResult(
                admitted=False,
                reason=decision.reason,
                reason_code=decision.reason_code,
            )

        # 3. Record. Transport address is the first endpoint.
        peer = Peer(
            spiffe_id=record.workload_iss,
            kid=record.workload_kid,
            transport_address=record.endpoints[0],
            learned_at=now,
        )
        self._peers[peer.spiffe_id] = peer
        return LearnResult(
            admitted=True, reason="ok", reason_code="ok", peer=peer
        )

    def routing_table(self) -> tuple[Peer, ...]:
        """The diversity-selected subset of known peers.

        Applies `eclipse_resistance.select_neighbors` so one trust
        domain cannot dominate the node's active peer set."""
        candidates = [
            NeighborCandidate(
                peer_iss=p.spiffe_id, peer_kid=p.kid, last_seen=p.learned_at
            )
            for p in self._peers.values()
        ]
        selection = select_neighbors(candidates, rule=self.routing_rule)
        selected_ids = {c.peer_iss for c in selection.selected}
        return tuple(
            p for p in self._peers.values() if p.spiffe_id in selected_ids
        )

    def known_peer(self, spiffe_id: str) -> Peer | None:
        return self._peers.get(spiffe_id)

    # ----- data plane -----

    def send_to(self, peer_spiffe_id: str, payload: bytes) -> None:
        """Send ``payload`` (a signed envelope's bytes) to an admitted
        peer over the transport. Raises if the peer is unknown — you
        cannot send to an identity you haven't learned and admitted."""
        peer = self._peers.get(peer_spiffe_id)
        if peer is None:
            raise MeshNodeError(
                f"cannot send to unknown/unadmitted peer: {peer_spiffe_id!r}"
            )
        self.transport.send(peer.transport_address, payload)

    def receive(self) -> Frame | None:
        """Pull the next inbound frame from the transport. The caller
        runs the substrate verification stack on ``frame.payload`` —
        the node does not trust the transport source address."""
        return self.transport.receive()
