"""Gossip membership protocol (Phase 6 Track B, D6.3). [RUNNABLE]

The vision's §5 zero-trust P2P topology needs nodes to **find each other
and notice when a peer dies** without a central registry or a shared
config file. This is a SWIM-style membership protocol
(Scalable Weakly-consistent Infection-style Process Group Membership):

- **Join** — a new node contacts one or more *seeds* and learns the rest
  of the cluster by gossip, not by configuration.
- **Failure detection** — each node periodically pings its peers; a peer
  that stops acking is marked SUSPECT, then DEAD after a grace period.
- **Gossip dissemination** — every ping/ack piggybacks a digest of the
  sender's membership view, so state (joins, suspicions, deaths) spreads
  epidemically across the cluster in O(log N) rounds.
- **Incarnation refutation** — a node wrongly suspected bumps its
  *incarnation* number and re-asserts ALIVE, which supersedes the stale
  suspicion everywhere. This is what stops a transient hiccup from
  permanently evicting a healthy node.

Transport-agnostic: it runs over any :class:`transport.Transport`, so the
same protocol works over `InMemoryTransport` (deterministic tests) or
`TlsSocketTransport` (encrypted, mutually-authenticated wire). Membership
answers *"who is in the cluster and reachable"*. An optional
`admission` + `peer_tier` pair (the D6.4
:class:`~envelope.peer_admission.PeerAdmissionPolicy` seam) additionally
gates *learning*: a gossiped id enters :attr:`members` only when it
passes deny-by-default admission. That bounds the table by the admitted
set rather than a magic cap — ``_digest()`` is not truncated, and nothing
is evicted. Operator-supplied seeds are retained as bootstrap even if
they would fail the optional admission gate. Callers that omit the pair
keep the original reachability-only table (loopback/LAN tests).
Routing-table deny-by-default stays on
:class:`gossip_discovery.GossipDiscovery`.

The gate keys on ``node_id``, and ``node_id`` is also the
``transport.send`` destination — the existing Transport contract, older
than this leftover. So the membership gate applies when node ids are
already valid dests *and* SPIFFE ids (the D6.4 ``InMemoryTransport``
path). ``TlsSocketTransport`` callers use ``host:port`` dests and omit
the membership gate; admission stays on routing / TLS. A dest-mapping
callable would be an address book and is out of scope here.

Loopback / small-N is real protocol, bounded scale. v0 probes every
non-dead peer each tick (simple, O(N²) messages); production SWIM probes
one random peer per period + relies on gossip for O(N) load — a
documented, deferred optimization, not a correctness gap.

Out of scope for v0 (deferred, see DEFERRED.md):
- Indirect probing (ping-req via k relays) for false-positive suppression
  under transient packet loss.
- Lifeguard refinements (local health multiplier, adaptive timeouts).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from envelope.peer_admission import PeerAdmissionPolicy, admit_peer

from .transport import Transport, TransportError

_PING = "ping"
_ACK = "ack"

# A gossiped node id becomes a key in the members table and is re-gossiped
# to every peer, so an unbounded id is unbounded memory that propagates.
# Far above any real SPIFFE-style id.
MAX_NODE_ID_LEN = 256

class MemberState(StrEnum):
    ALIVE = "alive"
    SUSPECT = "suspect"
    DEAD = "dead"

@dataclass
class Member:
    """One peer as this node currently sees it."""

    node_id: str
    incarnation: int
    state: MemberState
    ticks_since_heard: int = 0

def _supersedes(
    in_state: MemberState, in_inc: int, cur_state: MemberState, cur_inc: int
) -> bool:
    """SWIM state-merge precedence: does an incoming (state, incarnation)
    override the current one?

    - ALIVE overrides only a strictly older incarnation (a refutation).
    - SUSPECT overrides an older incarnation, or an equal-incarnation ALIVE.
    - DEAD overrides an older incarnation, or anything not-already-DEAD at
      equal incarnation.
    """
    if in_state is MemberState.ALIVE:
        return in_inc > cur_inc
    if in_state is MemberState.SUSPECT:
        return in_inc > cur_inc or (in_inc == cur_inc and cur_state is MemberState.ALIVE)
    if in_state is MemberState.DEAD:
        return in_inc > cur_inc or (in_inc == cur_inc and cur_state is not MemberState.DEAD)
    return False

class SwimMembership:
    """One node's membership state machine.

    Drive it by calling :meth:`tick` on a period (a real deployment runs a
    timer thread; tests step it deterministically). Each tick: process
    inbound gossip, age peers toward SUSPECT/DEAD, and probe peers.

    ``admission`` + ``peer_tier`` are optional and must be supplied
    together. ``peer_key`` is an optional sibling that returns a
    verified SVID public key (or ``None``) so pinned admission rules
    can evaluate. When the pair is set, new gossiped ids enter
    :attr:`members` only if they pass deny-by-default
    :func:`~envelope.peer_admission.admit_peer`. Resolver exceptions
    fail closed — drop that candidate; ``tick`` continues.
    """

    def __init__(
        self,
        node_id: str,
        transport: Transport,
        *,
        seeds: Iterable[str] = (),
        suspect_after: int = 3,
        dead_after: int = 3,
        admission: PeerAdmissionPolicy | None = None,
        peer_tier: Callable[[str], str | None] | None = None,
        peer_key: Callable[[str], Ed25519PublicKey | None] | None = None,
    ) -> None:
        if not isinstance(node_id, str) or not node_id:
            raise TransportError("node_id must be a non-empty string")
        if not isinstance(transport, Transport):
            raise TransportError("transport must be a Transport")
        if suspect_after < 1 or dead_after < 1:
            raise TransportError("suspect_after/dead_after must be >= 1")
        if (admission is None) ^ (peer_tier is None):
            raise TransportError("admission and peer_tier must be provided together")
        if peer_key is not None and admission is None:
            raise TransportError("peer_key requires admission and peer_tier")
        self.node_id = node_id
        self.transport = transport
        self.incarnation = 0
        self.suspect_after = suspect_after
        self.dead_after = dead_after
        self.admission = admission
        self.peer_tier = peer_tier
        self.peer_key = peer_key
        self.members: dict[str, Member] = {}
        self._seq = 0
        # Seeds are retained as operator-supplied bootstrap. Do not
        # evict them even if they would fail the optional gossip gate.
        for s in seeds:
            if s and s != node_id:
                self.members[s] = Member(s, 0, MemberState.ALIVE)

    # ---- public view --------------------------------------------------
    def alive_ids(self) -> set[str]:
        return {m.node_id for m in self.members.values() if m.state is MemberState.ALIVE}

    def state_of(self, node_id: str) -> MemberState | None:
        m = self.members.get(node_id)
        return m.state if m else None

    def known_ids(self) -> set[str]:
        return set(self.members)

    # ---- protocol driver ---------------------------------------------
    def join(self) -> None:
        """Contact the seeds to bootstrap into the cluster."""
        for nid, m in list(self.members.items()):
            if m.state is not MemberState.DEAD:
                self.transport.send(nid, self._encode(_PING))

    def tick(self) -> None:
        self._receive()
        self._age()
        self._probe()

    # ---- internals ----------------------------------------------------
    def _may_learn(self, nid: str) -> bool:
        """Whether a *new* id may enter :attr:`members`.

        No gate → yes (existing callers unchanged). When the D6.4 pair
        is attached, only ids that pass deny-by-default admission are
        learned. ``peer_tier`` returning ``None``, a mismatched tier, a
        pinned rule without a matching ``peer_key``, or an id
        ``admit_peer`` rejects (invalid SPIFFE, etc.) all deny. Resolver
        exceptions (``peer_tier`` / ``peer_key``) fail closed too —
        drop that candidate, never raise into ``tick``.
        """
        if self.admission is None or self.peer_tier is None:
            return True
        try:
            tier = self.peer_tier(nid)
            if not isinstance(tier, str) or not tier:
                return False
            presented = self.peer_key(nid) if self.peer_key is not None else None
            return admit_peer(
                spiffe_id=nid,
                env_tier=tier,
                policy=self.admission,
                presented_key=presented,
            ).allowed
        except Exception:  # noqa: BLE001 — resolver/admit_peer must not halt tick
            return False

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _digest(self) -> list[list]:
        """Membership updates to piggyback on every message: self (always
        ALIVE at the current incarnation) plus every known peer."""
        updates = [[self.node_id, self.incarnation, MemberState.ALIVE.value]]
        for m in self.members.values():
            updates.append([m.node_id, m.incarnation, m.state.value])
        return updates

    def _encode(self, typ: str) -> bytes:
        return json.dumps(
            {"type": typ, "from": self.node_id, "seq": self._next_seq(),
             "gossip": self._digest()}
        ).encode("utf-8")

    def _merge(self, updates: list) -> None:
        for update in updates:
            # A gossip update is a peer-supplied ``[node_id, incarnation,
            # state]`` triple. Anything else — a dict (``update[0]`` would
            # KeyError), a short list, an unhashable node id (``members``
            # is keyed on it) — is dropped, not raised: one malformed
            # entry must not discard the rest of the digest.
            if not isinstance(update, list) or len(update) < 3:
                continue
            try:
                nid, inc, raw_state = update[0], int(update[1]), MemberState(update[2])
            except (ValueError, IndexError, TypeError):
                continue
            if not isinstance(nid, str) or not nid or len(nid) > MAX_NODE_ID_LEN:
                continue
            if nid == self.node_id:
                # Someone thinks I'm suspect/dead — refute by out-incarnating.
                if raw_state is not MemberState.ALIVE and inc >= self.incarnation:
                    self.incarnation = inc + 1
                continue
            cur = self.members.get(nid)
            if cur is None:
                if not self._may_learn(nid):
                    continue
                self.members[nid] = Member(nid, inc, raw_state, 0)
                continue
            if _supersedes(raw_state, inc, cur.state, cur.incarnation):
                cur.incarnation = inc
                cur.state = raw_state
                if raw_state is MemberState.ALIVE:
                    cur.ticks_since_heard = 0

    def _mark_heard(self, sender: str) -> None:
        if not sender or sender == self.node_id:
            return
        m = self.members.get(sender)
        if m is None:
            if not self._may_learn(sender):
                return
            self.members[sender] = Member(sender, 0, MemberState.ALIVE, 0)
        elif m.state is not MemberState.DEAD:
            m.state = MemberState.ALIVE
            m.ticks_since_heard = 0

    def _receive(self) -> None:
        while True:
            frame = self.transport.receive()
            if frame is None:
                break
            # Every field below is peer-controlled. A malformed frame from
            # one peer must not kill the tick — that would stop failure
            # detection for the whole cluster, turning a single bad sender
            # into a mesh-wide availability failure. Skip the frame and
            # keep draining the queue.
            try:
                msg = json.loads(frame.payload)
            except (ValueError, TypeError):
                continue
            if not isinstance(msg, dict):
                continue
            gossip = msg.get("gossip", [])
            if isinstance(gossip, list):
                self._merge(gossip)
            sender = msg.get("from")
            # Same bound as a gossiped id: `_mark_heard` stores the sender in
            # `members`, and `_digest()` re-gossips every known id to every
            # peer — so an unbounded `from` is unbounded memory that
            # propagates across the cluster, not just this node.
            if not isinstance(sender, str) or not sender or len(sender) > MAX_NODE_ID_LEN:
                continue
            self._mark_heard(sender)
            if msg.get("type") == _PING and sender:
                self.transport.send(sender, self._encode(_ACK))

    def _age(self) -> None:
        for m in self.members.values():
            if m.state is MemberState.DEAD:
                continue
            m.ticks_since_heard += 1
            if m.state is MemberState.ALIVE and m.ticks_since_heard >= self.suspect_after:
                m.state = MemberState.SUSPECT
            elif (
                m.state is MemberState.SUSPECT
                and m.ticks_since_heard >= self.suspect_after + self.dead_after
            ):
                m.state = MemberState.DEAD

    def _probe(self) -> None:
        # v0: probe every non-dead peer each tick (simple; O(N^2) cluster
        # load). Probing SUSPECT peers too gives them a chance to ack back
        # to ALIVE before the dead timeout.
        for nid, m in list(self.members.items()):
            if m.state is not MemberState.DEAD:
                self.transport.send(nid, self._encode(_PING))
