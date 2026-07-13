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
here answers *"who is in the cluster and reachable"*; it does **not**
decide *"who is allowed"* — that is `peer_admission` (wired in D6.4).

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
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from transport import Transport, TransportError

_PING = "ping"
_ACK = "ack"


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
    """

    def __init__(
        self,
        node_id: str,
        transport: Transport,
        *,
        seeds: Iterable[str] = (),
        suspect_after: int = 3,
        dead_after: int = 3,
    ) -> None:
        if not isinstance(node_id, str) or not node_id:
            raise TransportError("node_id must be a non-empty string")
        if not isinstance(transport, Transport):
            raise TransportError("transport must be a Transport")
        if suspect_after < 1 or dead_after < 1:
            raise TransportError("suspect_after/dead_after must be >= 1")
        self.node_id = node_id
        self.transport = transport
        self.incarnation = 0
        self.suspect_after = suspect_after
        self.dead_after = dead_after
        self.members: dict[str, Member] = {}
        self._seq = 0
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
            try:
                nid, inc, raw_state = update[0], int(update[1]), MemberState(update[2])
            except (ValueError, IndexError, TypeError):
                continue
            if nid == self.node_id:
                # Someone thinks I'm suspect/dead — refute by out-incarnating.
                if raw_state is not MemberState.ALIVE and inc >= self.incarnation:
                    self.incarnation = inc + 1
                continue
            cur = self.members.get(nid)
            if cur is None:
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
            self.members[sender] = Member(sender, 0, MemberState.ALIVE, 0)
        elif m.state is not MemberState.DEAD:
            m.state = MemberState.ALIVE
            m.ticks_since_heard = 0

    def _receive(self) -> None:
        while True:
            frame = self.transport.receive()
            if frame is None:
                break
            try:
                msg = json.loads(frame.payload)
            except (ValueError, TypeError):
                continue
            self._merge(msg.get("gossip", []))
            sender = msg.get("from")
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
