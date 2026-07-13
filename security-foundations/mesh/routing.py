"""Routing table + multi-hop forwarding (Phase 6 Track C, D6.5). [RUNNABLE]

The Phase 5 mesh delivers only *directly* — A hands bytes straight to B.
A real overlay must let A reach C when A and C are not directly
connected, by **forwarding through** an intermediary B. This module is
the forwarding logic, and it is security-shaped:

- **Deny-by-default forwarding.** A node forwards a message only to a
  next hop it is *allowed* to route to (the admitted, routable set from
  D6.4). An intermediary never relays toward an unadmitted peer.
- **Loop safety.** Every routed message carries a TTL (decremented per
  hop; dropped at zero) and a message id; each node remembers ids it has
  already handled and drops duplicates. A routing loop cannot amplify.
- **The intermediary is not the recipient.** B forwards A→C's message
  without being its `recipient_spiffe_id`, so B cannot make C accept the
  message *as if from B*: the signed envelope inside still names A as
  sender and C as recipient. Forwarding moves bytes; it grants no
  authority (the same principle as the transport layer).

This module is transport-agnostic and pure: :meth:`Router.handle`
returns a :class:`RoutingDecision` (deliver / forward / drop) that the
caller executes over whatever transport it holds. D6.6 wires it over the
real socket transport for a 3-node signed round trip.

Route computation (which next hop reaches which destination) is provided
by the caller as a ``next_hop`` resolver. v0 uses static/gossiped tables;
a full distance-vector or link-state routing protocol is a documented
deferral — the *forwarding* security invariants (deny-by-default, loop
safety) hold regardless of how the table is computed.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, replace

_DEFAULT_TTL = 8


@dataclass(frozen=True)
class RoutedMessage:
    """A payload plus the routing envelope that carries it across hops.

    ``payload`` is the opaque application bytes (a signed WalkieTalkie
    envelope in practice — routing never inspects it). ``dest`` is the
    final-destination node id; ``ttl`` bounds hops; ``msg_id`` deduplicates.
    """

    dest: str
    ttl: int
    msg_id: str
    payload: bytes

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "dest": self.dest,
                "ttl": self.ttl,
                "msg_id": self.msg_id,
                "payload_b64": base64.b64encode(self.payload).decode("ascii"),
            }
        ).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> RoutedMessage:
        obj = json.loads(data)
        return cls(
            dest=obj["dest"],
            ttl=int(obj["ttl"]),
            msg_id=obj["msg_id"],
            payload=base64.b64decode(obj["payload_b64"]),
        )


@dataclass(frozen=True)
class RoutingDecision:
    action: str  # "deliver" | "forward" | "drop"
    payload: bytes | None = None       # set for "deliver"
    next_hop: str | None = None        # set for "forward"
    forwarded: RoutedMessage | None = None  # set for "forward" (ttl-1)
    reason: str = ""                   # set for "drop"


class Router:
    """Per-node forwarding engine.

    - ``next_hop(dest) -> node_id | None`` resolves the next hop toward a
      destination (the routing table; None if no route is known).
    - ``is_routable(node_id) -> bool`` gates forwarding — typically
      ``GossipDiscovery.is_routable`` so a node forwards only toward
      admitted peers.
    """

    def __init__(
        self,
        node_id: str,
        *,
        next_hop: Callable[[str], str | None],
        is_routable: Callable[[str], bool],
        default_ttl: int = _DEFAULT_TTL,
    ) -> None:
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("node_id must be a non-empty string")
        if default_ttl < 1:
            raise ValueError("default_ttl must be >= 1")
        self.node_id = node_id
        self._next_hop = next_hop
        self._is_routable = is_routable
        self.default_ttl = default_ttl
        self._seen: set[str] = set()

    def originate(self, dest: str, payload: bytes, *, msg_id: str) -> RoutedMessage:
        """Wrap a payload for delivery to ``dest`` with a fresh TTL."""
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError("payload must be bytes")
        return RoutedMessage(
            dest=dest, ttl=self.default_ttl, msg_id=msg_id, payload=bytes(payload)
        )

    def handle(self, routed: RoutedMessage) -> RoutingDecision:
        """Decide what to do with an inbound routed message."""
        if routed.msg_id in self._seen:
            # Already handled — loop protection.
            return RoutingDecision(action="drop", reason="duplicate")
        self._seen.add(routed.msg_id)

        if routed.dest == self.node_id:
            return RoutingDecision(action="deliver", payload=routed.payload)

        ttl = routed.ttl - 1
        if ttl <= 0:
            return RoutingDecision(action="drop", reason="ttl_exhausted")

        nh = self._next_hop(routed.dest)
        if nh is None:
            return RoutingDecision(action="drop", reason="no_route")
        if not self._is_routable(nh):
            # Deny-by-default: never relay toward an unadmitted peer.
            return RoutingDecision(action="drop", reason="next_hop_not_admitted")

        return RoutingDecision(
            action="forward", next_hop=nh, forwarded=replace(routed, ttl=ttl)
        )
