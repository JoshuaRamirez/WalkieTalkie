"""Mesh transport layer (Phase 5 Track C, D5.4). [RUNNABLE]

The vision's §5 ("Zero-Trust P2P Topology") calls for an overlay mesh
where nodes exchange messages. The substrate has deliberately been
transport-less since Phase 0 — that kept the kernel pure. Phase 5's
mesh needs *a* way to move bytes between nodes, but the substrate's
guarantee is that security holds **regardless of transport**: the
envelope is signed, so the wire can be anything. This module makes
transport a swappable seam rather than a hard dependency.

- :class:`Transport` — the ABC. One endpoint bound to an address;
  ``send(dest, frame)`` and ``receive()``. Intentionally tiny — a
  transport moves bytes, nothing more. It does no verification; the
  mesh node (C2) runs the full substrate stack on what it receives.
- :class:`InMemoryTransport` + :class:`Switchboard` — a deterministic,
  in-process transport for tests and the two-node round trip. The
  switchboard is a shared address→mailbox registry; endpoints send by
  appending to a peer's mailbox and receive by draining their own.

A real networked transport (`LocalSocketTransport`) lands in C3
alongside the round-trip proof. It implements the same ABC, so the
node code is identical whether the bytes cross a function call or a
socket — which is the whole point of the seam.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field


class TransportError(ValueError):
    """Raised when transport inputs violate v0 invariants."""


@dataclass(frozen=True)
class Frame:
    """One unit crossing the transport: raw bytes plus the sender's
    transport address (NOT a trusted identity — identity comes from
    the signed envelope inside ``payload``)."""

    source: str
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source:
            raise TransportError("source must be a non-empty string")
        if not isinstance(self.payload, (bytes, bytearray)):
            raise TransportError("payload must be bytes")


class Transport(ABC):
    """A single endpoint bound to a transport address."""

    @property
    @abstractmethod
    def address(self) -> str:
        ...

    @abstractmethod
    def send(self, dest: str, payload: bytes) -> None:
        """Deliver ``payload`` to the endpoint bound at ``dest``."""

    @abstractmethod
    def receive(self) -> Frame | None:
        """Return the next inbound :class:`Frame`, or None if the inbox
        is empty. Non-blocking."""


@dataclass
class Switchboard:
    """Shared in-process router: address → FIFO mailbox.

    Endpoints register on construction; sending appends to the
    destination's mailbox; receiving drains the caller's own.
    """

    _mailboxes: dict[str, deque[Frame]] = field(default_factory=dict)

    def register(self, address: str) -> None:
        if not isinstance(address, str) or not address:
            raise TransportError("address must be a non-empty string")
        if address in self._mailboxes:
            raise TransportError(f"address already registered: {address!r}")
        self._mailboxes[address] = deque()

    def deliver(self, *, dest: str, frame: Frame) -> None:
        mailbox = self._mailboxes.get(dest)
        if mailbox is None:
            raise TransportError(f"unknown destination address: {dest!r}")
        mailbox.append(frame)

    def drain_one(self, address: str) -> Frame | None:
        mailbox = self._mailboxes.get(address)
        if mailbox is None:
            raise TransportError(f"unknown address: {address!r}")
        if not mailbox:
            return None
        return mailbox.popleft()


@dataclass
class InMemoryTransport(Transport):
    """Deterministic in-process transport over a shared switchboard."""

    _address: str
    switchboard: Switchboard

    def __post_init__(self) -> None:
        if not isinstance(self._address, str) or not self._address:
            raise TransportError("address must be a non-empty string")
        if not isinstance(self.switchboard, Switchboard):
            raise TransportError("switchboard must be a Switchboard")
        self.switchboard.register(self._address)

    @property
    def address(self) -> str:
        return self._address

    def send(self, dest: str, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise TransportError("payload must be bytes")
        self.switchboard.deliver(
            dest=dest, frame=Frame(source=self._address, payload=bytes(payload))
        )

    def receive(self) -> Frame | None:
        return self.switchboard.drain_one(self._address)
