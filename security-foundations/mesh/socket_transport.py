"""Real loopback socket transport (Phase 5 Track C, D5.4). [RUNNABLE]

`LocalSocketTransport` implements the same :class:`transport.Transport`
ABC as `InMemoryTransport`, but moves bytes over real TCP on
localhost. Its whole purpose is to prove the substrate's
transport-agnosticism: the mesh node code (C2) is byte-for-byte
identical whether frames cross a function call (in-memory) or a
socket — because security lives in the signed envelope, not the wire.

Design:

- Binds an ephemeral loopback port (``127.0.0.1:0``); the OS-assigned
  ``address`` is ``"127.0.0.1:<port>"``.
- A daemon listener thread accepts connections, reads one
  length-prefixed frame per connection, and appends it to a
  thread-safe inbox. ``receive()`` drains the inbox (non-blocking,
  same contract as the ABC).
- ``send(dest, payload)`` opens a short-lived connection to ``dest``,
  writes a 4-byte big-endian length prefix + the payload, and closes.
- ``close()`` stops the listener and releases the socket. Callers
  MUST close (tests use try/finally) so no thread or port leaks.

This is loopback only and single-host — genuine networking, but not a
distributed deployment. A planet-scale mesh (NAT traversal, TLS on
the wire, connection pooling, backpressure) is out of scope and lives
in the Phase 6 pool. What this proves is that the node abstraction
holds over a real socket, which is the claim that matters.
"""

from __future__ import annotations

import socket
import threading
from collections import deque

from transport import Frame, Transport, TransportError

_LEN_PREFIX = 4  # bytes, big-endian frame length
_MAX_FRAME = 8 * 1024 * 1024  # 8 MiB cap; envelopes are small


def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class LocalSocketTransport(Transport):
    """A :class:`Transport` over real TCP on localhost.

    ``source_address`` is the transport address embedded in inbound
    :class:`Frame`s so a receiver can see who connected — but, exactly
    like the in-memory transport, that is NOT a trusted identity;
    identity comes from the signed envelope inside the payload.
    """

    def __init__(self, source_address: str = "local") -> None:
        if not isinstance(source_address, str) or not source_address:
            raise TransportError("source_address must be a non-empty string")
        self._source_address = source_address
        self._inbox: deque[Frame] = deque()
        self._lock = threading.Lock()
        self._closed = threading.Event()

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.25)
        host, port = self._listener.getsockname()
        self._address = f"{host}:{port}"

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return self._address

    def _serve(self) -> None:
        while not self._closed.is_set():
            try:
                conn, _peer = self._listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                header = _recv_exactly(conn, _LEN_PREFIX)
                if header is None:
                    continue
                length = int.from_bytes(header, "big")
                if length < 0 or length > _MAX_FRAME:
                    continue
                payload = _recv_exactly(conn, length)
                if payload is None:
                    continue
                with self._lock:
                    self._inbox.append(
                        Frame(source=self._source_address, payload=payload)
                    )
            finally:
                conn.close()

    def send(self, dest: str, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise TransportError("payload must be bytes")
        payload = bytes(payload)
        if len(payload) > _MAX_FRAME:
            raise TransportError("payload exceeds max frame size")
        try:
            host, port_str = dest.rsplit(":", 1)
            port = int(port_str)
        except (ValueError, AttributeError) as exc:
            raise TransportError(f"invalid dest address: {dest!r}") from exc
        with socket.create_connection((host, port), timeout=2.0) as conn:
            conn.sendall(len(payload).to_bytes(_LEN_PREFIX, "big") + payload)

    def receive(self) -> Frame | None:
        with self._lock:
            if not self._inbox:
                return None
            return self._inbox.popleft()

    def close(self) -> None:
        """Stop the listener thread and release the socket."""
        self._closed.set()
        self._thread.join(timeout=2.0)
        try:
            self._listener.close()
        except OSError:
            pass

    def __enter__(self) -> LocalSocketTransport:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
