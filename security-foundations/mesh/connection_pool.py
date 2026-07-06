"""Pooled, persistent connection transport (Phase 6 Track D, D6.7). [RUNNABLE]

`LocalSocketTransport` opens a fresh TCP connection for **every** frame
and closes it — correct, but a real mesh under load can't pay a handshake
per message. `PooledSocketTransport` implements the same
:class:`transport.Transport` ABC but keeps connections **alive and
reused**, with the operational properties a real network layer needs:

- **Connection reuse** — one persistent TCP connection per destination
  carries many frames (a length-prefixed stream), so N messages cost one
  handshake, not N.
- **Keepalive** — ``SO_KEEPALIVE`` on every socket so the OS reaps dead
  peers.
- **Reconnect with backoff** — if a pooled connection has dropped, the
  next send transparently reconnects, retrying with exponential backoff.
- **Bounded pool (backpressure)** — at most ``max_connections`` outbound
  connections; the least-recently-used is evicted (and closed) when the
  cap is exceeded, so a fan-out to many peers can't exhaust file
  descriptors.

This is an *operational* layer, not a security one: it changes how bytes
move, not what they mean. Identity still comes from the signed envelope
(and, when composed with `TlsSocketTransport`-style material, the peer
SVID). Framing is unchanged (4-byte big-endian length prefix), so a
pooled endpoint interoperates with the same wire the other transports
speak.

v0 serializes sends with a single lock (simple + correct); a per-
destination lock for higher concurrency is a documented deferral. TLS on
pooled connections composes the same way `TlsSocketTransport` wraps a
socket — wiring the two together is a follow-up, not a new primitive.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections import OrderedDict, deque

from transport import Frame, Transport, TransportError

_LEN_PREFIX = 4
_MAX_FRAME = 8 * 1024 * 1024


def _recv_exactly(conn: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class PooledSocketTransport(Transport):
    """A :class:`Transport` over persistent, pooled loopback-TCP
    connections."""

    def __init__(
        self,
        source_address: str = "local",
        *,
        max_connections: int = 64,
        connect_retries: int = 3,
        backoff_base: float = 0.02,
    ) -> None:
        if not isinstance(source_address, str) or not source_address:
            raise TransportError("source_address must be a non-empty string")
        if max_connections < 1:
            raise TransportError("max_connections must be >= 1")
        if connect_retries < 1:
            raise TransportError("connect_retries must be >= 1")
        self._source = source_address
        self._max_conns = max_connections
        self._retries = connect_retries
        self._backoff = backoff_base

        self._inbox: deque[Frame] = deque()
        self._inbox_lock = threading.Lock()
        self._closed = threading.Event()

        # Outbound pool, LRU-ordered. Guarded by _out_lock; _send_lock
        # serializes actual writes so frames never interleave on a socket.
        self._out: OrderedDict[str, socket.socket] = OrderedDict()
        self._out_lock = threading.Lock()
        self._send_lock = threading.Lock()

        self._accepted = 0  # inbound connections accepted (observability/tests)
        self._readers: list[threading.Thread] = []

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        self._listener.settimeout(0.25)
        host, port = self._listener.getsockname()
        self._address = f"{host}:{port}"

        self._acceptor = threading.Thread(target=self._accept_loop, daemon=True)
        self._acceptor.start()

    @property
    def address(self) -> str:
        return self._address

    @property
    def accepted_connections(self) -> int:
        """Total inbound connections accepted — reuse shows up as this
        staying flat while many frames arrive."""
        return self._accepted

    def open_connections(self) -> int:
        with self._out_lock:
            return len(self._out)

    # ---- inbound ------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._closed.is_set():
            try:
                conn, _peer = self._listener.accept()
            except (TimeoutError, OSError):
                continue
            with self._inbox_lock:
                self._accepted += 1
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            t = threading.Thread(target=self._read_conn, args=(conn,), daemon=True)
            self._readers.append(t)
            t.start()

    def _read_conn(self, conn: socket.socket) -> None:
        try:
            while not self._closed.is_set():
                header = _recv_exactly(conn, _LEN_PREFIX)
                if header is None:
                    return
                length = int.from_bytes(header, "big")
                if length < 0 or length > _MAX_FRAME:
                    return
                payload = _recv_exactly(conn, length)
                if payload is None:
                    return
                with self._inbox_lock:
                    self._inbox.append(Frame(source=self._source, payload=payload))
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def receive(self) -> Frame | None:
        with self._inbox_lock:
            if not self._inbox:
                return None
            return self._inbox.popleft()

    # ---- outbound -----------------------------------------------------
    def _connect(self, dest: str) -> socket.socket:
        try:
            host, port_str = dest.rsplit(":", 1)
            port = int(port_str)
        except (ValueError, AttributeError) as exc:
            raise TransportError(f"invalid dest address: {dest!r}") from exc
        conn = socket.create_connection((host, port), timeout=5.0)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        return conn

    def _get_conn(self, dest: str) -> socket.socket:
        with self._out_lock:
            conn = self._out.get(dest)
            if conn is not None:
                self._out.move_to_end(dest)  # mark most-recently-used
                return conn
            conn = self._connect(dest)
            self._out[dest] = conn
            # Bounded pool: evict + close the least-recently-used.
            while len(self._out) > self._max_conns:
                _old_dest, old = self._out.popitem(last=False)
                with contextlib.suppress(OSError):
                    old.close()
            return conn

    def _drop(self, dest: str) -> None:
        with self._out_lock:
            conn = self._out.pop(dest, None)
        if conn is not None:
            with contextlib.suppress(OSError):
                conn.close()

    def send(self, dest: str, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise TransportError("payload must be bytes")
        payload = bytes(payload)
        if len(payload) > _MAX_FRAME:
            raise TransportError("payload exceeds max frame size")
        frame = len(payload).to_bytes(_LEN_PREFIX, "big") + payload

        last_exc: Exception | None = None
        with self._send_lock:
            for attempt in range(self._retries):
                try:
                    conn = self._get_conn(dest)
                    conn.sendall(frame)
                    return
                except OSError as exc:
                    # Stale/dropped connection: discard it and back off before
                    # reconnecting on the next attempt.
                    last_exc = exc
                    self._drop(dest)
                    if attempt < self._retries - 1:
                        time.sleep(self._backoff * (2 ** attempt))
        raise TransportError(
            f"send to {dest!r} failed after {self._retries} attempts: {last_exc}"
        )

    def close(self) -> None:
        self._closed.set()
        self._acceptor.join(timeout=2.0)
        with self._out_lock:
            for conn in self._out.values():
                with contextlib.suppress(OSError):
                    conn.close()
            self._out.clear()
        with contextlib.suppress(OSError):
            self._listener.close()

    def __enter__(self) -> PooledSocketTransport:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
