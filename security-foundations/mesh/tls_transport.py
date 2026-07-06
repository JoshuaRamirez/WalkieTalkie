"""Mutually-authenticated TLS transport (Phase 6 Track A, D6.1). [RUNNABLE]

`TlsSocketTransport` implements the same :class:`transport.Transport` ABC
as `LocalSocketTransport`, but the bytes cross a **mutual TLS 1.3**
channel instead of a bare socket. Each endpoint presents its Phase 5
**SVID** (a `workload_ca` X.509 cert with a SPIFFE URI SAN) and, on every
handshake, verifies the peer's cert:

1. TLS verifies the peer cert chains to the trusted CA root (via
   ``load_verify_locations`` + ``CERT_REQUIRED``) and negotiates TLS 1.3.
2. Post-handshake, the substrate's own :func:`verify_svid` re-checks the
   peer cert (chain + time window + key usage + SPIFFE SAN) and extracts
   the peer's SPIFFE id — the identity the mesh admits on.

**Defense in depth, not replacement.** TLS authenticates and encrypts the
*channel*; the signed envelope still authenticates the *message*. Either
alone is a full security layer; together they are the vision's Layer A
(mTLS peer identity) composed with Layer B (message signature). A peer
without a CA-issued SVID cannot complete the handshake, so unauthenticated
bytes never reach the envelope verifier at all.

Loopback is real TLS: the handshake, cipher negotiation, certificate
verification, and record encryption are identical whether the socket is
``127.0.0.1`` or a WAN address. Loopback bounds *scale* (one host's ports
and threads), not *realness*. NAT traversal, WAN CA custody, and planet
scale are the D6.8 deployment frontier — [REFERENCE], not here.
"""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import tempfile
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from transport import Frame, Transport, TransportError

# Substrate identity primitives live in the envelope package; the mesh
# test/discovery paths already add it to sys.path. Import lazily-safe names.
from workload_ca import (  # noqa: E402  (sys.path set by importer, as in the package)
    SvidVerificationError,
    verify_svid,
)

_LEN_PREFIX = 4
_MAX_FRAME = 8 * 1024 * 1024


def _recv_exactly(conn: ssl.SSLSocket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


@dataclass(frozen=True)
class TlsIdentity:
    """One node's TLS material: its SVID + private key + the CA root it
    trusts. Build via :func:`mint_identity` (test/demo) or construct
    directly from material issued out of band (real deployment)."""

    spiffe_id: str
    private_key: Ed25519PrivateKey
    svid_cert: x509.Certificate
    root_cert: x509.Certificate

    def _cert_pem(self) -> bytes:
        return self.svid_cert.public_bytes(serialization.Encoding.PEM)

    def _key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _root_pem(self) -> str:
        return self.root_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def _context(self, *, server: bool) -> ssl.SSLContext:
        proto = ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT
        ctx = ssl.SSLContext(proto)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # SPIFFE identity lives in a URI SAN, not a DNS name; the standard
        # hostname check does not apply. We verify the SPIFFE id ourselves
        # post-handshake via the substrate's verify_svid.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=self._root_pem())
        # load_cert_chain needs files; write to a 0700 tempdir, load, remove.
        d = tempfile.mkdtemp()
        try:
            cp = os.path.join(d, "svid.pem")
            kp = os.path.join(d, "key.pem")
            with open(cp, "wb") as f:
                f.write(self._cert_pem())
            os.chmod(kp if os.path.exists(kp) else cp, 0o600)
            with open(kp, "wb") as f:
                f.write(self._key_pem())
            os.chmod(kp, 0o600)
            ctx.load_cert_chain(cp, kp)
        finally:
            with contextlib.suppress(OSError):
                for fn in ("svid.pem", "key.pem"):
                    p = os.path.join(d, fn)
                    if os.path.exists(p):
                        os.remove(p)
                os.rmdir(d)
        return ctx


def mint_identity(ca, spiffe_id: str, *, now: datetime | None = None) -> TlsIdentity:
    """Generate a keypair, have ``ca`` issue it an SVID, and bundle it with
    the CA root as a :class:`TlsIdentity`. For tests/demos; in a real mesh
    the node holds a key and receives its SVID from the CA out of band."""
    when = now or datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    cert = ca.issue_svid(spiffe_id=spiffe_id, public_key=key.public_key(), now=when)
    return TlsIdentity(
        spiffe_id=spiffe_id, private_key=key, svid_cert=cert, root_cert=ca.root_cert
    )


class TlsSocketTransport(Transport):
    """A :class:`Transport` over mutually-authenticated TLS 1.3 on loopback.

    The listener thread accepts connections, completes the mTLS handshake,
    verifies the peer's SVID, reads one length-prefixed frame, and appends
    it to a thread-safe inbox with ``source`` set to the peer's
    TLS-verified SPIFFE id. ``send`` opens a short-lived mTLS connection,
    verifies the peer's SVID, and writes one frame.

    ``now_fn`` supplies the current time for SVID validity checks (default
    real clock; injectable for tests).
    """

    def __init__(
        self,
        identity: TlsIdentity,
        *,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(identity, TlsIdentity):
            raise TransportError("identity must be a TlsIdentity")
        self._id = identity
        self._now = now_fn or (lambda: datetime.now(UTC))
        self._server_ctx = identity._context(server=True)
        self._client_ctx = identity._context(server=False)

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

    @property
    def spiffe_id(self) -> str:
        return self._id.spiffe_id

    def _verify_peer(self, tls: ssl.SSLSocket) -> str:
        """Verify the peer's SVID with the substrate verifier; return its
        SPIFFE id. Raises SvidVerificationError on any failure."""
        der = tls.getpeercert(binary_form=True)
        if not der:
            raise SvidVerificationError("peer presented no certificate")
        peer_cert = x509.load_der_x509_certificate(der)
        # verify_svid returns the verified SPIFFE id (chain + window + key
        # usage + SAN shape all checked by the substrate verifier).
        return verify_svid(
            peer_cert, root_cert=self._id.root_cert, current=self._now()
        )

    def _serve(self) -> None:
        while not self._closed.is_set():
            try:
                raw, _peer = self._listener.accept()
            except (TimeoutError, OSError):
                continue
            try:
                tls = self._server_ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                # Peer failed the mTLS handshake (no/invalid SVID). Deny.
                with contextlib.suppress(OSError):
                    raw.close()
                continue
            try:
                peer_id = self._verify_peer(tls)
                header = _recv_exactly(tls, _LEN_PREFIX)
                if header is None:
                    continue
                length = int.from_bytes(header, "big")
                if length < 0 or length > _MAX_FRAME:
                    continue
                payload = _recv_exactly(tls, length)
                if payload is None:
                    continue
                with self._lock:
                    self._inbox.append(Frame(source=peer_id, payload=payload))
            except SvidVerificationError:
                continue  # authenticated TLS but not a valid SVID: deny
            finally:
                with contextlib.suppress(OSError):
                    tls.close()

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
        raw = socket.create_connection((host, port), timeout=5.0)
        try:
            tls = self._client_ctx.wrap_socket(raw, server_hostname=None)
        except ssl.SSLError as exc:
            with contextlib.suppress(OSError):
                raw.close()
            raise TransportError(f"mTLS handshake to {dest!r} failed: {exc}") from exc
        try:
            # Verify the server's SVID too — mutual, not just server-auth.
            self._verify_peer(tls)
            tls.sendall(len(payload).to_bytes(_LEN_PREFIX, "big") + payload)
        except SvidVerificationError as exc:
            raise TransportError(
                f"peer at {dest!r} has no valid SVID: {exc}"
            ) from exc
        finally:
            with contextlib.suppress(OSError):
                tls.close()

    def receive(self) -> Frame | None:
        with self._lock:
            if not self._inbox:
                return None
            return self._inbox.popleft()

    def close(self) -> None:
        self._closed.set()
        self._thread.join(timeout=2.0)
        with contextlib.suppress(OSError):
            self._listener.close()

    def __enter__(self) -> TlsSocketTransport:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
