"""Mesh MCP bridge — let a Claude Code instance send/receive signed
messages to a peer over the WalkieTalkie mesh. [RUNNABLE]

This is the transport loop the substrate deliberately left to "the
operator" (see ``envelope_adapter.py`` / ``host.py``). It is a real MCP
server over stdio that Claude Code launches, wired to a real loopback-TCP
mesh transport on the other side:

    Claude ──stdio/JSON-RPC──▶ this bridge ──signed envelope / TCP──▶ peer bridge ──stdio──▶ peer's Claude

What crosses the mesh is a WalkieTalkie signed envelope: the peer bridge
verifies the Ed25519 signature + capability binding + replay before it
ever surfaces a message. An impostor without the sender's private key is
rejected — exactly the property proven in ``mesh/test_mesh_round_trip.py``.

Two MCP tools are exposed to Claude:

- ``send_message(body, to?)`` — sign ``body`` into an envelope and ship it
  to the peer over the mesh.
- ``check_inbox()`` — return verified messages received since last check.

Receiving is decoupled from Claude's turn: a background thread verifies
inbound envelopes and appends them to a file-backed inbox. That file is
what the ``mail_hook.py`` pre-hook surfaces so Claude "checks mail" often
without a manual tool call. MCP is client-initiated; the hook is how you
turn that into push-like delivery.

ENFORCEMENT BOUNDARY: this is a local, single-host demo. It proves the
end-to-end message security (sign → verify → deliver) works through a real
MCP server. It does NOT add TLS on the wire, NAT traversal, or PKI custody
— those are the Phase 6 deployment frontier (see ``DEFERRED.md``).

Usage (per agent):
    python mesh_mcp_bridge.py --name alice --peer bob
    # --config defaults to ~/.claude/mesh (shared, user-scoped)
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

# --- substrate imports (sibling packages) --------------------------------
_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))  # integrations/mcp (envelope_adapter)
sys.path.insert(0, str(_HERE.parents[2] / "envelope"))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

import jcs  # noqa: E402
from audit import JsonlAuditSink  # noqa: E402
from capability_issuer import CapabilityIssuer, generate_uuidv7  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    load_pem_private_key,
)
from envelope_adapter import (  # noqa: E402
    EnvelopeFields,
    MCPRequest,
    build_envelope,
    envelope_from_json,
    envelope_to_json,
    mcp_request_to_payload,
    sign_envelope,
    unwrap_request,
)
from verify_envelope import (  # noqa: E402
    EnvelopeVerificationError,
    InMemoryReplayCache,
    verify_envelope,
)

_MSG_SCOPE = "agent_message"
_MSG_METHOD = "agent_message"
_SEND_RETRY_SECONDS = 3.0
_PROTOCOL_FALLBACK = "2025-06-18"

# Shared, user-scoped home so two local Claude instances find each other +
# their mailboxes without any path wiring. See gen_bridge_config.py.
DEFAULT_CONFIG_DIR = pathlib.Path.home() / ".claude" / "mesh"


def _log(msg: str) -> None:
    """Everything human-facing goes to stderr — stdout is JSON-RPC only."""
    print(f"[bridge] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Config / trust
# ---------------------------------------------------------------------------


class BridgeConfig:
    """Loads a bridge's identity + the shared trust manifest and exposes the
    trust-store callbacks ``verify_envelope`` needs."""

    def __init__(self, config_dir: pathlib.Path, name: str) -> None:
        self.dir = config_dir
        self.name = name
        self.trust = json.loads((config_dir / "trust.json").read_text())
        priv = json.loads((config_dir / f"{name}.private.json").read_text())

        self.agents = self.trust["agents"]
        if name not in self.agents:
            raise SystemExit(f"agent {name!r} not in trust.json")
        me = self.agents[name]
        self.spiffe_id = me["spiffe_id"]
        self.env_kid = me["env_kid"]
        self.issuer_iss = me["issuer_iss"]
        self.issuer_kid = me["issuer_kid"]

        self.env_priv = load_pem_private_key(
            priv["env_priv_pem"].encode(), password=None
        )
        issuer_priv = load_pem_private_key(
            priv["issuer_priv_pem"].encode(), password=None
        )
        self.issuer = CapabilityIssuer(
            iss=self.issuer_iss,
            kid=self.issuer_kid,
            signing_key=issuer_priv,
            default_ttl=timedelta(minutes=5),
        )

        # (iss,kid)->pem and env-kid->pem lookups over every known agent.
        self._env_by_kid = {a["env_kid"]: a["env_pub_pem"] for a in self.agents.values()}
        self._issuer_by = {
            (a["issuer_iss"], a["issuer_kid"]): a["issuer_pub_pem"]
            for a in self.agents.values()
        }

    def key_lookup(self, kid: str) -> bytes:
        pem = self._env_by_kid.get(kid)
        if pem is None:
            raise EnvelopeVerificationError(f"unknown envelope kid: {kid!r}")
        return pem.encode()

    def issuer_lookup(self, iss: str, kid: str) -> bytes:
        pem = self._issuer_by.get((iss, kid))
        if pem is None:
            raise EnvelopeVerificationError(f"unknown issuer: {iss!r}/{kid!r}")
        return pem.encode()

    def resolve_name(self, name: str) -> str:
        """Return the canonical agent name for ``name``, matching
        case-insensitively. Models naturally write "Bob"; the manifest
        stores "bob". Raises with the known peers listed on a miss."""
        if name in self.agents:
            return name
        lowered = {n.lower(): n for n in self.agents}
        if isinstance(name, str) and name.lower() in lowered:
            return lowered[name.lower()]
        raise KeyError(
            f"unknown peer {name!r}; known peers: {sorted(self.agents)}"
        )

    def spiffe_of(self, name: str) -> str:
        return self.agents[self.resolve_name(name)]["spiffe_id"]

    def name_of_spiffe(self, spiffe_id: str) -> str:
        for n, a in self.agents.items():
            if a["spiffe_id"] == spiffe_id:
                return n
        return spiffe_id

    # rendezvous: each bridge writes its transport address; peers read it.
    def addr_path(self, name: str) -> pathlib.Path:
        return self.dir / f"rt-{name}.addr"

    def inbox_path(self) -> pathlib.Path:
        return self.dir / f"inbox-{self.name}.jsonl"

    def audit_path(self) -> pathlib.Path:
        return self.dir / f"audit-{self.name}.jsonl"


# ---------------------------------------------------------------------------
# Inbox (file-backed, shared with the pre-hook)
# ---------------------------------------------------------------------------


def read_unread(inbox: pathlib.Path) -> list[dict]:
    """Return inbox entries not yet marked read, and mark them read.

    Uses an flock on a sidecar so the MCP ``check_inbox`` tool and the
    pre-hook can both drain safely. Returns [] if the inbox is empty.
    """
    import fcntl

    if not inbox.exists():
        return []
    lock = inbox.with_suffix(".lock")
    with lock.open("w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = [
                json.loads(x) for x in inbox.read_text().splitlines() if x.strip()
            ]
            fresh = [e for e in lines if not e.get("read")]
            if fresh:
                for e in lines:
                    e["read"] = True
                inbox.write_text(
                    "\n".join(json.dumps(e) for e in lines) + "\n"
                )
            return fresh
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _append_inbox(inbox: pathlib.Path, entry: dict) -> None:
    import fcntl

    lock = inbox.with_suffix(".lock")
    with lock.open("w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            with inbox.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# The bridge
# ---------------------------------------------------------------------------


class MeshBridge:
    def __init__(self, cfg: BridgeConfig, peer: str, *, send_only: bool = False) -> None:
        self.cfg = cfg
        self.peer = peer
        self.send_only = send_only
        self.audit = JsonlAuditSink(cfg.audit_path())
        self.replay = InMemoryReplayCache()
        self._stop = threading.Event()

        # Lazy import so the module is importable without a bound socket.
        from socket_transport import LocalSocketTransport

        self.transport = LocalSocketTransport(source_address=cfg.name)

        # send_only: a per-turn client bridge (e.g. one Claude spawns) that
        # only SENDS + reads the shared inbox file. It must NOT claim the
        # rendezvous address or run a receiver — the always-on daemon bridge
        # owns those, so an ephemeral client can't hijack delivery. Without
        # this, each Claude turn would overwrite rt-<name>.addr with a port
        # that dies when the turn ends, breaking the next inbound message.
        if send_only:
            _log(f"{cfg.name} send-only client (peer={peer}); daemon owns the listener")
            return

        cfg.addr_path(cfg.name).write_text(self.transport.address)
        _log(f"{cfg.name} listening on {self.transport.address} (peer={peer})")
        self._receiver = threading.Thread(target=self._receive_loop, daemon=True)
        self._receiver.start()

    # ----- inbound: verify every frame, append verified to inbox ----------
    def _receive_loop(self) -> None:
        while not self._stop.is_set():
            frame = self.transport.receive()
            if frame is None:
                time.sleep(0.05)
                continue
            try:
                env = envelope_from_json(frame.payload)
                claims = verify_envelope(
                    env,
                    key_lookup=self.cfg.key_lookup,
                    issuer_lookup=self.cfg.issuer_lookup,
                    replay_cache=self.replay,
                    now=datetime.now(UTC),
                    audit_sink=self.audit,
                )
                req = unwrap_request(env)
                body = (req.params or {}).get("body", "")
                entry = {
                    "ts": datetime.now(UTC).isoformat(),
                    "from": claims.sub,
                    "from_name": self.cfg.name_of_spiffe(claims.sub),
                    "body": body,
                    "read": False,
                }
                _append_inbox(self.cfg.inbox_path(), entry)
                _log(f"delivered verified message from {entry['from_name']}")
            except EnvelopeVerificationError as exc:
                # A forged / tampered / replayed frame lands here. It is
                # dropped, never surfaced to Claude, and logged.
                _log(f"REJECTED inbound frame: {exc}")
            except Exception as exc:  # noqa: BLE001 - never kill the loop
                _log(f"inbound error (dropped): {exc}")

    # ----- outbound: sign a message and ship it to the peer ---------------
    def send_message(self, body: str, to: str | None = None) -> str:
        # Resolve to the canonical name so a case variant ("Bob") maps to
        # the manifest entry ("bob") for the spiffe id AND the rendezvous file.
        target = self.cfg.resolve_name(to or self.peer)
        recipient = self.cfg.spiffe_of(target)
        now = datetime.now(UTC)

        payload = mcp_request_to_payload(
            MCPRequest(
                method=_MSG_METHOD,
                params={"body": body, "from": self.cfg.name},
                id=1,
            )
        )
        import hashlib

        digest = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
        cap = self.cfg.issuer.issue(
            sub=self.cfg.spiffe_id,
            aud=recipient,
            scope=_MSG_SCOPE,
            envelope_digest=digest,
            now=now,
        )
        fields = EnvelopeFields(
            sender_spiffe_id=self.cfg.spiffe_id,
            recipient_spiffe_id=recipient,
            purpose_of_use=_MSG_SCOPE,
            kid=self.cfg.env_kid,
            capability_token=cap,
            message_id=generate_uuidv7(now=now),
            nonce="n-" + uuid.uuid4().hex,
            issued_at=now,
            ttl=timedelta(minutes=5),
        )
        env = sign_envelope(build_envelope(payload=payload, fields=fields), self.cfg.env_priv)

        addr = self._peer_addr(target)
        self.transport.send(addr, envelope_to_json(env))
        return f"sent to {target} ({recipient})"

    def _peer_addr(self, name: str) -> str:
        path = self.cfg.addr_path(name)
        deadline = time.monotonic() + _SEND_RETRY_SECONDS
        while time.monotonic() < deadline:
            if path.exists():
                addr = path.read_text().strip()
                if addr:
                    return addr
            time.sleep(0.1)
        raise RuntimeError(
            f"peer {name!r} is not reachable — is its bridge running? "
            f"(no {path})"
        )

    def check_inbox(self) -> str:
        fresh = read_unread(self.cfg.inbox_path())
        if not fresh:
            return "(no new messages)"
        return "\n".join(f"[from {e['from_name']}] {e['body']}" for e in fresh)

    def close(self) -> None:
        self._stop.set()
        self.transport.close()


# ---------------------------------------------------------------------------
# Minimal MCP server over stdio (JSON-RPC 2.0, newline-delimited)
# ---------------------------------------------------------------------------

_TOOLS = [
    {
        "name": "send_message",
        "description": (
            "Send a signed message to your peer agent over the secure mesh. "
            "The peer cryptographically verifies it came from you."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "body": {"type": "string", "description": "message text to send"},
                "to": {
                    "type": "string",
                    "description": "peer name (optional; defaults to your configured peer)",
                },
            },
            "required": ["body"],
        },
    },
    {
        "name": "check_inbox",
        "description": (
            "Return messages received from peers since the last check. Only "
            "cryptographically verified messages appear here."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _text_result(text: str, is_error: bool = False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def serve_stdio(bridge: MeshBridge) -> None:
    """Read newline-delimited JSON-RPC from stdin, write replies to stdout."""
    _log("MCP stdio server ready")
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue  # can't even parse — no id to reply to
        method = msg.get("method")
        mid = msg.get("id")
        is_notification = "id" not in msg

        try:
            if method == "initialize":
                params = msg.get("params") or {}
                reply = _result(
                    mid,
                    {
                        "protocolVersion": params.get(
                            "protocolVersion", _PROTOCOL_FALLBACK
                        ),
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {
                            "name": "walkietalkie-mesh-bridge",
                            "version": "0.1.0",
                        },
                    },
                )
            elif method == "tools/list":
                reply = _result(mid, {"tools": _TOOLS})
            elif method == "tools/call":
                reply = _result(mid, _dispatch_tool(bridge, msg.get("params") or {}))
            elif method == "ping":
                reply = _result(mid, {})
            elif is_notification:
                # notifications/initialized, notifications/cancelled, etc.
                continue
            else:
                reply = _error(mid, -32601, f"method not found: {method}")
        except Exception as exc:  # noqa: BLE001 - surface as JSON-RPC, never crash
            if is_notification:
                _log(f"notification handler error (ignored): {exc}")
                continue
            reply = _error(mid, -32603, f"internal error: {exc}")

        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


def _dispatch_tool(bridge: MeshBridge, params: dict) -> dict:
    name = params.get("name")
    args = params.get("arguments") or {}
    if name == "send_message":
        body = args.get("body")
        if not isinstance(body, str) or not body:
            return _text_result("send_message requires a non-empty 'body'", True)
        try:
            info = bridge.send_message(body, to=args.get("to"))
            return _text_result(f"✓ {info}")
        except Exception as exc:  # noqa: BLE001
            return _text_result(f"send failed: {exc}", True)
    if name == "check_inbox":
        return _text_result(bridge.check_inbox())
    return _text_result(f"unknown tool: {name}", True)


def main() -> None:
    ap = argparse.ArgumentParser(description="WalkieTalkie mesh MCP bridge")
    ap.add_argument("--name", required=True, help="this agent's name (in trust.json)")
    ap.add_argument("--peer", required=True, help="default peer agent name")
    ap.add_argument(
        "--config", type=pathlib.Path, default=DEFAULT_CONFIG_DIR,
        help=f"config dir (default: {DEFAULT_CONFIG_DIR})",
    )
    ap.add_argument(
        "--send-only", action="store_true",
        help="client mode: send + read inbox, but don't own the listener "
        "(use when an always-on daemon bridge is the receiver)",
    )
    args = ap.parse_args()

    cfg = BridgeConfig(args.config, args.name)
    bridge = MeshBridge(cfg, args.peer, send_only=args.send_only)
    try:
        serve_stdio(bridge)
    finally:
        bridge.close()


if __name__ == "__main__":
    main()
