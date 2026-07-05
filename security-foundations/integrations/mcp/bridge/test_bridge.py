"""End-to-end tests for the mesh MCP bridge.

Two proofs:

1. **MCP protocol** — spawn the bridge as a real subprocess and drive the
   JSON-RPC handshake (initialize -> tools/list -> tools/call) exactly as
   Claude Code would over stdio.
2. **Secure delivery** — run two bridges and pass a message through the
   real mesh transport: a legit message is verified and delivered, a
   replayed one is rejected, a forged one is rejected.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import time
import unittest
import uuid
from datetime import UTC, datetime, timedelta

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE.parents[2] / "envelope"))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

import jcs  # noqa: E402
from capability_issuer import generate_uuidv7  # noqa: E402
from envelope_adapter import (  # noqa: E402
    EnvelopeFields,
    MCPRequest,
    build_envelope,
    envelope_to_json,
    mcp_request_to_payload,
    sign_envelope,
)
from gen_bridge_config import generate  # noqa: E402
from mesh_mcp_bridge import BridgeConfig, MeshBridge  # noqa: E402

_BRIDGE = _HERE / "mesh_mcp_bridge.py"


def _mkconfig(tmp: pathlib.Path) -> pathlib.Path:
    cfgdir = tmp / "mesh-config"
    generate(cfgdir, ["alice", "bob"])
    return cfgdir


def _wait_inbox(path: pathlib.Path, want: int, timeout: float = 4.0) -> list:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            entries = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
            if len(entries) >= want:
                return entries
        time.sleep(0.05)
    return (
        [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
        if path.exists()
        else []
    )


class MCPProtocolTests(unittest.TestCase):
    """Drive the stdio handshake as Claude Code would."""

    def test_initialize_and_tools_list(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfgdir = _mkconfig(pathlib.Path(td))
            proc = subprocess.Popen(
                [sys.executable, str(_BRIDGE), "--name", "alice",
                 "--peer", "bob", "--config", str(cfgdir)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
            )
            try:
                def rpc(obj):
                    proc.stdin.write(json.dumps(obj) + "\n")
                    proc.stdin.flush()

                def read():
                    return json.loads(proc.stdout.readline())

                rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18",
                                "capabilities": {}, "clientInfo": {"name": "t"}}})
                init = read()
                self.assertEqual(init["id"], 1)
                self.assertEqual(
                    init["result"]["serverInfo"]["name"],
                    "walkietalkie-mesh-bridge",
                )
                self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")

                # notification: no reply
                rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})

                rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                tools = read()
                names = {t["name"] for t in tools["result"]["tools"]}
                self.assertEqual(names, {"send_message", "check_inbox"})

                # check_inbox on an empty inbox
                rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "check_inbox", "arguments": {}}})
                empty = read()
                self.assertIn(
                    "no new messages",
                    empty["result"]["content"][0]["text"],
                )
            finally:
                proc.stdin.close()
                proc.terminate()
                proc.wait(timeout=5)


class SecureDeliveryTests(unittest.TestCase):
    """Two bridges over the real mesh transport."""

    def _pair(self, cfgdir):
        bob_cfg = BridgeConfig(cfgdir, "bob")
        alice_cfg = BridgeConfig(cfgdir, "alice")
        bob = MeshBridge(bob_cfg, "alice")
        alice = MeshBridge(alice_cfg, "bob")
        return alice, bob, alice_cfg, bob_cfg

    def test_legit_message_delivered_and_verified(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfgdir = _mkconfig(pathlib.Path(td))
            alice, bob, *_ = self._pair(cfgdir)
            try:
                alice.send_message("hello bob, this is alice", to="bob")
                entries = _wait_inbox(bob.cfg.inbox_path(), 1)
                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["from_name"], "alice")
                self.assertEqual(entries[0]["body"], "hello bob, this is alice")

                # check_inbox returns it once, then marks read.
                first = bob.check_inbox()
                self.assertIn("hello bob", first)
                self.assertEqual(bob.check_inbox(), "(no new messages)")
            finally:
                alice.close()
                bob.close()

    def test_replayed_message_rejected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfgdir = _mkconfig(pathlib.Path(td))
            alice, bob, alice_cfg, bob_cfg = self._pair(cfgdir)
            try:
                raw = _build_signed(alice_cfg, bob_cfg, "replay me",
                                    signing_key=alice_cfg.env_priv,
                                    kid=alice_cfg.env_kid)
                addr = bob.transport.address
                alice.transport.send(addr, raw)
                self.assertEqual(len(_wait_inbox(bob.cfg.inbox_path(), 1)), 1)
                # Same bytes again -> nonce already seen -> rejected, no 2nd entry.
                alice.transport.send(addr, raw)
                time.sleep(0.5)
                entries = [json.loads(x) for x in
                           bob.cfg.inbox_path().read_text().splitlines() if x.strip()]
                self.assertEqual(len(entries), 1, "replay must not be delivered")
            finally:
                alice.close()
                bob.close()

    def test_forged_message_rejected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cfgdir = _mkconfig(pathlib.Path(td))
            alice, bob, alice_cfg, bob_cfg = self._pair(cfgdir)
            try:
                # Claim to be alice, but sign the envelope with BOB's key.
                forged = _build_signed(alice_cfg, bob_cfg, "i am totally alice",
                                       signing_key=bob_cfg.env_priv,
                                       kid=alice_cfg.env_kid)
                alice.transport.send(bob.transport.address, forged)
                time.sleep(0.6)
                inbox = bob.cfg.inbox_path()
                entries = ([json.loads(x) for x in inbox.read_text().splitlines()
                            if x.strip()] if inbox.exists() else [])
                self.assertEqual(entries, [], "forged message must be rejected")
            finally:
                alice.close()
                bob.close()


def _build_signed(sender_cfg, recipient_cfg, body, *, signing_key, kid) -> bytes:
    """Build a signed envelope from sender->recipient. Caller controls the
    signing key + kid so tests can forge (wrong key) deliberately."""
    now = datetime.now(UTC)
    payload = mcp_request_to_payload(
        MCPRequest(method="agent_message",
                   params={"body": body, "from": sender_cfg.name}, id=1)
    )
    digest = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
    cap = sender_cfg.issuer.issue(
        sub=sender_cfg.spiffe_id, aud=recipient_cfg.spiffe_id,
        scope="agent_message", envelope_digest=digest, now=now,
    )
    fields = EnvelopeFields(
        sender_spiffe_id=sender_cfg.spiffe_id,
        recipient_spiffe_id=recipient_cfg.spiffe_id,
        purpose_of_use="agent_message", kid=kid, capability_token=cap,
        message_id=generate_uuidv7(now=now), nonce="n-" + uuid.uuid4().hex,
        issued_at=now, ttl=timedelta(minutes=5),
    )
    return envelope_to_json(sign_envelope(build_envelope(payload=payload, fields=fields), signing_key))


if __name__ == "__main__":
    unittest.main()
