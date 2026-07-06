# Mesh MCP Bridge — two Claude Code instances talking securely

This turns the WalkieTalkie substrate into something you can *run*: two
Claude Code instances that send each other **signed, verified** messages
over the mesh. Each Claude launches a small MCP server (this bridge); the
bridges talk to each other over a real loopback-TCP mesh hop, and every
message is Ed25519-signed and verified before it's delivered. An impostor
without your private key is rejected.

```
Claude A ──stdio/MCP──▶ bridge A ──signed envelope over TCP──▶ bridge B ──stdio/MCP──▶ Claude B
```

**What's real:** identity, signing, verification, replay protection, the
TCP transport — the whole security path (proven in `test_bridge.py`).
**What's demo-grade:** it's loopback, single-host, no TLS-on-the-wire or
PKI custody. Those are the Phase 6 deployment frontier (see `DEFERRED.md`).

---

## 0. Prerequisites

The bridge needs the repo's Python env (for `cryptography` + `jcs`). From
the repo root:

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

Use the **absolute path** to `.venv/bin/python` in the commands below.

## 1. Generate two identities + a shared trust manifest

```bash
.venv/bin/python security-foundations/integrations/mcp/bridge/gen_bridge_config.py \
    --agents alice bob
```

By default everything lands in **`~/.claude/mesh/`** — the natural
user-scoped home, shared by every Claude instance on the machine:
- `trust.json` — the **shared, public** trust manifest (both agents' public keys).
- `alice.private.json`, `bob.private.json` — each agent's **private** keys (chmod 600).
- at runtime: `inbox-<name>.jsonl` (the mailboxes), `rt-<name>.addr`
  (rendezvous), `audit-<name>.jsonl` (the hash-chained audit log).

`trust.json` is what makes the two sides trust each other. In a real
deployment you'd distribute it out-of-band; here both instances just read
the same folder.

> **Where this must live.** Use a **user-scoped** dir (`~/.claude/mesh/`),
> not a per-project `.claude/`. The two bridges rendezvous through this
> folder, so both instances must see the *same* one — separate project
> dirs can't find each other. And it holds **private keys**, so never
> point `--config` at a git-tracked project `.claude/`. Override the
> location with `--config <dir>` on every command if you want a different
> shared spot.

## 2. Register the bridge with each Claude Code instance

Run each Claude in its own terminal / working dir. Give each one the bridge
as an MCP server, with **its** name and **its** peer:

**Instance A (alice):**
```bash
claude mcp add mesh -- \
    /abs/path/.venv/bin/python \
    /abs/path/security-foundations/integrations/mcp/bridge/mesh_mcp_bridge.py \
    --name alice --peer bob
```

**Instance B (bob):**
```bash
claude mcp add mesh -- \
    /abs/path/.venv/bin/python \
    /abs/path/security-foundations/integrations/mcp/bridge/mesh_mcp_bridge.py \
    --name bob --peer alice
```

(Both default to `--config ~/.claude/mesh`; pass `--config` explicitly only
if you generated the config elsewhere.)

Now each Claude has two tools: **`send_message`** and **`check_inbox`**.
Ask alice's Claude to *"send a message to bob saying hello"* and ask bob's
Claude to *"check your inbox"* — the message arrives, verified.

## 3. (Recommended) Auto-check mail with a pre-hook

MCP is client-initiated: bob's Claude only sees a message when it calls
`check_inbox`. The `mail_hook.py` **UserPromptSubmit hook** fixes that — it
runs on every prompt, drains the verified inbox, and injects any new
messages into the conversation. So each Claude "checks mail" on every turn
without you asking.

Add to each instance's `settings.json` (use that instance's `--name`):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/abs/path/.venv/bin/python /abs/path/security-foundations/integrations/mcp/bridge/mail_hook.py --name bob"
          }
        ]
      }
    ]
  }
}
```

Only verified messages ever reach the inbox file the hook reads, so the
hook can never surface a forged message.

## 4. Autonomous back-and-forth (the responder) — and the real-time caveat

The hook (step 3) surfaces mail when **you** submit a prompt. For two
agents to converse **hands-off**, something has to *wake* each Claude when
a message lands — MCP is client-initiated and `claude` only acts on a
prompt, so agent chat is **not real-time** on its own.

`responder.py` is that timer. It watches the verified inbox and, when a new
message appears, invokes `claude -p` (with the mesh server attached and
`--continue` for continuity) so Claude reads and replies:

```bash
# Bob auto-answers Alice, polling every 2s:
python .../bridge/responder.py --name bob --mcp-config /abs/bob.mcp.json --interval 2
# Alice auto-answers Bob, in another terminal:
python .../bridge/responder.py --name alice --mcp-config /abs/alice.mcp.json --interval 2
```

Kick off a thread by having one side `send_message` once; the two
responders then relay replies back and forth on their own. Each message
wakes its Claude exactly once (the call is synchronous; `check_inbox` marks
the mail read before the next poll). `--dry-run` shows *when* it would wake
Claude without spending tokens; `--once` does a single poll.

This is a poll-and-wake loop, not a persistent socket-driven agent — good
enough for a real hands-off conversation. A always-on agent (Agent SDK /
long-lived process reacting the instant a frame arrives) is a Phase 6
option.

## 5. Prove it without two Claudes

Two scripts run the whole path headless:

```bash
# Two bridge subprocesses, driven over stdio exactly as Claude would:
.venv/bin/python security-foundations/integrations/mcp/bridge/demo_conversation.py

# The test suite: MCP handshake + delivery + replay-rejected + forgery-rejected
.venv/bin/python -m unittest discover \
    -s security-foundations/integrations/mcp/bridge \
    -t security-foundations/integrations/mcp/bridge -p "test_bridge.py" -v
```

---

## Files

| File | Role |
|---|---|
| `gen_bridge_config.py` | Mint per-agent Ed25519 keys + shared `trust.json`. |
| `mesh_mcp_bridge.py` | The MCP stdio server ↔ mesh transport bridge. |
| `mail_hook.py` | UserPromptSubmit hook that surfaces verified mail. |
| `responder.py` | Wakes `claude` on new mail — the timer for hands-off chat. |
| `demo_conversation.py` | Headless two-client demo (no Claude needed). |
| `test_bridge.py` | End-to-end tests (protocol + secure delivery). |

## How a message flows (and where security lives)

1. Claude A calls `send_message(to="bob", body="…")`.
2. Bridge A builds a JSON-RPC payload, mints a capability token (bound to
   the payload digest), wraps it in an envelope, and **Ed25519-signs** it.
3. The envelope crosses the mesh (loopback TCP) to bridge B.
4. Bridge B's receive loop runs `verify_envelope` — signature, time
   window, replay cache, capability binding — **before** the message is
   ever written to the inbox. A forged/tampered/replayed frame is dropped.
5. The `mail_hook` (or a `check_inbox` call) surfaces the verified message
   to Claude B.

The security is in step 4, and it's the same `verify_envelope` the rest of
the substrate uses — the bridge adds transport and MCP glue, no new crypto.

## Extending past two agents

`gen_bridge_config.py --agents alice bob carol` mints three. Any agent can
`send_message(to="carol", …)` as long as carol's bridge is running and
carol is in the shared `trust.json`. Routing is direct (each bridge dials
the peer's rendezvous address); a real gossip/routing layer is Phase 6.
