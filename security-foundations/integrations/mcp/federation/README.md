# MCP Federation — many tool servers, one endpoint

MCP today is point-to-point: your Claude Code config lists a handful of
*local* stdio servers, and there's no way to have a **shared, discoverable,
networked** set. This turns MCP into a network — many tool servers on the
mesh, one **gateway** that discovers them and routes calls, so a client
configures **one** endpoint and reaches all of them.

```
Claude ──stdio/MCP──▶ gateway ──mesh──▶ repo   (list_files, read_file)
                              └────────▶ deploy (status, history)
```

Claude sees `repo__read_file`, `deploy__status`, … as if they were one
server's tools. **Add a backend and it appears** in the next `tools/list` —
no gateway restart, no client config change.

## Why this is useful

- **No config sprawl.** A team runs the tool servers once; every dev's
  Claude points at one gateway instead of each person configuring (and
  re-syncing) N local servers.
- **Specialize + share.** One server wraps the DB, one wraps deploys, one
  wraps the internal docs. Any dev reaches all of them.
- **Dynamic.** Servers join and leave; the gateway tracks it live (gossip-
  style discovery via the shared registry).
- **Namespaced.** Tools are `<server>__<tool>`, so two servers can offer a
  tool of the same name without collision and calls route unambiguously.

The stub servers here return canned data — swap the handlers in
`tool_server.py` for real integrations and it's a real team tool mesh. It
rides on the same mesh transports as the rest of the substrate, so the
mTLS/identity layer composes on top when you want it.

## Run it headless (no Claude needed)

```bash
python security-foundations/integrations/mcp/federation/demo_federation.py
```

Spawns the gateway + two backends and drives the full MCP handshake +
federated `tools/list` + routed `tools/call`, printing each step.

## Wire it to a real Claude Code instance

1. **Start the backend tool servers** (each in its own terminal; they stay
   running and announce to a shared registry dir):

```bash
python .../federation/tool_server.py --name repo   --preset repo   --registry ~/mcp-mesh
python .../federation/tool_server.py --name deploy --preset deploy --registry ~/mcp-mesh
```

2. **Register the gateway with Claude** (one endpoint, all tools):

```bash
claude mcp add tools -- \
    /abs/.venv/bin/python \
    /abs/.../federation/mcp_gateway.py --registry ~/mcp-mesh
```

Now ask Claude to *"list your tools"* — it sees `repo__*` and `deploy__*`.
Ask it to *"check the deploy status"* → the call routes through the gateway
to the `deploy` server and back. Start a third server later and Claude
picks up its tools on the next list.

## Files

| File | Role |
|---|---|
| `tool_server.py` | A backend: offers a named toolset, announces to the registry, serves calls over the mesh. `repo` + `deploy` presets. |
| `mcp_gateway.py` | The MCP stdio server Claude connects to: discovers backends, aggregates tools, routes calls. |
| `demo_federation.py` | Headless end-to-end demo. |
| `test_federation.py` | Federation logic + real MCP stdio handshake tests. |

## How a call flows

1. Claude calls `deploy__status` on the gateway.
2. The gateway splits `<server>__<tool>`, looks up `deploy`'s mesh address
   from the registry, and sends a `call` request (with its own address as
   `reply_to`).
3. The `deploy` server runs the tool and sends the result back to the
   gateway's address.
4. The gateway returns it to Claude as the tool result.

Discovery is a shared registry directory (each server drops a
`backend-<name>.json` announce file); swapping that for the substrate's
gossip membership (`mesh/membership.py`) is the next step toward a
fully-decentralized version.
