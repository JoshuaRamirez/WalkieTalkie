# Workspace status — share feature progress without being spied on

A developer working on an important feature stands up a **status server**
for that workspace. A teammate connects to follow along — **asynchronously,
so the owner is never interrupted** with a context switch. The hard part
isn't the plumbing; it's the privacy model, so a dev never feels surveilled
outside the workspace.

This makes "don't feel spied on" **structural**, not a promise:

| Guarantee | How it's enforced |
|---|---|
| **Read-only, curated surface** | The *only* exposed operation is `get_status`. There is no tool to read a file, run a command, or name a path — a watcher cannot ask for more, by construction. |
| **Workspace-bounded** | Auto-derived facts come only from *git in the configured directory*. Never other repos, never the rest of the machine. |
| **Visibility levels** | The owner caps how much even the status reveals: `summary` (branch + note), `standard` (+ commit subjects), `detailed` (+ changed file *names* — never contents/diffs). |
| **Consent / deny-by-default** | Only allow-listed watchers get an answer; everyone else is denied. |
| **Reciprocal transparency** | Every access — granted *and* denied — is logged with the watcher's id and time. The owner sees exactly who looked. Watching is not covert. |
| **Off means invisible** | Nothing is ambient. Server down → nothing to see. Standing it up is an explicit, revocable publish of *this workspace only*. |

Nobody gets tapped on the shoulder: the owner's server just answers reads
(the human owner is never in the loop), and the watcher's poller surfaces a
digest **only when something changed** — so an idle workspace produces no
noise.

## Run it headless (no Claude needed)

```bash
python security-foundations/integrations/mcp/workspace/demo_workspace.py
```

Owner publishes a feature's status; an allowed teammate follows it; an
un-listed peer is refused; the owner updates progress and the teammate sees
the news; the owner reviews who watched.

## Use it for real

1. **Owner** stands up the server for their feature workspace (allow-list
   the teammates who may follow, cap the visibility, point `--note-file` at
   a status note you keep):

```bash
echo "working on payment retry; blocked on webhook sig" > ~/status.md
python .../workspace/workspace_server.py \
    --workspace ~/code/payments --name payments-feature \
    --allow alice bob --visibility standard \
    --note-file ~/status.md --registry ~/ws-mesh
```

2. **Teammate** follows it (surfaces a digest only when it changes):

```bash
python .../workspace/watch.py \
    --watcher alice --workspace payments-feature --registry ~/ws-mesh --interval 30
```

Wire `watch.py --once` into a `UserPromptSubmit` hook (same pattern as the
mesh bridge's `mail_hook.py`) and new progress lands in the teammate's
Claude session passively — no context switch for either dev.

## Files

| File | Role |
|---|---|
| `workspace_server.py` | The read-only, workspace-bounded, allow-listed status server + access log. |
| `watch.py` | The teammate's async poller — pulls status, emits a digest only on change. |
| `demo_workspace.py` | Headless end-to-end demo. |
| `test_workspace.py` | Visibility gating, allow/deny, bounded surface, access logging, delivery. |

## Where identity comes from

On loopback the watcher's id is a name carried in the request. In the full
substrate it's the **mTLS-verified SVID** — a watcher can't spoof another's
identity to get onto the allow list, and the access log names the
cryptographically-verified peer. The privacy model here composes with, but
does not depend on, that layer.
