# Running the example MCP host

Phase 4 D4.4 integration runbook. This document walks you from a
fresh `git clone` to a working end-to-end smoke test of the
WalkieTalkie substrate against a single in-process MCP host. The
target is **under 15 minutes** per the Phase 4 plan's exit gate.

There is **no networking, no daemon, no Docker image**. The example
host accepts envelope dicts in memory and returns envelope dicts in
memory. Adding a transport (HTTP / WebSocket / stdio) is your job;
the substrate is correctness-first and stays transport-agnostic.

## Prerequisites

- Python 3.11 or 3.12.
- Git.
- ~50 MB of disk for the `.venv`.

That's it. No Redis, no Postgres, no Kubernetes, no Anthropic API key.

## Step 1 — Set up the environment

From the repo root:

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

This installs the `walkietalkie-envelope` package (the substrate)
and the `walkietalkie-envelope[dev]` ruff dependency.

## Step 2 — Verify the substrate is healthy

```bash
.venv/bin/python -m unittest discover \
  -s security-foundations/envelope \
  -t security-foundations/envelope
```

Expect **705 tests OK**. If this fails, do not proceed; the
substrate kernel has a problem.

## Step 3 — Generate the example trust material

```bash
.venv/bin/python security-foundations/integrations/mcp/example/gen_keys.py
```

This writes three Ed25519 keypairs and two manifest files into
`security-foundations/integrations/mcp/example/`:

- `client-priv.pem` + `client-pub.pem` — the calling workload's key.
- `host-priv.pem` + `host-pub.pem` — the example MCP host's key.
- `issuer-priv.pem` + `issuer-pub.pem` — the capability-issuer's key.
- `workload-manifest.json` — `FileSystemTrustStore` manifest listing
  the client and host public keys by `kid`.
- `issuer-manifest.json` — `IssuerTrustStore` manifest listing the
  capability issuer by `(iss, kid)`.

The seeds are deterministic (sha256 of label strings), so re-running
the script produces byte-identical output. The keys are **demo
material only** — real deployments use HSM- or KMS-backed key
generation.

## Step 4 — Run the end-to-end smoke test

```bash
.venv/bin/python -m unittest discover \
  -s security-foundations/integrations \
  -t security-foundations/integrations
```

Expect **50 tests OK**. The four `test_smoke` tests are the
interesting ones; the others are adapter and host shape tests.

What the happy-path smoke test (`test_round_trip_succeeds_and_reply_is_verifiable`) actually does:

1. Builds three Ed25519 keypairs in memory (client, host, issuer).
2. Mints a real capability token bound to the request's payload digest.
3. Builds an MCP `read_file` request, packs it into a signed envelope.
4. Hands the envelope to `ExampleMCPHost.handle()`.
5. The host runs the full Phase 1/2 verification stack:
   `verify_envelope` → `unwrap_request` → `tool_policy_gate.evaluate_tool_call` →
   tool dispatch → `output_scanning.scan` → `egress_policy.evaluate` →
   sign reply envelope with a payload-bound capability token.
6. The test then **independently verifies the reply via
   `verify_envelope`** — proving the reply is end-to-end verifiable
   by any peer, not just by the host.
7. The audit chain hash-validates via `audit.verify_chain`.

The three sad-path tests pin: empty capability rejection (no nonce
burn), post-signing payload mutation rejection, and CRITICAL tool
(`exec_sql`) without step-up → `tool_step_up_required`.

Two lifecycle tests exercise the security features a production
deployment enables via `HostConfig`:

- **Revoke-then-reject** (`RevocationLifecycleTests`): a capability
  that verified a moment ago is rejected on its next use once its
  jti is entered into the `revocation_list` the host consults — no
  host code change, just an out-of-band revocation. The
  `envelope.verify` audit event records `capability_revoked`.
- **Post-auth rate limit** (`RateLimitLifecycleTests`): requests
  past the per-identity limit are denied with `rate_limited`, and a
  badly-signed envelope claiming a victim's SPIFFE ID is rejected at
  `envelope.verify` **before** the limiter runs — so it consumes
  none of the victim's allowance.

To enable these in your own host, set `HostConfig.rate_limiter`
(an `IdentityRateLimiter`) and `HostConfig.revocation_list` (a
`RevocationList`), and give your `CapabilityIssuer` an
`AllowlistPolicy` so issuance is least-privilege. All three default
to off/permissive so the minimal demo stays minimal.

## Step 5 — Inspect the sample audit log

```bash
.venv/bin/python security-foundations/integrations/mcp/example/_gen_sample_audit.py
cat security-foundations/integrations/mcp/example/sample-audit.jsonl
```

`_gen_sample_audit.py` regenerates `sample-audit.jsonl` from the
deterministic example keys — re-running it leaves the working tree
clean. The file contains the hash-chained audit events from a
happy-path round trip:

| order | `event_type`        | meaning                                    |
|-------|---------------------|--------------------------------------------|
| 1     | `capability.issue`  | client requests a cap token from the issuer |
| 2     | `envelope.verify`   | host's verifier accepts the inbound envelope |
| 3     | `tool.gate`         | host's tool policy allows the call          |
| 4     | `egress.evaluate`   | host's egress policy allows the response    |
| 5     | `capability.issue`  | host requests a cap token for its reply     |
| 6     | `envelope.verify`   | (none in v0; the host doesn't re-verify its own reply, the peer will) |

Each event has a `prev_hash` + `this_hash` field. `audit.verify_chain`
re-derives the chain and rejects any insertion, deletion, or
reordering. Use this file as a "did the substrate accept my setup?"
reference; your local run should produce the same `event_type` and
`outcome` sequence (the timestamps and per-event hashes will differ
if your generator isn't using the deterministic clock wrapper).

## Step 6 — Read the audit chain in code

```python
import pathlib
import sys
sys.path.insert(0, "security-foundations/envelope")

from audit import JsonlAuditSink, verify_chain

sink = JsonlAuditSink(
    pathlib.Path("security-foundations/integrations/mcp/example/sample-audit.jsonl")
)
events = sink.read_all()
verify_chain(events)            # raises AuditChainError on tampering
print(f"{len(events)} events validated")
for ev in events:
    print(f"  {ev.event_type:18} {ev.outcome:5} {ev.reason}")
```

## What this proves

If steps 1-5 pass, you have direct empirical evidence that the
substrate works as a system: a real signed message round-trips
through every Phase 1/2 verification step, the reply is independently
verifiable end-to-end, and the audit log hash-validates.

## What this does NOT prove

- Performance under load (deferred to Phase 5).
- Distributed behavior (the substrate is single-process; backends
  are all in-memory).
- Real-world adversarial coverage beyond the 18-entry adversarial
  corpus.
- Networking, persistence, multi-tenant isolation, compound-failure
  drills, formal verification.

See `DEFERRED.md` at the repo root for the explicit Phase 5
candidates and the items intentionally out of substrate scope.

## Replacing the demo wiring with your own

`example/_gen_sample_audit.py` and the smoke test
(`test_smoke.py:_Stage`) are the two places that wire a complete
host together. Use either as the starting point for your real
integration:

- Replace the demo `read_file` / `exec_sql` tools with your actual
  MCP tool handlers.
- Replace `InMemoryReplayCache` with `SQLiteReplayCache` (or any
  `ReplayCache` subclass) when you need persistence.
- Replace `InMemoryAuditSink` with `JsonlAuditSink` pointed at a
  durable path.
- Replace the in-memory key-lookup callbacks with
  `FileSystemTrustStore.from_manifest(...)` and
  `IssuerTrustStore.from_manifest(...)`, both already exercised
  here.
- When you need a transport, wrap `host.handle(envelope_dict)` in
  whatever request/response loop you like — the substrate is
  transport-agnostic by design.

If something feels wrong or you find a real-world failure mode the
substrate doesn't handle, that's exactly the kind of input
**Phase 5** is supposed to be scoped from.
