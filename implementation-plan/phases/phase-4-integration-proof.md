# Phase 4 — Integration Proof Implementation Plan

## 1) Phase Intent

Phase 4 takes the Phase 0-3 substrate (the in-process safety kernel)
and proves it works inside a running system. The goal is not
operational maturity — that's reserved for Phase 5. The goal is the
minimum integration loop that demonstrates: a real MCP message can
flow through the substrate, get verified, scanned, gated, and
audited end-to-end, on a single host.

### Mission

Wrap the substrate around a real MCP host (the simplest one we can
get our hands on) and run a single end-to-end exchange that
exercises every Phase 1/2 verification step:

- Envelope verification on every inbound message.
- Capability token validation.
- Replay-cache check.
- Tool dispatch gate (`tool_policy_gate.evaluate_tool_call`) ahead of every tool invocation.
- Output scanning + egress policy on every outbound message.
- Audit emission for each decision.

If a single round-trip survives all that, the substrate is shown to
*work as a system*, not just as a library.

---

## 2) Scope

### In Scope

1. One MCP adapter module that translates between MCP's wire format
   and the envelope shape `verify_envelope.verify_envelope` expects.
2. One example MCP host (Python, local-only, intentionally minimal)
   wired with the substrate as its safety layer.
3. One smoke test that round-trips a real signed message through
   the example host and asserts each substrate gate fires correctly.
4. A short integration runbook (README) for an operator to stand up
   the example.

### Out of Scope (deferred to Phase 5 or DEFERRED.md)

- Compound-failure drills (Phase 3 §6 — Phase 5).
- Shared-component isolation validation (Phase 3 §7 — Phase 5).
- Observability surface and metrics (Phase 3 §8 — Phase 5).
- Phase-close evidence bundles (Phase 3 §11 — Phase 5).
- Distributed deployment, multi-host networking, Kubernetes, etc.
- External security review (still tracked as Phase 1 Exit Gate #5).
- Performance, load, or chaos testing.

Phase 4 deliberately ships the smallest thing that runs. Phase 5
will then have real failure modes to chase instead of imagined ones.

---

## 3) Deliverables

### D4.1 MCP Envelope Adapter
- Bidirectional translation between MCP message format and the
  envelope schema (`schema-v0.json`).
- Signed-envelope construction helper that takes an MCP request and
  emits a wire-ready envelope.
- Inbound parser that takes a wire envelope and exposes the MCP
  payload after `verify_envelope` accepts it.
  **Landed (v0):** `security-foundations/integrations/mcp/envelope_adapter.py`
  ships the bidirectional translation. `MCPRequest`/`MCPResponse`
  dataclasses normalize JSON-RPC 2.0; `mcp_request_to_payload` /
  `payload_to_mcp_request` (plus response equivalents) handle the
  payload-level translation. `EnvelopeFields` carries operator-
  supplied envelope metadata. `build_envelope()` assembles an
  unsigned envelope dict whose required-field set exactly matches
  `schema-v0.json`. `sign_envelope()` attaches an Ed25519 signature
  over the JCS canonical body (same convention `_regen_vectors.py`
  uses). `unwrap_request` / `unwrap_response` pull the MCP message
  out after `verify_envelope` succeeds. 27 unit tests pin payload
  round-trips, schema field coverage, signature validity, and JSON
  transport. `pyproject.toml` adds `security-foundations/integrations`
  to the wheel build.

### D4.2 Example MCP Host
- A minimal Python MCP server that accepts envelope-wrapped
  messages, runs them through `verify_envelope`, dispatches the
  request (one or two demo tools), runs the response through
  `output_scanning` + `egress_policy`, and emits an envelope-wrapped
  reply.
- Configuration via the existing `FileSystemTrustStore` and
  `IssuerTrustStore` manifest formats.

### D4.3 End-to-End Smoke Test
- One automated test that:
  - stands up the example host in-process,
  - mints a real capability token,
  - sends one signed envelope,
  - receives the signed reply,
  - asserts the audit log has the expected event chain
    (`envelope.verify` ok → `capability.verify` ok → tool dispatch →
    output scan clean → egress allow → outbound envelope sign).

### D4.4 Integration Runbook
- A README under `security-foundations/integrations/mcp/` covering:
  - prerequisites (Python version, the `.venv`),
  - how to generate keypairs and write a trust-store manifest,
  - how to start the example host,
  - how to send a test message,
  - how to read the audit log.

---

## 4) Integration Architecture

```
              ┌──────────────────────────────────────────┐
              │            Example MCP Host              │
              │                                          │
  wire   ┌────┴────┐  envelope    ┌──────────────────┐  │
─envelope──▶ adapter ├────────────▶ verify_envelope() │  │
              │      .from_wire   └────────┬─────────┘  │
              │                            │            │
              │                   (raises  │            │
              │                    on fail)│            │
              │                            ▼            │
              │                ┌─────────────────────┐  │
              │                │ tool_policy_gate    │  │
              │                │ .evaluate_tool_call │  │
              │                └────────┬────────────┘  │
              │                         │ ok            │
              │                         ▼               │
              │                ┌─────────────────────┐  │
              │                │ MCP tool dispatch   │  │
              │                └────────┬────────────┘  │
              │                         │ result        │
              │                         ▼               │
              │                ┌─────────────────────┐  │
              │                │ output_scanning     │  │
              │                │ + egress_policy     │  │
              │                └────────┬────────────┘  │
              │                         │ allow         │
              │                         ▼               │
              │      ┌──────────────────────────────┐   │
  wire   ◀─────────┤ adapter.to_wire(signed reply) │   │
─envelope         └──────────────────────────────┘   │
              │                                          │
              │  audit.JsonlAuditSink — every step       │
              │                                          │
              └──────────────────────────────────────────┘
```

No transport. The example host accepts envelopes as in-memory dicts
(or, optionally, via stdin/stdout for a CLI-driven loop). Adding
HTTP / WebSocket / gRPC / QUIC is Phase 5's call.

---

## 5) Work Breakdown Structure (WBS)

### Track A — Adapter

#### A1. MCP message ↔ envelope translation
- `from_mcp(mcp_message, sender_iss, recipient_iss, purpose, …)` →
  unsigned envelope dict.
- `to_mcp(envelope) → mcp_message` (after `verify_envelope` succeeds).
- Helpers to populate `payload_digest`, `nonce`, `message_id`, and
  the time window from operator-supplied clock + TTL.

#### A2. Capability token wiring
- `mint_capability_for(envelope, issuer, scope)` returns a JWT-shaped
  cap token bound to the envelope's `payload_digest`.
- Integration with the existing `CapabilityIssuer`.

### Track B — Example Host

#### B1. Minimal MCP server
- Two demo tools registered: `read_file` (low risk) and `exec_sql`
  (critical, requires step-up).
- Tool registry maps to a `ToolPolicy` so the gate has real rules.
- Single in-process loop: receive envelope → verify → dispatch →
  scan → sign reply.

#### B2. Trust-store configuration
- Sample manifest files under `security-foundations/integrations/mcp/example/`
  with one dev signer key, one dev issuer key, one dev workload.
- Operator can regenerate with a small `gen_keys.py` helper.

### Track C — Smoke test + runbook

#### C1. End-to-end smoke test
- `test_mcp_smoke.py` runs the host in-process and exercises:
  - happy path: low-risk tool call succeeds, reply verifies.
  - sad path 1: missing capability → `CAP_MISSING` / `EnvelopeVerificationError`.
  - sad path 2: tampered envelope → signature failure.
  - sad path 3: tool call without step-up → `TOOL_STEP_UP_REQUIRED`.
- Asserts the JSONL audit log chain hash-validates per
  `audit_query.verify_chain`.

#### C2. Integration runbook
- README explaining how to run the smoke test by hand, what each
  step proves, and where to look in the audit log for the
  corresponding decision.

---

## 6) Acceptance Criteria

Phase 4 closes when ALL of the following hold:

1. The smoke test (D4.3) runs green and exercises every substrate
   primitive named in §1 Mission.
2. The runbook (D4.4) lets a fresh operator run the smoke test
   on their machine in under 15 minutes from `git clone`.
3. The audit log produced by the smoke test chain-validates.
4. The example host code is under 500 lines (intentionally — if
   it grows beyond that, we're solving Phase 5 problems early).
5. No new substrate modules are introduced; the adapter is a thin
   translation layer on top of existing primitives.
6. New proof obligation `mcp_smoke_round_trip_verifies` lands in
   `proof_obligations.py` pointing at the smoke test.

---

## 7) Test Strategy

- The smoke test IS the integration test. There is no separate
  unit test layer for the adapter — the smoke test exercises every
  function in it.
- Existing 705 substrate tests stay green throughout.
- The adversarial corpus (`test_adversarial_corpus.py`) keeps
  enforcing 100% block-rate.
- No load, no fuzz, no chaos — deferred to Phase 5.

---

## 8) Risk Register (Phase 4)

| Risk | Likelihood | Impact | Mitigation |
|---|---:|---:|---|
| Real MCP message shape differs from substrate envelope assumptions | M | H | Build the adapter against a real MCP spec, not what we wish MCP looked like |
| Example host scope creep | H | M | Hard 500-line ceiling + every PR cites the WBS leaf |
| Smoke test becomes a "shaped to pass" tautology | M | M | Include the three sad paths so the test asserts the gates fire on failure too |
| Adapter assumes a transport we then change | L | L | Stay transport-agnostic — operate on in-memory dicts |

---

## 9) Exit Gates

Phase 4 can close only when:

1. D4.1 + D4.2 + D4.3 + D4.4 are all merged on `main`.
2. The smoke test green-passes on the CI matrix (Python 3.11+3.12).
3. The proof-obligations registry has the new entry resolving cleanly.
4. CLAUDE.md is updated to mention the example host location and
   integration runbook.
5. DEFERRED.md is updated with the Phase 5 candidate items (drills,
   isolation tests, observability, runbook) that Phase 4 explicitly
   skipped — so a future agent doesn't re-litigate the scope.

---

## 10) Artifacts to Produce at Phase Close

- The adapter module + the example host module + the smoke test.
- Integration runbook.
- Audit log sample (committed under
  `security-foundations/integrations/mcp/example/sample-audit.jsonl`)
  showing a known-good round trip for any developer to compare against.
- One-paragraph phase-close note appended to the
  `implementation-plan/phases/README.md` summarizing what running
  the substrate against a real MCP host taught us (informs
  Phase 5 scoping).

---

## 11) Phase 5 hand-off (for the next agent)

Phase 4 deliberately does NOT cover:

- Compound-failure drill harness (Phase 3 §6).
- Shared-component isolation validation (Phase 3 §7).
- Observability surface — metrics, traces, dashboards (Phase 3 §8).
- Phase-close evidence bundle — runbook, drill reports, capacity
  policy package, Go/No-Go memo (Phase 3 §11).
- Audit emission wiring for the Phase 2 primitives that lack it
  (delegation, retrieval, egress, etc.).
- Property-based delegation chain tests (Phase 2 A3).
- ML classifiers for output scanning (Phase 2 C1).
- Multi-host / networked deployment.
- Distributed backends for any in-memory store.
- Performance, load, chaos, formal verification.

Phase 5's scope is whatever Phase 4 reveals to be the biggest
operational gap, plus whichever of the above the operator decides
matters most. The Phase 4 close-out note in §10 will inform that
decision.
