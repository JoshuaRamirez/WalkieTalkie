# DEFERRED.md — Items intentionally not shipped (yet, or ever in this substrate)

This file is the registry of work the substrate has *deliberately*
not done, with the reasoning. Read this before proposing work that
might already be on the "intentionally not doing" list. Add to it
whenever you defer something — never silently.

There are three categories:

- **Deferred (follow-up viable):** code-shippable, just not yet
  scheduled. Adding this to a future Phase 4 plan is the natural
  path.
- **Out of substrate scope:** belongs to a layer outside the
  in-process safety kernel (deployment, distributed infra,
  upstream identity issuance, etc.). Won't be done here regardless
  of priority.
- **Beyond v0 commitment:** the substrate intentionally ships v0
  primitives. Some capabilities are reserved for v1+ when
  operational experience tells us what shape they should take.

---

## Deferred (follow-up viable)

### Independent peer sampling paths (Phase 3 Track A A2)
Multi-process / network-topology concern. v0 takes the combined
candidate pool as input to `select_neighbors`. Follow-up would
introduce per-sampler diagnostics so the diversity gate can detect
"both samplers returned identical sets" — a signal that the
operator's gossip layers aren't actually independent.

### Attestation burden tuning (Phase 3 Track A A1)
Proof-of-work or hardware-attestation cost dial belongs in the
higher-level identity-issuance flow, not the in-process substrate.
Follow-up would add a `SybilDeterrence`-shaped hook for "verify
this attestation proof has at least X work units" callable from
the issuance pipeline.

### Property / fuzz tests for delegation chains (Phase 2 Track A A3)
The substrate ships deterministic case-based tests for every
non-escalation invariant. The plan calls for property-based tests
over random delegation graphs as a follow-up; Hypothesis-shaped
suite would be the right v0.

### ML classifiers for output scanning (Phase 2 Track C C1)
The deterministic-patterns half is shipped. `ScanResult.matches`
is a flat tuple specifically so an ML classifier can append matches
without breaking consumers. v0 reserved `RiskLevel.LOW` for future
low-confidence ML hits.

### Signed audit checkpoint emission (most modules)
Every signed primitive returns a verification result; wiring an
audit-pipeline `XXX.verify` event for each one is a follow-up that
pairs with the rest of the Phase 2 checkpoint suite. Currently
Phase 1's `audit.py` covers envelope/capability events; extending
coverage to delegation, retrieval, egress, etc. is incremental.

### Tenant-level capacity rebalancing (Phase 3 Track B B3)
The capacity rebalancer adjusts pool ceilings. Adjusting per-tenant
`TenantBudget.burst` caps under the same heuristic is a follow-up
extension of the same primitive.

### Resource claim in capability tokens (Phase 1)
Capability tokens carry `scope` but not `resource`. Adding a
`resource` claim later is a backward-compatible claim addition;
the validator can begin enforcing it then.

### Scope narrowing in delegation (Phase 2 Track A)
v0 requires identical `scope` at every hop. Partial-order scope
narrowing is a v1 extension and would require a controlled
vocabulary first.

---

## Out of substrate scope

### Distributed-backend swaps
Every backend (`InMemoryReplayCache`, `InMemoryRevocationLedger`,
`InMemorySybilLedger`, `InMemoryConvergenceTracker`,
`InMemoryDiscoveryFreshnessTracker`, `InMemoryDiscoveryPropagationLimiter`)
is single-process. ABCs exist so a Redis / etcd swap-in is
straightforward, but cluster-wide consistency is an infrastructure
concern and belongs to the operator's deployment layer.

### TLA+ / Coq / Lean formal model (Phase 3 Track E E1)
Real formal verification is out of scope for the Python substrate.
The v0 equivalent is the proof-obligations registry: executable
specification via tests, not mathematical proof. A future Phase 4+
slice could introduce TLA+ proofs and feed them back into the
registry as additional `proof_artifact` references.

### External security review (Phase 1 Exit Gate #5)
Out of code scope; needs human security review by an outside team.
Track separately.

### Performance, load testing, benchmarks
Zero load tests. Nothing has been measured under contention. This
is a deployment-stack concern — the substrate is correctness-first;
performance lives in the surrounding system.

### Network / RPC layer
There is no networking. The substrate is a pure-Python kernel.
Wrapping it in gRPC / WebSocket / QUIC / etc. is the operator's
job.

### Real MCP host integration
The substrate doesn't talk to any actual MCP server. Wiring it as
the safety layer in front of a real MCP host is the application
layer.

### Automatic key generation / publishing
v0 takes new kids as input; how they're minted (HSM, KMS,
hardware-backed) is upstream of the substrate.

### Distributed convergence / consensus
The Phase 3 `ConvergenceTracker` ABC accepts an ack-per-node model
that any distributed store can implement, but the substrate ships
the in-process variant only.

### Sealed / attested baseline integrity for re-admission
v0 takes `baseline_digest` as opaque hex. TPM quotes / image
signatures / runtime attestation are operator concerns.

---

## Beyond v0 commitment

### Multi-attester / quorum approvals
- Reviewer workflow (`reviewer_workflow.py`)
- Step-up attestations (`tool_policy_gate.py`)
- Re-admission attestations (`recovery_readmission.py`)
- Signed downgrade approvals (`signed_safe_mode.py`)

Each currently takes a single signature. Quorum (N-of-M) belongs
at a higher layer; v0 intentionally takes a single trusted signer.

### Proof-of-possession holder binding (Phase 1)
Capability tokens are bearer in v0. A leaked token grants the same
capability for at most `max_capability_ttl` (5 minutes default).
Proof-of-possession via `cnf.jwk` is a known v1 candidate.

### Per-message confidentiality (Phase 0/1)
The envelope verifies integrity + authenticity, not
confidentiality. Adding HPKE / ECDH for payload encryption is a
distinct primitive; out of scope for the v0 verifier.

### Per-callsite output-scanning allowlists (Phase 2 Track C C1)
v0 `PatternRegistry` is a closed set. Ignore-rules for
"this specific output is allowed to contain X" belong in the C2
egress policy layer.

### Reversible tokenization for reviewer workflow (Phase 2 Track C C3)
v0 redacts irreversibly. Retaining originals under a separate
review-time key for "show me what I was about to send" is a C3
extension.

### Replay caching for short-lived signed artifacts
Step-up attestations, downgrade approvals, etc. enforce time
windows but don't cache jtis. Replay within the window is the
operator's concern; v0 ships narrow windows + per-call jti.

### Bidirectional session resume chains
v0 takes a single resume chain per session. Per-direction chains
for bidirectional streaming would compose two `SessionToken`
instances at a higher layer.

---

## Phase 4 status

There is no Phase 4 plan doc. The four shipped plans
(`phase-0-security-foundations.md` through
`phase-3-resilience-and-scale.md`) all have every deliverable
annotated `**Landed (v0):**`. To start new substrate work either:

1. Write a Phase 4 plan first, drawing items from the "Deferred"
   section above, and run it through the same cadence the prior
   phases used.
2. OR pick a single deferred item, write a focused circle-back
   slice, and ship it the same way.

Do not start refactoring or rewriting v0 modules without an
explicit reason. The v0 contract is "this is what the substrate
guarantees today"; replacing a module mid-flight without an
upstream prompt is the wrong default.
