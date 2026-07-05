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

## Phase 4 (complete) — example host feature coverage

`implementation-plan/phases/phase-4-integration-proof.md` shipped in
full (D4.1-D4.5). The running example host
(`security-foundations/integrations/mcp/host.py`) now exercises,
end-to-end through a signed message: envelope verification,
capability tokens + gated issuance (`AllowlistPolicy`),
**capability revocation** (revoke-then-reject lifecycle),
**post-auth rate limiting**, replay cache, trust stores, tool policy
gate + step-up, output scanning, egress policy, and hash-chained
audit.

Substrate features that remain **host-dormant** (built + unit-tested
+ CI-pinned, but no message flows through them in the example host
because a single-host demo has nowhere to put them):

- Phase 2: delegation receipts, retrieval policy, prompt assembly,
  instruction isolation (no LLM prompt is composed in the demo),
  reviewer workflow (egress QUARANTINE currently just denies),
  checkpointed execution, session tokens.
- Phase 3: every mesh/operational primitive — sybil deterrence,
  eclipse resistance, discovery propagation, capacity budgets +
  rebalancer, safe-mode engine, key rotation, revocation
  convergence, recovery re-admission.

Wiring any of these into a running system is a real-integration task
(needs delegation chains, multi-turn LLM sessions, a mesh, etc.),
not a substrate gap. Pick them up when a real deployment needs them.

## Items routed to Phase 5 (deferred from Phase 3, surfaced after Phase 4)

The Phase 3 plan document specifies these but the substrate has
not implemented them. Phase 4 intentionally skips them so the
operator can pick which matter once a real running system reveals
the actual failure modes:

### Compound-failure drill harness (Phase 3 §6)
Four required scenarios — clock skew + policy rollback, ledger
divergence + revocation race, anomaly quarantine + export
attestation failure, partition during trust anchor rotation. The
safe-mode engine is built; the harness that runs these scenarios
end-to-end is not.

### Shared-component isolation validation (Phase 3 §7)
Noisy-neighbor saturation tests, cross-tenant replay and retrieval
abuse simulations, embedding and nearest-neighbor bleed checks on
replay cache, queue/scheduler, model serving, vector index, and
policy bundle distribution. None built.

### Observability surface (Phase 3 §8)
State-machine transition metrics, revocation convergence timing,
quorum health and partition status, security-service protected-
capacity utilization. Audit emission exists for envelope /
capability; everything else is not wired to telemetry.

### Phase-close evidence bundle (Phase 3 §11)
Safe-mode state machine implementation spec + runbook, compound-
failure drill reports and trend analysis, capacity protection and
fairness policy package, revocation / rotation game-day evidence,
formal verification artifact set + CI gate report, final Go/No-Go
recommendation memo. None produced.

### Audit-emission coverage for Phase 2 primitives
The Phase 2 verifiers (delegation, retrieval, egress, reviewer,
tool gate, checkpointed execution, session tokens) return their
decisions; the audit pipeline only consumes envelope / capability
events. Wiring the rest is an additive slice.

---

## Phase 5 (complete) — the deployment-enforcement frontier

Phase 5 ("The Fabric") shipped the substrate half of the vision's
Layer A identity, Layer C policy engine, the §5 mesh, Layer E
runtime tiers, and the §9 evidence docs. What it deliberately did
**not** do — the Phase 6 candidate pool — is the *enforcement* that
requires infrastructure the in-process kernel cannot be:

### Kernel-level sandbox enforcement (Out of substrate scope)
`runtime_profile.py` + `generate_seccomp` produce a real, loadable
OCI seccomp document and a declarative confinement profile; nothing
in-process *loads* it into a kernel or confines a filesystem /
network. That is a container runtime + mount namespaces + network
policy — a deployment concern, labelled [REFERENCE] throughout.

### Image-admission enforcement (Out of substrate scope)
`image_attestation.verify_image_signature()` proves an image digest
was attested; refusing to *run* an unattested image is an admission
webhook / runtime policy, not the kernel.

### Transport security — mTLS / TLS 1.3 (Out of substrate scope)
The substrate binds identity + integrity at the envelope layer
(proven transport-agnostic over in-memory and real-socket
transports). Wire confidentiality and the mTLS handshake the vision
Layer A also names are the deployment transport.

### Production PKI custody + issuance operations (Out of substrate scope)
`workload_ca.py` mints and verifies SVIDs against a self-signed
root; HSM custody of the root key, the real issuance/attestation
workflow (SPIRE-style), and operational rotation are the identity
plane's, consumed here through `IssuerTrustStore`.

### Mesh scale — gossip, routing at size, distributed consensus (Deferred / Out of scope)
The discovery *record* format and a two-node authenticated exchange
are specified and proven; the gossip protocol that disseminates
records, routing at scale, partition behavior, and DDoS absorption
are distributed-systems infrastructure.

### Native-engine → Cedar/Rego interop (Deferred, follow-up viable)
`policy_engine.py` is a structured native evaluator with decision
IDs — deliberately not a DSL parser. Interop with Cedar or Rego
(so operators reuse existing policy corpora) is a viable follow-up.

### Post-quantum signatures, load / chaos program (Beyond v0 commitment)
Ed25519 everywhere; a PQ migration and any load/fuzz/chaos program
are beyond the v0 commitment.

Together with the Phase 3 §§6–8 + §11 operational-evidence gaps and
the Phase 2 audit-emission wiring above, these are the Phase 6 pool.

---

## Phase numbering

Plans run Phase 0 through Phase 5; Phase 5 ("The Fabric") is
complete. Phase 6, if it exists, draws from the Phase 6 candidate
pool above (the deployment-enforcement frontier) PLUS the Phase 3
operational-evidence gaps and the Phase 2 audit-emission wiring —
and whatever the Phase 5 close-out note in
`implementation-plan/phases/README.md` records about what building
the fabric taught us.

Do not start refactoring or rewriting v0 modules without an
explicit reason. The v0 contract is "this is what the substrate
guarantees today"; replacing a module mid-flight without an
upstream prompt is the wrong default.
