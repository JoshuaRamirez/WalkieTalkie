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

### Installable-package import restructure
**Shipped.** `pip install` / `pip install -e .` produces an importable
library. Hatch ships the three source trees as top-level packages
(`envelope`, `mesh`, `integrations`). Intra-package imports are
relative; cross-package imports are fully qualified
(`from envelope.workload_ca import …`). Proof-obligation
`canonical_test` paths are packaged
(`envelope.test_…` / `mesh.test_…` / `integrations.mcp.test_…`).
Tests run against the package:
`python -m unittest discover -s security-foundations -p 'test_*.py'`.
Consumer import without flat source dirs on `sys.path` is pinned by
`envelope/test_installable_import.py`. See `pyproject.toml` (NOTE ON
DISTRIBUTION) and `CLAUDE.md`.

### Independent peer sampling paths (Phase 3 Track A A2)
**Shipped.** Optional `sampler_pools` on `select_neighbors` plus
`NeighborSelection.samplers_identical`. The selector still takes
the combined candidate pool, so the per-domain cap and
min-distinct-domain invariants are unchanged. The diagnostic is
True iff two or more labeled sampler outputs are the same
`(peer_iss, peer_kid)` set — the leftover signal that the
operator's gossip layers aren't actually independent. Combined-
pool-only callers keep `samplers_identical is None`. No gossip
layer is invented; callers tag their own sampler outputs. Proof
obligation `independent_samplers_identical_sets_detected` pins
the report. See leftover #98.

### Attestation burden tuning (Phase 3 Track A A1)
Proof-of-work or hardware-attestation cost dial belongs in the
higher-level identity-issuance flow, not the in-process substrate.
Follow-up would add a `SybilDeterrence`-shaped hook for "verify
this attestation proof has at least X work units" callable from
the issuance pipeline.

### Property / fuzz tests for delegation chains (Phase 2 Track A A3)
**Shipped.** `security-foundations/envelope/test_delegation_receipt_properties.py`
is a Hypothesis suite over random valid and mutated delegation
graphs. Valid chains verify hop-by-hop; mutations that widen or
narrow scope, drift audience, extend TTL, break parent/hop/issuer
bindings, overrun `max_chain_depth`, or invalidate the signature
fail closed with the matching `DenyReason`. v0 still requires
identical `scope` at every hop (partial-order narrowing remains
deferred below). Deterministic case-based tests in
`test_delegation_receipt.py` are unchanged. `hypothesis` is a
`[dev]` extra only. Proof obligation
`delegation_random_graph_non_escalation` pins the suite.

### ML classifiers for output scanning (Phase 2 Track C C1)
The deterministic-patterns half is shipped. `ScanResult.matches`
is a flat tuple specifically so an ML classifier can append matches
without breaking consumers. v0 reserved `RiskLevel.LOW` for future
low-confidence ML hits.

### Signed audit checkpoint emission (most modules)
**Shipped.** Optional `audit_sink` on the Phase 2 verifiers
(delegation, retrieval, egress, reviewer, tool gate, checkpointed
execution, session tokens). Each emits one hash-chained
`XXX.verify` / `checkpoint.evaluate` event on allow and on deny
using the existing `AuditEvent` schema. Sink failure fails closed
(`AUDIT_SINK_FAILURE`) so an unaudited allow is not an allow.
Callers that omit the sink are unchanged. The MCP host still emits
its own `tool.gate` / `egress.evaluate` events and does not pass
the sink through (no double emission). Proof obligation
`phase2_verifiers_emit_audit_checkpoints` pins the suite. See
leftover #100.

### Tenant-level capacity rebalancing (Phase 3 Track B B3)
**Shipped.** `CapacityRebalancer` applies the same
stress/slack/cascade heuristic to per-tenant `TenantBudget.burst`,
reading live consumption from `BudgetController.tenant_snapshot()`.
Cascade detection and burst transfer are intra-pool: a slack
tenant in pool A never donates to a stressed tenant in pool B.
A tenant's burst never falls below that tenant's reserve or current
in-flight; `burst >= reserve` remains the `TenantBudget` invariant.
Reserved stays a permanent declaration of intent — only burst
headroom moves. Pool-ceiling rebalancing stays global. Callers that
never configure `tenant_budgets` see a no-op tenant half.
`BudgetController.adjust_tenant_burst` is the mutation sibling of
`adjust_ceiling`. Proof obligation
`rebalancer_tenant_burst_respects_floors` pins the floors. See
leftover #102.

### Resource claim in capability tokens (Phase 1)
Capability tokens carry `scope` but not `resource`. Adding a
`resource` claim later is a backward-compatible claim addition;
the validator can begin enforcing it then.

### Scope narrowing in delegation (Phase 2 Track A)
v0 requires identical `scope` at every hop. Partial-order scope
narrowing is a v1 extension and would require a controlled
vocabulary first.

### Bounded membership table under gossip pressure (Phase 6 Track B)
**Shipped.** Optional `admission` + `peer_tier` on `SwimMembership`
reuses the D6.4 `PeerAdmissionPolicy` seam. `_merge` and new
`_mark_heard` entries insert an id only when it passes deny-by-default
admission, so the members table is bounded by the admitted set
rather than a magic number. Optional `peer_key` supplies a verified
SVID public key so pinned rules can evaluate; resolver exceptions
fail closed. Operator-supplied seeds are retained as bootstrap
(the gate does not evict them, even if they would fail admission).
`_digest()` is not truncated — unadmitted ids never enter, so they
are never re-gossiped. Callers that omit the gate are unchanged.
Proof obligation `unadmitted_gossip_does_not_enter_membership`
pins the leftover. See leftover #104.

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
**Shipped.** Same slice as "Signed audit checkpoint emission"
above. The Phase 2 verifiers emit into `audit.py` / `AuditSink`
when an optional `audit_sink` is attached. See leftover #100.

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

## Phase 6 (complete) — what the network stack resolved, and what didn't

Phase 6 ("The Network") turned the mesh into a real network stack, all
[RUNNABLE] and loopback-tested. It **resolved** two items from the Phase 5
pool above, and **sharpened** the boundary on the rest:

### Resolved by Phase 6
- **Transport security — mTLS / TLS 1.3.** `mesh/tls_transport.py`
  (`TlsSocketTransport`) is genuine mutual TLS 1.3 with SVID peer
  verification. This is no longer deferred at the substrate level —
  loopback mTLS is real TLS. (WAN *tuning* — session resumption, cipher
  policy — remains deployment; see `docs/deployment-networking.md`.)
- **Mesh — gossip + routing (the runnable half).**
  `mesh/membership.py` (SWIM-style convergence + failure detection) and
  `mesh/routing.py` (multi-hop, loop-safe, deny-by-default) are shipped
  and tested. What remains deferred is the *scale* half (below).

### Still deferred / out of scope after Phase 6 (the Phase 7 pool)
- **Kernel-level sandbox enforcement** — unchanged (Phase 5 item).
- **Image-admission enforcement** — unchanged (Phase 5 item).
- **NAT traversal / cross-NAT WAN reachability** — STUN/TURN/ICE, relays.
  As of v0.1 the transport bind is configurable (`bind_host` /
  `advertise_host`), so peers on a mutually reachable network (LAN, VPN, or
  port-forwarded hosts) now connect directly over the same mTLS + envelope
  path. What stays deferred is the case where *both* peers sit behind NAT
  with no dialable address, which needs public relays. See
  `docs/deployment-networking.md` §1. Out of substrate scope.
- **Production PKI custody + issuance ops** — unchanged; HSM/KMS root,
  SPIRE-style attestation, rotation ops. Out of substrate scope.
- **Membership/routing at scale** — SWIM indirect probing (ping-req via
  k relays), O(N) probe load, route *computation* protocol
  (distance-vector/link-state), partition behavior. The *forwarding
  security* invariants hold regardless of table computation; the scale
  refinements need many real hosts + real loss to test. Deferred.
- **Native-engine → Cedar/Rego interop** — unchanged, follow-up viable.
- **Post-quantum signatures, load/chaos program** — unchanged, beyond v0.
- **Fleet-wide observability aggregation** — per-node hash-chained audit
  exists; cross-fleet metrics/tracing is deployment.

---

## Phase numbering

Plans run Phase 0 through Phase 6; Phase 5 ("The Fabric") and Phase 6
("The Network") are complete. Phase 7, if it exists, draws from the
Phase 7 pool above (kernel sandbox, image admission, NAT/WAN, PKI
custody, mesh scale) PLUS the still-open Phase 3 operational-evidence
gaps and the Phase 2 audit-emission wiring — and whatever the Phase 6
close-out note in `implementation-plan/phases/README.md` records about
what building the network taught us.

Do not start refactoring or rewriting v0 modules without an
explicit reason. The v0 contract is "this is what the substrate
guarantees today"; replacing a module mid-flight without an
upstream prompt is the wrong default.
