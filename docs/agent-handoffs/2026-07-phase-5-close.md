# Handoff: Phase 5 "The Fabric" close (2026-07)

Supersedes `2026-06-host-security-features.md` as the most-recent brief.
Read `CLAUDE.md` for durable patterns/cadence and `DEFERRED.md` for
what's intentionally not done; read this for the moment-in-time framing
Phase 5 ended on.

## What just landed

Phase 5 closed the gap between the safety kernel and the
`SECURITY_FIRST_P2P_MCP_PLAN.md` vision. Thirteen loop iterations across
five tracks, each a branch → PR → merge:

- **Track A — Real Identity [RUNNABLE].** `workload_ca.py` mints Ed25519
  X.509 SVIDs with a critical SPIFFE URI SAN (1-hour TTL, cross-trust-
  domain issuance refused); `verify_svid()` fail-fast chain (shape →
  issuer/signature → window → key usage → SPIFFE binding);
  `peer_admission.py` deny-by-default admission with cert-fingerprint
  pinning.
- **Track B — Policy Engine [RUNNABLE].** `policy_engine.py` is a
  structured first-match deny-by-default evaluator with UUIDv7 decision
  IDs — a native engine, **not** a DSL parser (Cedar/Rego interop
  deferred). `policy_audit.py` emits `policy.decide` events with the
  decision ID landing in the hash-chained trace.
- **Track C — The Mesh [RUNNABLE].** New `security-foundations/mesh/`
  package: `transport.py` (`Transport` ABC + `InMemoryTransport`),
  `node.py` (authenticate-then-authorize `MeshNode`),
  `socket_transport.py` (real loopback TCP, 4-byte length prefix).
- **Track D — Runtime Tiers [REFERENCE].** `runtime_profile.py` (trust-
  tier model + `generate_seccomp` → real OCI seccomp document +
  `seccomp_to_json`), `image_attestation.py` (`wt-image-sig/v0` cosign-
  style detached signature verification).
- **Track E — Evidence [DOCS].** `docs/threat-model.md` (STRIDE + attack
  trees over the 8 vision threat classes), `docs/compliance-mapping.md`
  (all 40 obligations → SOC 2 / ISO 27001:2022 / GDPR),
  `docs/protocol-spec-v0.1.md` (consolidated wire spec).

## The marquee result

`mesh/test_mesh_round_trip.py::RoundTripTests::test_two_node_signed_round_trip`:
two mutually-admitted `MeshNode`s complete a full signed exchange —
authenticated discovery → admission → signed request → full-stack verify
→ authorize (policy.decide) → signed reply → independent re-verify — and
**both** nodes' audit chains hash-validate. It passes identically over
the in-memory transport and real loopback TCP, which is the proof that
Layer-B integrity is transport-agnostic. This is vision §8 re-proven at
mesh scale.

Pinned by proof obligation `mesh_round_trip_verifies`. The registry grew
34 → **40** obligations (added: `svid_binding_verified`,
`unadmitted_peer_denied`, `policy_decision_in_trace`,
`mesh_authenticate_then_authorize`, `mesh_round_trip_verifies`,
`image_signature_binds_digest_to_signer`).

## State at handoff

- **Tests green:** 794 envelope + 23 mesh + 61 mcp. ruff clean. All 40
  proof obligations resolve (`test_every_obligation_resolves`).
- **`mesh/` is a top-level package.** It needed three wiring touches a
  future agent must remember for any new cross-package module:
  `pyproject.toml` wheel `packages`, its own unittest `discover`
  invocation, and its path added in `test_proof_obligations.py` so
  cross-package `canonical_test` strings resolve.
- All Phase 5 plan deliverables annotated `**Landed (v0):**`;
  `security-foundations/README.md` has primitive entries; CLAUDE.md
  Phase 5 status = complete; DEFERRED.md has the Phase 6 pool.

## The load-bearing decision: [RUNNABLE] vs [REFERENCE]

The single most important thing to preserve. Track D and the egress
control are **[REFERENCE]**: the substrate produces loadable seccomp
documents, verifies image attestations, and declares confinement
profiles, but **enforces none of it in-process** — that needs a kernel,
a container runtime, a firewall. Every Track D docstring, the threat
model, and the compliance mapping say so explicitly. The registry
deliberately has **no** proof obligation for `generate_seccomp` or the
`RuntimeProfile` model: a document's shape is testable, but claiming it
is an *enforcement* invariant would be exactly the overclaim the labels
exist to prevent. `image_signature_binds_digest_to_signer` **does** get
one because signature *verification* is genuinely machine-checkable.
When you extend Track D, keep this discipline.

## What Phase 5 did NOT do — the Phase 6 pool

The deployment-enforcement frontier (full detail in `DEFERRED.md`
"Phase 5 (complete)"):

1. Kernel-level sandbox enforcement (load the seccomp doc; confine FS).
2. Image-admission enforcement (refuse to *run* an unattested image).
3. Transport security — mTLS / TLS 1.3 wire confidentiality.
4. Production PKI custody + SPIRE-style issuance/rotation ops.
5. Mesh scale — gossip dissemination, routing at size, partition/DDoS.
6. Native-engine → Cedar/Rego interop.
7. Post-quantum signatures; a load/fuzz/chaos program.

Plus the still-open Phase 3 §§6–8 + §11 operational-evidence gaps and
the Phase 2 audit-emission wiring, both pre-existing in `DEFERRED.md`.

## Priority-ordered next options

1. **Integrate the mesh against a real transport/deployment.** Start
   from `mesh/test_mesh_round_trip.py:_Fabric` — the richest end-to-end
   wiring in the repo now (two complete nodes). This is a real-
   integration task (mTLS, a gossip layer, kernel sandbox), i.e. the
   start of Phase 6, not a substrate gap.
2. **Wire audit emission for the still-dormant Phase 2 primitives**
   (delegation, retrieval, egress, reviewer, tool gate, checkpointed
   execution, session tokens). Additive; the pattern is proven.
3. **Cedar/Rego interop** for `policy_engine.py`, if an operator needs
   to reuse an existing policy corpus.

Do **not** start refactoring v0 modules without an explicit upstream
reason — the v0 contract is "what the substrate guarantees today."

## Cadence + anti-patterns

Unchanged — see `CLAUDE.md`. Branch → cite the plan deliverable in the
commit + PR → update the plan doc `**Landed (v0):**` + README + proof
obligations → full suite + ruff clean → merge → sync `main`.
