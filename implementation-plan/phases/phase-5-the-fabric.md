# Phase 5 — The Fabric Implementation Plan

## 1) Phase Intent

Phases 0–4 built and proved the **in-process safety kernel**. Phase 5
closes the gap between that kernel and the vision in
`SECURITY_FIRST_P2P_MCP_PLAN.md`: a **peer-to-peer distributed MCP
fabric where AI agents safely discover each other, exchange
requests/responses, and cooperate autonomously**.

The vision's layered architecture (§2, Layers A–F) maps onto the
substrate. Phases 1–4 delivered Layers B (message security), C
(authorization/capabilities), D (data governance), and F
(observability/audit). **Phase 5 delivers the missing edges:**

- **Layer A** — real cryptographic identity: an internal CA issuing
  short-lived X.509 SVIDs bound to SPIFFE IDs, cert-chain
  verification, peer admission policy, aggressive rotation.
- **Layer C engine** — a structured policy engine (Cedar-shaped) that
  produces a **policy decision ID** on every authorization, wired
  into the audit chain, replacing the ad-hoc allowlist checks.
- **Zero-trust P2P topology (§5)** — an authenticated overlay mesh:
  discovery, routing, a pluggable transport, and a real two-node
  round trip.
- **Layer E** — runtime trust tiers as a declarative model, with
  runnable seccomp-profile generation and image-signature
  verification. (Kernel-level *enforcement* is deployment
  infrastructure and stays a documented reference.)
- **§9 evidence artifacts** — the STRIDE threat model, the
  SOC 2 / ISO 27001 / GDPR compliance control mapping, and a
  consolidated protocol spec.

### Runnable vs. reference (honesty contract)

Every Phase 5 slice is labeled:

- **[RUNNABLE]** — ships real, tested Python that executes in this
  repo with no external infrastructure.
- **[REFERENCE]** — ships a data model, generator, or verifier that
  is runnable and tested, but whose *enforcement* requires deployment
  infrastructure (a kernel, a container runtime, a real network at
  scale). The enforcement boundary is documented, never faked.

No slice claims enforcement it doesn't have. The
proof-obligations registry gains an entry only for invariants that
are actually machine-checked here.

### Mission (vision §8 acceptance criteria, now at fabric scope)

1. Unauthorized peer cannot join the mesh.
2. Tampered or replayed message is rejected.
3. Agent cannot access tool/data without explicit valid capability.
4. Sensitive data is redacted or blocked on unauthorized egress.
5. Compromised node blast radius is bounded (no lateral escalation).
6. Full forensic trace exists for every privileged action.

Criteria 2–4 and 6 already hold at kernel scope. Phase 5 extends
1 (real identity + admission), 5 (cert-scoped blast radius +
runtime tiers), and re-proves all six at **mesh scope** in the
two-node round trip.

---

## 2) Scope

### In Scope
1. Internal CA + X.509 SVID issuance/verification (Layer A).
2. Peer admission policy (deny-by-default, identity + env tier).
3. Structured policy engine with decision IDs (Layer C engine).
4. Authenticated overlay mesh: discovery, routing, transport,
   two-node round trip (§5).
5. Runtime trust-tier model + seccomp generator + image-signature
   verification (Layer E, reference enforcement).
6. STRIDE threat model, compliance mapping, protocol spec (§9).

### Out of Scope (documented in DEFERRED.md)
- Kernel-level sandbox *enforcement* (gVisor/Firecracker/Kata,
  live seccomp/AppArmor). Reference profiles + generators only.
- Production PKI operations (HSM/KMS key custody, OCSP responders).
  In-process CA is the reference; custody is deployment.
- A globally deployed mesh at real scale. The mesh is proven with a
  deterministic in-memory transport + a runnable local transport;
  planetary scale is a load/ops concern (Phase 6+).
- Post-quantum hybrid signatures. Migration space is preserved in
  the envelope; PQ itself is deferred.

---

## 3) Deliverables

### D5.1 Workload CA + SVID (Layer A) [RUNNABLE]
- `WorkloadCA` mints short-lived X.509 certs whose SAN carries the
  SPIFFE ID, signed by an internal Ed25519 root.
- `verify_svid()` validates chain, expiry, SPIFFE-SAN binding, and
  key usage.
- Rotation reuses the existing `key_rotation` overlap-window model.

### D5.2 Peer Admission (Layer A) [RUNNABLE]
- `PeerAdmissionPolicy` — deny-by-default allowlist keyed on
  `(spiffe_id, env_tier)`; optional cert pinning for high-trust peers.
- `admit_peer()` returns a decision with a stable deny reason.

### D5.3 Policy Engine (Layer C engine) [RUNNABLE]
- `PolicyEngine` ABC + `NativePolicyEngine` — structured
  `(principal, action, resource, context)` → `permit|deny` +
  `decision_id` (UUIDv7).
- Baseline policy library mirroring the existing tool / retrieval /
  egress gates so the engine is a drop-in decision authority.
- Decision IDs flow into the audit chain (`policy.decide` events).

### D5.4 Mesh Transport + Node (§5) [RUNNABLE]
- `Transport` ABC + `InMemoryTransport` (deterministic, test-grade)
  + `LocalSocketTransport` (real, runnable on one host).
- `MeshNode` — authenticated discovery via `discovery_record` +
  `bootstrap_bundle`, routing table via the `eclipse_resistance`
  diversity selector, admission via D5.2.

### D5.5 Two-Node Round Trip (§8 at mesh scope) [RUNNABLE]
- Node A discovers Node B, admits it, sends a signed envelope over
  the transport; B verifies (full stack) and replies; A verifies the
  reply. Audit chains on both nodes validate. The mesh-scope proof
  of all six §8 criteria.

### D5.6 Runtime Trust Tiers (Layer E) [REFERENCE]
- `RuntimeProfile` — trust tier → allowed syscalls, writable paths,
  egress policy, secret scope.
- `generate_seccomp(profile)` emits a real seccomp-BPF JSON document.
- `verify_image_signature()` — cosign-style detached signature check
  over an image digest. Enforcement (loading the profile into a
  kernel) is documented as deployment.

### D5.7 Evidence Artifacts (§9) [REFERENCE/DOCS]
- `docs/threat-model.md` — STRIDE + attack trees over the 8 threat
  classes.
- `docs/compliance-mapping.md` — proof-obligations → SOC 2 / ISO
  27001 / GDPR control IDs.
- `docs/protocol-spec-v0.1.md` — consolidated normative envelope +
  capability + discovery spec, promoted from `contracts/`.

---

## 4) Work Breakdown Structure (loop iterations)

Each iteration is one branch → commit → PR → merge cycle. The loop
keeps the plan doc and the task list updated after every iteration.

### Track A — Real Identity
- **A1** `workload_ca.py`: `WorkloadCA`, SVID issuance. [RUNNABLE]
  **Landed (v0):** `WorkloadCA` mints Ed25519 X.509 SVIDs with a
  critical SPIFFE URI SAN, signed by a self-signed internal root
  (cached `root_cert`). Default 1-hour TTL ("hours, not weeks"),
  cross-trust-domain issuance rejected, `svid_spiffe_id()` extracts
  the bound id. 17 tests.
- **A2** SVID verification + chain + SPIFFE-SAN binding. [RUNNABLE]
  **Landed (v0):** `verify_svid()` validates shape (one SPIFFE URI
  SAN) → signature under the trusted root → time window → key usage
  (digital_signature set, key_cert_sign forbidden) → optional
  expected-id binding, fail-fast with a distinct `DenyReason`
  (`SVID_*`) per failure. Proof obligation `svid_binding_verified`.
  10 tests.
- **A3** `peer_admission.py`: deny-by-default admission. [RUNNABLE]
  **Landed (v0):** `PeerAdmissionPolicy` is a closed allowlist of
  `AdmissionRule(spiffe_id, env_tier, pinned_fingerprint?)`.
  `admit_peer()` denies unknown identities
  (`ADMISSION_PEER_NOT_ALLOWED`), wrong-tier presentation
  (`ADMISSION_TIER_MISMATCH`), and pin mismatches
  (`ADMISSION_CERT_PIN_MISMATCH`). Proof obligation
  `unadmitted_peer_denied` (vision §8.1). 13 tests.

### Track B — Policy Engine
- **B1** `policy_engine.py`: ABC + `NativePolicyEngine` + decision IDs. [RUNNABLE]
  **Landed (v0):** `PolicyEngine.decide(PolicyRequest)` →
  `PolicyDecision(effect, decision_id, matched_rule, reason)`.
  `NativePolicyEngine` is a first-match, deny-by-default evaluator
  over `PolicyRule(principal, action, resource, conditions)` with
  wildcard (`*`) matching and typed `Condition`s
  (equals/not_equals/in/not_in) over the request context. Every
  decision carries a UUIDv7 `decision_id`. Structured, not a DSL;
  Cedar/Rego interop deferred behind the `PolicyEngine` ABC. 15 tests.
- **B2** baseline policy library + `policy.decide` audit wiring. [RUNNABLE]
  **Landed (v0):** `decide_and_audit()` runs the engine and emits a
  `policy.decide` audit event whose hashed `reason` embeds the
  `decision_id` — tamper-evident by construction, chain still
  validates. `build_baseline_engine()` assembles the vision's
  "baseline policy library" as engine rules mirroring the Phase 2
  gates (low-risk tool permit, step-up-required deny, deny-by-
  default). Proof obligation `policy_decision_in_trace`. 7 tests.
  Track B complete.

### Track C — The Mesh
- **C1** `mesh/transport.py`: `Transport` ABC + `InMemoryTransport`. [RUNNABLE]
  **Landed (v0):** `Transport` ABC (`address`, `send(dest, payload)`,
  `receive() -> Frame | None`) — a transport moves bytes and does no
  verification (identity comes from the signed envelope inside the
  frame). `InMemoryTransport` + `Switchboard` give a deterministic
  in-process transport for tests and the round trip. New
  `security-foundations/mesh/` package added to the wheel build. 10
  tests.
- **C2** `mesh/node.py`: `MeshNode` discovery + routing + admission. [RUNNABLE]
  **Landed (v0):** `MeshNode.learn_peer()` verifies a signed
  `DiscoveryRecord` (`verify_record`) → admits via
  `PeerAdmissionPolicy` (deny-by-default) → records the peer with its
  transport address from the record's endpoints. `routing_table()`
  applies `eclipse_resistance.select_neighbors` for diversity;
  `send_to()` routes signed envelope bytes to an admitted peer over
  the transport. Authentication ≠ authorization: a verified-but-
  unadmitted peer is not learned. Proof obligation
  `mesh_authenticate_then_authorize`. 18 tests.
- **C3** two-node round-trip test (D5.5) + `LocalSocketTransport`. [RUNNABLE]
  **Landed (v0):** `LocalSocketTransport` is a real loopback-TCP
  implementation of the `Transport` ABC (length-prefixed framing,
  daemon listener thread). `test_mesh_round_trip` proves the fabric
  works as a system: two mutually-admitted nodes complete a signed
  round trip — A's envelope crosses the transport, B runs the full
  `verify_envelope` stack, B's reply crosses back, A re-verifies, both
  audit chains validate. Sad paths: unadmitted peer has nowhere to
  route (§8.1), replayed envelope rejected at the receiver (§8.2).
  The same signed envelope verifies after crossing a real socket
  (transport-agnosticism). Proof obligation `mesh_round_trip_verifies`.
  5 tests. **Track C complete.**

### Track D — Runtime Tiers
- **D1** `runtime_profile.py`: tier model. [REFERENCE]
  **Landed (v0):** `RuntimeProfile(tier, allowed_syscalls,
  writable_paths, egress, egress_allowlist, secret_scopes)` is the
  declarative model for the vision's Layer E trust tiers, with
  built-ins `strict_profile` / `standard_profile` /
  `limited_trust_profile`. The module docstring states the
  enforcement boundary explicitly: a profile *declares* constraints;
  actual confinement needs a kernel + container runtime + network
  policy + secrets manager. No proof obligation (nothing is
  machine-enforced here — that would overclaim). 10 tests.
- **D2** `generate_seccomp` + reference profiles for the three tiers. [REFERENCE]
  **Landed (v0):** `generate_seccomp(profile)` renders a profile's
  `allowed_syscalls` into the exact OCI/Docker seccomp document a
  kernel loads — deny-by-default `SCMP_ACT_ERRNO`, the x86_64/x86/x32
  architecture list (so an ABI-swap can't evade the filter), and one
  sorted `SCMP_ACT_ALLOW` rule. `seccomp_to_json` gives a stable
  serialization. Generation is deterministic and testable in-process;
  *loading* the document into a kernel is the operator's runtime
  (why it stays [REFERENCE]). 6 tests.
- **D3** `image_attestation.py`: image-signature verification. [REFERENCE]
  **Landed (v0):** `ImageSignature` is a signed artifact (typ
  `wt-image-sig/v0`) binding a SPIFFE signer to one image digest,
  following the substrate's frozen-dataclass + JCS-body +
  sign/verify/from_json/to_json pattern with keys resolved through the
  usual `IssuerTrustStore` shape. `verify_image_signature()` fails
  fast: shape → exact digest match → signer-key lookup → signature,
  with distinct deny reasons (`IMAGE_SIG_MALFORMED`,
  `IMAGE_SIG_DIGEST_MISMATCH`, `IMAGE_SIG_UNKNOWN_SIGNER`,
  `IMAGE_SIG_INVALID`). Proof obligation
  `image_signature_binds_digest_to_signer` pins the digest→signer
  binding; the runtime gate that refuses to *run* an unattested image
  is [REFERENCE] deployment. 11 tests.

### Track E — Evidence
- **E1** `docs/threat-model.md` (STRIDE). [DOCS]
  **Landed (v0):** `docs/threat-model.md` maps all eight vision threat
  classes (§1) through the STRIDE lens, each with an attack tree, the
  substrate control that answers it, the pinning proof obligation(s),
  and an explicit [RUNNABLE]/[REFERENCE] enforcement boundary. A
  coverage-summary table reads the state honestly: classes 1–3 and 8
  enforced in-process, class 4 minus network egress, class 5 measured
  against the finite corpus, classes 6–7 the deployment-dependent
  frontier. Cross-references every cited module path and obligation
  name; a maintenance note ties updates to the proof-obligations
  workflow.
- **E2** `docs/compliance-mapping.md`. [DOCS]
- **E3** `docs/protocol-spec-v0.1.md`. [DOCS]

---

## 5) Acceptance Criteria

Phase 5 closes when:

1. The two-node round trip (D5.5) passes: authenticated discovery →
   admission → signed request → verify → reply → verify, both audit
   chains valid.
2. An unadmitted peer's request is rejected before any tool runs
   (vision §8.1 at mesh scope).
3. Every authorization emits a `policy.decide` event carrying a
   decision ID that appears in the forensic trace (vision §8.6).
4. `generate_seccomp` output validates against the seccomp JSON
   shape; a bad image signature is rejected.
5. Every RUNNABLE slice keeps the full suite green and ruff clean;
   every new machine-checked invariant has a proof obligation.
6. The three evidence docs exist and cross-reference the
   proof-obligations registry.

---

## 6) Test Strategy

- Each RUNNABLE slice ships unit tests in the substrate's style.
- The mesh round trip is the integration test (mirrors Phase 4's
  smoke test, at two-node scope).
- REFERENCE slices test the generator/verifier output shape, and
  explicitly document what enforcement they do NOT provide.
- No load, fuzz, or chaos — those remain Phase 6+.

---

## 7) Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---:|---:|---|
| REFERENCE slices read as enforcement | M | H | Every module docstring + the plan label state the enforcement boundary explicitly |
| Mesh transport scope-creeps into a framework | H | M | `Transport` ABC stays ~1 method; in-memory + local-socket only |
| Policy engine reinvents Cedar badly | M | M | Structured evaluator only, no DSL parser; documented as a v0 native engine, Cedar-interop deferred |
| X.509 handling introduces a crypto footgun | M | H | Use `cryptography` high-level x509 builders only; verify with the same library; test expiry + tamper paths |
| Session context exhaustion mid-loop | H | L | Plan doc + task list + git are the durable loop state; any agent resumes from them |

---

## 8) Exit Gates

1. All Track A–E deliverables merged on `main`.
2. Two-node round trip green on the CI matrix.
3. Proof-obligations registry extended for the new mesh-scope and
   identity invariants, all resolving.
4. CLAUDE.md Phase 5 status = complete; DEFERRED.md updated with the
   enforcement boundaries (kernel sandbox, PKI custody, mesh scale)
   as explicit Phase 6 candidates.
5. A Phase 5 close-out note in `implementation-plan/phases/README.md`
   recording what building the fabric taught us.

---

## 9) Phase 6 hand-off (anticipated)

Phase 5 deliberately does NOT deliver: kernel-level sandbox
enforcement, production PKI custody, a planet-scale deployed mesh,
post-quantum signatures, or a load/chaos program. Those, plus the
Phase 3 §§6–8 + §11 operational-evidence gaps already in
DEFERRED.md, are the Phase 6 candidate pool.
