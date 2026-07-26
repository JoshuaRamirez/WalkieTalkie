# WalkieTalkie Threat Model (v0)

*STRIDE + attack trees over the eight vision threat classes, each
mapped to the substrate control that answers it and the proof
obligation that pins that control.*

This document closes **Phase 5 Track E, E1** (evidence artifact D5.7,
vision §9 deliverable 1: "Formal threat model document — STRIDE +
attack trees"). It is the design-time companion to the machine-checked
registry in `security-foundations/envelope/proof_obligations.py`: the
registry proves invariants hold; this document explains *which threat*
each invariant defends against and *where the defense stops*.

## How to read this document

Every control carries an honesty label, the same taxonomy the code
uses (see `implementation-plan/phases/phase-5-the-fabric.md` §1):

- **[RUNNABLE]** — real, tested, in-process enforcement. The substrate
  itself denies the attack; a proof obligation pins it.
- **[REFERENCE]** — a verifiable data model / generator / checker whose
  *enforcement* requires deployment infrastructure the in-process
  kernel does not provide (a kernel, a container runtime, a network
  policy engine, a secrets manager). The substrate supplies the
  authoritative, testable artifact; the operator wires the gate.

A threat is only "mitigated" to the strength of its weakest labelled
link. Where a class rests on [REFERENCE] controls, this document says
so plainly rather than implying enforcement the kernel does not have.

## STRIDE ↔ vision threat class matrix

The vision (§1) names eight threat classes. STRIDE is the orthogonal
lens. The matrix shows where each vision class lands in STRIDE terms;
the numbered sections below work class-by-class.

| Vision threat class            | S | T | R | I | D | E |
|--------------------------------|:-:|:-:|:-:|:-:|:-:|:-:|
| 1. Identity spoofing           | ● |   | ● |   |   | ● |
| 2. Message tampering / replay  |   | ● | ● |   |   |   |
| 3. Capability escalation       |   |   | ● |   |   | ● |
| 4. Data exfiltration           |   |   |   | ● |   |   |
| 5. Model manipulation          |   | ● |   | ● |   | ● |
| 6. Supply-chain compromise     | ● | ● |   |   |   | ● |
| 7. Runtime breakout            |   |   |   | ● |   | ● |
| 8. Consensus / availability    | ● |   | ● |   | ● |   |

(S=Spoofing, T=Tampering, R=Repudiation, I=Information disclosure,
D=Denial of service, E=Elevation of privilege.)

---

## 1. Identity spoofing (STRIDE: Spoofing, Elevation)

**Threat.** A malicious node presents itself as a trusted agent or
server to receive requests, issue replies, or join the mesh.

**Attack tree.**
```
Goal: be treated as a trusted peer
├── Forge a workload identity (SVID)
│   ├── Mint a cert with a victim's SPIFFE id      → blocked: SVID must
│   │                                                 chain to a trusted
│   │                                                 root (A2)
│   └── Present a self-signed cert with valid SAN  → blocked: issuer/
│                                                     signature check (A2)
├── Replay a real peer's signed envelope as your own
│   └── (see §2 — sender identity is signed, not asserted)
└── Get admitted to the mesh without authorization
    └── Connect + advertise a discovery record     → blocked: deny-by-
                                                      default admission (A3)
```

**Substrate controls.**
- `envelope/workload_ca.py` — `WorkloadCA.issue_svid()` mints
  short-lived (1-hour default) X.509 SVIDs with a critical SPIFFE URI
  SAN; `verify_svid()` fails fast on shape → issuer/signature → time
  window → key usage → SPIFFE binding. **[RUNNABLE]**
- `envelope/peer_admission.py` — deny-by-default first-match admission
  keyed on `(spiffe_id, env_tier)` with optional cert-fingerprint
  pinning. **[RUNNABLE]**
- `mesh/node.py` — `learn_peer()` verifies the discovery record's
  signature *before* running admission (authenticate-then-authorize);
  an unverified or unadmitted peer never enters the routing table.
  **[RUNNABLE]**

**Proof obligations.** `svid_binding_verified`, `unadmitted_peer_denied`,
`mesh_authenticate_then_authorize`.

**Enforcement boundary.** In-process the substrate verifies SVIDs and
admits peers. The transport-layer mTLS handshake the vision also calls
for (Layer A) now ships [RUNNABLE] in `mesh/tls_transport.py` (Phase 6,
proven over loopback); WAN-scale handshake operations remain
deployment-layer. Either way the substrate binds identity at the
*envelope* layer, which holds regardless of transport (proven by the
same envelope verifying over both InMemory and real-socket transports
in `mesh/test_mesh_round_trip.py`).

---

## 2. Message tampering / replay (STRIDE: Tampering, Repudiation)

**Threat.** Request/response payloads are modified in transit, or a
captured envelope is replayed to re-trigger a privileged action.

**Attack tree.**
```
Goal: get a forged or stale message accepted
├── Modify payload after signing        → blocked: signature covers the
│                                          JCS-canonical body incl. payload
│                                          digest (envelope verify)
├── Swap the declared capability intent  → blocked: capability binding is
│                                          inside the signed body
├── Replay a captured valid envelope     → blocked: nonce anti-replay cache
│                                          + timestamp window
└── Canonicalization ambiguity attack    → blocked: strict JCS (RFC 8785)
                                           before signature verification
```

**Substrate controls.**
- `envelope/verify_envelope.py` — schema validation → strict JCS
  canonicalization → Ed25519 signature verification, in that order; the
  signature binds sender, timestamp, nonce, payload digest, and
  capability intent. **[RUNNABLE]**
- Anti-replay: nonce cache + timestamp freshness window; the mesh
  round-trip test drives a real replayed envelope and asserts rejection
  at the receiver (`test_replayed_envelope_rejected_at_receiver`).
  **[RUNNABLE]**
- `envelope/discovery_record.py` — signed, time-bounded discovery
  records; stale records fail the window (anti-poisoning). **[RUNNABLE]**

**Proof obligations.** `envelope_signature_required`,
`session_resume_sequence_strict`, `discovery_freshness_monotonic`,
`mesh_round_trip_verifies` (its replay-rejection assertion).

**Enforcement boundary.** Fully [RUNNABLE]. Confidentiality on the wire
(TLS 1.3) is deployment-layer, but integrity/authenticity of the
message is enforced in-process by the envelope signature independent of
transport encryption.

---

## 3. Capability escalation (STRIDE: Elevation, Repudiation)

**Threat.** An agent obtains tools or scopes beyond its grant — by
widening a delegated capability, replaying a token to another audience,
extending a TTL, or invoking a step-up-gated tool without the step-up.

**Attack tree.**
```
Goal: act beyond granted authority
├── Reuse a bearer token from another principal → blocked: cnf key
│                                                  binding (proof-of-
│                                                  possession)
├── Delegate a broader scope than held          → blocked: scope
│                                                  monotonicity
├── Retarget a delegated cap to a new audience  → blocked: audience
│                                                  monotonicity
├── Extend the validity window on delegation    → blocked: window
│                                                  containment
├── Chain delegations without bound             → blocked: depth cap
├── Call a high-risk tool without step-up        → blocked: step-up call
│                                                  binding
└── Use a revoked capability                     → blocked: revocation
                                                   checkpoint
```

**Substrate controls.**
- `envelope/capability_token.py` — per-request least-privilege tokens
  with `cnf` proof-of-possession binding. **[RUNNABLE]**
- `envelope/delegation_receipt.py` — scope/audience/window/depth
  monotonicity across delegation hops; no hop can widen authority.
  **[RUNNABLE]**
- `envelope/tool_policy_gate.py` — step-up binding for high-risk tools.
  **[RUNNABLE]**
- `envelope/policy_engine.py` + `policy_audit.py` — deny-by-default
  authorization with a decision ID emitted into the forensic trace
  (non-repudiation). **[RUNNABLE]**
- Revocation checkpoints (`host_revocation_lifecycle_enforced`).
  **[RUNNABLE]**

**Proof obligations.** `capability_cnf_binding_prevents_reuse`,
`capability_signer_pool_separation`, `delegation_scope_monotonicity`,
`delegation_audience_monotonicity`, `delegation_window_containment`,
`delegation_depth_bounded`, `tool_step_up_call_binding`,
`policy_decision_in_trace`, `revoked_capability_blocked_at_checkpoint`,
`host_revocation_lifecycle_enforced`.

**Enforcement boundary.** Fully [RUNNABLE] — this is the substrate's
densest coverage.

---

## 4. Data exfiltration (STRIDE: Information disclosure)

**Threat.** Sensitive context leaks via retrieval across tenant
boundaries, classification downgrade, or unrestricted egress.

**Attack tree.**
```
Goal: move protected data out of scope
├── Read another tenant's context        → blocked: cross-tenant default
│                                          deny on retrieval
├── Relabel secret data as public        → blocked: classification
│                                          non-demotion
└── Export data to an unapproved sink     → blocked: egress restriction
                                           (allowlist / deny-all)
```

**Substrate controls.**
- `envelope/retrieval_policy.py` — cross-tenant default-deny.
  **[RUNNABLE]**
- `envelope/data_classification.py` — classification lattice; labels
  may only move up (non-demotion). **[RUNNABLE]**
- `envelope/egress_policy.py` — egress allowlist / deny-all posture.
  **[RUNNABLE]** (policy decision); the *network* enforcement of egress
  is deployment-layer — see §7.

**Proof obligations.** `retrieval_cross_tenant_default_deny`,
`data_classification_non_demotion`, `egress_restricted_no_export`.

**Enforcement boundary.** The retrieval and classification decisions are
[RUNNABLE]. Egress *policy* is [RUNNABLE]; egress *network enforcement*
(a firewall honoring the posture) is [REFERENCE] / deployment.

---

## 5. Model manipulation (STRIDE: Tampering, Information disclosure, Elevation)

**Threat.** A peer poisons tool output or injects instructions to
subvert the receiving agent's model (prompt injection, tool-output
poisoning).

**Attack tree.**
```
Goal: make a peer's model act on attacker-controlled content
├── Return poisoned tool output as trusted → blocked: tool output is
│                                            untrusted unless signed
├── Smuggle instructions via an unsigned    → blocked: same — unsigned
│   channel                                   content is not authority
└── Evade with a known injection pattern     → measured: adversarial
                                               corpus full-block rate
```

**Substrate controls.**
- Tool-output trust boundary — output is untrusted unless carried by a
  signed, verifiable artifact. **[RUNNABLE]**
- `envelope/reviewer_workflow.py` — reviewer record binding for
  human-in-the-loop gates. **[RUNNABLE]**
- Adversarial corpus (18 entries) — a measured full-block rate over
  known injection patterns. **[RUNNABLE]** (a *measured* control, not a
  completeness proof; see caveat below).

**Proof obligations.** `tool_output_untrusted_unless_signed`,
`reviewer_record_binding`, `adversarial_corpus_full_block_rate`.

**Enforcement boundary.** The trust boundary is [RUNNABLE]. The
adversarial corpus proves the substrate blocks *the 18 known patterns*;
it does **not** prove coverage of unknown injections — real-world
adversarial breadth is explicitly deferred (see `DEFERRED.md`). This is
the substrate's most partial class and is labelled as such.

---

## 6. Supply-chain compromise (STRIDE: Spoofing, Tampering, Elevation)

**Threat.** A compromised container image, dependency, or model
artifact enters the mesh as if it were a trusted build.

**Attack tree.**
```
Goal: run attacker-controlled code as a trusted workload
├── Substitute a tampered image           → blocked (attestation): image
│                                            signature binds signer→digest
├── Present a signature over a different    → blocked: exact digest match
│   image
├── Sign with an untrusted key             → blocked: signer-key lookup in
│                                            trust store
└── Actually run the unattested image       → NOT blocked in-process:
                                             admission gate is deployment
```

**Substrate controls.**
- `envelope/image_attestation.py` — `verify_image_signature()` binds a
  SPIFFE signer to one image digest (cosign-style detached Ed25519),
  failing fast on digest mismatch, unknown signer, or bad signature.
  **[REFERENCE]**
- `envelope/bootstrap_bundle.py` — signed, epoch-versioned trust anchor
  set; key-pool separation (`capability_signer_pool_separation`,
  `readmission_attester_pool_separation`) limits blast radius of a
  compromised signing key. **[RUNNABLE]** for the pool-separation
  invariants.

**Proof obligations.** `image_signature_binds_digest_to_signer`,
`capability_signer_pool_separation`, `readmission_attester_pool_separation`.

**Enforcement boundary.** The substrate *verifies* an attestation
in-process ([RUNNABLE] verification of a [REFERENCE] control). The
admission gate that refuses to *run* an image lacking a verifying
signature is deployment-layer (an admission webhook / runtime policy).
Dependency and model-artifact provenance beyond container images is out
of scope for v0 (`DEFERRED.md`).

---

## 7. Runtime breakout (STRIDE: Elevation, Information disclosure)

**Threat.** A server escapes its sandbox and reaches host resources,
the network, or secrets outside its scope.

**Attack tree.**
```
Goal: escape the workload sandbox
├── Invoke a dangerous syscall            → constrained: seccomp allowlist
│                                            (generated deny-by-default)
├── Evade the filter via a 32-bit ABI      → constrained: all x86 ABIs
│                                            named in the profile
├── Write outside the sandbox             → declared: writable-path set
├── Open outbound connections             → declared: egress posture
└── Read secrets beyond scope             → declared: secret-scope set
```

**Substrate controls.**
- `envelope/runtime_profile.py` — `RuntimeProfile` declares the trust
  tier's allowed syscalls, writable paths, egress posture, and secret
  scope; `generate_seccomp()` renders the syscall allowlist into a real
  OCI/Docker seccomp document (deny-by-default `SCMP_ACT_ERRNO`, all
  x86 ABIs, one sorted allow-rule). **[REFERENCE]**

**Proof obligations.** None. The profile model and seccomp generator
are deliberately *not* backed by proof obligations because nothing is
machine-*enforced* in-process — claiming one would overclaim (see the
`runtime_profile.py` docstring and the D1/D2 plan annotations).

**Enforcement boundary.** This is the substrate's most [REFERENCE]
class. The substrate produces a versioned, type-checked, loadable
seccomp document and a declarative confinement profile; *loading* it
into a kernel, confining the filesystem, and enforcing egress are the
container runtime's and network policy's job (Phase 7 / deployment).
The value is a single authoritative source the enforcement layer
consumes instead of scattered ad-hoc config.

---

## 8. Consensus / availability attacks (STRIDE: Spoofing, Repudiation, Denial of service)

**Threat.** Eclipse, Sybil, DDoS, partitioning, or routing abuse
degrade the mesh's view, starve honest workloads, or dominate a peer's
neighbor set.

**Attack tree.**
```
Goal: distort the mesh or starve honest peers
├── Flood identities to dominate a peer view → blocked: Sybil cluster
│                                               cannot dominate neighbor
│                                               selection
├── Eclipse a node's routing table            → blocked: eclipse-resistant
│                                               neighbor selection
├── Starve non-preemptible workloads          → blocked: non-preemptible
│                                               floor invariant
├── Oversubscribe capacity                     → blocked: oversubscription
│                                               cap (rebalancer)
├── Flood requests post-auth                    → blocked: post-auth rate
│                                               limit
└── Trigger cascading failure                   → contained: signed
                                                safe-mode with deterministic,
                                                authority-dominant transitions
```

**Substrate controls.**
- `envelope/eclipse_resistance.py` / sybil deterrence —
  `select_neighbors()` resists Sybil clusters and eclipse. **[RUNNABLE]**
- Scheduler invariants — non-preemptible floor + oversubscription cap
  preserved across rebalancing. **[RUNNABLE]**
- `integrations/mcp/host.py` — post-authentication rate limiting.
  **[RUNNABLE]**
- `envelope/signed_safe_mode.py` — signed, deterministic, authority-
  dominant safe-mode transitions for controlled degradation. **[RUNNABLE]**

**Proof obligations.** `sybil_cluster_cannot_dominate_peer_view`,
`non_preemptible_floor_invariant`, `rebalancer_preserves_non_preemptible_floor`,
`rebalancer_preserves_oversubscription_cap`, `host_rate_limit_enforced_post_auth`,
`discovery_freshness_monotonic`, `safe_mode_authority_hierarchy_dominance`,
`safe_mode_determinism`, `signed_safe_mode_transition_integrity`.

**Enforcement boundary.** The *algorithmic* defenses (neighbor
selection, scheduler floors, rate-limit logic, safe-mode state machine)
are [RUNNABLE]. Network-level DDoS absorption and real partition
behavior in a distributed deployment are out of scope for the
in-process kernel (`DEFERRED.md`).

---

## Coverage summary

| # | Vision threat class          | Strongest control label | Backing obligations |
|---|------------------------------|-------------------------|:-------------------:|
| 1 | Identity spoofing            | [RUNNABLE]              | 3 |
| 2 | Message tampering / replay   | [RUNNABLE]              | 4 |
| 3 | Capability escalation        | [RUNNABLE]              | 10 |
| 4 | Data exfiltration            | [RUNNABLE] + [REF] egress | 3 |
| 5 | Model manipulation           | [RUNNABLE], corpus measured | 3 |
| 6 | Supply-chain compromise      | [REFERENCE] (verify [RUNNABLE]) | 3 |
| 7 | Runtime breakout             | [REFERENCE]            | 0 (by design) |
| 8 | Consensus / availability     | [RUNNABLE]             | 9 |

**Reading the table honestly.** Classes 1–3 and 8 are enforced
in-process. Class 4 is enforced except for network egress. Class 5 is
enforced at the trust boundary but only *measured* against a finite
corpus. Classes 6–7 are the deployment-dependent frontier: the
substrate supplies verifiable, testable artifacts (attestations,
seccomp documents, confinement profiles) but the enforcing runtime is
the operator's. This is intentional and documented, not a gap being
papered over.

## What this document does not claim

- It is **not** a formal proof. It is a design-time threat map keyed to
  the machine-checked `proof_obligations.py` registry, which pins the
  *tests*, not the *invariants themselves* (see that module's
  "Stability contract" note).
- It does **not** cover performance, distributed-deployment behavior,
  compound-failure drills, or adversarial breadth beyond the 18-entry
  corpus. Those are enumerated in `DEFERRED.md`.
- [REFERENCE] controls (§§4 egress, 6, 7) are honest markers that
  in-process verification exists but runtime enforcement is
  deployment-layer. A control is never presented as [RUNNABLE] unless a
  proof obligation pins it.

## Maintenance

Per the vision (§7, "threat modeling at design kickoff and every major
change") and CLAUDE.md's workflow rule: when a new safety invariant
ships, add its `ProofObligation` **and** map it into the relevant
section here. When a threat class gains or loses a control, update its
section and the coverage table in the same commit. This document is
part of the inventory the next agent trusts.
