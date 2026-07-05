# WalkieTalkie Compliance Mapping (v0)

*Every machine-checked proof obligation, mapped to the SOC 2, ISO/IEC
27001:2022, and GDPR control it supplies technical evidence for.*

This document closes **Phase 5 Track E, E2** (evidence artifact D5.7,
vision §9 deliverable: compliance mapping). It is the bridge between the
substrate's `security-foundations/envelope/proof_obligations.py`
registry and the control frameworks an operator is audited against.

## What this is — and is not

This is a **technical-evidence map**, not a certification. A proof
obligation is a machine-checked invariant of the in-process kernel;
mapping it to (say) SOC 2 CC6.1 means *"this invariant is evidence the
substrate contributes toward that control's intent,"* not *"the
substrate is SOC 2 compliant."* Compliance is an organizational
property spanning people, process, and the full deployment — most of
which lives outside this kernel (see the [REFERENCE] and coverage-gap
notes below, and `DEFERRED.md`).

Read it as: *when your auditor asks "how do you enforce least-privilege
authorization?", these obligations are the substrate's answer, and each
one resolves to a real passing test.*

Frameworks referenced:
- **SOC 2** — AICPA Trust Services Criteria (2017), the `CC*`/`A*`/`C*`
  series.
- **ISO 27001** — ISO/IEC 27001:2022 Annex A controls (`A.5`–`A.8`).
- **GDPR** — Regulation (EU) 2016/679, security-relevant Articles.

## Framework crosswalk by control theme

### Identity, authentication, admission

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `svid_binding_verified` | CC6.1 | A.5.16, A.8.5 | Art. 32(1)(b) |
| `unadmitted_peer_denied` | CC6.1, CC6.2 | A.5.15, A.5.18 | Art. 32(1)(b) |
| `mesh_authenticate_then_authorize` | CC6.1, CC6.2 | A.5.15, A.8.2 | Art. 25, Art. 32 |
| `readmission_kid_must_be_fresh` | CC6.1 | A.5.17, A.8.24 | Art. 32(1)(b) |
| `readmission_attester_pool_separation` | CC6.1, CC6.3 | A.5.16, A.8.31 | Art. 32 |
| `rotation_phases_deterministic` | CC6.1, CC8.1 | A.5.17, A.8.24 | Art. 32(1)(b) |

Short-lived SVIDs, deny-by-default admission, authenticate-before-
authorize ordering, and aggressive key rotation are the substrate's
answer to *"only known, current identities act."*

### Message integrity, authenticity, anti-replay

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `envelope_signature_required` | CC6.7, PI1.1 | A.8.24, A.5.14 | Art. 5(1)(f), Art. 32(1)(b) |
| `session_resume_sequence_strict` | CC6.7 | A.8.24 | Art. 32(1)(b) |
| `discovery_freshness_monotonic` | CC6.7, CC7.1 | A.8.24 | Art. 32(1)(b) |
| `mcp_adapter_emits_schema_complete_envelope` | PI1.1 | A.8.24 | Art. 5(1)(f) |
| `mesh_round_trip_verifies` | CC6.7, PI1.1 | A.8.24 | Art. 5(1)(f), Art. 32 |
| `discovery_test_vectors_coherent` | PI1.1 | A.8.28 | — |

Detached envelope signatures over canonical bodies + nonce/timestamp
anti-replay are the integrity-in-transit control independent of
transport encryption.

### Authorization, least privilege, capability control

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `capability_cnf_binding_prevents_reuse` | CC6.1, CC6.3 | A.5.15, A.8.2 | Art. 32(1)(b) |
| `capability_signer_pool_separation` | CC6.1 | A.8.31 | Art. 32 |
| `delegation_scope_monotonicity` | CC6.3 | A.5.15, A.8.2 | Art. 5(1)(c), Art. 25 |
| `delegation_audience_monotonicity` | CC6.3 | A.5.15 | Art. 5(1)(b) |
| `delegation_window_containment` | CC6.3 | A.5.18 | Art. 5(1)(e) |
| `delegation_depth_bounded` | CC6.3 | A.5.15 | Art. 32 |
| `tool_step_up_call_binding` | CC6.1, CC6.3 | A.8.2, A.8.5 | Art. 32 |
| `revoked_capability_blocked_at_checkpoint` | CC6.2, CC6.3 | A.5.18 | Art. 32 |
| `host_revocation_lifecycle_enforced` | CC6.2, CC6.3 | A.5.18 | Art. 17*, Art. 32 |
| `policy_decision_in_trace` | CC6.1, CC7.2 | A.5.15, A.8.15 | Art. 30, Art. 32 |

Least-privilege tokens, monotone (never-widening) delegation, step-up
gating, and revoke-then-reject are the core authorization evidence.
(*Art. 17 "right to erasure" is supported only insofar as revocation
promptly stops a capability from acting; data erasure itself is
deployment-layer.)

### Data governance, confidentiality, egress

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `retrieval_cross_tenant_default_deny` | CC6.1, C1.1 | A.5.15, A.8.3 | Art. 5(1)(f), Art. 25 |
| `data_classification_non_demotion` | C1.1, PI1.1 | A.5.12, A.5.13 | Art. 5(1)(f), Art. 25 |
| `egress_restricted_no_export` | CC6.6, C1.2 | A.8.12, A.8.3 | Art. 5(1)(f), Art. 32 |

Cross-tenant default-deny, non-demotable classification, and egress
posture are the confidentiality/data-loss-prevention evidence. Network
enforcement of egress is [REFERENCE] (deployment firewall).

### Content trust, injection resistance, human review

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `tool_output_untrusted_unless_signed` | CC6.8, PI1.1 | A.8.28, A.5.14 | Art. 5(1)(f) |
| `reviewer_record_binding` | CC6.8, CC7.3 | A.5.15, A.8.15 | Art. 32 |
| `adversarial_corpus_full_block_rate` | CC6.8, CC7.2 | A.5.7, A.8.28 | Art. 32 |

Treating tool output as untrusted-unless-signed and the reviewer gate
answer *"how do you resist poisoned/injected content."* The adversarial
corpus is a **measured** control over 18 known patterns, not a
completeness proof — see the gap note.

### Availability, capacity, anti-abuse

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `sybil_cluster_cannot_dominate_peer_view` | A1.1, CC6.6 | A.8.6, A.5.7 | Art. 32(1)(b) |
| `non_preemptible_floor_invariant` | A1.1, A1.2 | A.8.6 | Art. 32(1)(b) |
| `rebalancer_preserves_non_preemptible_floor` | A1.1, A1.2 | A.8.6 | Art. 32(1)(b) |
| `rebalancer_preserves_oversubscription_cap` | A1.1, A1.2 | A.8.6 | Art. 32(1)(b) |
| `host_rate_limit_enforced_post_auth` | A1.1, CC6.6 | A.8.6, A.8.20 | Art. 32(1)(b) |

Eclipse/Sybil-resistant neighbor selection, scheduler floors, and
post-auth rate limiting are the availability-under-attack evidence.

### Controlled degradation, change integrity

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `safe_mode_authority_hierarchy_dominance` | CC7.4, A1.2 | A.5.29, A.8.16 | Art. 32(1)(c) |
| `safe_mode_determinism` | CC7.4 | A.5.29 | Art. 32(1)(c) |
| `signed_safe_mode_transition_integrity` | CC7.4, CC8.1 | A.5.29, A.8.24 | Art. 32(1)(c) |
| `signed_downgrade_signature_runs_before_engine` | CC7.4, CC8.1 | A.8.24 | Art. 32(1)(c) |

Signed, deterministic, authority-dominant safe-mode transitions are the
resilience / "restore availability after an incident" evidence (GDPR
Art. 32(1)(c)).

### Supply-chain / build provenance ([REFERENCE])

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `image_signature_binds_digest_to_signer` | CC6.8, CC8.1 | A.8.28, A.5.23 | Art. 32(1)(b) |

Image-signature attestation is the build-provenance evidence. In-process
*verification* is [RUNNABLE]; the admission gate that refuses to run an
unattested image is [REFERENCE] (deployment).

### Forensics, auditability, engineering assurance

| Proof obligation | SOC 2 | ISO 27001:2022 | GDPR |
|---|---|---|---|
| `mcp_smoke_round_trip_verifies` | CC4.1, PI1.1 | A.8.16, A.8.28 | Art. 32(1)(d) |
| `example_host_under_500_lines` | CC8.1 | A.8.28 | — |

The hash-chained audit log underlying `policy_decision_in_trace`,
`reviewer_record_binding`, and the round-trip obligations is the
**tamper-evident forensic record** — the substrate's answer to SOC 2
CC7.2/CC7.3 monitoring, ISO A.8.15 logging, and GDPR Art. 30 (records)
/ Art. 33 (breach evidence).

## Coverage gaps an auditor must know

The map above is honest only if its edges are labelled:

1. **Organizational controls are out of scope.** SOC 2 CC1 (control
   environment), CC2 (communication), CC3 (risk assessment), CC9
   (vendor management), and ISO A.5.1–A.5.6 / A.6 (policies, roles, HR
   security) are process controls the *operator* owns. The substrate
   supplies none of them.
2. **[REFERENCE] controls need deployment enforcement.** Network egress
   (CC6.6/A.8.12), image admission (CC6.8), and runtime sandboxing
   (A.8.31) are *verified/declared* in-process but *enforced* by a
   firewall, admission webhook, and container runtime respectively. The
   substrate is the authoritative source; the enforcing infrastructure
   is Phase 6 / deployment.
3. **Encryption in transit is deployment-layer.** Envelope signatures
   give integrity+authenticity in-process; TLS 1.3 confidentiality on
   the wire (CC6.7 encryption, A.8.24 cryptography-in-transit) is the
   operator's transport.
4. **The adversarial control is measured, not complete.**
   `adversarial_corpus_full_block_rate` proves a 100% block rate over 18
   known patterns; it is not evidence of coverage against novel
   injections.
5. **Availability figures are algorithmic, not load-tested.** The
   scheduler/rate-limit obligations prove the *logic* preserves floors
   and caps; they are not performance or DDoS-absorption benchmarks.

Everything in this list is enumerated with rationale in `DEFERRED.md`.

## Maintenance

Per CLAUDE.md's workflow rule: when a new proof obligation ships, add a
row to the relevant theme table here **and** to `docs/threat-model.md`,
in the same commit that adds the obligation. When an obligation is
retired, remove its row. This document is only as trustworthy as its
sync with `proof_obligations.py`; the row count here should always equal
the obligation count there.
