# Phase 2 — Controlled Autonomy Implementation Plan

## 1) Phase Intent
Phase 2 introduces autonomy features while preserving strict non-escalation and data-protection guarantees. The primary challenge is preventing capabilities, model outputs, and contextual retrieval from becoming covert privilege-escalation or exfiltration channels.

### Mission
Enable useful peer-to-peer delegated workflows with:
- constrained delegation chains,
- context-level data governance,
- robust output filtering and quarantine,
- AI-specific prompt/tool injection resistance,
- strict evidence for every privileged autonomous action.

---

## 2) Scope

### In Scope
1. Delegation chain semantics and validation.
2. Context firewall for retrieval and prompt assembly.
3. Output DLP and trust-label propagation.
4. AI-specific injection defenses.
5. Long-running execution controls (revocation-aware).
6. Enhanced auditability and policy explainability.

### Out of Scope
- Full mesh-wide adaptive abuse economics.
- Final global safe-mode orchestration at scale.

---

## 3) Deliverables

### D2.1 Delegation Chain Framework
- Chain ID, signed receipts, and hop metadata.
- Enforced depth limits.
- Monotonic non-escalation checks (scope, TTL, audience).

### D2.2 Context Firewall Service
- Data classification at ingress.
- Policy-driven retrieval checks against purpose-of-use.
- Redaction and minimization prior to model exposure.

### D2.3 Output Governance Pipeline
- Trust labels on all retrieved/tool/peer outputs.
- DLP checks before egress.
- Quarantine and reviewer workflow for uncertain outputs.

### D2.4 Prompt and Tool Safety Guardrails
- Instruction/data channel separation.
- Tool allowlists external to model reasoning.
- Injection pattern detection with adversarial test corpus.

### D2.5 Revocation-Aware Workflow Control
- Capability revocation behavior for async/streaming jobs.
- Execution checkpoint revalidation before commits.

---

## 4) Autonomy Safety Model

### Core Invariants
1. Delegation never increases authority.
2. Any high-risk data movement requires policy and classification alignment.
3. Untrusted content never directly controls tool invocation semantics.
4. Revoked authority cannot commit privileged writes.
5. Every autonomous step is reconstructable from evidence logs.

### Autonomy Levels
- **A0**: No delegation, direct call only.
- **A1**: Single-hop constrained delegation.
- **A2**: Multi-hop delegation with strict depth and chain receipts.

Phase 2 target: stable A1, controlled pilot for A2.

---

## 5) Work Breakdown Structure (WBS)

## Track A — Delegation Integrity

### A1. Delegation Data Model
- Define chain IDs, hop index, parent reference, and signed receipt schema.
- Standardize clock and expiry semantics across hops.

### A2. Delegation Validator
- Validate depth limits.
- Verify monotonic scope and TTL constraints.
- Enforce audience continuity constraints.

### A3. Non-Escalation Proof Tests
- Property-based tests for random delegation graphs.
- Differential tests under mixed policy versions.

**Acceptance Criteria**
- No test case can produce broader privilege at child hop.
- Invalid chain receipt always denies execution.

---

## Track B — Context Firewall and Retrieval Policy

### B1. Data Classification Pipeline
- Class labels (public/internal/confidential/restricted).
- Metadata binding and immutable lineage tags.

### B2. Purpose-of-Use Policy Enforcement
- Retrieval denied unless class + purpose + identity align.
- Cross-tenant retrieval denied by default.

### B3. Prompt Assembly Minimization
- Least-sensitive-first context composition.
- Max context sensitivity budget per action class.

**Acceptance Criteria**
- Unauthorized retrieval attempts are denied with explicit policy reason.
- Prompt assembly logs include source sensitivity and trust labels.

---

## Track C — Output DLP and Quarantine

### C1. Output Scanning
- Deterministic secret patterns + ML classifiers.
- Risk score assigned to every outbound artifact.

### C2. Policy-Adaptive Egress
- Deny, allow, or quarantine based on risk and data class.
- Mandatory NO_EXPORT for restricted-class outputs where required.

### C3. Reviewer Workflow
- Quarantined outputs route to human review queue.
- Signed reviewer decision record with expiration and scope.

**Acceptance Criteria**
- Synthetic secret/PII corpora produce expected block/quarantine rates.
- False-negative threshold remains under target budget.

---

## Track D — Prompt/Tool Injection Defense

### D1. Instruction Isolation
- Treat peer/tool outputs as untrusted data channel.
- Ensure model cannot treat arbitrary external data as control instructions.

### D2. Tool Policy Gate
- Runtime tool-call validation independent of model deliberation.
- High-risk tools require step-up authorization path.

### D3. Adversarial Corpus CI Gate
- Curated injection and smuggling corpus run per release.
- Block release on regressions below safety threshold.

**Acceptance Criteria**
- Known injection patterns cannot force unauthorized tool actions.
- Regression suite is stable and tracked over time.

---

## Track E — Long-Running and Async Revocation Semantics

### E1. Checkpointed Execution
- Revalidate capability and policy at commit points.
- Abort or downgrade behavior on revocation or policy epoch mismatch.

### E2. Streaming and Resume Controls
- Session tokens with bounded lifetime and strict resume conditions.
- Replay-safe resume identifiers.

**Acceptance Criteria**
- Revoked capability cannot commit writes post-revocation checkpoint.

---

## 6) Testing Plan

### Security Functional
- Single-hop and multi-hop delegation matrix.
- Retrieval deny/allow matrix by class and purpose-of-use.
- Egress deny/allow/quarantine matrix by risk score.

### Adversarial
- Prompt injection through peer content.
- Tool output poisoning.
- Delegation laundering attempts.

### Resilience
- Policy epoch change during long-running task.
- Revocation event during streaming output.

### Model Safety Quality Metrics
- Injection block-rate.
- False-positive and false-negative rates for DLP.
- Abstain/refuse correctness under uncertainty triggers.

---

## 7) Operational Playbooks

### Playbook P2-A: Delegation Abuse Spike
- Detect repeated chain validation failures.
- Isolate abusive peer scope.
- Tighten depth limit and issuance rate temporarily.

### Playbook P2-B: DLP Incident
- Force quarantine mode for affected operation class.
- Trigger forensic review of recent outputs.
- Validate redaction provenance metadata.

### Playbook P2-C: Revocation Race Event
- Enter restricted execution mode for affected workflows.
- Flush token caches and force checkpoint revalidation.

---

## 8) Risk Register (Phase 2)

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---:|---:|---|---|
| Delegation laundering | M | H | non-escalation validator + depth limits | AuthZ Lead |
| Prompt injection bypass | M | H | instruction isolation + adversarial CI | AI Safety Lead |
| DLP false negatives | M | H | classifier+rules ensemble + quarantine | Data Gov Lead |
| Revocation race in async tasks | M | H | checkpoint revalidation + resume constraints | Runtime Lead |
| Reviewer bottleneck | M | M | queue SLAs + triage policy tiers | SecOps Lead |

---

## 9) Exit Gates
Phase 2 closes only when:
1. Delegation non-escalation invariants pass all fuzz/property tests.
2. Context firewall blocks unauthorized retrieval reliably.
3. DLP + quarantine controls meet agreed efficacy thresholds.
4. Injection corpus gate passes with no critical regressions.
5. Long-running execution revocation semantics validated in failure drills.

---

## 10) Artifacts to Produce at Phase Close
- Delegation chain protocol and proof test report.
- Context firewall policy library.
- Output governance and quarantine runbook.
- Injection test corpus report and trend dashboard.
- Revocation semantics validation report for async/streaming operations.
