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
  **Landed (v0):** `DelegationReceipt` in
  `security-foundations/envelope/delegation_receipt.py` carries
  `chain_id` (UUIDv7), `hop_index`, `parent_jti`, `delegator_iss`/
  `delegator_kid`, `delegate_iss`, `scope`, `aud`, `iat`/`nbf`/`exp`,
  `jti`, and a base64url EdDSA signature over the JCS-canonicalized
  body with `typ: "wt-delegation/v0"`.
- Standardize clock and expiry semantics across hops.
  **Landed (v0):** NumericDate `iat`/`nbf`/`exp` per JWT; the
  validator enforces `iat <= nbf < exp` and the same skew tolerance
  used by the capability validator.

### A2. Delegation Validator
- Validate depth limits.
  **Landed (v0):** `DelegationVerificationConfig.max_chain_depth`
  defaults to 3; `hop_index >= max_chain_depth` raises
  `DelegationError(DELEGATION_DEPTH_EXCEEDED)`.
- Verify monotonic scope and TTL constraints.
  **Landed (v0):** Child scope MUST equal parent scope
  (`DELEGATION_SCOPE_ESCALATION`); child `[iat, exp]` MUST be contained
  within parent's window (`DELEGATION_TTL_ESCALATION`).
- Enforce audience continuity constraints.
  **Landed (v0):** Child aud MUST equal parent aud
  (`DELEGATION_AUDIENCE_DRIFT`); child `delegator_iss` MUST equal
  parent `sub` (`DELEGATION_PARENT_MISMATCH`).

### A3. Non-Escalation Proof Tests
- Property-based tests for random delegation graphs.
- Differential tests under mixed policy versions.

**Acceptance Criteria**
- No test case can produce broader privilege at child hop.
  **Landed (deterministic v0 tests):** explicit cases for scope
  divergence (both directions), audience drift, TTL extension, hop
  reordering, parent-jti mismatch, and depth overrun all raise
  `DelegationError` with the matching `DenyReason` family. A3's
  property/fuzz tests remain a follow-up.
- Invalid chain receipt always denies execution.
  **Landed:** the validator raises on every invariant breach; the
  consumer never sees a partial-success return value.

---

## Track B — Context Firewall and Retrieval Policy

### B1. Data Classification Pipeline
- Class labels (public/internal/confidential/restricted).
  **Landed (v0):** `DataClass` StrEnum in
  `security-foundations/envelope/data_classification.py` with the four
  required labels and a strict ordering for "more restrictive" comparisons.
- Metadata binding and immutable lineage tags.
  **Landed (v0):** `ClassifiedData` (frozen dataclass) carries a
  `data_digest`, a `DataClass` label, an immutable tuple of
  `LineageTag` entries, and an immutable tuple-of-pairs metadata bag.
  `classify()` / `derive()` / `combine()` are the only ways to construct
  multi-link lineages. `derive()` rejects class demotion; `combine()`
  takes the max class. Each lineage tag commits to its parent's
  `chain_hash` so tampering anywhere in the lineage is detectable by
  re-derivation.

### B2. Purpose-of-Use Policy Enforcement
- Retrieval denied unless class + purpose + identity align.
  **Landed (v0):** `AllowlistRetrievalPolicy` in
  `security-foundations/envelope/retrieval_policy.py` evaluates a
  closed tuple of `RetrievalRule(caller_iss, purpose_of_use, max_class)`
  in declaration order; the first matching `(caller_iss, purpose_of_use)`
  decides, and `data.data_class` must be at most as restrictive as the
  rule's `max_class`. Denials carry stable `DenyReason` codes
  (`RETRIEVAL_NO_RULE_MATCH`, `RETRIEVAL_CLASS_EXCEEDS_RULE`).
  `require_retrieval()` raises `RetrievalError` carrying the decision.
- Cross-tenant retrieval denied by default.
  **Landed (v0):** the policy carries a `CrossTenantRetrieval` dial
  defaulting to `DENY`. Origin tenant is derived from the trust-domain
  component of the first lineage tag's `actor_iss`; when caller and
  origin trust domains differ, retrieval is rejected with
  `RETRIEVAL_CROSS_TENANT` regardless of any matching rule. Operators
  must explicitly set `cross_tenant=ALLOW` to opt in.

### B3. Prompt Assembly Minimization
- Least-sensitive-first context composition.
  **Landed (v0):** `compose()` in
  `security-foundations/envelope/prompt_assembly.py` sorts surviving
  candidates by `DataClass` rank ascending (PUBLIC → RESTRICTED), with
  `source_label` breaking ties for deterministic output.
- Max context sensitivity budget per action class.
  **Landed (v0):** `ActionBudget(action, max_class, max_items)` caps both
  the most-restrictive class allowed in the assembled prompt and the
  item count. Candidates above the class ceiling are dropped with
  `reason_code="class_exceeds_budget"`; survivors past `max_items` are
  dropped with `reason_code="items_over_budget"`. Every `IncludedItem`
  carries `source_label`, `data_class`, and `trust_label` (the
  trust-domain of the first lineage tag's `actor_iss`), satisfying the
  "prompt assembly logs include source sensitivity and trust labels"
  acceptance criterion.

**Acceptance Criteria**
- Unauthorized retrieval attempts are denied with explicit policy reason.
- Prompt assembly logs include source sensitivity and trust labels.

---

## Track C — Output DLP and Quarantine

### C1. Output Scanning
- Deterministic secret patterns + ML classifiers.
  **Landed (v0, deterministic half):** `PatternRegistry` + `scan()` in
  `security-foundations/envelope/output_scanning.py`. Built-in patterns
  cover AWS access keys, generic PEM private-key blocks, Anthropic /
  OpenAI / GitHub / Stripe API keys, and RFC 7519 JWTs. Each pattern
  carries a `RiskLevel` (NONE / LOW / MEDIUM / HIGH / CRITICAL). The
  `ML classifiers` half is deferred; `ScanResult.matches` is a flat
  tuple so a future classifier can append matches without breaking
  consumers.
- Risk score assigned to every outbound artifact.
  **Landed (v0):** every `scan()` returns a `ScanResult` whose `.risk`
  property is the most-severe match's severity (or `RiskLevel.NONE`
  for clean output). `ScanResult.redact()` returns a copy of the text
  with each match replaced by `[REDACTED:<pattern_name>]`, with
  overlapping-match resolution favouring earlier start, then higher
  severity, then longer match.

### C2. Policy-Adaptive Egress
- Deny, allow, or quarantine based on risk and data class.
  **Landed (v0):** `MatrixEgressPolicy` in
  `security-foundations/envelope/egress_policy.py` evaluates a closed
  matrix of `EgressMatrixCell(risk, data_class, action)` where `action`
  is one of `ALLOW`, `QUARANTINE`, `DENY`. Cells not present in the
  matrix default to `EgressAction.DENY` (`EGRESS_NO_MATRIX_ENTRY`).
  Quarantine returns `reason_code="egress_quarantined"` so downstream
  systems can fan a single verdict out to allow / review-queue / drop
  without re-encoding the decision. `require_egress()` raises
  `EgressError` on any non-ALLOW verdict.
- Mandatory NO_EXPORT for restricted-class outputs where required.
  **Landed (v0):** `MatrixEgressPolicy.restricted_no_export` (default
  `True`) overrides every matrix entry to deny when
  `data_class==DataClass.RESTRICTED`, carrying
  `EGRESS_RESTRICTED_NO_EXPORT`. Operators that want to take
  responsibility for restricted artifacts inside the matrix can set the
  flag to `False`.

### C3. Reviewer Workflow
- Quarantined outputs route to human review queue.
  **Landed (v0):** `QuarantineRecord` in
  `security-foundations/envelope/reviewer_workflow.py` is the queue
  entry shape — a frozen dataclass binding `record_id` (UUIDv7),
  `artifact_digest`, `risk`, `data_class`, `requested_at`,
  `requester_iss`, and `purpose_of_use`. Storage and routing belong to
  the operator; the in-process primitive guarantees the binding stays
  immutable. A JCS-stable `record_digest` is exposed for cnf-style
  reviewer-decision binding.
- Signed reviewer decision record with expiration and scope.
  **Landed (v0):** `ReviewDecision` is an EdDSA-signed JCS body with
  `typ="wt-review/v0"` cross-protocol binding, carrying
  `record_digest`, `verdict` (RELEASE / REJECT), `reason`, reviewer
  SPIFFE id + kid, `[iat, nbf, exp]` window, and a UUIDv7 `jti`.
  `verify_release_authorization()` is the release-path check that
  validates shape, record binding, time window (default max TTL 24h),
  signature (via `IssuerTrustStore`), and that the verdict is RELEASE.
  A REJECT raises `REVIEW_REJECTED`. `verify_decision()` is the
  audit/archive entry point that does the same shape/signature/window
  checks without the RELEASE requirement.

**Acceptance Criteria**
- Synthetic secret/PII corpora produce expected block/quarantine rates.
- False-negative threshold remains under target budget.

---

## Track D — Prompt/Tool Injection Defense

### D1. Instruction Isolation
- Treat peer/tool outputs as untrusted data channel.
  **Landed (v0):** `ContentChannel` StrEnum (`SYSTEM` / `USER` / `TOOL`
  / `RETRIEVED`) + `Trust` StrEnum (`TRUSTED` / `UNTRUSTED`) in
  `security-foundations/envelope/instruction_isolation.py`.
  `ContentSegment` enforces channel/trust pairings at construction:
  `SYSTEM` must be `TRUSTED`, `USER` and `RETRIEVED` must be
  `UNTRUSTED`, and `TOOL` may only be `TRUSTED` when a non-empty
  `signature_ref` is supplied — that's the "tool outputs treated as
  untrusted unless signed" rule, lifted into the type system.
- Ensure model cannot treat arbitrary external data as control instructions.
  **Landed (v0):** `assemble_isolated_prompt()` renders non-SYSTEM
  segments inside `<<wt-iso:NONCE:CHANNEL ...>>` ... `<<wt-iso:NONCE:end>>`
  fences keyed off a fresh 96-bit random nonce. Segment text and
  source labels are HTML-escaped so a payload literally cannot
  produce a `<<` in the wrapped region. The system prompt is
  expected to instruct the model to treat anything inside a
  `<<wt-iso:…>>` fence as inert data. An `audit_log` of
  `(channel, source_label, trust, signature_ref)` per segment is
  returned alongside the assembled text.

### D2. Tool Policy Gate
- Runtime tool-call validation independent of model deliberation.
  **Landed (v0):** `ToolPolicy` (closed allowlist of `ToolRule`
  records) + `evaluate_tool_call()` in
  `security-foundations/envelope/tool_policy_gate.py`. The gate's
  inputs are operator-configured (policy) and out-of-band (optional
  step-up attestation); the model has zero influence on the decision.
  Unknown tools → `TOOL_UNKNOWN`. Per-tool caller allowlists →
  `TOOL_CALLER_NOT_ALLOWED`. `require_tool_call()` raises
  `ToolPolicyDenied` on any non-ALLOW verdict.
- High-risk tools require step-up authorization path.
  **Landed (v0):** `ToolRule.risk_tier` (LOW / MEDIUM / HIGH /
  CRITICAL) drives `effective_step_up_required` (defaulting to True
  for HIGH and CRITICAL); operators can override per-rule.
  `StepUpAttestation` is an EdDSA-signed JCS body with
  `typ="wt-stepup/v0"` cross-protocol binding, carrying
  `tool_name`, `caller_iss`, `arguments_digest` (so a stale
  attestation cannot be reused for a different call), `iat`/`nbf`/`exp`,
  and a UUIDv7 `jti`. Verification (call binding, time window,
  signature via `IssuerTrustStore`) is in-line; failures surface
  `TOOL_STEP_UP_*` reason codes.

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
