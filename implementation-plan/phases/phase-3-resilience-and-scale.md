# Phase 3 — Resilience and Scale Implementation Plan

## 1) Phase Intent
Phase 3 hardens the system against large-scale adversarial pressure, distributed-system failure modes, and compound security incidents. The objective is not merely survival, but deterministic and policy-compliant degradation/recovery.

### Mission
Operate a security-first MCP mesh that:
- resists identity and routing abuse at scale,
- preserves control-plane integrity under contention,
- executes deterministic safe-mode transitions,
- recovers trust state correctly after partitions or compromise events,
- produces release-grade evidence that resilience controls actually work.

---

## 2) Scope

### In Scope
1. Sybil/eclipsing/routing abuse defenses.
2. Capacity protection and anti-amplification constraints.
3. Compound-failure global state machine implementation.
4. Revocation/rotation drills and convergence SLOs.
5. Formal verification gates for protocol safety properties.
6. Tenant and shared-component isolation stress validation.

### Out of Scope
- Post-phase feature expansion unrelated to resilience/security controls.

---

## 3) Deliverables

### D3.1 Topology Abuse Defense Layer
- Identity issuance throttles and attestation cost controls.
- Diversity-aware neighbor selection.
- Routing update integrity checks.

### D3.2 Capacity & Fairness Guardrails
- Independent control-plane/data-plane budgets.
- Protected capacity floor for security-critical services.
- Contention-aware quota rebalancing.

### D3.3 Global Safe-Mode Engine
- S0/S1/S2/S3/S4 implementation.
- Trigger-to-state mapping and precedence handling.
- Signed state transition and recovery attestation artifacts.

### D3.4 Compound-Failure Drill Suite
- Automated chaos and adversarial scenarios.
- Deterministic transition conformance scoring.
- Release-gate integration.

### D3.5 Formal Verification and Model Checking Gate
- Replay-resistance and non-escalation proof obligations.
- Revocation safety in streaming/long-running contexts.

### D3.6 Recovery and Re-Admission Framework
- Quarantine and re-attestation workflow.
- Clean-room rebuild requirements.
- Signed checkpoint reconciliation for rejoin.

---

## 4) Safe-Mode and Failure-Orchestration Design

## 4.1 Authority Hierarchy Enforcement
Implement strict conflict resolution where:
1. cryptographic trust integrity outranks all,
2. then authorization correctness,
3. then data protection,
4. then availability goals.

No subsystem may downgrade global severity unilaterally.

## 4.2 Global State Semantics
- **S0 Normal**
- **S1 Guarded Degrade**
- **S2 Restricted**
- **S3 Quarantine**
- **S4 Recovery Lockdown**

Transitions must follow deterministic workflow:
- freeze privileged writes,
- push revalidation,
- increase forensic logging,
- recompute containment,
- publish machine-readable state.

## 4.3 Partition and Split-Brain Rules
- Missing cross-region quorum forces stricter state.
- Policy epoch advancement blocked without quorum witness.
- Rejoin requires signed checkpoint reconciliation.

---

## 5) Work Breakdown Structure (WBS)

## Track A — Topology and Admission Abuse Resistance

### A1. Sybil Deterrence
- Identity issuance quotas.
  **Landed (v0):** `SybilDeterrence` in
  `security-foundations/envelope/sybil_deterrence.py` enforces two
  independent sliding-window quotas: `max_per_issuer` and
  `max_per_tenant` (trust-domain aggregated via
  `audit_query.trust_domain_of`). Saturation surfaces distinct
  `SYBIL_ISSUER_QUOTA_EXCEEDED` and `SYBIL_TENANT_QUOTA_EXCEEDED`
  reason codes. `InMemorySybilLedger` is the v0 backend; operators
  wanting cluster-wide consistency swap in a distributed store
  behind the `SybilLedger` ABC.
- Attestation burden tuning.
  **Deferred:** the attestation cost dial (proof-of-work or
  hardware-attestation strength) belongs in the higher-level
  identity-issuance flow and is documented as out-of-scope for the
  in-process v0 primitive.
- Reputation hygiene and decay controls.
  **Landed (v0):** `IssuerReputation` tracks a per-`(iss, kid)`
  score with configurable `decay_per_interval` / `decay_interval`,
  bounded `[floor, ceiling]`. `reward()` and `penalize()` adjust the
  score; `current_score()` applies decay lazily. The deterrence gate
  refuses issuance when the decayed score falls below
  `min_reputation` (`SYBIL_REPUTATION_INSUFFICIENT`).

### A2. Eclipse Resistance
- Neighbor diversity rules.
  **Landed (v0):** `select_neighbors()` + `DiversityRule` in
  `security-foundations/envelope/eclipse_resistance.py`. Greedy
  freshness-first selector with two diversity invariants:
  `max_per_trust_domain` (per-domain cap that a Sybil cluster
  cannot overflow no matter how many candidates it submits) and
  `min_distinct_trust_domains` (minimum spread, reported as a
  `diversity_shortfall` flag when not met). Rejection diagnostics
  carry distinct reason codes (`diversity_per_domain_cap`,
  `diversity_target_reached`).
- Independent peer sampling paths.
  **Deferred:** multi-process / network-topology concern. Operators
  pull peers from separate gossip layers and feed the combined pool
  into `select_neighbors`. The selector takes the union as input.
- Routing anomaly detection.
  **Landed (v0, surge half):** `detect_trust_domain_surges()` returns
  any trust domain that posted ≥ `surge_threshold` candidates with
  `last_seen` inside a configurable window. A surge is a signal for
  operators to investigate, not a denial — pair with the per-domain
  cap for the deny path.

### A3. Discovery and Routing Integrity
- Signed updates and freshness checks.
  **Signed updates landed earlier** via Phase 1's
  `discovery_record.py` (`DiscoveryRecord` + `verify_record()`
  enforce signature, window, and TTL).
  **Freshness checks landed (v0):** `DiscoveryFreshnessTracker` in
  `security-foundations/envelope/discovery_propagation.py` pins the
  highest `issued_at` seen per `(workload_iss, workload_kid)` and
  refuses any record whose timestamp doesn't strictly increase.
  Catches operator-mistake rewinds AND an adversary recovering an
  old still-in-window signed record to overwrite a newer one. Surfaces
  `DISCOVERY_REWOUND`.
- Rate-limited propagation channels.
  **Landed (v0):** `DiscoveryPropagationLimiter` enforces a per-
  workload sliding-window republish cap (default 1 per 60 s).
  Surfaces `DISCOVERY_RATE_LIMITED`. The limiter runs AFTER the
  Phase 1 signature/window verification (running it pre-auth would
  let any spoofed `workload_iss` exhaust another workload's
  allowance — same lesson as the Phase 1 rate-limit hardening).
  `DiscoveryAdmissionGate` composes both checks into one
  `admit()` entry point.

**Acceptance Criteria**
- Simulated Sybil clusters cannot dominate peer view beyond tolerated threshold.

---

## Track B — Capacity Protection and Economic Abuse Controls

### B1. Resource Budget Partitioning
- Separate pools for control-plane and data-plane.
  **Landed (v0):** `BudgetController` + `BudgetPool` in
  `security-foundations/envelope/capacity_budgets.py`. Operators
  define one pool per workload class (e.g. `security-critical`,
  `control-plane`, `data-plane`); `acquire()` admits a request
  against a named pool.
- Security-critical services get non-preemptible floor.
  **Landed (v0):** every pool carries a `reserved` allocation. The
  controller enforces that any pool's burst cannot dip into another
  pool's `reserved` even when the other pool is idle — that's the
  "non-preemptible floor" invariant and the substrate-level proof
  that "data-plane flood cannot starve revocation/authZ/policy
  services" (the Track B acceptance criterion). Surfaces
  `BUDGET_FLOOR_GUARD`.

### B2. Anti-Amplification Controls
- Bounded expensive verification paths.
- Work-token or equivalent throttles for abuse-heavy identities.
  **Landed (v0):** every `acquire()` accepts a positive `cost`
  parameter. Operators charge expensive routes more so a flood of
  expensive calls hits the ceiling faster than a flood of cheap
  ones. The cost API is the work-token equivalent. Per-pool
  ceilings (`BUDGET_CEILING_EXCEEDED`) bound the worst-case spend
  per pool.

### B3. Fairness Controller
- Tenant reserve pools and burst ceilings.
  **Landed (v0):** `TenantBudget(pool, tenant, reserve, burst)`
  pins a per-`(pool, tenant)` allowance. A noisy tenant hits their
  own `burst` cap (`BUDGET_TENANT_BURST_EXCEEDED`) before draining
  the pool's burst headroom, so other tenants in the same pool are
  insulated.
- Automatic rebalance on cascading throttle detection.
  **Deferred:** the reactive controller belongs in a follow-up.
  v0 exposes `BudgetController.snapshot()` / `tenant_snapshot()`
  so a rebalancer can read live consumption and trigger
  reallocation.

**Acceptance Criteria**
- Data-plane flood cannot starve revocation/authZ/policy services.

---

## Track C — Compound-Failure Engine

### C1. Trigger Detection
- Clock trust failure.
- Ledger divergence.
- Policy rollback detection.
- Revocation uncertainty.
- Critical anomaly quarantine signal.
  **Landed (v0):** `TriggerKind` StrEnum in
  `security-foundations/envelope/safe_mode_engine.py` covers all
  five categories. `Trigger(kind, category, minimum_state,
  observed_at, detail)` is the in-process observation shape.
  `trigger_for(kind, …)` uses a built-in default profile derived
  from §4.1 (e.g. `LEDGER_DIVERGENCE` → S4_LOCKDOWN with
  `CRYPTO_TRUST` authority).

### C2. State Computation
- Determine min required state per trigger.
- Resolve to max severity.
- Apply authority hierarchy if conflicts arise.
  **Landed (v0):** `SafeModeEngine.observe()` admits triggers into
  a per-kind active map. The engine's current state is
  `max(t.minimum_state for t in active)`. The §4.1 authority
  hierarchy is enforced on the downgrade path: a
  `DowngradeApproval.authority` must be at least as high as every
  still-active trigger's `TriggerCategory`. `is_higher_authority()`
  and `is_more_severe_state()` are the ordering predicates.

### C3. Transition Runtime
- Deterministic transition handlers with idempotent steps.
- Recovery downgrade checks with signed approvals.
  **Landed (v0):** `observe()` and `clear()` are idempotent
  (re-observing a same-kind trigger with equal/lower severity is a
  no-op; clearing a non-active kind is a no-op). Every state change
  returns a `StateTransition(from_state, to_state, transition_at,
  cause, active_kinds, detail)` record so transitions are
  machine-readable. Manual `downgrade()` requires a
  `DowngradeApproval` whose authority dominates every active
  trigger AND a target state at-or-above the current trigger floor;
  `require_authorized_downgrade()` tags failures with
  `SAFE_MODE_DOWNGRADE_UNAUTHORIZED` / `_TRIGGERS_ACTIVE`. Signed
  artifacts are documented as a follow-up (the shapes are
  signing-ready).
  The Track C acceptance criterion — "Compound failures always
  result in predictable state and logs" — is pinned by
  `test_two_engines_walk_identical_history` and `test_expected_history`.

**Acceptance Criteria**
- Compound failures always result in predictable state and logs.

---

## Track D — Rotation, Revocation, and Recovery

### D1. Key Rotation Drills
- Overlap windows and deterministic cutovers.
  **Landed (v0):** `KeyRotationPlan` in
  `security-foundations/envelope/key_rotation.py` defines a rotation
  via three timestamps (`overlap_start`, `cutover_at`,
  `overlap_end`). `current_phase()` returns exactly one of
  `PRE_OVERLAP` / `OVERLAP` / `POST_CUTOVER` / `COMPLETE` for any
  `now`; the cutover moment is deterministic.
- Compatibility validation during transition.
  **Landed (v0):** `accepted_kids()` returns the frozenset of kids
  a verifier should honor for a given plan at a given time:
  `{old}` before overlap, `{old, new}` during overlap and the
  post-cutover sunset window, `{new}` after `overlap_end`.
  `RotationRegistry` aggregates multiple plans and rejects
  conflicts (`ROTATION_PLAN_CONFLICT`). `require_accepted_kid()`
  raises `ROTATION_KID_NOT_ACCEPTED` when a candidate kid is not
  in any active acceptance window.

### D2. Revocation Convergence
- Push + pull propagation.
- Emergency fast-path revocation.
- Convergence SLO telemetry.

### D3. Recovery and Re-Admission
- Quarantine policy.
- Clean-room rebuild proof.
- Re-attestation and scoped monitoring period post rejoin.

**Acceptance Criteria**
- Revoked entities cannot perform privileged writes post checkpoint.
- Re-admitted nodes satisfy clean-state evidence requirements.

---

## Track E — Formal Verification and Release Gates

### E1. Protocol State-Machine Model
- Include reorder/partition and delegation edges.
- Encode safety and liveness assumptions explicitly.

### E2. Proof Obligations
- No unauthorized privileged action reachable.
- No duplicate privileged mutation reachable.
- Delegation scope/TTL/audience monotonicity.
- Revoked capability cannot commit post-revocation checkpoint.

### E3. CI Blocking Integration
- Fail release on model/proof regression.
- Archive proof artifacts for audit reproducibility.

**Acceptance Criteria**
- All mandatory obligations proven or release blocked.

---

## 6) Compound-Failure Drill Program

## Required Scenarios
1. Clock skew + policy rollback attempt.
2. Ledger divergence + revocation race.
3. Anomaly quarantine + export attestation failure.
4. Partition during trust anchor rotation.

## Drill Output Schema
- Trigger timeline.
- State transition timeline.
- Invariant pass/fail list.
- Control coverage matrix.
- Remediation owner and ETA for each deviation.

## Drill Cadence
- Pre-release mandatory run.
- Monthly broad chaos campaign.
- Quarterly independent validation run.

---

## 7) Shared-Component Isolation Validation

### Components to Validate
- Replay cache
- Queue/scheduler
- Model serving
- Vector index
- Policy bundle distribution

### Required Guarantees
- Per-tenant namespace separation.
- Quota and priority fences.
- Cross-tenant context leakage = zero tolerance.
- Reject foreign-scope policy bundles always.

### Testing
- Noisy-neighbor saturation tests.
- Cross-tenant replay and retrieval abuse simulations.
- Embedding and nearest-neighbor bleed checks.

---

## 8) Observability and Evidence at Scale

### Telemetry Requirements
- State machine transition metrics.
- Revocation convergence timing.
- Quorum health and partition status.
- Security service protected-capacity utilization.

### Evidence Requirements
- Signed incident markers.
- Signed recovery attestation packets.
- Release evidence bundle with invariant trend history.

---

## 9) Risk Register (Phase 3)

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---:|---:|---|---|
| Sybil saturation | M | H | issuance quotas + diversity constraints | Network Security |
| Control-plane starvation | M | H | protected floors + budget partitioning | Reliability Lead |
| Non-deterministic safe-mode transitions | L | H | deterministic state engine + drills | Runtime Security |
| Revocation lag under partition | M | H | emergency fast-path + convergence SLOs | Identity Lead |
| Formal proof drift vs implementation | M | M | CI proof gate + model maintenance SOP | Formal Methods Lead |

---

## 10) Exit Gates
Phase 3 can close only when:
1. Compound-failure drills pass required scenario set.
2. Global safe-mode transitions are deterministic and policy-compliant.
3. Protected capacity guarantees hold under stress.
4. Revocation and rotation SLOs pass in game-day drills.
5. Formal verification obligations pass with reproducible artifacts.
6. Shared-component tenant isolation tests show zero critical leakage.

---

## 11) Artifacts to Produce at Phase Close
- Safe-mode state machine implementation spec + runbook.
- Compound-failure drill reports and trend analysis.
- Capacity protection and fairness policy package.
- Revocation/rotation game-day evidence.
- Formal verification artifact set and CI gate report.
- Final Go/No-Go recommendation memo for post-phase feature expansion.
