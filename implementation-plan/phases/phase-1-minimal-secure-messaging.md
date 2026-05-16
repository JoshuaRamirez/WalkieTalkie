# Phase 1 — Minimal Secure Messaging Implementation Plan

## 1) Phase Intent
Phase 1 delivers a production-usable, tightly scoped messaging lane between admitted peers with strict security semantics and high-fidelity auditability.

### Mission
Enable authenticated peer discovery and request/response execution with anti-replay, capability-limited authorization, and verifiable tracing, while keeping blast radius intentionally narrow.

---

## 2) Scope

### In Scope
1. Authenticated peer discovery with bootstrap trust validation.
2. Request/response lifecycle using signed envelopes.
3. Replay/tamper protection in normal and degraded network conditions.
4. Narrow capability model for controlled tool/action execution.
5. Core rate limits and quotas by identity + operation class.
6. Deterministic error semantics for security failures.

### Out of Scope
- Rich delegation chain semantics.
- Full context firewall and advanced DLP.
- Adaptive abuse intelligence and global safe-mode orchestration.

---

## 3) Deliverables

### D1.1 Discovery Service (Authenticated)
- Discovery records signed and freshness-validated.
- Bootstrap trust bundle validation at first-join.
- Peer metadata attestation checks.

### D1.2 Secure Messaging Gateway
- Request ingress middleware with full validation order.
- Response signing pipeline.
- Security rejection taxonomy (e.g., invalid signature, stale packet, authz deny).

### D1.3 Capability Service v1
- Capability issuance API (short TTL, narrow scope, audience bound).
  **Landed as in-process library (v0):** `CapabilityIssuer` in
  `security-foundations/envelope/capability_issuer.py` mints `wt-cap+jwt`
  tokens that round-trip through the validator. The HTTP/RPC issuance API
  surface and per-request authorization for *who can ask for which scope*
  remain outstanding.
- Capability validator middleware. **Landed (v0):** RFC 7519 JWT (EdDSA) with
  `cnf.envelope_digest` binding, separate `IssuerTrustStore`, default 5-minute
  TTL. See `security-foundations/envelope/capability_token.py`.
- Capability revocation API + cache invalidation channel.
  **Local revocation list landed (v0):** `RevocationList` interface with
  `InMemoryRevocationList` and `FileBackedRevocationList` in
  `security-foundations/envelope/revocation_list.py`. The validator rejects
  revoked tokens with a distinct `capability token: revoked` reason. The
  *cache invalidation channel* (cross-process / cross-node propagation) is
  deferred until a transport choice exists.

### D1.4 Audit and Trace Enhancements
- Complete request/response correlation. **Not yet landed.**
- Explicit checkpoints for discovery, verification, policy, execution.
  **Verification checkpoint landed (v0):** every `verify_envelope` call
  emits exactly one hash-chained `AuditEvent` with outcome (allow/deny),
  reason, message_id, sender, recipient, envelope_kid, and capability
  issuer (iss, kid). See `security-foundations/envelope/audit.py`. Discovery,
  policy, and execution checkpoints remain outstanding.

### D1.5 Operational Guardrails
- Identity-aware rate limits.
- Basic anomaly alerts for token usage spikes and repeated reject patterns.

---

## 4) End-to-End Flow (Normative Behavior)

1. Peer attempts discovery.
2. Discovery verifies bootstrap trust and identity metadata.
3. Request arrives with signed envelope.
4. Schema + canonicalization verified.
5. Timestamp/nonce/sequence replay checks.
6. Signature/digest verification.
7. Capability validation (scope/audience/TTL).
8. Policy decision.
9. Execution (or deny).
10. Signed response returned with complete trace linkage.

**Mandatory Property:** any failure from steps 3–8 results in no execution.

---

## 5) Work Breakdown Structure (WBS)

## Track A — Discovery-Plane Security

### A1. Bootstrap Artifact Validation
- Validate anchor set, environment identity, epoch metadata.
  **Landed (v0):** `BootstrapBundle` in
  `security-foundations/envelope/bootstrap_bundle.py` carries
  `version`, `trust_domain`, `epoch`, and a tuple of
  `BootstrapAnchor` ``(iss, kid, pem_b64)``. `verify_bundle()`
  validates shape (positive epoch/version, SPIFFE ID and KID format,
  no duplicate anchors, every PEM parses as Ed25519) and signature.
- Enforce no-join on mismatch.
  **Landed (v0):** `verify_bundle()` accepts an optional
  `expected_trust_domain` pin; a mismatch raises
  `BootstrapBundleError("trust_domain mismatch: ...")` and the bundle
  is not materialized. Unsigned bundles, signatures by the wrong root
  key, and corrupt PEMs are all fatal.
- Add out-of-band re-seeding path for suspected compromise.
  **Landed (v0):** the root verification key is passed via the
  `expected_root_pem` parameter — explicitly out-of-band by
  construction. Re-seeding is a new root PEM through that channel +
  a new bundle epoch.

### A2. Discovery Record Integrity
- Signed discovery records with expiry.
  **Landed (v0):** `DiscoveryRecord` in
  `security-foundations/envelope/discovery_record.py` carries
  `workload_iss`, `workload_kid`, `endpoints[]`, `issuer_iss`,
  `issuer_kid`, `issued_at`, `expires_at`, and an EdDSA `signature`
  over a JCS-canonicalized body (with `typ: "wt-discovery-record/v0"`
  cross-protocol binding).
- Anti-poisoning checks for stale/forged records.
  **Landed (v0):** `verify_record()` enforces a time window
  (`issued_at ≤ now ≤ expires_at`, both with clock-skew tolerance),
  a max-TTL cap (default 1 hour), and signature verification against
  an `IssuerTrustStore` (typically the one materialized from the
  bootstrap bundle). Forged records fail at the signature step;
  stale records fail at the time-window step; both raise
  `DiscoveryRecordError`.

### A3. Admission Coupling
- Discovery output only feeds admitted peers.
- Discovery and admission policy versions must match compatibility matrix.

**Acceptance Criteria**
- Forged discovery entries always rejected.
- Stale discovery records never admitted.

---

## Track B — Messaging Gateway Hardening

### B1. Validation Middleware Composition
- Implement deterministic middleware chain in one place.
- Ensure canonicalization failure short-circuits processing.

### B2. Replay Controls in Distributed Conditions
- Region-local nonce caches.
- Signed sequence checkpoints.
- Duplicate mutation key rejection for state-changing operations.

### B3. Deterministic Error Contracts
- Security-deny responses are machine-readable and auditable.
  **Landed (v0):** `security-foundations/envelope/deny_reason.py` defines the
  `DenyReason` enum; every `EnvelopeVerificationError` raised by the
  verification path carries a stable `reason_code` (also embedded in
  `AuditEvent.reason_code`). Identifiers are immutable once shipped — see
  the stability contract in the module docstring.
- No ambiguous errors that could cause insecure fallback. **Landed (v0):**
  the verifier exclusively raises `EnvelopeVerificationError`; no validation
  path returns a partial-success result. Callers that want a structured deny
  use `Verifier.try_verify` which returns `VerificationResult(ok, reason, claims)`.

**Acceptance Criteria**
- Replay under reorder/partition simulation is denied.
  **Landed:** `test_sqlite_replay_cache_detects_replay_across_instances` covers
  the cross-process case; `test_replay_fails` covers the in-process case; both
  carry `reason_code = replay_detected`.
- No validation path permits bypass of signature verification.
  **Landed:** signature verification is unconditional and unguarded;
  capability validation, replay reservation, and audit emission all occur
  *after* the envelope signature check. `test_invalid_signature_does_not_reserve_nonce`
  pins the ordering invariant.

---

## Track C — Capability and Policy Lane

### C1. Capability Issuance Rules
- Enforce least privilege at issuance.
  **Landed (v0):** `CapabilityIssuer` consults a pluggable
  `IssuancePolicy` before minting. The default `AllowAllPolicy` preserves
  pre-policy behavior for callers that haven't opted in;
  `AllowlistPolicy` (in `security-foundations/envelope/issuance_policy.py`)
  rejects any (sub, aud, scope) tuple not in its frozen allowlist.
- Explicit purpose-of-use required. **Landed (v0):** `scope` is the third
  tuple element of `AllowlistPolicy.allowed_grants` and must match exactly.
  The token's `scope` is also bound to `envelope.purpose_of_use` at
  validation time (Track C C2).
- Audience pinning and minimum viable TTL. **Landed (v0):** `aud` is the
  second tuple element of `AllowlistPolicy.allowed_grants`.
  `AllowlistPolicy.max_ttl` (default 5 minutes) caps the maximum TTL the
  policy will allow per call; callers may always request a smaller TTL.

### C2. Capability Validation Rules
- Reject expired, out-of-scope, wrong-audience, or revoked tokens.
  **All four arms landed (v0):** `verify_capability_token` rejects each with
  a distinct reason string (`token expired`, `scope does not match envelope
  purpose_of_use`, `aud does not match envelope recipient`, `revoked`).
  Revocation requires a `RevocationList` to be passed; absent that the other
  three arms still apply.
- Deny on missing delegation metadata (if delegation present).
  **Not yet applicable;** delegation is a Phase 2 concern (D2.1).

### C3. Policy Bundle Hygiene
- Signed policy bundles.
  **Landed (v0):** `PolicyBundle` in
  `security-foundations/envelope/policy_bundle.py` is a JCS-canonicalized,
  EdDSA-signed artifact carrying a `version`, `issuer_iss`, `issuer_kid`,
  `allowlist_grants`, and `max_ttl_seconds`. `verify_bundle()` checks the
  signature against an `IssuerTrustStore` (operator-supplied; SHOULD be
  distinct from the capability-issuer trust store), and returns a realized
  `AllowlistPolicy`.
- Anti-rollback version checks.
  **Landed (v0):** `RollbackGuard` ABC with `InMemoryRollbackGuard` and
  `FileBackedRollbackGuard` implementations. Each `accept(bundle)` enforces
  `bundle.version > last_accepted_for_issuer`; per-issuer isolation so two
  policy authorities can have overlapping integer sequences.
- Canary + auto-rollback for policy releases. **Not yet landed;** separate
  slice. Requires a release-traffic split mechanism.

**Acceptance Criteria**
- Policy error path is fail-closed.
  **Landed:** policy denials raise `IssuancePolicyError` (subclass of
  `ValueError`) and emit a `capability.issue` deny audit event when an
  `audit_sink` is attached. `CapabilityIssuer.issue` does not mint when
  the policy denies; the test
  `test_allowlist_policy_denies_unlisted_grant` pins the invariant.
- Issuance service cannot mint broader scope than policy permits.
  **Landed:** `AllowlistPolicy` requires (sub, aud, scope) tuple
  membership; tests cover wrong-sub, wrong-aud, wrong-scope, and
  ttl-above-cap denial paths.

---

## Track D — Auditing and Operational Visibility

### D1. Trace Checkpoint Expansion
- Add discovery and capability checkpoints.
  **Capability checkpoint landed (v0):** `verify_envelope` now emits a
  separate `capability.verify` `AuditEvent` alongside the existing
  `envelope.verify`. Emission topology is documented in
  [audit-event-schema.md](../../security-foundations/contracts/audit-event-schema.md#emission-topology).
  Discovery checkpoint remains outstanding (depends on Track A).
- Include decision reason codes and artifact versions.
  **Both landed (v0):** every `AuditEvent` carries a `reason_code` (a
  `DenyReason` value or `"ok"`) and an `artifact_version`
  (`"envelope/v0"` for envelope checkpoints, `"wt-cap+jwt"` for capability
  checkpoints).

### D2. Queryability and Incident Readiness
- Search views for break-glass, denies, replay attempts, and cross-tenant attempts.
  **Landed (v0):** canned filter functions in
  `security-foundations/envelope/audit_query.py` —
  `allows`, `denies`, `with_event_type`, `with_reason_code`, `with_sender`,
  `with_recipient`, `with_message_id`, `replays`, `cross_tenant_attempts`,
  `break_glass_attempts`. Each is a pure generator over an
  `Iterable[AuditEvent]`, composable with `itertools` and caller predicates.
  Cross-tenant = sender and recipient in different SPIFFE trust domains;
  break-glass is reserved until a break-glass mechanism ships. Anything
  richer (SQL views, OpenSearch indices) is a storage concern deferred to
  the transport layer.

### D3. Alerting
- Thresholds for repeated validation failures per identity.
  **Landed (v0):** `ThresholdAlertingPolicy` in
  `security-foundations/envelope/alerting.py` keys a per-sender sliding
  window on `envelope.verify` deny events and fires
  `REPEATED_VALIDATION_FAILURE` alerts when the count crosses
  `repeated_deny_threshold` within `window`.
- Thresholds for abnormal capability issuance volume.
  **Landed (v0):** the same policy keys a per-sender sliding window on
  `capability.issue` allow events and fires `ABNORMAL_ISSUANCE_VOLUME`
  alerts when the count crosses `issuance_volume_threshold` within
  `window`. `AlertingAuditSink` decorates any underlying `AuditSink`,
  preserving the hash chain; alerts dispatch through a caller-supplied
  `on_alert` callable so v0 stays transport-agnostic.

**Acceptance Criteria**
- Security incidents can be reconstructed from logs without missing links.

---

## 6) APIs and Contracts to Freeze in Phase 1

Frozen contracts live in [`security-foundations/contracts/`](../../security-foundations/contracts/).
Each document records the artifact, the backwards-compatibility policy, the
schema test vectors, and the change-control procedure.

| Contract | Status | Document |
|---|---|---|
| Envelope schema v1 | **frozen** | [envelope-schema.md](../../security-foundations/contracts/envelope-schema.md) |
| Capability token schema v1 | **frozen** | [capability-token-schema.md](../../security-foundations/contracts/capability-token-schema.md) |
| Policy decision log schema v1 | **frozen** (verification checkpoint; emitted as `AuditEvent`) | [audit-event-schema.md](../../security-foundations/contracts/audit-event-schema.md) |
| Security error response schema v1 | **frozen** (transport-agnostic shape) | [security-error-response-schema.md](../../security-foundations/contracts/security-error-response-schema.md) |
| Discovery record schema v1 | deferred | depends on Track A (discovery-plane security) |

Each contract requires:
- backwards compatibility policy,
- schema test vectors,
- change control procedure and approvers.

---

## 7) Test Plan

### Functional
- Discovery join success/failure matrix by trust state.
- End-to-end request lifecycle with valid capability.

### Security Negative Testing
- Forged identity with plausible metadata.
- Payload tampering after signature.
- Replay with delayed and reordered packets.
- Wrong-audience capability use.

### Resilience
- Partial network partition behavior.
- Cache eviction and replay checks under high load.

### Performance
- P95 and P99 latency for verify + authz path.
- Throughput under deny-heavy traffic patterns.

---

## 8) Dependency and Integration Plan
- Depends on Phase 0 identity, policy, runtime, and audit substrate.
- Integrates with runtime evidence packets from baseline.
- Must preserve deny-by-default semantics from Phase 0 without override paths.

Integration checkpoints:
1. Discovery -> Admission
2. Gateway -> Policy
3. Gateway -> Capability service
4. Gateway -> Audit pipeline

---

## 9) Risk Register (Phase 1)

| Risk | Likelihood | Impact | Mitigation | Owner |
|---|---:|---:|---|---|
| Discovery poisoning | M | H | signed records + bootstrap validation | Discovery Lead |
| Capability over-issuance | L | H | issuance policy hard checks + audits | Auth Lead |
| Replay false negatives in partitions | M | H | sequence checkpoints + mutation IDs | Protocol Lead |
| Deny-path instability | M | M | deterministic error taxonomy + chaos tests | Gateway Lead |
| Audit cardinality overload | M | M | sampling strategy for non-critical events | Observability Lead |

---

## 10) Exit Gates
Phase 1 can close only when:
1. Discovery trust checks are enforced and tested.
2. Messaging gateway rejects all tamper/replay negative tests.
3. Capability and policy lane blocks unauthorized execution with no bypass.
4. End-to-end traces include all mandated security checkpoints.
5. No unresolved critical/high findings in adversarial and protocol reviews.

---

## 11) Artifacts to Produce at Phase Close
- Discovery trust model + bootstrap procedure.
- Messaging gateway verification flow diagram.
- Capability issuance/validation contract package.
- Security test evidence bundle (including partition simulations).
- Operational playbook for deny-spike and replay attack response.
