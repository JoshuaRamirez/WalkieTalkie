# Security Foundations Bootstrap (Phase 0)

This directory starts implementation of **Phase 0 — Security Foundations** from
the approved plan.

## Implemented in this bootstrap
- Envelope schema v0 as a JSON Schema artifact.
- Canonicalization contract pinned to **RFC 8785 (JCS)** — see
  `envelope/canonicalization.md`.
- Reference verifier (`envelope/verify_envelope.py`) implementing:
  - schema + required field checks,
  - timestamp validity checks,
  - nonce replay rejection,
  - payload digest verification,
  - in-process Ed25519 signature verification via the `cryptography` library
    (no `openssl` subprocess),
  - key-id lookup behind a callable interface,
  - capability token validation (see below).
- **Capability token v0** (`envelope/capability_token.py` validator,
  `envelope/capability_issuer.py` issuer): RFC 7519 JWT with EdDSA, bound to
  the envelope via `cnf.envelope_digest` so a leaked or replayed token only
  authorizes its specific payload. Issuer trust is a separate
  `IssuerTrustStore` (`envelope/issuer_trust_store.py`) keyed on `(iss, kid)`,
  so envelope-signing keys cannot be used to mint tokens. `CapabilityIssuer`
  validates `iss`/`kid`/`ttl` at construction and auto-generates UUIDv7 `jti`
  values; `generate_uuidv7` is a small RFC 9562 implementation.
- **Issuance policy v0** (`envelope/issuance_policy.py`): `IssuancePolicy`
  ABC + `AllowAllPolicy` (default) + `AllowlistPolicy` (frozen
  `(sub, aud, scope)` tuples + `max_ttl`). Policy denials raise
  `IssuancePolicyError` and emit a `capability.issue` deny audit event when
  an `audit_sink` is attached.
- **Alerting v0** (`envelope/alerting.py`): `AlertingAuditSink` decorator
  + `ThresholdAlertingPolicy` (per-identity sliding windows) firing
  `REPEATED_VALIDATION_FAILURE` (on `envelope.verify` denies) and
  `ABNORMAL_ISSUANCE_VOLUME` (on `capability.issue` allows). Alerts
  dispatch through a caller-supplied `on_alert` callable; the underlying
  hash-chained audit sink is preserved unchanged.
- **Audit search views v0** (`envelope/audit_query.py`): canned filters
  over an `Iterable[AuditEvent]` — `allows`, `denies`, `with_event_type`,
  `with_reason_code`, `with_sender`, `with_recipient`, `with_message_id`,
  `replays`, `cross_tenant_attempts`, `break_glass_attempts`. Pure
  generators so they compose with `itertools` and caller predicates.
  Cross-tenant = sender and recipient in different SPIFFE trust domains.
- **Signed policy bundles v0** (`envelope/policy_bundle.py`): `PolicyBundle`
  carries a monotonic `version`, an EdDSA signature, and a serialized
  `AllowlistPolicy`. `verify_bundle()` checks the signature against an
  `IssuerTrustStore` and returns the realized policy. `RollbackGuard`
  (`InMemoryRollbackGuard` / `FileBackedRollbackGuard`) enforces per-issuer
  monotonic-version acceptance.
- **Canary policy releases v0** (`envelope/canary_policy.py`): `CanaryPolicy`
  wraps a stable + candidate `IssuancePolicy` pair and routes a percentage
  of grants to the candidate via a deterministic sha256-based bucket over
  `(sub, aud, scope)`. Auto-rollback engages once the candidate's denial
  count crosses `rollback_after_denials`; rollback is sticky for the
  lifetime of the instance.
- **Delegation receipts v0** (`envelope/delegation_receipt.py`, Phase 2
  Track A): `DelegationReceipt` records one hop of a delegation chain
  (`chain_id`, `hop_index`, `parent_jti`, `delegator_iss`, `delegate_iss`,
  scope/aud/window, signature with `typ: "wt-delegation/v0"`).
  `verify_receipt()` enforces every non-escalation invariant: hop_index
  must be exactly `parent.hop_index + 1`, parent_jti must match,
  `delegator_iss == parent.sub`, scope must equal parent's scope, aud
  must equal parent's, and `[iat, exp]` must be contained within the
  parent's window. Depth capped at `max_chain_depth` (default 3).
- **Data classification + lineage v0**
  (`envelope/data_classification.py`, Phase 2 Track B B1): `DataClass`
  enum (public / internal / confidential / restricted), `ClassifiedData`
  frozen wrapper around a `data_digest`, `lineage` chain, and metadata
  bag. `classify()` / `derive()` / `combine()` are the only constructors;
  derivation rejects class demotion (`DataClassificationError`), combine
  takes the max class. Each `LineageTag` commits to its parent's
  `chain_hash` so tamper-evident lineage walks are possible without
  trusting any single producer.
- **Bootstrap artifact validation v0** (`envelope/bootstrap_bundle.py`):
  `BootstrapBundle` is a signed, epoch-versioned anchor set for a trust
  domain. `verify_bundle()` validates shape + signature against a root
  PEM supplied out-of-band, pins the trust domain, and materializes the
  bundle into an `IssuerTrustStore` so downstream components consume it
  through the same interface as manifest-loaded keys.
- **Discovery record integrity v0** (`envelope/discovery_record.py`):
  `DiscoveryRecord` advertises `(workload_iss, workload_kid, endpoints)`
  signed by a discovery authority. `verify_record()` enforces shape,
  time window (default 1-hour max TTL, 60-second clock skew), and
  signature against an `IssuerTrustStore` — typically the one
  materialized from the bootstrap bundle. Anti-poisoning: stale records
  fail the time window; forged records fail the signature.
- **Admission coupling v0** (`envelope/admission_coupling.py`): after
  `verify_record()` succeeds, `admit(record, policy)` /
  `require_admission(record, policy)` checks the workload SPIFFE ID
  against `AdmissionPolicy.allowed_workloads` and the discovery
  version against `accepted_discovery_versions` (the "compatibility
  matrix"). Denied decisions zero out the `endpoints` field so the
  deny path never propagates transport hints for an unadmitted peer.
- **Discovery + admission audit checkpoints**: `verify_record` and
  `admit` / `require_admission` accept an optional `audit_sink` and
  emit `discovery.verify` / `admission.evaluate` events with stable
  `reason_code` values (`discovery_malformed`, `discovery_expired`,
  `discovery_signature_invalid`, `discovery_unknown_issuer`,
  `admission_workload_not_allowed`, `admission_version_incompatible`).
  Pairs with the existing `envelope.verify` / `capability.verify` /
  `capability.issue` checkpoints in `audit.py`.
- **Identity-aware rate limits v0** (`envelope/rate_limiter.py`):
  `IdentityRateLimiter` enforces per-identity fixed-count sliding
  windows with per-identity overrides. `RateLimitedVerifier` decorates
  a `Verifier` so throttled requests never reach signature verification;
  throttled-deny is `RateLimitExceededError` (a subclass of
  `EnvelopeVerificationError` with `DenyReason.RATE_LIMITED`).
- **Revocation list v0** (`envelope/revocation_list.py`): `InMemoryRevocationList`
  and `FileBackedRevocationList` (append-only JSONL with an `integrity_hash()`
  for tamper detection). The validator consults the list *after* signature
  verification so an attacker forging a token with a guessed `jti` cannot
  probe the list. Distributed cache invalidation remains out of scope for v0.
- **Deterministic error contract** (`envelope/deny_reason.py`): every
  `EnvelopeVerificationError` carries a `DenyReason` enum value. `reason_code`
  is exposed on the exception and embedded in audit events for machine-readable
  matching. New deny paths get new identifiers; shipped values are never
  renamed or repurposed.

## Frozen contracts

All five Phase 1 §6 contracts (envelope, capability token, audit / policy
decision log, security error response, discovery record) are documented in
[`contracts/`](./contracts/). Each contract records artifact, backwards-
compatibility policy, schema test vectors, and change control.
- **Hash-chained audit events v0** (`envelope/audit.py`): every
  `verify_envelope` call records exactly one event (allow or deny) with the
  envelope identifiers and the rejection reason. `InMemoryAuditSink` and
  `JsonlAuditSink` ship; `verify_chain` re-derives the hash chain to detect
  insertion, deletion, or in-place mutation of past records.
- **`Verifier` facade** (`envelope/verifier.py`): a frozen dataclass that holds
  the trust stores, replay cache, audit sink, and config so callers don't pass
  seven keyword arguments per request. `Verifier.verify(envelope)` raises and
  returns the validated `CapabilityClaims`; `Verifier.try_verify(envelope)`
  never raises and returns a `VerificationResult` with `ok`, `reason`, and
  `claims`.
- Replay cache implementations:
  - `InMemoryReplayCache` for local use,
  - `SQLiteReplayCache` for cross-process replay protection.
- `FileSystemTrustStore` reference implementation (`envelope/trust_store.py`)
  that loads trusted keys from a directory or a JSON manifest with optional
  `not_after` expiry.
- Test vectors regenerated under JCS by
  `envelope/_regen_vectors.py`, with the matching public key checked in.
- Unit tests covering positive paths, tampering, replay, downgrade,
  non-Ed25519 key rejection, JCS semantics, cross-process replay, and
  trust-store loading.

## Out of scope for this bootstrap
- Production PKI and mTLS wiring.
- Workload-identity-bound trust store (replaces `FileSystemTrustStore` in
  Phase 1+ Track A2).
- Policy engine integration.
- Runtime hardening controls.
- Tamper-evident distributed audit pipeline.

## Running tests

From the repository root:

```sh
pip install -e ".[dev]"
python -m unittest discover -s security-foundations/envelope -t security-foundations/envelope -v
```

CI runs the same install + `python -m compileall`, `ruff check`, and the
unittest suite on Python 3.11 and 3.12 — see `.github/workflows/test.yml`.

## Next implementation targets
1. Wire verifier into network ingress middleware.
2. Add an external distributed replay backend option (e.g., Redis) for
   multi-node deployments.
3. Swap `FileSystemTrustStore` for a workload-identity-bound trust store.
