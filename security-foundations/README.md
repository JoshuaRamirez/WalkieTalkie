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

The Phase 1 §6 freeze for envelope, capability token, audit/policy decision
log, and security error response is documented in
[`contracts/`](./contracts/). Each contract records artifact, backwards-
compatibility policy, schema test vectors, and change control. The discovery
record schema is deferred until Phase 1 Track A starts.
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
