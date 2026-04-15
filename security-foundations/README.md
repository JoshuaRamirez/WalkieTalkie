# Security Foundations Bootstrap (Phase 0)

This directory starts implementation of **Phase 0 — Security Foundations** from the approved plan.

## Implemented in this bootstrap
- Envelope schema v0 as a JSON Schema artifact.
- Canonicalization contract for deterministic signing input.
- Reference verifier implementation for:
  - schema + required field checks,
  - timestamp validity checks,
  - nonce replay rejection,
  - payload digest verification,
  - key-id based Ed25519 signature verification.
- Replay cache implementations:
  - `InMemoryReplayCache` for local use,
  - `SQLiteReplayCache` for cross-process replay protection.
- Test vectors and unit tests for baseline negative/positive paths.

## Out of scope for this bootstrap
- Production PKI and mTLS wiring.
- Policy engine integration.
- Runtime hardening controls.
- Tamper-evident distributed audit pipeline.

## Next implementation targets
1. Wire verifier into network ingress middleware.
2. Add external distributed replay backend option (e.g., Redis) for multi-node deployments.
3. Swap local key lookup interface with workload identity-bound trust store.
4. Replace OpenSSL subprocess verification with a dedicated in-process crypto provider.
