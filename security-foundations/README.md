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
  - key-id lookup behind a callable interface.
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
