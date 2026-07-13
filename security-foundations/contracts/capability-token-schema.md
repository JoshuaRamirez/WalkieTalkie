# Capability Token Schema (Phase 1 v1)

Plan citation: `phase-1-minimal-secure-messaging.md` §6 — "Capability token
schema v1." On-wire identifier: `typ: "wt-cap+jwt"`.

## Artifact

- Module: [`security-foundations/envelope/capability_token.py`](../envelope/capability_token.py) (validator)
- Module: [`security-foundations/envelope/capability_issuer.py`](../envelope/capability_issuer.py) (issuer)
- Trust store: [`security-foundations/envelope/issuer_trust_store.py`](../envelope/issuer_trust_store.py)
- Revocation: [`security-foundations/envelope/revocation_list.py`](../envelope/revocation_list.py)

The Python modules are the normative sources for v0. A separate JSON Schema
artifact would be redundant — the JWT structure is fully fixed by the header
and claim invariants below. Cross-language implementers should use the
header/claim list here as the contract and the test vector below as the
conformance fixture.

## Wire format

`<base64url(header)>.<base64url(payload)>.<base64url(signature)>` — JWS
Compact Serialization (RFC 7515) with no padding. Signature is detached
EdDSA (RFC 8037) over the ASCII bytes `base64url(header) + "." +
base64url(payload)`. Maximum total length: **4096 bytes**.

## Frozen invariants

### Header (all required)

| Field | Constraint |
|---|---|
| `alg` | MUST be `"EdDSA"` |
| `typ` | MUST be `"wt-cap+jwt"` |
| `kid` | matches `^[A-Za-z0-9._:-]{1,128}$` |

### Payload claims (all required)

| Claim | Constraint |
|---|---|
| `iss` | SPIFFE ID (matches `^spiffe://[a-zA-Z0-9._/-]+$`) |
| `sub` | SPIFFE ID — MUST equal envelope `sender_spiffe_id` |
| `aud` | SPIFFE ID — MUST equal envelope `recipient_spiffe_id` |
| `scope` | non-empty string — MUST equal envelope `purpose_of_use` |
| `iat` | NumericDate (seconds since epoch) |
| `nbf` | NumericDate; MUST be `>= iat` |
| `exp` | NumericDate; MUST be `> nbf`; `exp - nbf` MUST be `<= max_capability_ttl` (default 5 minutes) |
| `jti` | UUIDv7 (RFC 9562) — used by the revocation list |
| `cnf` | object containing `envelope_digest` (hex sha256) — MUST equal envelope `payload_digest` |

### Validation order

The validator performs checks in this order and the order is part of the
contract:

1. Length cap (≤ 4096 bytes).
2. Three base64url segments.
3. Header well-formedness (alg, typ, kid).
4. Claim presence and per-claim format.
5. Envelope binding (sub, aud, scope, cnf.envelope_digest).
6. Time window (iat ≤ nbf, nbf-skew ≤ now ≤ exp+skew, exp-nbf ≤ TTL cap).
7. Issuer key lookup `(iss, kid) -> PEM`. Missing or expired key is fatal.
8. EdDSA signature verification.
9. Revocation list check (only if a revocation list is provided).

Step 9 deliberately runs **after** signature verification so an attacker
cannot probe the revocation list with forged tokens.

## Backwards-compatibility policy

| Change | Compatibility |
|---|---|
| Adding a new optional claim | backwards-compatible |
| Adding a new required claim | **incompatible** — new `typ` (e.g., `"wt-cap+jwt-2"`) |
| Changing claim type or format | **incompatible** |
| Loosening a constraint | backwards-compatible |
| Tightening a constraint that rejects previously-valid tokens | **incompatible** |
| Reordering validation steps in a way that changes the deny reason | observable change — coordinate with deny-reason taxonomy |
| Changing the signing input (e.g., URL-safe base64 vs standard) | **incompatible** |

## Test vectors

| File | What it demonstrates |
|---|---|
| [`test-vectors/capability-token.txt`](../envelope/test-vectors/capability-token.txt) | A complete `wt-cap+jwt` produced by `_regen_vectors.py` from the deterministic issuer seed. Verifies under `dev-issuer-1.pub.pem`. |
| [`test-vectors/valid-envelope.json`](../envelope/test-vectors/valid-envelope.json) — the `capability_token` field | Embedded in a real envelope context; the same token, but as it actually travels on the wire. |

## Change control

Per [contracts README](./README.md).
