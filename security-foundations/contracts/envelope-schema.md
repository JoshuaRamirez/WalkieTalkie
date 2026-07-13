# Envelope Schema (Phase 1 v1)

Plan citation: `phase-1-minimal-secure-messaging.md` §6 — "Envelope schema v1."
On-wire `version` value remains `"v0"` (changing it is a backwards-
incompatible bump and requires a new contract version per the policy below).

## Artifact

- JSON Schema: [`security-foundations/envelope/schema-v0.json`](../envelope/schema-v0.json)
- Canonicalization rules: [`security-foundations/envelope/canonicalization.md`](../envelope/canonicalization.md)
- Reference verifier: [`security-foundations/envelope/verify_envelope.py`](../envelope/verify_envelope.py)

The schema file is the normative source for field presence, types, and
patterns. The canonicalization document is the normative source for the
exact byte sequence that gets signed (RFC 8785 / JCS).

## Frozen invariants

- `version` MUST be the literal string `"v0"`.
- `alg` MUST be `"Ed25519"`. Algorithm agility requires a wire bump.
- Signature is a base64url-without-padding-encoded EdDSA signature over the
  RFC 8785 canonicalization of the envelope object with the `signature` field
  removed.
- `payload_digest` is `hex(sha256(jcs(payload)))`.
- `capability_token` is bound by the `cnf.envelope_digest` claim — see
  [capability-token-schema.md](./capability-token-schema.md).
- `kid` matches `^[A-Za-z0-9._:-]{1,128}$`.
- `nonce` matches `^[A-Za-z0-9._:-]{16,256}$`.
- `message_id` is a UUIDv7.
- `sender_spiffe_id` and `recipient_spiffe_id` match the SPIFFE ID format.

## Backwards-compatibility policy

| Change | Compatibility |
|---|---|
| Adding a new optional field with a default | backwards-compatible |
| Adding a new required field | **incompatible** — new contract version |
| Removing any field | **incompatible** |
| Tightening a regex/pattern | **incompatible** |
| Loosening a regex/pattern | backwards-compatible |
| Changing canonicalization rules | **incompatible** — invalidates all existing signatures |
| Adding an `alg` value | **incompatible** — algorithm agility is a wire concern |
| Adding a `version` value (e.g., `"v1"`) | new schema; old verifier rejects |

## Test vectors

| File | What it demonstrates |
|---|---|
| [`test-vectors/valid-envelope.json`](../envelope/test-vectors/valid-envelope.json) | A complete envelope that verifies cleanly under `dev-kid-1.pub.pem` and `dev-issuer-1.pub.pem`. |
| [`test-vectors/tampered-envelope.json`](../envelope/test-vectors/tampered-envelope.json) | Same envelope with one byte of payload mutated. Both the digest check and the signature check fail. |

Vectors are regenerated deterministically by
[`security-foundations/envelope/_regen_vectors.py`](../envelope/_regen_vectors.py)
from named seeds — re-running the script must leave the working tree clean.

## Change control

Per [contracts README](./README.md). A backwards-incompatible change MUST:

1. Be authored as a separate document (e.g., `envelope-schema-v2.md`).
2. Include a migration plan (dual-version verifier window, deprecation
   timeline).
3. Be approved by the change-control approvers listed in the README.
