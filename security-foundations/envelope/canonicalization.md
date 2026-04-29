# Canonicalization Contract (Envelope v0)

The verifier computes signature input from a canonical JSON representation of
all envelope fields **except** `signature`. The contract is **RFC 8785 — JSON
Canonicalization Scheme (JCS)**.

## Rules
1. Encoding is RFC 8785 conformant. Implementations MUST use a JCS library
   that has been validated against the RFC's test suite. Reference:
   <https://www.rfc-editor.org/rfc/rfc8785>.
2. JSON object members are emitted in lexicographic order of their UTF-16 key
   sequences (RFC 8785 §3.2.3).
3. Number serialization follows ECMAScript `Number.prototype.toString`
   (RFC 8785 §3.2.2). In particular, `1.0` and `1` serialize identically, so
   tools producing envelopes MUST NOT rely on JSON to preserve the
   integer/float distinction.
4. String serialization preserves the input code points and applies the
   minimum-length JSON escaping defined in RFC 8785 §3.2.1. **No Unicode
   normalization is applied.** Senders that need stable signatures across
   platforms MUST normalize their string inputs themselves before signing.
5. Arrays preserve element order.
6. The verifier rejects an envelope if `payload_digest` does not equal the hex
   SHA-256 of the JCS canonicalization of `payload`.

## Signature input
- Build the JCS canonicalization of the envelope dict with the `signature`
  member removed.
- Sign the resulting bytes directly with the workload's Ed25519 private key.
- Base64url encode the detached 64-byte signature without padding and place it
  in the `signature` field.

## Security notes
- `alg` is policy-pinned to `Ed25519` for envelope v0. Downgrade attempts are
  fatal.
- The reference verifier loads PEM public keys via `cryptography` and asserts
  they are `Ed25519PublicKey` instances; SubjectPublicKeyInfo PEMs declaring a
  different algorithm are rejected.
