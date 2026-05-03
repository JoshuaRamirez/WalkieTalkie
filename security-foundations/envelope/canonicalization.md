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

## Capability token (envelope v0 / token v0)

The `capability_token` field is a **RFC 7519 JWT** signed with **EdDSA**
(RFC 8037). Wire form is the JWS Compact Serialization
`<base64url(header)>.<base64url(payload)>.<base64url(signature)>` with no
padding. The token is capped at 4096 bytes. Detailed format and validation
rules live in `capability_token.py`; the contract for the verifier is:

- **Header** MUST set `alg: "EdDSA"`, `typ: "wt-cap+jwt"`, and a `kid` matching
  `KID_RE`. `alg=none`, `HS256`, etc. are fatal.
- **Claims** (all required): `iss`, `sub`, `aud`, `scope`, `iat`, `nbf`, `exp`,
  `jti`, `cnf.envelope_digest`. Times are NumericDate (seconds since epoch).
- **Envelope binding** (the validator enforces all four):
  - `sub == envelope.sender_spiffe_id`
  - `aud == envelope.recipient_spiffe_id`
  - `scope == envelope.purpose_of_use`
  - `cnf.envelope_digest == envelope.payload_digest`
- **Time window** uses `VerificationConfig.max_clock_skew` and a separate
  `max_capability_ttl` (default 5 minutes). `iat <= nbf < exp`.
- **Issuer trust** is a separate `IssuerTrustStore` keyed on `(iss, kid)`. The
  envelope-signing trust store and the issuer trust store are deliberately
  distinct types — a workload that signs envelopes physically cannot also mint
  capability tokens.

Validation happens **after** envelope signature verification and **before**
the replay reservation. A capability failure raises `EnvelopeVerificationError`
with a `"capability token: …"` reason and the nonce is not reserved.
