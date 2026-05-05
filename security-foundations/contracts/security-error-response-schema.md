# Security Error Response Schema (Phase 1 v1)

Plan citation: `phase-1-minimal-secure-messaging.md` §6 — "Security error
response schema v1." Also closes the spirit of Track B B3 ("Security-deny
responses are machine-readable and auditable") by defining what those
responses look like *on the wire*, independent of any chosen transport.

## Artifact

This contract defines the error-response payload shape that every gateway,
issuer, or middleware MUST emit when denying a security-relevant request. It
is intentionally transport-agnostic: HTTP, gRPC, message queues, etc. each
embed this object in whatever envelope they natively use.

The Python equivalent is the `EnvelopeVerificationError` instance plus its
`reason` enum value — see
[`security-foundations/envelope/deny_reason.py`](../envelope/deny_reason.py).

## Wire format

A JSON object with a single top-level `error` member:

```json
{
  "error": {
    "reason_code": "<DenyReason value>",
    "reason": "<human-readable string>",
    "message_id": "<envelope.message_id, or empty if pre-parse>"
  }
}
```

## Frozen invariants

### Required fields under `error`

| Field | Type | Notes |
|---|---|---|
| `reason_code` | string | A `DenyReason` value (e.g., `"replay_detected"`, `"capability_revoked"`). MUST be one of the shipped enum values. New denial paths require a new `DenyReason` value first; see the deny-reason stability contract. |
| `reason` | string | Human-readable. SHOULD be the exact `str(EnvelopeVerificationError)` value the verifier produced. |
| `message_id` | string | Envelope `message_id` if the failure occurred after the field was read; `""` otherwise. Lets clients correlate the deny with their pending request. |

### Optional fields under `error`

| Field | Type | Notes |
|---|---|---|
| `decision_id` | string | Reserved for future policy-decision-id correlation (Phase 1 D1.4 trace work). |
| `retry_after_seconds` | integer | Reserved for rate-limit responses (Phase 1 D1.5). |

Implementations MUST ignore unknown fields under `error` for forward
compatibility, and MUST NOT emit fields not listed here.

### Top-level invariant

The top-level object MUST contain `error` and SHOULD NOT contain any other
top-level field. A success response is whatever the surrounding transport
defines; this schema only constrains the *failure* shape.

### Reason-code coupling

The set of permitted `reason_code` values is exactly the
[`DenyReason`](../envelope/deny_reason.py) enum. Any change to that enum is
governed by the deny-reason stability contract (identifiers immutable once
shipped, new ones may be added).

## Why no transport here

Every transport already defines its own status semantics (HTTP 4xx/5xx,
gRPC status codes). Embedding deny information in a transport-specific way
would force every consumer to understand every transport. By freezing the
*payload* shape and letting each transport map `reason_code` to its native
status surface, we keep the contract one place.

Recommended HTTP mapping (informational, not normative):

| `reason_code` family | HTTP status |
|---|---|
| `signature_invalid`, `capability_signature_invalid`, `replay_detected`, anything `*_mismatch` | 401 Unauthorized |
| `capability_revoked`, `key_expired`, `issuer_key_expired`, `envelope_expired`, `capability_expired`, `capability_not_yet_valid` | 403 Forbidden |
| `unknown_kid`, `unknown_issuer_key`, `disallowed_algorithm`, `unsupported_version` | 403 Forbidden |
| Any `invalid_*`, `*_malformed`, `missing_*`, `*_oversized`, `*_invalid_window`, `*_ttl_exceeded` | 400 Bad Request |
| Internal/unexpected (none in v0) | 500 Internal Server Error |

## Backwards-compatibility policy

| Change | Compatibility |
|---|---|
| Adding a new optional field under `error` | backwards-compatible (per the "ignore unknown" rule) |
| Adding a new `reason_code` value | backwards-compatible at this contract's layer (see deny-reason policy) |
| Removing or renaming any field | **incompatible** |
| Changing the top-level wrapper from `error` to anything else | **incompatible** |
| Changing the type of any field | **incompatible** |

## Change control

Per [contracts README](./README.md).
