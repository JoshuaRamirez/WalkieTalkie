# Discovery Record Schema (Phase 1 v1)

Plan citation: `phase-1-minimal-secure-messaging.md` §6 — "Discovery record
schema v1." Deferred at the original Phase 1 schema freeze pending Track A
(discovery-plane security); now that A1 / A2 / A3 have shipped, this
contract freezes the wire artifact those modules produce.

## Artifact

- Module: [`security-foundations/envelope/discovery_record.py`](../envelope/discovery_record.py)
- Companion: [`security-foundations/envelope/admission_coupling.py`](../envelope/admission_coupling.py) (consumes verified records)
- Anchor source: [`security-foundations/envelope/bootstrap_bundle.py`](../envelope/bootstrap_bundle.py) materializes an `IssuerTrustStore` for the verifier

## Wire format

A JSON object signed by a *discovery authority*. The body of the signature
is the JCS-canonicalization of all fields except `signature`, prefixed
with `typ: "wt-discovery-record/v0"` for cross-protocol binding.

```json
{
  "version": "v0",
  "workload_iss": "spiffe://mesh.example/ns-a/svc",
  "workload_kid": "envelope-kid-a",
  "endpoints": ["mesh://node-a.example.test:443"],
  "issuer_iss": "spiffe://mesh.example/discovery-authority",
  "issuer_kid": "discovery-kid-1",
  "issued_at": "2026-04-14T12:00:00Z",
  "expires_at": "2026-04-14T12:30:00Z",
  "signature": "<base64url EdDSA>"
}
```

## Frozen invariants

### Required fields (all)

| Field | Constraint |
|---|---|
| `version` | MUST be the literal `"v0"`. |
| `workload_iss` | SPIFFE ID (matches `^spiffe://[a-zA-Z0-9._/-]+$`). The workload being advertised. |
| `workload_kid` | matches `^[A-Za-z0-9._:-]{1,128}$`. The kid the workload uses on envelope signatures. |
| `endpoints` | non-empty list of non-empty strings. Opaque transport hints; URI grammar is defined by whichever transport layer the operator chooses. |
| `issuer_iss` | SPIFFE ID. The discovery authority that signed this record. |
| `issuer_kid` | KID format. The discovery authority's signing key id. |
| `issued_at` | RFC 3339 timestamp with explicit timezone. |
| `expires_at` | RFC 3339 timestamp with explicit timezone. MUST satisfy `issued_at < expires_at`. |
| `signature` | base64url EdDSA over the JCS body (no padding). |

### Validation rules

`verify_record()` MUST enforce, in order:

1. **Shape** (every field present and well-formed; invalid → `DiscoveryRecordError("…", reason=DenyReason.DISCOVERY_MALFORMED)`).
2. **Signature presence** (empty → `discovery_malformed`).
3. **Time window** with caller-configurable `max_clock_skew` (default 60 s) and `max_record_ttl` (default 1 hour):
   - `issued_at < expires_at` (else `discovery_expired`)
   - `expires_at - issued_at <= max_record_ttl` (else `discovery_expired`)
   - `issued_at - now <= max_clock_skew` (else `discovery_expired`)
   - `now - expires_at <= max_clock_skew` (else `discovery_expired`)
4. **Signature encoding** decodes as base64url (else `discovery_malformed`).
5. **Issuer key lookup** via `issuer_lookup(issuer_iss, issuer_kid) -> PEM`. Missing key or invalid PEM → `discovery_unknown_issuer`.
6. **EdDSA signature verification** over `_body_for_signing(record)`. Failure → `discovery_signature_invalid`.

The order is part of the contract: malformed input is rejected before
time-window checks, time-window before signature, signature before audit
emission. Anti-poisoning: stale records fail at step 3; forged records
fail at step 5 or 6.

## Audit checkpoint

`verify_record()` with an `audit_sink` emits exactly one
`discovery.verify` `AuditEvent` per call with `artifact_version =
"wt-discovery-record/v0"`. See
[audit-event-schema.md](./audit-event-schema.md) for the topology and
`reason_code` mapping.

## Backwards-compatibility policy

| Change | Compatibility |
|---|---|
| Adding a new optional field (with a default that preserves existing semantics) | backwards-compatible |
| Adding a new required field | **incompatible** — new `version` (e.g., `"v1"`) |
| Removing or renaming any field | **incompatible** |
| Tightening any pattern / format | **incompatible** if it rejects previously-valid records |
| Loosening a constraint | backwards-compatible |
| Changing the canonicalization rules or `typ` string | **incompatible** — invalidates all prior signatures |
| Adding a new `DenyReason` in the discovery family | backwards-compatible at this contract's layer (subject to the deny-reason taxonomy's own policy) |

## Test vectors

Not checked in for v0. Discovery records embed the signing authority's
identity in `issuer_iss` and the workload's identity in `workload_iss`,
both of which a downstream conformance run would want to override. The
deterministic regen pattern used by envelope and capability-token vectors
can be ported to discovery later — tracked as a follow-up.

A working sample exists in
[`test_discovery_record.py`](../envelope/test_discovery_record.py) (the
`_record()` factory plus `sign_record`), which downstream implementers can
copy directly.

## Change control

Per [contracts README](./README.md). The "deferred" entry in that README
should be updated alongside this contract landing.
