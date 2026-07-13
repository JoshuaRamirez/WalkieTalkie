# Audit / Policy Decision Log Schema (Phase 1 v1)

Plan citation: `phase-1-minimal-secure-messaging.md` §6 — "Policy decision
log schema v1." The verification checkpoint of D1.4 produces one
`AuditEvent` per `verify_envelope` call; that event *is* the policy
decision log entry for envelope-level decisions.

## Artifact

- Module: [`security-foundations/envelope/audit.py`](../envelope/audit.py)
- Reason taxonomy: [`security-foundations/envelope/deny_reason.py`](../envelope/deny_reason.py)

## Wire format

Newline-delimited JSON (JSONL). Each line is one `AuditEvent` serialized as a
flat object. The current sink implementation is `JsonlAuditSink`; any future
sink (Kafka, syslog, OpenSearch, etc.) MUST use the same field names and
types.

## Frozen invariants

### Required fields

| Field | Type | Notes |
|---|---|---|
| `timestamp` | RFC 3339 string in UTC, ending in `Z` | Wall-clock time at event emission. |
| `event_type` | string | v0 emits `"envelope.verify"`, `"capability.verify"`, `"capability.issue"`, `"discovery.verify"`, and `"admission.evaluate"`. Future checkpoints (`policy.evaluate`, `execution.dispatch`) MUST use additional values; existing values are immutable. |
| `outcome` | `"allow"` or `"deny"` | Closed enum. |
| `reason` | string | Human-readable. May contain a colon-prefixed namespace (e.g., `"capability token: revoked"`). |
| `reason_code` | string | Machine-readable. Either `"ok"`, `""` (legacy), or a `DenyReason` value (e.g., `"replay_detected"`). See deny-reason contract below. |
| `artifact_version` | string | Wire format / contract version that produced the decision. v0: `"envelope/v0"` for `envelope.verify`, `"wt-cap+jwt"` for `capability.verify`. Empty string for legacy events. |
| `message_id` | string | Envelope `message_id` if available; `""` if the failure occurred before the envelope was parsed. |
| `sender` | string | Envelope `sender_spiffe_id` or `""`. |
| `recipient` | string | Envelope `recipient_spiffe_id` or `""`. |
| `envelope_kid` | string | Envelope-signing kid, or `""`. |
| `issuer_iss` | string | Capability token `iss` if validated, else `""`. |
| `issuer_kid` | string | Capability token's issuer kid (JWT header `kid`) if validated, else `""`. |
| `prev_hash` | hex sha256 | Previous event's `this_hash`, or 64 zeros for the genesis event. |
| `this_hash` | hex sha256 | sha256(prev_hash ‖ JCS(body)), where `body` is every field above except `prev_hash` and `this_hash`. |

### Emission topology

A single `verify_envelope` call emits between one and two events depending
on where it fails:

| Outcome | Events emitted (in order) |
|---|---|
| Success | `capability.verify` allow → `envelope.verify` allow |
| Pre-cap deny (e.g., digest mismatch, expired envelope) | `envelope.verify` deny only |
| Cap-level deny (e.g., revoked, sub mismatch) | `capability.verify` deny → `envelope.verify` deny (same `reason_code`) |
| Post-cap deny (replay) | `capability.verify` allow → `envelope.verify` deny (`replay_detected`) |

A single `CapabilityIssuer.issue` call emits exactly one
`capability.issue` event when an `audit_sink` is attached:

| Outcome | Event |
|---|---|
| Issuance allowed | `capability.issue` allow (`reason_code = "ok"`) |
| Issuance policy denial | `capability.issue` deny (`reason_code = "issuance_policy_denied"`, `reason` echoes the `PolicyDecision.reason`) |

A single `discovery_record.verify_record` call emits exactly one
`discovery.verify` event when an `audit_sink` is attached:

| Outcome | `reason_code` examples |
|---|---|
| Allow | `"ok"` |
| Deny | `"discovery_malformed"`, `"discovery_expired"`, `"discovery_signature_invalid"`, `"discovery_unknown_issuer"` |

A single `admission_coupling.admit` (or `require_admission`) call emits
exactly one `admission.evaluate` event when an `audit_sink` is attached:

| Outcome | `reason_code` |
|---|---|
| Admitted | `"ok"` |
| Denied — wrong discovery format | `"admission_version_incompatible"` |
| Denied — workload not in allowlist | `"admission_workload_not_allowed"` |

### Hash chain

`this_hash = sha256(prev_hash_ascii_bytes + jcs(body))` where `body` is built
from `_HASHED_FIELDS` (in that exact order). New fields MUST be appended to
`_HASHED_FIELDS` to preserve hash compatibility for existing chains.
`verify_chain(events)` re-derives both `prev_hash` and `this_hash` and raises
`AuditChainError` on the first break.

### Reason code coupling

`reason_code` values come from
[`DenyReason`](../envelope/deny_reason.py). The deny-reason module's
stability contract applies: identifiers, once shipped, are never renamed or
repurposed. New denial paths get new identifiers; deprecated ones can be
retired but their string form is reserved.

### Field attribution on deny events

On a successful verification (`outcome = "allow"`), every identity field
(`sender`, `recipient`, `envelope_kid`, `issuer_iss`, `issuer_kid`) has
been *cryptographically validated* — the envelope's signature, the
capability token's signature, and the issuer-trust-store lookup all
passed.

On a denied verification (`outcome = "deny"`), identity fields reflect
what the envelope **claimed at the point the deny fired**, not what the
verifier confirmed. A deny that fires before signature verification
(e.g., `payload_digest_mismatch`, missing required field, malformed
timestamp) records the *claimed* `sender_spiffe_id` without proof. An
attacker who sends garbage envelopes can therefore cause deny events to
appear with a victim's SPIFFE ID in the `sender` column.

Consequences for downstream consumers:

- Threshold alerts on deny counts per-`sender` (see :mod:`alerting`) may
  fire on innocent identities. The alert means "someone is sending
  envelopes that claim to be from X, and they're failing" — not
  necessarily "X is misbehaving." Operators MUST treat these alerts as
  investigation triggers, not automatic enforcement.
- Search views (see :mod:`audit_query`) that filter by `sender` will
  include both verified and unverified attributions on the deny side.
- The rate limiter (see :mod:`rate_limiter`) is deliberately wired
  **after** signature verification so it does not act on claimed-but-
  unverified identities. That's a hard requirement for any future
  automated enforcement built on these events.

This is a documented v0 trade-off. A future hardening pass could split
the schema into `claimed_sender` (always present) and `verified_sender`
(present only when `outcome == "allow"`), but that's a backwards-
incompatible field change and would require a contract version bump.

## Backwards-compatibility policy

| Change | Compatibility |
|---|---|
| Appending a new optional field to `AuditEvent` and `_HASHED_FIELDS` (defaulting to `""` when absent) | backwards-compatible if `JsonlAuditSink.read_all` defaults missing keys |
| Inserting a new field anywhere except the end of `_HASHED_FIELDS` | **incompatible** — invalidates all prior `this_hash` values |
| Changing `event_type`, `outcome`, or `reason_code` to be free-form | **incompatible** |
| Switching the hash to anything but sha256 | **incompatible** |
| Changing the canonicalization from JCS | **incompatible** |
| Changing the encoding from JSONL | requires explicit migration; not a contract change in itself |

## Test vectors

| File | What it demonstrates |
|---|---|
| [`test-vectors/audit-event.jsonl`](../envelope/test-vectors/audit-event.jsonl) | Five events covering three scenarios: a successful verify (`capability.verify` allow + `envelope.verify` allow), a pre-cap deny (`envelope.verify` `payload_digest_mismatch` only), and a cap-level deny (`capability.verify` deny + `envelope.verify` deny, both `capability_revoked`). `verify_chain` must accept the file as-is. |

## Change control

Per [contracts README](./README.md).
