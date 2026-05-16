# Phase 1 Frozen Contracts

Closes Phase 1 §6 ("APIs and Contracts to Freeze in Phase 1") for the
contracts that have shipped code. Each contract document records:

1. The artifact (schema file, module reference, or wire format).
2. The backwards-compatibility policy (when does the major version bump?).
3. Schema test vectors (small example payloads that downstream
   implementations can use to verify their own decoders/validators).
4. Change control (who must approve a contract change).

| Contract | Status | Document |
|---|---|---|
| Envelope schema v1 | **frozen** (on-wire `version: "v0"`) | [envelope-schema.md](./envelope-schema.md) |
| Capability token schema v1 | **frozen** (`typ: "wt-cap+jwt"`) | [capability-token-schema.md](./capability-token-schema.md) |
| Audit / policy decision log schema v1 | **frozen** | [audit-event-schema.md](./audit-event-schema.md) |
| Security error response schema v1 | **frozen** (transport-agnostic shape) | [security-error-response-schema.md](./security-error-response-schema.md) |
| Discovery record schema v1 | **frozen** (`typ: "wt-discovery-record/v0"`) | [discovery-record-schema.md](./discovery-record-schema.md) |

## Naming convention

The plan uses "v1" to mean "the Phase 1 freeze." On-wire identifiers were
chosen earlier and are preserved — bumping wire identifiers requires a
backwards-incompatible schema change (see each contract's policy). For
example, the envelope's `"version": "v0"` string remains; the freeze
documented here is *the v1 of the contract document*, not a wire bump.

## Stability contract (applies to all)

Once a contract document is **frozen**:

- Adding a new optional field (with a default that preserves existing
  semantics) is backwards-compatible. Document it; do not bump the contract
  version.
- Adding a new required field, removing a field, changing a field's type,
  or tightening validation in a way that rejects previously-accepted
  payloads is backwards-incompatible. It requires a new contract version,
  a transition plan, and approval from the change-control approvers.
- Reordering fields in serialized output is backwards-incompatible if the
  serialization is canonical (envelope, audit hash chain). It is
  cosmetic-only otherwise.
- Removing a `DenyReason` value is backwards-incompatible. New values may
  be added at any time per the deny-reason module's stability contract.

## Change control approvers

Phase 1 placeholder: the project maintainer. The Phase 1 plan §11 calls for
named tracks (Discovery Lead / Auth Lead / Protocol Lead / Gateway Lead /
Observability Lead); when those roles are assigned, this section will be
updated to require multi-party approval.
