# WalkieTalkie Protocol Specification v0.1

*The consolidated normative wire specification for the WalkieTalkie
security substrate: cryptographic primitives, the signed-artifact
registry, and the end-to-end mesh message flow.*

This document closes **Phase 5 Track E, E3** (evidence artifact D5.7,
vision §9 deliverable: consolidated protocol spec). It is an **index +
delta**, not a replacement: the per-artifact field schemas frozen in
`security-foundations/contracts/` remain the normative source for field
presence, types, and patterns. This spec pulls them into one place,
records the complete cross-protocol identifier registry, adds the
Phase 5 artifacts (SVID, image signature) that postdate the Phase 1
freeze, and specifies how the artifacts compose into a single
authenticated mesh exchange.

## Versioning philosophy

"v0.1" names *this consolidated document*. Individual wire artifacts
keep their own frozen identifiers (the envelope's `"version": "v0"`,
the capability token's `typ: "wt-cap+jwt"`, etc.). Bumping any wire
identifier is a backwards-incompatible change governed by the stability
contract in `security-foundations/contracts/README.md`; it is **not**
implied by a bump to this document's version. Per the substrate's
anti-patterns (CLAUDE.md), there are no feature flags or compat shims —
a breaking change replaces the module and mints a new identifier.

## 1. Cryptographic primitives (normative, apply to all artifacts)

| Concern | Choice | Notes |
|---|---|---|
| Signature | **Ed25519** (EdDSA, RFC 8032) | The only permitted algorithm. Algorithm agility requires a wire bump. |
| Hash | **SHA-256** | `payload_digest = hex(sha256(jcs(payload)))`. |
| Canonicalization | **JCS (RFC 8785)** | The exact byte sequence signed is the JCS canonicalization of the artifact body. |
| Binary encoding | **base64url without padding** | All signatures and binary fields. |
| Identifiers | **UUIDv7** | `message_id`, capability `jti`, chain ids. Time-ordered. |
| Identity | **SPIFFE ID** + **X.509 SVID** | `spiffe://<trust-domain>/<path>`, carried as a critical URI SAN. |

**Cross-protocol binding rule.** Every JCS-signed artifact prefixes its
signed body with a `typ` field naming the artifact kind (e.g.
`typ: "wt-delegation/v0"`). This binds a signature to its artifact type
so a signature over one artifact can never be replayed as another. The
verifier reconstructs the body — including `typ` — before checking the
signature; a mismatched `typ` fails verification.

## 2. Signed-artifact identifier registry (normative)

Every wire identifier the substrate mints, in one place. Adding a row is
additive; changing or removing one is a backwards-incompatible bump.

| Identifier | Artifact | Module | Phase |
|---|---|---|---|
| `version: "v0"` | Message envelope | `verify_envelope.py` | 1 |
| `wt-cap+jwt` | Capability token (JWS Compact) | `capability_token.py` | 1 |
| `wt-discovery-record/v0` | Discovery record | `discovery_record.py` | 1 |
| *(AuditEvent JSONL)* | Audit / policy-decision log | `audit.py` | 1 |
| *(error payload)* | Security error response | `deny_reason.py` + verifier | 1 |
| `wt-delegation/v0` | Delegation receipt | `delegation_receipt.py` | 2 |
| `wt-review/v0` | Reviewer approval record | `reviewer_workflow.py` | 2 |
| `wt-stepup/v0` | Step-up authorization | `tool_policy_gate.py` | 2 |
| `wt-session/v0` | Session resume token | `session_token.py` | 2 |
| `wt-safe-mode-transition/v0` | Safe-mode transition | `signed_safe_mode.py` | 3 |
| `wt-safe-mode-downgrade/v0` | Safe-mode downgrade | `signed_safe_mode.py` | 3 |
| `wt-readmission/v0` | Recovery readmission | `recovery_readmission.py` | 3 |
| `wt-bootstrap-bundle/v0` | Trust-anchor bootstrap bundle | `bootstrap_bundle.py` | 3 |
| `wt-admission/v0` | Admission decision | `admission_coupling.py` | 3 |
| `wt-policy-bundle/v0` | Signed policy bundle | (policy) | 3 |
| *(X.509 + SPIFFE SAN)* | Workload SVID | `workload_ca.py` | **5** |
| `wt-image-sig/v0` | Image signature attestation | `image_attestation.py` | **5** |

## 3. Frozen Phase 1 contracts (normative — see `contracts/`)

These five contracts are frozen; their schema documents are the
field-level normative source. Summarized here for the consolidated view:

### 3.1 Message envelope (`contracts/envelope-schema.md`)
A JSON object; `version` MUST be `"v0"`, `alg` MUST be `"Ed25519"`. The
signature is EdDSA over the RFC 8785 canonicalization of the object with
`signature` removed. `payload_digest = hex(sha256(jcs(payload)))`. The
carried `capability_token` is bound to the envelope by the token's
`cnf.envelope_digest` claim. `message_id` is UUIDv7; `sender_spiffe_id`
and `recipient_spiffe_id` are SPIFFE IDs; `nonce` and `kid` match their
frozen patterns. **Verification order (normative):** schema validation →
JCS canonicalization → signature → replay/window checks. Nothing
untrusted is acted on before the signature verifies.

### 3.2 Capability token (`contracts/capability-token-schema.md`)
JWS Compact (`<b64u(header)>.<b64u(payload)>.<b64u(sig)>`), `typ:
"wt-cap+jwt"`, detached EdDSA, max 4096 bytes. Least-privilege scope,
short TTL, `cnf` proof-of-possession binding to the envelope digest so a
captured token cannot be replayed on a different envelope.

### 3.3 Discovery record (`contracts/discovery-record-schema.md`)
`typ: "wt-discovery-record/v0"`, signed by a discovery authority over
`(workload_iss, workload_kid, endpoints, issued_at, expires_at)`.
Time-bounded (default 1-hour max TTL, 60-second skew). Stale records
fail the window; forged records fail the signature.

### 3.4 Audit event (`contracts/audit-event-schema.md`)
JSONL, one flat object per line. Required: `timestamp` (RFC 3339 UTC
`Z`), `event_type`, `outcome` (`"allow"`/`"deny"`), `reason`,
`reason_code` (a `DenyReason` value / `"ok"`). Hash-chained for
tamper-evidence. New `event_type` values are additive; existing ones are
immutable.

### 3.5 Security error response (`contracts/security-error-response-schema.md`)
Transport-agnostic deny payload carrying a stable `DenyReason`. Every
gateway/issuer/middleware emits this shape on a security denial so
clients never fall back insecurely on an ambiguous error.

## 4. Phase 5 additions (normative delta)

### 4.1 Workload SVID (`workload_ca.py`)
An X.509 leaf certificate, Ed25519, carrying exactly one **critical
SPIFFE URI SAN** (`spiffe://<trust-domain>/<path>`), signed by a
self-signed internal root. Default TTL **1 hour** ("hours, not weeks").
`verify_svid()` order (normative): shape → issuer/subject match +
signature under the root → time window → key usage (`digital_signature`
set, `key_cert_sign` forbidden on a leaf) → SPIFFE binding. Denials use
the `SVID_*` reason codes. Cross-trust-domain issuance is refused.

### 4.2 Image signature attestation (`image_attestation.py`)
`typ: "wt-image-sig/v0"`. A cosign-style detached Ed25519 signature over
the JCS body `{typ, image_digest, signer_id, signer_kid}` where
`image_digest` is a bare lowercase sha256 hex and `signer_id` is a
SPIFFE ID. `verify_image_signature(sig, expected_digest, issuer_lookup)`
order (normative): shape → **exact digest match** → signer-key lookup →
signature. Denials: `IMAGE_SIG_MALFORMED` / `_DIGEST_MISMATCH` /
`_UNKNOWN_SIGNER` / `_INVALID`. Verification is [RUNNABLE]; the runtime
admission gate that refuses to *run* an unattested image is [REFERENCE]
(deployment).

## 5. End-to-end mesh exchange (normative flow)

The single authoritative wiring is `mesh/test_mesh_round_trip.py`
(`_Fabric`) and `integrations/mcp/test_smoke.py` (`_Stage`). The
normative ordering of a two-node request/response:

```
Node A                          transport                    Node B
  │                                                             │
  │ 1. resolve peer via signed discovery record ───────────────▶
  │    (B.verify_record: sig + window)                          │
  │ 2. admit peer (deny-by-default, SVID/tier/pin) ─────────────▶
  │    authenticate-THEN-authorize; unadmitted → no route       │
  │ 3. build envelope: sign body, bind capability via cnf       │
  │    ──────────────── Frame(source, payload) ────────────────▶│
  │                                     4. B.verify_envelope:    │
  │                                        schema → JCS → sig →  │
  │                                        replay → cap binding  │
  │                                     5. B authorize:          │
  │                                        policy_engine →       │
  │                                        policy.decide audit   │
  │                                        (decision_id in trace)│
  │                                     6. B sign reply envelope │
  │◀─────────────── Frame(source, reply) ───────────────────────│
  │ 7. A.verify_envelope(reply) independently                   │
  │ 8. both nodes' audit chains hash-validate                   │
```

**Invariants the flow enforces** (each pinned by a proof obligation):
- The `Frame.source` is a transport hint, **never** trusted identity;
  identity comes from the verified envelope/SVID (§4.1).
- Step 2 precedes step 4: a peer is authenticated and admitted before
  any request it sends is processed (`mesh_authenticate_then_authorize`,
  `unadmitted_peer_denied`).
- Step 4 precedes step 5: authorization runs only on a verified envelope
  (`envelope_signature_required`, `policy_decision_in_trace`).
- A replayed envelope is rejected at step 4
  (`session_resume_sequence_strict`, and the mesh replay-rejection test).
- The whole exchange re-verifies independently on both ends and both
  audit chains validate (`mesh_round_trip_verifies`,
  `mcp_smoke_round_trip_verifies`).

The same signed envelope verifies **identically** over the in-memory
transport and a real loopback TCP transport, proving the flow is
transport-agnostic (Layer B integrity holds independent of the wire).

## 6. Conformance

An implementation conforms to v0.1 if:

1. It accepts every frozen contract's test vectors
   (`contracts/*-schema.md`) and the discovery vectors pinned by
   `discovery_test_vectors_coherent`.
2. It enforces each artifact's normative verification *order* (§§3–4);
   fail-fast ordering is itself a security property (e.g. never checking
   a signature after acting on the payload).
3. It reproduces the mesh flow (§5) with both audit chains validating.
4. Every denial carries a stable `DenyReason` (§3.5).

The substrate's own conformance is the CI-gated proof-obligations
registry (`proof_obligations.py`): 40 obligations, each resolving to a
passing canonical test, with `test_every_obligation_resolves` blocking a
release on any broken pin.

## 7. What v0.1 does not specify

- **Transport.** mTLS/TLS 1.3, connection management, and network
  addressing are deployment-layer. The substrate binds identity and
  integrity at the envelope layer, above the transport.
- **Key custody and PKI operations.** The root key's HSM/custody,
  issuance workflow, and rotation operations are out of scope; the
  substrate consumes keys through the `IssuerTrustStore` interface.
- **Distributed consensus / gossip.** The discovery *record* format is
  specified; the gossip protocol that disseminates records is not.

These are enumerated with rationale in `DEFERRED.md`.

## Maintenance

When a new signed artifact ships, add its identifier to the §2 registry
and its verification delta to §4 (or a new section), in the same commit
that adds the module — mirroring the CLAUDE.md signed-artifact-pattern
rule. The §2 registry must always be a superset of the `typ` strings
present in the code.
