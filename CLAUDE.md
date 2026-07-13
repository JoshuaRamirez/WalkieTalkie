# CLAUDE.md — Orientation for AI agents working in this repo

This file is the cold-start brief for an agent picking up the
WalkieTalkie security substrate. Read this once; read
`security-foundations/README.md` for the full primitive inventory;
read `implementation-plan/phases/*.md` for the phase plans and
landed-status annotations; read the **most recent** brief in
`docs/agent-handoffs/` for the moment-in-time framing the previous
session ended on.

## What this repo is

WalkieTalkie is a security substrate for peer-to-peer MCP-style
workloads. The `security-foundations/envelope/` package is the
in-process safety kernel: cryptographic envelope verification,
capability tokens, delegation receipts, retrieval / egress / tool
policies, safe-mode engine, sybil deterrence, etc. There is no
network layer, no persistence backend, no live deployment — this
is the kernel only.

Phases shipped (Phase 0 through Phase 3) are tracked in
`implementation-plan/phases/`. Every deliverable in those docs is
annotated `**Landed (v0):**` with a pointer to the module that
implements it.

## Source of truth for "what's proven"

`security-foundations/envelope/proof_obligations.py` holds the
stable registry of every safety invariant the substrate claims to
enforce. Each entry names a canonical test that pins it. The
companion `test_every_obligation_resolves` test imports each
canonical-test path and asserts the test method exists — a renamed
or deleted backing test fails CI.

**Workflow rule:** when you ship a new safety invariant, add a
`ProofObligation` entry pointing at its backing test. When you
intentionally retire one, delete the entry in the same commit.

## Workflow conventions

The user has standing authorization to create and merge PRs from
within an agent session. The cadence is:

1. `git checkout -b claude/<slug>` from `main`.
2. Write the slice. Cite the plan deliverable (e.g. "Phase 3 Track
   B B3") in the commit message AND the PR title.
3. Update the relevant `implementation-plan/phases/*.md` deliverable
   with a `**Landed (v0):**` annotation.
4. Update `security-foundations/README.md` with a primitive entry.
5. Add proof obligations for new invariants in
   `security-foundations/envelope/proof_obligations.py`.
6. Run `.venv/bin/python -m unittest discover -s
   security-foundations/envelope -t security-foundations/envelope`
   and `.venv/bin/ruff check security-foundations`. Both must be
   clean.
7. Commit with a substantive message (what, why, what changed, test
   delta). Include `https://claude.ai/code/session_<id>` as the
   trailing reference.
8. `git push -u origin claude/<slug>`.
9. `mcp__github__create_pull_request` against `main`.
10. `mcp__github__merge_pull_request` with `merge_method="merge"`.
11. `git checkout main && git pull origin main`.

If the repo doesn't have a `.venv`, recreate with
`python -m venv .venv && .venv/bin/pip install -e ".[dev]"`.

## Pattern for signed artifacts

The codebase uses a consistent shape for EdDSA-signed JCS-canonical
records. See `delegation_receipt.py`, `reviewer_workflow.py`,
`tool_policy_gate.py` (step-up), `recovery_readmission.py`,
`signed_safe_mode.py`. The pattern:

- Frozen dataclass with all fields including `signature`.
- `_body(...)` builds a dict with `typ: "wt-<kind>/v0"` cross-protocol
  binding, runs `jcs.canonicalize`.
- `sign_<thing>()` returns a copy with the signature populated.
- `verify_<thing>()` validates shape → bindings → time window →
  signature, in that order, fail-fast on each.
- `from_json` / `to_json` for serialization.
- Lookup via `IssuerTrustStore`-shaped `Callable[[str, str], bytes]`.

When you add a new signed artifact, follow this pattern exactly.
Don't invent a new shape unless there's a documented reason.

## Pattern for deny reasons

`security-foundations/envelope/deny_reason.py` holds the stable
taxonomy. Names are immutable once shipped (see the stability
contract in the module docstring). Add new codes at the end of the
relevant section; never reuse a name for a different invariant.

## What is NOT proven (read DEFERRED.md)

The proof-obligations registry covers the substrate's safety
invariants. It does **not** cover performance, distributed
behavior, real-world adversarial coverage beyond the 18-entry
adversarial corpus, or formal model checking. The full list of
intentionally deferred and out-of-scope items lives in
`DEFERRED.md` at the repo root. Read it before proposing work that
might already be on the "intentionally not doing" list.

## Phase 4 status

Phase 4 is **complete**. See
`implementation-plan/phases/phase-4-integration-proof.md`. The
deliverables that landed:

- D4.1 MCP envelope adapter — `security-foundations/integrations/mcp/envelope_adapter.py`.
- D4.2 Example MCP host — `security-foundations/integrations/mcp/host.py`, hard 500-line ceiling, pinned by `test_host.HostLineCountTests`.
- D4.3 End-to-end smoke test — `security-foundations/integrations/mcp/test_smoke.py`, drives a real signed envelope through the full substrate pipeline and asserts the reply independently re-verifies. Pinned by proof obligation `mcp_smoke_round_trip_verifies`.
- D4.4 Integration runbook — `security-foundations/integrations/mcp/example/README.md` walks a fresh operator from `git clone` to a passing smoke test in under 15 minutes. `gen_keys.py` mints deterministic Ed25519 keypairs + trust-store manifests; `_gen_sample_audit.py` produces a hash-chained reference audit log under `sample-audit.jsonl`.

When integrating against a real MCP host, **start from the smoke
test fixtures in `test_smoke.py:_Stage` or `example/_gen_sample_audit.py`**
— they're the two places that wire a complete host end-to-end.

## Phase 5 status

Phase 5 (**The Fabric**) is **complete**. See
`implementation-plan/phases/phase-5-the-fabric.md` (§10 close-out) and
the handoff brief `docs/agent-handoffs/2026-07-phase-5-close.md`. It
closed the gap between the kernel and the
`SECURITY_FIRST_P2P_MCP_PLAN.md` vision. The deliverables that landed:

- **Track A — Real Identity [RUNNABLE]:** `workload_ca.py` (Ed25519
  X.509 SVIDs with a critical SPIFFE URI SAN, 1-hour TTL, `verify_svid`
  fail-fast chain), `peer_admission.py` (deny-by-default admission with
  cert pinning).
- **Track B — Policy Engine [RUNNABLE]:** `policy_engine.py` (structured
  first-match deny-by-default evaluator with UUIDv7 decision IDs — a
  native engine, not a DSL), `policy_audit.py` (`policy.decide` events
  with the decision ID in the forensic trace).
- **Track C — The Mesh [RUNNABLE]:** `mesh/` package — `transport.py`
  (`Transport` ABC + `InMemoryTransport`), `node.py` (authenticate-
  then-authorize `MeshNode`), `socket_transport.py` (real loopback TCP).
  The two-node signed round trip verifies over both transports.
- **Track D — Runtime Tiers [REFERENCE]:** `runtime_profile.py` (trust-
  tier model + `generate_seccomp` OCI document), `image_attestation.py`
  (cosign-style image-signature verification).
- **Track E — Evidence [DOCS]:** `docs/threat-model.md` (STRIDE),
  `docs/compliance-mapping.md` (obligations → SOC 2 / ISO 27001 /
  GDPR), `docs/protocol-spec-v0.1.md` (consolidated wire spec).

Every slice is labeled **[RUNNABLE]** (real tested code, no infra) or
**[REFERENCE]** (data model / generator / verifier that is runnable
and tested, but whose enforcement needs deployment infrastructure —
a kernel, a container runtime, a real network). No slice claims
enforcement it doesn't have. The proof-obligations registry now holds
40 obligations, all resolving.

When integrating a real mesh deployment, **start from
`mesh/test_mesh_round_trip.py:_Fabric`** — it wires two complete
`MeshNode`s end-to-end (discovery → admission → signed request →
verify → authorize → reply → re-verify, both audit chains validating).

Phase 3 §§6–8 + §11 (drills, isolation tests, observability,
phase-close artifacts) and the audit-emission-wiring for Phase 2
primitives that lack it remain deferred; see DEFERRED.md.

## Phase 6 status

Phase 6 (**The Network**) is **complete**. See
`implementation-plan/phases/phase-6-the-network.md` (§10 close-out) and
the handoff brief `docs/agent-handoffs/2026-07-phase-6-close.md`. It
turned the Phase 5 mesh (connection-per-frame loopback, file discovery,
direct-only) into a **real network stack**, all [RUNNABLE] and tested on
loopback:

- **Track A — mTLS [RUNNABLE]:** `mesh/tls_transport.py`
  (`TlsSocketTransport` — mutual TLS 1.3, each peer presents its Phase 5
  SVID, verified by TLS *and* the substrate `verify_svid`). Signed round
  trip verifies over the encrypted channel; the two layers agree on
  identity.
- **Track B — Gossip [RUNNABLE]:** `mesh/membership.py`
  (`SwimMembership` — join/heartbeat/suspicion/failure-detection + gossip
  + incarnation refutation) and `mesh/gossip_discovery.py`
  (`GossipDiscovery` — discovery is not authorization: routable = alive ∩
  admitted).
- **Track C — Routing [RUNNABLE]:** `mesh/routing.py` (`Router` —
  multi-hop forwarding, deny-by-default, loop-safe) with the 3-node
  multi-hop signed round trip over mTLS (`test_mtls_multihop`).
- **Track D — Connections [RUNNABLE]:** `mesh/connection_pool.py`
  (`PooledSocketTransport` — persistent/keepalive/reconnect/bounded pool;
  operational, no safety obligation).
- **Track E — Frontier [DOCS]:** `docs/deployment-networking.md` — the
  honest WAN boundary (NAT, PKI custody, scale) and which seam each
  attaches through.

**The load-bearing rule Phase 6 reinforced:** loopback bounds *scale and
reachability, not security*. mTLS over `127.0.0.1` is real TLS; an
in-process gossip cluster is a real protocol. What stays [REFERENCE] (the
deployment-networking doc) is exactly the part that *is* infrastructure.
The proof-obligations registry now holds **48** obligations, all
resolving.

When integrating a real WAN deployment, **start from
`mesh/test_mtls_multihop.py`** (the full stack composed: mTLS + routing +
signed envelope, A→relay→C) and attach the deployment pieces through the
seams named in `docs/deployment-networking.md`. Kernel-sandbox
enforcement, production PKI custody, real WAN/NAT, and mesh scale are the
Phase 7 candidate pool.

## Anti-patterns

- Don't create a new module pattern when an existing pattern fits.
  The substrate's coherence is its strength.
- Don't ship a slice without updating the plan doc and the README.
  The agent that follows you will trust these as the inventory.
- Don't add a ProofObligation pointing at a test you haven't
  written. The CI gate will fail on the same commit; you'll have
  to amend.
- Don't bypass the proof-obligations resolution check by editing
  the registry to remove an obligation whose backing test is
  failing. Fix the underlying invariant or document the retirement
  in the same commit.
- Don't ship a "feature flag" or "backwards compat shim." Every
  module is v0; breaking changes happen by replacing the module.
