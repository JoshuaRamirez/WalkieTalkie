# CLAUDE.md — Orientation for AI agents working in this repo

This file is the cold-start brief for an agent picking up the
WalkieTalkie security substrate. Read this once; read
`security-foundations/README.md` for the full primitive inventory;
read `implementation-plan/phases/*.md` for the phase plans and
landed-status annotations.

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

Phase 4 is **planned, not yet implemented**. See
`implementation-plan/phases/phase-4-integration-proof.md`. Its
scope is the minimum integration loop that proves the substrate
works inside a real MCP host: one adapter module, one example host,
one end-to-end smoke test, one integration runbook. Hard 500-line
ceiling on the example host. No drills, observability, or
distributed deployment — those are Phase 5.

Phase 3 §§6–8 + §11 (drills, isolation tests, observability,
phase-close artifacts) and the audit-emission-wiring for Phase 2
primitives that lack it are explicitly deferred to Phase 5; see
DEFERRED.md.

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
