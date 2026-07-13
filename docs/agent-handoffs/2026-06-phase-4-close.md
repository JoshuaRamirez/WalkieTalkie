# Handoff: Phase 4 close (2026-06)

You are picking up the WalkieTalkie security substrate. This is an
in-process Python safety kernel for peer-to-peer MCP-style
workloads. **Phases 0–4 are complete**; Phase 4 (the integration
proof) just closed with the substrate-works-as-a-system smoke test
and an operator runbook.

There is no Phase 5 plan. Whether to write one — and what to put in
it — is the scoping decision waiting for you below.

## Read these before doing anything else (10 minutes total)

1. `CLAUDE.md` (repo root) — workflow conventions, PR-merge
   authorization, signed-artifact pattern, deny-reason stability,
   Phase 4 close-out note pointing at the integration starting
   points (`security-foundations/integrations/mcp/example/_gen_sample_audit.py`
   and `security-foundations/integrations/mcp/test_smoke.py:_Stage`).

2. `DEFERRED.md` (repo root) — the explicit registry of items
   intentionally not shipped, grouped into "deferred (Phase 5
   candidates)", "out of substrate scope", and "beyond v0
   commitment". **Read this before proposing anything**; you'll
   immediately know what's already on the "intentionally not doing"
   list.

3. `implementation-plan/phases/README.md` — index of phase docs
   plus the one-paragraph Phase 4 close-out note documenting what
   running the substrate against a real MCP host actually taught us
   (the smoke test caught a real defect — the host was emitting
   `outcome="ok"` to an audit sink that only accepts
   `("allow", "deny")`).

4. `security-foundations/envelope/proof_obligations.py` — 31
   machine-checked safety invariants. `test_every_obligation_resolves`
   is the CI gate; renaming or deleting a canonical_test breaks it.

5. `security-foundations/integrations/mcp/example/README.md` — the
   operator runbook. Run it yourself end-to-end to confirm the
   substrate is healthy on the host you're working from. Six steps,
   under 15 minutes from a clean clone.

## Verify clean state before proposing work

```bash
.venv/bin/python -m unittest discover \
  -s security-foundations/envelope \
  -t security-foundations/envelope                 # expect 705 OK
.venv/bin/python -m unittest discover \
  -s security-foundations/integrations \
  -t security-foundations/integrations             # expect 55 OK
.venv/bin/ruff check security-foundations          # expect "All checks passed!"
```

If any of those fail, **do not propose new work** — diagnose the
regression first.

## Natural next-slice options, in priority order

### 1. Pivot off the substrate, integrate against a real MCP host

The substrate is now ready for this. Staying in-repo any longer is
mostly diminishing returns. The smoke test fixtures in
`test_smoke.py:_Stage` and `example/_gen_sample_audit.py` are the
canonical starting points; both wire a complete host end-to-end.

What this looks like as a slice: pick a real MCP server (Anthropic's
reference implementation, `mcp-python-sdk`, or whatever the operator
has in mind), build a small adapter that routes its inbound messages
through `ExampleMCPHost.handle()`, run it against a real workload,
and watch what breaks. Every real failure mode is a candidate
Phase 5 scope item; without real failure modes, Phase 5 is
speculation.

### 2. Wire audit emission for the Phase 2 primitives that lack it

Phase 2's delegation receipts, retrieval policy, egress policy,
reviewer workflow, tool policy gate, checkpointed execution, and
session tokens all return decisions but don't emit
`audit.AuditSink.record(...)` events. The D4.3 smoke test caught the
host's outcome-alphabet defect because we'd finally sent traffic
through the audit pipe — wiring the rest of Phase 2 will likely
catch the same shape of bug.

This is a small slice per primitive (~50-100 lines each, including
tests). Each one updates `proof_obligations.py` with an
"emits audit event" obligation pointing at its backing test.

### 3. Write Phase 5 to address the Phase 3 §§6–8 + §11 gaps

`DEFERRED.md` enumerates these: compound-failure drill harness,
shared-component isolation tests, observability surface, phase-close
evidence bundle. **Only do this if the operator has a specific
compliance or audit need that forces the work.** Otherwise see
option 1 — real running experience will tell you which of these
gaps actually matters, and you can scope Phase 5 from operational
learnings instead of speculation.

## Anti-patterns (do not commit any of these)

- Inventing a new module shape when an existing pattern fits.
- Shipping a slice without updating the plan + README + obligations.
- Adding a ProofObligation pointing at a test you haven't written.
- Bypassing the obligations resolution check.
- Feature flags or backwards-compat shims — every module is v0;
  breaking changes happen by replacing the module.

## Cadence (same as the prior sessions)

```
git checkout -b claude/<slug>
# write slice, cite plan deliverable in commit + PR title
# update plan doc with **Landed (v0):** annotation
# update security-foundations/README.md with a primitive entry
# add proof obligation for any new invariant
.venv/bin/python -m unittest discover \
  -s security-foundations/envelope \
  -t security-foundations/envelope          # must stay green
.venv/bin/python -m unittest discover \
  -s security-foundations/integrations \
  -t security-foundations/integrations      # must stay green
.venv/bin/ruff check security-foundations    # must stay clean
git add -A && git commit -m "..."
git push -u origin claude/<slug>
mcp__github__create_pull_request
mcp__github__merge_pull_request
git checkout main && git pull origin main
```

The user has standing authorization to create and merge PRs from
inside the session. The cadence is the substrate's coherence —
follow it.

## What the previous session ended on

- 31 PRs merged in one session (#28–#57).
- 760 tests green at handoff (705 substrate + 55 integration).
- 32 proof obligations machine-checked.
- All four shipped phase docs (Phase 1, 2, 3, 4) have every
  deliverable annotated `**Landed (v0):**` or `**Deferred:**`.
- The previous session's reference URL was
  `https://claude.ai/code/session_0148d5aCV1mxhwPhHwwsQAAm`. Use a
  fresh session URL in your own commits.

When you write the next handoff brief, add it to
`docs/agent-handoffs/` with the date prefix and update the index in
`docs/agent-handoffs/README.md`.
