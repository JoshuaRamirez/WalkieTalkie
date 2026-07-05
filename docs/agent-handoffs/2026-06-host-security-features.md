# Handoff: example-host security-feature coverage (2026-06)

Supersedes `2026-06-phase-4-close.md` as the most-recent brief. Read
that one for the still-accurate Phase 4 patterns and cadence; read
this one for what changed after it.

## What just landed

The example MCP host from Phase 4 (D4.1-D4.4) exercised the
message-path core but skipped three Phase 1 security features a real
deployment would enable. This follow-up (D4.5) wired all three into
the running host + smoke test:

- **Rate limiting** — `HostConfig.rate_limiter: IdentityRateLimiter |
  None`. Runs POST-auth (step 1b in `host.handle()`) on the
  authenticated sender; emits a `rate_limit.check` audit event;
  signed `rate_limited` error reply on deny.
- **Capability revocation** — `HostConfig.revocation_list:
  RevocationList | None`, threaded into `verify_envelope` so a
  revoked jti is rejected with `CAP_REVOKED`.
- **Gated issuance** — smoke `_Stage` + `example/_gen_sample_audit.py`
  issuers run an `AllowlistPolicy` (least-privilege grants) instead
  of `AllowAllPolicy`.

The marquee result is `test_smoke.RevocationLifecycleTests`: a
capability that verified a moment ago is rejected on its next use
once its jti is revoked — the substrate's headline
revoke-then-reject claim, demonstrated end-to-end. Plus
`RateLimitLifecycleTests` proves the post-auth hardening invariant
(a spoofed victim-sender burns none of the victim's allowance).

Two new proof obligations pin these: `host_revocation_lifecycle_enforced`,
`host_rate_limit_enforced_post_auth` (34 obligations total).

To stay under the 500-line host ceiling, demo tools and pure helpers
were extracted to `demo_tools.py` / `host_support.py`. The
enabled-feature count in the running host went 12 → 15.

## State at handoff

- 705 substrate + 61 integration tests green.
- ruff clean. host.py at ~469 lines (comfortable headroom).
- All four shipped plan docs annotated; DEFERRED.md updated with the
  host-dormant feature list (what's built but not wired into the
  single-host demo, and why).

## What's still host-dormant (built, CI-pinned, no message flows through)

Per `DEFERRED.md` "Phase 4 (complete) — example host feature
coverage":

- Phase 2: delegation receipts, retrieval policy, prompt assembly,
  instruction isolation, reviewer workflow, checkpointed execution,
  session tokens.
- Phase 3: every mesh/operational primitive.

Wiring any of these into a running system is a real-integration task
(needs delegation chains, multi-turn LLM sessions, a mesh), not a
substrate gap.

## Priority-ordered next options (unchanged from phase-4-close)

1. **Integrate against a real MCP host.** Start from
   `test_smoke.py:_Stage` or `example/_gen_sample_audit.py` — now
   the richest end-to-end wiring in the repo, exercising 15 features.
2. **Wire audit emission for the still-dormant Phase 2 primitives**
   (delegation, retrieval, egress, reviewer, tool gate, checkpointed
   execution, session tokens). The host-security work confirmed the
   pattern: sending traffic through a primitive surfaces shape bugs
   (D4.3 caught an `outcome="ok"` vs `("allow","deny")` defect this
   way).
3. **Write Phase 5** from the Phase 3 §§6-8 + §11 gaps in
   `DEFERRED.md` — only if a compliance/audit need forces it.

## Cadence + anti-patterns

Unchanged — see `CLAUDE.md` and `2026-06-phase-4-close.md`.
