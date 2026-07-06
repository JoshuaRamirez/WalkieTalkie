# Detailed Implementation Plan by Phase

This directory contains execution-focused plans for each build phase:

1. [Phase 0 — Security Foundations](./phase-0-security-foundations.md)
2. [Phase 1 — Minimal Secure Messaging](./phase-1-minimal-secure-messaging.md)
3. [Phase 2 — Controlled Autonomy](./phase-2-controlled-autonomy.md)
4. [Phase 3 — Resilience and Scale](./phase-3-resilience-and-scale.md)
5. [Phase 4 — Integration Proof](./phase-4-integration-proof.md)
6. [Phase 5 — The Fabric](./phase-5-the-fabric.md)
7. [Phase 6 — The Network](./phase-6-the-network.md)

## Plan quality and verification
- [Plan Verification Report](./plan-verification-report.md)

The verification report checks each phase plan for:
- complete section coverage,
- consistency of sequencing and dependency assumptions,
- presence of test strategy and explicit exit gates,
- actionable closeout artifacts for governance and release decisions.

## Standard plan structure
Each phase document includes:
- mission and scope,
- concrete deliverables,
- work breakdown structure,
- acceptance criteria,
- test strategy,
- risks and exit gates,
- closeout artifact checklist.

## Phase 4 close-out note

Phase 4 shipped exactly what its plan called for: the substrate
primitives compose end-to-end against an in-process MCP host, the
reply re-verifies independently, and an operator can reproduce the
loop from a clean `git clone` in well under 15 minutes via
`security-foundations/integrations/mcp/example/README.md`. What
running the substrate against a real MCP host taught us, in one
paragraph: the host's audit emissions had been using the wrong
outcome alphabet (`"ok"` instead of `"allow"`) — a real defect
that no unit test caught because no unit test sent traffic through
the audit pipe. The smoke test surfaced it immediately. That's
exactly the value Phase 4 was supposed to deliver: forcing the
primitives to actually compose under load reveals shape mismatches
that primitive-level testing can't. Phase 5, if it exists, should
be scoped from operational learnings of this kind, not from another
round of primitive design.

## Phase 5 close-out note

Phase 5 ("The Fabric") did the one thing the Phase 4 note warned
against — it went back to primitive design — but for a defensible
reason: a gap analysis against the `SECURITY_FIRST_P2P_MCP_PLAN.md`
vision showed the kernel had the *hard* parts (signed envelopes,
capabilities, delegation, safe-mode) but was missing the *connective*
Layer A identity, the Layer C policy engine, and the §5 mesh that turn
a pile of primitives into a fabric. Phase 5 built exactly those and
nothing more: real Ed25519 X.509 SVIDs, deny-by-default peer admission,
a native decision-ID'd policy engine, and a two-node authenticated mesh
that completes a signed round trip over both an in-memory transport and
real loopback TCP — with both audit chains hash-validating.

What building the fabric taught us, in one paragraph: **the honesty
label was the load-bearing design decision.** Forcing every slice to
declare [RUNNABLE] vs [REFERENCE] up front stopped the mesh and runtime
work from quietly overclaiming. `runtime_profile.py` /
`generate_seccomp` / `image_attestation.py` are genuinely useful — they
produce loadable seccomp documents and verify real attestations — but
none of them *enforce* anything in-process, and saying so plainly (in
the docstrings, the plan, the threat model, and the compliance mapping)
is what keeps the substrate trustworthy as an inventory. The proof-
obligations registry grew from 34 to 40; every new *machine-checkable*
invariant got one, and the [REFERENCE] generators deliberately did not
(a seccomp document's shape is testable; claiming it's an *enforcement*
invariant would be the lie the labels exist to prevent). Phase 6, if it
exists, is the deployment-enforcement frontier catalogued in
`DEFERRED.md` — kernel sandbox, image admission, mTLS, PKI custody,
mesh scale — none of which the in-process kernel can be.
