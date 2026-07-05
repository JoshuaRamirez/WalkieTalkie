# Detailed Implementation Plan by Phase

This directory contains execution-focused plans for each build phase:

1. [Phase 0 — Security Foundations](./phase-0-security-foundations.md)
2. [Phase 1 — Minimal Secure Messaging](./phase-1-minimal-secure-messaging.md)
3. [Phase 2 — Controlled Autonomy](./phase-2-controlled-autonomy.md)
4. [Phase 3 — Resilience and Scale](./phase-3-resilience-and-scale.md)
5. [Phase 4 — Integration Proof](./phase-4-integration-proof.md)
6. [Phase 5 — The Fabric](./phase-5-the-fabric.md)

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
