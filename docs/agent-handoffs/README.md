# Agent handoff prompts

This directory persists agent-to-agent handoff briefs at each major
substrate milestone. The cold-start orientation in `CLAUDE.md` and
the unbuilt-work registry in `DEFERRED.md` give a fresh agent the
*durable* repo state; the dated briefs below give an agent the
*moment-in-time framing* the previous session ended on — including
which next-slice options were live and why.

## Convention

Each file is `YYYY-MM-{slug}.md` where the slug names the milestone
or pivot point being handed off (e.g. `phase-4-close`,
`audit-emission-wiring-start`). Newest at the bottom of the index.

A new agent picking up the work should:

1. Read `CLAUDE.md` (workflow + patterns + conventions).
2. Read `DEFERRED.md` (what's intentionally not done).
3. Read **only the most recent** handoff brief in this directory
   (older ones are historical context, not instructions). Older
   briefs are kept because they record the rationale for past
   pivots; do not act on them.

## Index

| File | Hand-off moment |
|---|---|
| [2026-06-phase-4-close.md](./2026-06-phase-4-close.md) | Phase 4 (integration proof) closed; substrate now has an operator runbook. Pivot options: integrate against a real MCP host, write Phase 5, or wire audit emission for the Phase 2 primitives that lack it. |
| [2026-06-host-security-features.md](./2026-06-host-security-features.md) | Example host now wires rate limiting, capability revocation, and gated issuance; revoke-then-reject lifecycle demonstrated end-to-end. Enabled-feature count 12 → 15. |
| [2026-07-phase-5-close.md](./2026-07-phase-5-close.md) | Phase 5 "The Fabric" complete: real X.509 SVID identity, deny-by-default admission, native decision-ID policy engine, and a two-node authenticated mesh completing a signed round trip over in-memory + real TCP. 40 proof obligations. Phase 6 = the deployment-enforcement frontier. |
| [2026-07-phase-6-close.md](./2026-07-phase-6-close.md) | Phase 6 "The Network" complete: real mutual TLS 1.3 (SVID peer auth), SWIM gossip membership + failure detection, gossip discovery gated by admission, multi-hop deny-by-default routing, pooled connections — culminating in a 3-node A→relay→C signed round trip over mTLS. 48 proof obligations. Loopback ≠ fake; Phase 7 = real WAN/NAT, PKI custody, kernel sandbox, mesh scale. |
| [2026-07-release-prep.md](./2026-07-release-prep.md) | **(most recent)** Release-readiness sweep on branch `claude/resolve-merge-conflicts-tMxSj` (not merged): conflict resolution, full-suite CI, packaging metadata + `cryptography>=42` fix, README/SECURITY/CHANGELOG/CONTRIBUTING/PR-template, doc-vs-code reconciliation. 961 tests green. One real blocker (installed wheel doesn't import — source-checkout only; Path A measured as a dedicated phase). Gated on 5 maintainer decisions: packaging model (rec Path B), version+tag, package names, EPL-2.0, PR-to-main. |
