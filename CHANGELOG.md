# Changelog

All notable changes to WalkieTalkie are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

No versioned release has been cut yet, so everything to date sits under
**Unreleased**. Development milestones are tracked as phases; each phase's
deliverables carry `**Landed (v0):**` annotations in
[`implementation-plan/phases/`](./implementation-plan/phases/).

## [Unreleased]

### Added

- **Phase 0 — Security Foundations.** Signed-envelope kernel: RFC 8785 (JCS)
  canonicalization, in-process Ed25519 verification, replay caches (in-memory
  and SQLite), and a filesystem trust store.
- **Phases 1–3 — Messaging → Controlled Autonomy → Resilience.** Capability
  tokens, delegation receipts, retrieval/egress/tool policies, safe-mode
  engine, sybil deterrence, and eclipse resistance.
- **Phase 4 — Integration Proof.** End-to-end MCP host wiring.
- **Phase 5 — The Fabric.** In-process mesh: transport ABC + `Frame`, file-based
  discovery, and a loopback round-trip harness.
- **Phase 6 — The Network.** Real network stack, all [RUNNABLE]: mutual TLS 1.3
  transport with SPIFFE-style SVIDs (`mesh/tls_transport.py`), SWIM gossip
  membership with failure detection (`mesh/membership.py`), gossip discovery
  over admitted peers (`mesh/gossip_discovery.py`), multi-hop routing with TTL +
  seen-set + deny-by-default (`mesh/routing.py`), and a persistent connection
  pool (`mesh/connection_pool.py`).
- **MCP integration examples** on the mesh: a bridge that puts a Claude instance
  on the mesh with an inbox + hook (`integrations/mcp/bridge/`), a federation
  gateway aggregating multiple tool servers (`integrations/mcp/federation/`), and
  a workspace-status server that shares progress without context-switching the
  owner, with a spoof-resistant identity binding (`integrations/mcp/workspace/`).
- **Proof-obligation registry** (`envelope/proof_obligations.py`): 48 invariants,
  each pinned by a canonical test and gated by `test_every_obligation_resolves`.
- Root `README.md`, `SECURITY.md` disclosure policy, `CHANGELOG.md`,
  `CONTRIBUTING.md`, and a `.github/pull_request_template.md`.

### Changed

- Version set to `0.1.0` (first coherent milestone: Phases 0–6 complete).
- CI now runs the full test suite (all six import roots — envelope, mesh, and the
  MCP examples), not just the envelope package.
- Packaging metadata modernized: accurate description, `readme`, `license`
  (EPL-2.0), authors, keywords, trove classifiers, and project URLs.
- Packaging scoped honestly to the current reality: the project runs from a
  source checkout and is not yet a `pip install`-able library (the
  import-restructure that would make it one is tracked in `DEFERRED.md`).

### Fixed

- Resolved a stranded, disjoint-history branch against `main` so the two no
  longer conflict.
- Raised the `cryptography` dependency floor from `>=41` to `>=42`: the X.509
  layer uses the `*_utc` certificate accessors added in cryptography 42, so a
  fresh install resolving 41 would fail at runtime.

[Unreleased]: https://github.com/JoshuaRamirez/WalkieTalkie/commits/main
