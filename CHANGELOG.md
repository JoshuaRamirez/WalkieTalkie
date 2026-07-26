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
- **Cross-machine networking.** The mesh transports (`socket_transport`,
  `tls_transport`, `connection_pool`) take `bind_host` / `advertise_host`, so a
  node can bind all interfaces and advertise a routable address. Peers on a
  mutually reachable network (LAN, VPN, or port-forwarded hosts) now connect
  over the identical mTLS + signed-envelope path — no longer loopback-only. The
  default is unchanged (loopback), and the security logic (mTLS peer
  verification, admission) is untouched; only the bind interface is
  configurable. New tests pin identity binding over a wildcard (`0.0.0.0`) bind.
- **Proof-obligation registry** (`envelope/proof_obligations.py`): 53 invariants,
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

### Security

- **`verify_envelope` now fails closed on malformed input.** The inbound
  envelope is attacker-controlled JSON, but the verifier assumed each field's
  Python type: regex matches, set membership, and `str.replace` all *raise* on
  the wrong type instead of returning False. A peer sending
  `{"message_id": 123, …}` — or a payload nested 20k deep, or a value outside
  the JSON data model — got the verifier to throw a bare `TypeError` /
  `AttributeError` / `RecursionError`. That exception escaped every caller's
  `except EnvelopeVerificationError` handler **and** bypassed the verifier's
  own deny path, so the probe emitted **no audit event** — silent, and remotely
  reachable through `envelope_from_json`, which validates only that the wire
  bytes decode to a JSON object. Deep nesting was additionally a stack-
  exhaustion DoS. The verifier now type-checks fields before matching them,
  bounds nesting via `VerificationConfig.max_json_depth` (default 64, checked
  iteratively), converts canonicalization failures into denials, and backstops
  the path with a `verifier_internal_error` denial so no input yields anything
  but `EnvelopeVerificationError`. New deny reasons: `envelope_not_object`,
  `envelope_too_deep`, `envelope_not_canonicalizable`,
  `verifier_internal_error`. Pinned by `envelope/test_verifier_fail_closed.py`
  and three new proof obligations.
- **The denial audit path now survives the input it reports on.** The audit
  context is read off the envelope *before* validation — a denial has to name
  the message it denied — so those values are attacker-controlled, and the sink
  JCS-canonicalizes what it is handed in order to hash it. A field the encoder
  rejects therefore made the sink raise *while recording the denial*, so the
  foreign exception escaped the deny handler and no event was written. This is
  reachable from the wire: `json.loads` accepts a bare `NaN`, so
  `{"sender_spiffe_id": NaN}` parses. Identity fields are now coerced to
  bounded safe strings (`audit_safe`) before they reach the sink — which also
  stops an unbounded field from bloating every downstream audit record.
- **An allow that cannot be audited is now a denial.** A sink that raises (disk
  full, permissions) previously leaked its own `OSError` out of the verifier,
  reopening the partial-deny-path hole from the other end — and `_record` is
  called from inside the deny handlers themselves. Sink failures now surface as
  an `audit_sink_failure` denial with the cause chained. Fail-closed is the
  point: the hash-chained log exists to make unaudited allows impossible.
- **Bounded the depth check's own memory.** `check_json_depth` queued one tuple
  per child including scalars, so a wide-but-shallow payload (a few MB of frame
  holding millions of compact integers) cost hundreds of MB of transient
  tuples — a memory-exhaustion DoS inside the check meant to prevent one. Only
  containers are queued now, so auxiliary memory tracks nesting depth rather
  than breadth. New deny reason: `audit_sink_failure`.

[Unreleased]: https://github.com/JoshuaRamirez/WalkieTalkie/commits/main
