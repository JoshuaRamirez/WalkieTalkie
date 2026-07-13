# WalkieTalkie

[![test](https://github.com/JoshuaRamirez/WalkieTalkie/actions/workflows/test.yml/badge.svg)](https://github.com/JoshuaRamirez/WalkieTalkie/actions/workflows/test.yml)

A **security substrate for peer-to-peer, MCP-style AI-agent workloads** — a
safety kernel that lets autonomous agents discover each other, exchange
requests and responses, and cooperate, with security constraints kept primary
over feature velocity.

The design premise, stated in full in
[`SECURITY_FIRST_P2P_MCP_PLAN.md`](./SECURITY_FIRST_P2P_MCP_PLAN.md): threat
model first, then build controls for confidentiality, integrity, authenticity,
authorization, and auditability *before* the features that would depend on them.

## Status

Phases 0 through 6 are complete and tested. **961 unit tests** across six
suites, **48 registered proof obligations**, `ruff` clean, byte-compiles on
Python 3.11 and 3.12.

| Phase | Theme | What landed |
|-------|-------|-------------|
| 0 | Security foundations | Signed-envelope kernel: JCS canonicalization, Ed25519 verify, replay cache, trust store |
| 1–3 | Messaging → autonomy → resilience | Capability tokens, delegation receipts, retrieval/egress/tool policies, safe-mode, sybil deterrence, eclipse resistance |
| 4 | Integration proof | End-to-end MCP host wiring |
| 5 | The Fabric | In-process mesh: transport ABC, file discovery, loopback round-trip |
| 6 | The Network | Real network stack: mutual TLS 1.3 transport, SWIM gossip membership, multi-hop routing, connection pooling |

Every shipped deliverable is annotated `**Landed (v0):**` in
[`implementation-plan/phases/`](./implementation-plan/phases/) with a pointer to
the module that implements it.

## Honesty model

Capabilities are labelled so claims never outrun reality:

- **[RUNNABLE]** — real, tested code that runs today with no external
  infrastructure (the envelope kernel, the mesh transport/gossip/routing, the
  MCP integration examples).
- **[REFERENCE]** — runnable models, generators, or verifiers whose
  *enforcement* still needs deployment infrastructure (production PKI custody,
  WAN/NAT traversal, a container runtime). These are documented as such, not
  presented as operational.

The boundary is explicit: the mesh runs over loopback and localhost sockets.
That bounds **scale and reachability, not security** — WAN deployment (NAT/STUN/
TURN, PKI custody, mesh scale, runtime sandboxing) is the Phase 7 frontier and
is tracked in [`DEFERRED.md`](./DEFERRED.md) and
[`docs/deployment-networking.md`](./docs/deployment-networking.md).

## What's proven

[`security-foundations/envelope/proof_obligations.py`](./security-foundations/envelope/proof_obligations.py)
is the stable registry of every safety invariant the substrate claims to
enforce; each entry names the canonical test that pins it. The companion
`test_every_obligation_resolves` asserts every backing test still exists — a
renamed or deleted test fails CI. New invariant ⇒ new obligation, in the same
commit.

## Repository map

```
security-foundations/
  envelope/            Phase 0 safety kernel — the in-process trust core
  mesh/                Phase 5–6 network stack
    transport.py         Transport ABC + Frame
    socket_transport.py  localhost sockets
    tls_transport.py     mutual TLS 1.3 with SPIFFE-style SVIDs  [RUNNABLE]
    membership.py        SWIM gossip membership + failure detection
    gossip_discovery.py  alive ∩ admitted peer discovery
    routing.py           multi-hop routing, TTL + seen-set, deny-by-default
    connection_pool.py   persistent pooled connections
  integrations/mcp/    MCP-over-stdio examples on the mesh
    bridge/              bridge a Claude instance onto the mesh (inbox + hook)
    federation/          aggregate multiple tool servers behind one gateway
    workspace/           share workspace status without context-switching the owner
docs/                  design notes, deployment frontier, agent handoffs
implementation-plan/   per-phase plans with landed-status annotations
```

## Install and test

```sh
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Each package and example is its own import root (some MCP subdirs have no
`__init__.py` and set up `sys.path` per test), so run the suites per-root:

```sh
for r in \
  security-foundations/envelope \
  security-foundations/mesh \
  security-foundations/integrations/mcp \
  security-foundations/integrations/mcp/bridge \
  security-foundations/integrations/mcp/federation \
  security-foundations/integrations/mcp/workspace ; do
  .venv/bin/python -m unittest discover -s "$r" -t "$r"
done
.venv/bin/python -m ruff check security-foundations
```

CI (`.github/workflows/test.yml`) runs the same install, `compileall`, `ruff`,
and all six suites on Python 3.11 and 3.12.

> Note: the envelope suite needs `cryptography >= 42` for the modern X.509 API.
> A system-packaged `cryptography 41` (as some distros ship) will fail to
> import; the isolated virtualenv above avoids that.

## Threat model

The eight threat classes the substrate is built against — identity spoofing,
message tampering/replay, capability escalation, data exfiltration, model
manipulation, supply-chain compromise, runtime breakout, and
consensus/availability attacks — are enumerated in
[`SECURITY_FIRST_P2P_MCP_PLAN.md`](./SECURITY_FIRST_P2P_MCP_PLAN.md#1-threat-model-first-non-negotiable).

## For agents picking up this repo

Read [`CLAUDE.md`](./CLAUDE.md) first — it is the cold-start brief, including the
proof-obligation workflow rule and the branch/commit conventions.

## License

See [`LICENSE`](./LICENSE).
