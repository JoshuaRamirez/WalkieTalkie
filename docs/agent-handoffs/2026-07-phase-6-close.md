# Handoff: Phase 6 "The Network" close (2026-07)

Supersedes `2026-07-phase-5-close.md` as the most-recent brief. Read
`CLAUDE.md` for durable patterns/cadence and `DEFERRED.md` for what's
intentionally not done; read this for the moment-in-time framing Phase 6
ended on.

## What just landed

Phase 6 turned the Phase 5 mesh (connection-per-frame loopback, file
discovery, direct-only, no wire encryption) into a **real network
stack** — all [RUNNABLE], loopback-tested, production-shaped. Nine
iterations, each a branch → PR → merge:

- **Track A — mTLS [RUNNABLE].** `mesh/tls_transport.py`
  (`TlsSocketTransport`) is genuine mutual **TLS 1.3** with SVID peer
  auth: each node presents its Phase 5 SVID; every handshake verifies the
  peer cert via TLS *and* the substrate `verify_svid`, yielding the peer
  SPIFFE id as `Frame.source`. `test_mtls_round_trip` re-runs the Phase 5
  signed round trip over it and proves the two layers **agree on
  identity** (TLS peer id == envelope signed sender).
- **Track B — Gossip [RUNNABLE].** `mesh/membership.py`
  (`SwimMembership` — join-via-seed, ping/ack failure detection
  ALIVE→SUSPECT→DEAD, gossip dissemination, incarnation refutation) and
  `mesh/gossip_discovery.py` (`GossipDiscovery` — routable = reachable ∩
  admitted; **discovery is not authorization**).
- **Track C — Routing [RUNNABLE].** `mesh/routing.py` (`Router` —
  multi-hop forwarding, deny-by-default, TTL + seen-set loop safety) and
  `mesh/test_mtls_multihop.py` — a 3-node A→relay→C signed round trip
  where each hop is its own mTLS connection.
- **Track D — Connections [RUNNABLE].** `mesh/connection_pool.py`
  (`PooledSocketTransport` — persistent/reused connections, keepalive,
  reconnect-with-backoff, bounded LRU pool).
- **Track E — Frontier [DOCS].** `docs/deployment-networking.md` — the
  honest WAN boundary and its attach-points.

## The marquee result

`mesh/test_mtls_multihop.py::test_signed_envelope_reaches_far_node_through_relay`:
a signed envelope goes A → relay → C where A and C are not directly
connected, **each hop its own mutual-TLS 1.3 connection**, C verifies A's
signature end-to-end, and the reply re-verifies at A. The relay cannot
forge (it's not the envelope's recipient) and a relay that tampers the
payload fails C's verification. The full stack — mTLS + gossip-shaped
routing + signed envelope — composed.

Pinned by `mesh_multihop_round_trip_verifies`. The registry grew **40 →
48** (8 new: `mtls_two_layer_round_trip_verifies`,
`mtls_unauthenticated_peer_rejected`, `gossip_membership_converges`,
`gossip_detects_downed_node`, `gossiped_peer_still_gated_by_admission`,
`mesh_forwarding_deny_by_default`, `mesh_forwarding_loop_safe`,
`mesh_multihop_round_trip_verifies`).

## State at handoff

- **Tests green:** mesh 53 (was 23) + envelope 794 + mcp 61 + bridge 7.
  ruff clean. All 48 proof obligations resolve.
- All Phase 6 plan deliverables annotated `**Landed (v0):**`;
  `security-foundations/README.md` has primitive entries; CLAUDE.md
  Phase 6 status = complete; DEFERRED.md has the Phase 6-resolved list +
  Phase 7 pool.

## The load-bearing decision: loopback ≠ fake

The single most important framing to preserve. Every network slice is
[RUNNABLE], not [REFERENCE], because **loopback bounds scale and
reachability, not security.** mTLS over `127.0.0.1` is the same handshake
+ encryption as a WAN address; an in-process gossip cluster is the same
protocol as a distributed one. Resist any temptation to relabel these as
[REFERENCE] "because it's one machine" — the security properties are
fully exercised. What genuinely *is* infrastructure (NAT, HSM custody,
scale) is in `docs/deployment-networking.md`, honestly separated.

The one [RUNNABLE] slice that deliberately took **no** proof obligation
is `connection_pool.py` — a reliability feature (how bytes move) is not a
safety invariant (what they mean). Keep that line sharp when extending
Track D.

## What Phase 6 did NOT do — the Phase 7 pool

Per `DEFERRED.md` "Phase 6 (complete)":

1. Kernel-level sandbox enforcement (load the seccomp doc; confine FS).
2. Image-admission enforcement (refuse to run an unattested image).
3. NAT traversal / real WAN reachability (STUN/TURN/ICE, relays).
4. Production PKI custody + SPIRE-style issuance/rotation ops.
5. Membership/routing **at scale** (indirect probing, O(N) load, route
   computation, partitions) — the runnable *forwarding security* is done;
   the scale refinements need many real hosts + real loss.
6. Native-engine → Cedar/Rego interop.
7. Post-quantum signatures; a load/fuzz/chaos program.
8. Fleet-wide observability aggregation.

Every one of these attaches through an existing seam — see the summary
table and "attach-points" in `docs/deployment-networking.md`.

## Priority-ordered next options

1. **Take it to a real WAN.** Write a `RelayTransport` / `IceTransport`
   implementing the `Transport` ABC for NAT traversal, and stand up an
   HSM/SPIRE-backed issuer behind the `IssuerTrustStore` callable. Start
   from `mesh/test_mtls_multihop.py` (the richest end-to-end wiring) and
   the attach-points in `docs/deployment-networking.md`. This is Phase 7,
   not a substrate gap.
2. **Wire the mesh into the MCP bridge** (`integrations/mcp/bridge/`) so
   two Claude instances talk over the *authenticated mesh* (mTLS +
   admission + routing) instead of a bare socket — the security upgrade
   the bridge's README flagged as Phase 6/7.
3. **SWIM scale refinements** (indirect probing, O(N) probe) if a
   larger cluster is actually deployed.

Do **not** relabel or rewrite the [RUNNABLE] network modules without an
explicit upstream reason.

## Cadence + anti-patterns

Unchanged — see `CLAUDE.md`. Branch → cite the plan deliverable in the
commit + PR → update the plan doc `**Landed (v0):**` + README + proof
obligations → full suite + ruff clean → merge → sync `main`.
