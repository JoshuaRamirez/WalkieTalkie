# Phase 6 — The Network Implementation Plan

## 1) Phase Intent

Phase 5 delivered **The Fabric**: real identity (SVIDs), a policy
engine, and an authenticated overlay mesh that completes a signed
two-node round trip over loopback TCP. But the mesh transport is
deliberately minimal — a connection-per-frame loopback socket, peer
discovery via a shared file, direct-only delivery, no wire encryption.

**Phase 6 turns the mesh into a real network stack.** It closes the
gap between "two processes exchange a signed envelope over a socket"
and "a fleet of nodes discover each other, encrypt the wire, and route
messages across the mesh — securely." The vision's §5 zero-trust P2P
topology and Layer A's mTLS requirement land here for real.

The pieces, mapped to the vision:

- **Wire encryption (Layer A / Layer B transport)** — real **mTLS
  1.3** on the socket, with each peer presenting its Phase 5 **SVID**
  and verifying the other's SPIFFE identity during the handshake.
  Defense in depth: TLS authenticates the *channel*; the signed
  envelope still authenticates the *message*.
- **Membership + discovery (§5)** — a real gossip membership protocol
  (SWIM-style: join via seed, heartbeat, suspicion, failure
  detection) so nodes find each other without a shared config file.
- **Routing at scale (§5)** — a routing table and **multi-hop
  forwarding** so a node reaches peers it isn't directly connected to,
  deny-by-default (only forward for admitted peers).
- **Connection management** — persistent, pooled connections with
  keepalive, reconnect-with-backoff, and backpressure, replacing the
  connect-per-frame transport.
- **The deployment frontier (§5, honest reference)** — what real
  internet operation needs beyond a single host (NAT traversal,
  relays, WAN CA custody, planet scale): a tested design doc, not a
  runnable claim.

### Runnable vs. reference (honesty contract)

Same contract as Phase 5:

- **[RUNNABLE]** — real, tested Python that executes in this repo with
  no external infrastructure. Loopback is still a *real* network: mTLS
  over `127.0.0.1` is genuine TLS; a 5-node in-process gossip cluster
  is a genuine membership protocol. Loopback bounds *scale*, not
  *realness*.
- **[REFERENCE]** — a runnable, tested data model / design whose
  *deployment* needs infrastructure this repo can't be (multiple real
  hosts, public internet, a production CA). The boundary is documented,
  never faked.

No slice claims enforcement it doesn't have. A proof obligation is
added only for a machine-checkable invariant.

## 2) Why loopback mTLS + in-process gossip is honest "networking"

A fair challenge: "it's all on one machine — is this really
networking?" The answer the substrate stands behind:

- **mTLS over loopback is real TLS.** The same `ssl` handshake, cipher
  negotiation, certificate verification, and encryption run whether the
  socket is `127.0.0.1` or a WAN address. What loopback removes is
  latency, packet loss, and NAT — *operational* concerns, not
  *security* ones. The security property (an unauthenticated peer
  cannot complete the handshake; the channel is encrypted) is fully
  exercised.
- **In-process gossip is a real protocol.** N `MeshNode`s each with
  their own transport, exchanging membership over real sockets, running
  real failure detection, is the protocol — the algorithm doesn't know
  or care that the sockets happen to share a host.
- **What stays [REFERENCE]** is exactly the part that *is*
  infrastructure: crossing NATs, surviving the public internet,
  custody of a production root key, and scale past what one host's
  ports and threads allow. Those get a design doc, not a fake test.

## 3) Deliverables

### D6.1 mTLS Transport (Layer A/B) [RUNNABLE]
`mesh/tls_transport.py` — `TlsSocketTransport` implementing the
`Transport` ABC over **mutual TLS 1.3**. Each node presents its SVID
(Phase 5 `workload_ca`) and verifies the peer's cert chains to the
trusted root AND carries the expected SPIFFE URI SAN, using the
substrate's `verify_svid`. Deny on any handshake/identity failure.

### D6.2 Secure round trip over mTLS [RUNNABLE]
The Phase 5 two-node signed round trip re-run over `TlsSocketTransport`:
the same signed envelope verifies after crossing an encrypted, mutually
authenticated channel. Proves the two security layers compose (TLS peer
auth + envelope message auth) and that the node code is transport-blind.

### D6.3 Gossip membership (§5) [RUNNABLE]
`mesh/membership.py` — a SWIM-style membership protocol: `join(seed)`,
periodic heartbeat/ping, suspicion + failure detection, member-list
dissemination. An N-node in-process cluster converges on a shared view
and detects a downed node.

### D6.4 Gossip-driven discovery + admission [RUNNABLE]
Wire membership into node discovery: a node learns peers from gossip
(not a shared file), and every learned peer still passes Phase 5
`peer_admission` before entering the routing table. Deny-by-default
holds — a gossiped-but-unadmitted peer is not routable.

### D6.5 Routing table + multi-hop forwarding (§5) [RUNNABLE]
`mesh/routing.py` — a routing table and a forwarding function so node A
reaches node C via B when not directly connected. Forwarding is
deny-by-default (only for admitted peers) and loop-safe (TTL / seen-set).

### D6.6 Multi-hop secure round trip [RUNNABLE]
A 3-node (A–B–C) test: A's signed envelope reaches C through B, C
verifies it end-to-end, replies, A re-verifies. B forwards without being
able to forge or read-as-authentic (it isn't the envelope's recipient).

### D6.7 Connection management [RUNNABLE]
`mesh/connection_pool.py` — persistent pooled connections with
keepalive, reconnect-with-backoff, and bounded backpressure, replacing
connect-per-frame. Same `Transport` ABC surface.

### D6.8 WAN / deployment frontier (§5) [REFERENCE/DOCS]
`docs/deployment-networking.md` — the honest boundary: NAT traversal
(STUN/TURN/relays), WAN CA custody + rotation ops, seed/bootstrap
infrastructure, and scale limits. What each needs, why it's
infrastructure, and how the runnable core plugs into it.

### D6.9 Phase 6 close [DOCS]
Proof obligations for the new invariants, `mesh` README/primitive
entries, `DEFERRED.md` update (what Phase 6 resolved vs. what remains),
CLAUDE.md Phase 6 status, phases/README close-out note, handoff brief.

## 4) Work Breakdown Structure (loop iterations)

Each iteration is one branch → commit → PR → merge cycle. The loop keeps
this plan doc and the task list updated after every iteration.

- **0** Ship this plan (plan-only PR).
- **A1 (D6.1)** `tls_transport.py` — mTLS transport with SVID peer auth. [RUNNABLE]
  **Landed (v0):** `TlsSocketTransport` implements the `Transport` ABC
  over mutual **TLS 1.3** (verified: OpenSSL 3.0.13, Ed25519 SVIDs).
  Each endpoint presents its Phase 5 SVID; on every handshake the peer
  cert is verified twice — by TLS (chains to the trusted root,
  `CERT_REQUIRED`) and by the substrate's `verify_svid` (window + key
  usage + SPIFFE SAN), which yields the peer's SPIFFE id used as the
  `Frame.source`. A peer whose SVID chains to an untrusted root cannot
  complete the handshake, so its bytes never reach the envelope layer.
  `TlsIdentity` + `mint_identity(ca, spiffe_id)` bundle the material;
  hostname check is off (identity is the URI SAN, checked by the
  substrate). 4 tests (valid exchange, untrusted-CA rejected, expired
  SVID dropped, context manager).
- **A2 (D6.2)** Signed round trip over mTLS; two-layer security proof. [RUNNABLE]
  **Landed (v0):** `test_mtls_round_trip` re-runs the Phase 5 signed
  round trip (reusing `_Fabric` verbatim) over `TlsSocketTransport`.
  The same envelope verifies after crossing the encrypted,
  mutually-authenticated channel, and the two layers **agree on
  identity** — the TLS-verified peer SPIFFE id equals the envelope's
  signed sender. Plus: an impostor with an SVID from an untrusted root
  cannot complete the handshake, so its bytes never reach the envelope
  verifier. Two proof obligations added
  (`mtls_two_layer_round_trip_verifies`,
  `mtls_unauthenticated_peer_rejected`); registry now 42.
- **B1 (D6.3)** `membership.py` — SWIM-style gossip membership. [RUNNABLE]
  **Landed (v0):** `SwimMembership` — join-via-seed, ping/ack failure
  detection (ALIVE→SUSPECT→DEAD), gossip dissemination piggybacked on
  every message, and incarnation-based self-refutation (a wrongly
  suspected node out-incarnates the rumor). Transport-agnostic (runs
  over `InMemoryTransport` or `TlsSocketTransport`). A 4-node cluster
  converges purely by gossip (learning peers it was never seeded with)
  and detects a downed node as DEAD cluster-wide, with no false
  positives while everyone is live. v0 probes all non-dead peers per
  tick (O(N²)); one-random-probe + indirect ping-req are documented
  deferrals. 8 tests; 2 proof obligations
  (`gossip_membership_converges`, `gossip_detects_downed_node`);
  registry now 44.
- **B2 (D6.4)** Gossip-driven discovery + admission integration. [RUNNABLE]
  **Landed (v0):** `GossipDiscovery` couples the `SwimMembership` view
  to a Phase 5 `PeerAdmissionPolicy`: `routable_peers()` is the
  intersection of *reachable* (gossip ALIVE) and *allowed* (admission
  permits the peer's `(spiffe_id, env_tier)`). A rogue that gossip
  reports as alive is **not routable**; an unknown tier denies by
  default; a self-asserted escalated tier matches no rule and is denied
  (the spiffe_id itself is SVID-proven at the mTLS handshake, not
  self-asserted). Discovery ≠ authorization at network scope — vision
  §8.1. Proof obligation `gossiped_peer_still_gated_by_admission`;
  registry now 45. 3 tests.
- **C1 (D6.5)** `routing.py` — routing table + multi-hop forwarding. [RUNNABLE]
- **C2 (D6.6)** 3-node multi-hop secure round trip. [RUNNABLE]
- **D1 (D6.7)** `connection_pool.py` — pooled/keepalive/reconnect transport. [RUNNABLE]
- **E1 (D6.8)** `docs/deployment-networking.md` — WAN frontier. [REFERENCE/DOCS]
- **E2 (D6.9)** Phase 6 close. [DOCS]

## 5) Acceptance Criteria

Phase 6 closes when:

1. Two nodes complete the Phase 5 signed round trip over **real mTLS**;
   an unauthenticated peer cannot complete the handshake.
2. An N-node gossip cluster converges on a shared membership view and
   detects a downed node.
3. A gossiped-but-unadmitted peer is not routable (deny-by-default holds
   at network scope).
4. A 3-node multi-hop round trip verifies end-to-end; the forwarding
   intermediary cannot forge or impersonate.
5. The connection pool sustains many messages over persistent
   connections and recovers from a dropped link.
6. Every RUNNABLE slice keeps the full suite green + ruff clean; every
   new machine-checked invariant has a proof obligation.
7. The deployment-networking reference doc exists and states the WAN
   boundary honestly.

## 6) Test Strategy

- Each RUNNABLE slice ships unit tests in the substrate's style.
- Network slices are tested with multiple in-process nodes over the real
  socket/TLS transports (loopback = real network, bounded scale).
- No WAN, NAT, or chaos testing — that needs infrastructure and stays in
  the E1 reference doc.

## 7) Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---:|---:|---|
| Ed25519 SVIDs don't load cleanly into Python `ssl` | M | H | Verify in A1 first; fall back to writing PEM to secure temp files for `load_cert_chain`; SPIFFE identity checked via substrate `verify_svid` post-handshake |
| Gossip protocol scope-creeps into a full SWIM impl | H | M | v0 does join + heartbeat + suspicion + failure detection only; anti-entropy/lifeguard extensions deferred |
| Loopback "networking" reads as overclaim | M | H | §2 states the loopback-is-real-TLS argument explicitly; WAN concerns are E1 [REFERENCE] |
| Multi-hop forwarding introduces a routing loop | M | M | TTL + seen-set on every forwarded frame; loop-safety pinned by a test |
| Thread/port leaks across many-node tests | M | M | Every transport is context-managed / closed in try-finally, as in Phase 5 |

## 8) Exit Gates

1. All D6.1–D6.9 deliverables merged on `main`.
2. mTLS round trip + gossip convergence + multi-hop round trip all green.
3. Proof-obligations registry extended for the new network-security
   invariants, all resolving.
4. CLAUDE.md Phase 6 status = complete; DEFERRED.md updated with what
   Phase 6 resolved and what real-WAN work remains out of scope.
5. A Phase 6 close-out note in `implementation-plan/phases/README.md`.

## 9) Phase 7 hand-off (anticipated)

Phase 6 deliberately does NOT deliver: real multi-host/WAN deployment,
NAT traversal, production CA custody, or planet-scale operation. Those,
plus the still-open Phase 3 §§6–8 + §11 operational-evidence gaps and
the Phase 2 audit-emission wiring, are the Phase 7 candidate pool.
