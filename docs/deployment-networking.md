# WalkieTalkie Deployment Networking — the WAN frontier (v0)

*What it takes to run the Phase 6 mesh across real machines and the
public internet, why each piece is infrastructure the in-process kernel
cannot be, and how the runnable core plugs into it.* **[REFERENCE]**

This document closes **Phase 6 Track E, E1** (deliverable D6.8). Phase 6
made the mesh a real network stack — mTLS on the wire, gossip
membership, multi-hop routing, pooled connections — all **[RUNNABLE]**
and tested on loopback. This is the honest map of what stays **outside**
that boundary: the operational infrastructure a production, cross-machine,
internet-facing deployment needs. None of it is faked as a runnable
claim; each item says what it needs and where the tested core attaches.

## The one-sentence boundary

**Loopback bounds scale and reachability, not security.** Everything
Phase 6 proved about *security* (an unauthenticated peer can't handshake;
a gossiped-but-unadmitted peer isn't routable; a forwarder can't forge;
a tampered payload fails verification) holds identically over a WAN. What
loopback does *not* exercise is the *operational* reality of the open
internet: NAT, packet loss, latency, hostile scale, and the custody of
real keys. Those are the five frontiers below.

---

## 1. Reachability across NAT and firewalls

**What loopback skips.** On `127.0.0.1` every node can `connect()` to
every other directly. On the internet, most nodes sit behind NAT or a
firewall and have no publicly dialable address; two such peers cannot
open a direct TCP connection at all.

**What a deployment needs.**
- **STUN** for each node to discover its own public `ip:port`.
- **TURN / relays** for the (common) case where hole-punching fails —
  a publicly-reachable relay forwards traffic between two unreachable
  peers.
- **ICE**-style candidate gathering + connectivity checks to pick the
  best working path.

**Where the runnable core attaches.** The `Transport` ABC
(`address` / `send` / `receive`) is the exact seam. A `RelayTransport`
or `IceTransport` implements the same three methods; `MeshNode`,
`SwimMembership`, `Router`, and the envelope stack are unchanged —
they never learned they were on loopback. The multi-hop `Router`
(D6.5) already forwards through intermediaries, which is the same shape
a relay hop takes; a relay is just a forwarding node that isn't the
message's recipient (and, as C2 proved, therefore can't forge it).

**Why it's infrastructure, not kernel.** STUN/TURN require
publicly-hosted servers, real network paths, and coordination protocols
that only mean anything against actual NATs — there is nothing to test
in-process.

## 2. Transport security at internet scale

**What's already real.** `TlsSocketTransport` (D6.1) is genuine mutual
TLS 1.3 with SVID peer verification — the *same* handshake, ciphers, and
record encryption a WAN connection uses. This frontier is **not** "add
TLS"; TLS is done.

**What a deployment adds.**
- **Session resumption / 0-RTT** tuning so a fleet re-establishing many
  connections isn't handshake-bound (composes with the D6.7 pool).
- **Cipher / curve policy** pinned to an organization's compliance
  baseline.
- **SNI / ALPN** conventions if the mesh shares ports with other
  protocols at an ingress.

**Where it attaches.** All of this is `ssl.SSLContext` configuration on
the existing `TlsSocketTransport` — a parameterization, not a new
primitive.

## 3. PKI custody and issuance operations

**What loopback fakes.** Tests mint SVIDs from a `WorkloadCA` whose root
key is generated in-process and thrown away. That is correct for proving
*verification*; it is emphatically **not** how a real root key is held.

**What a deployment needs.**
- **Root key in an HSM / KMS** — never in application memory; signing is
  a delegated operation.
- **A real issuance flow** — SPIRE-style node + workload attestation
  (proving a workload is what it claims *before* it gets an SVID),
  short-TTL rotation, and an issuance API the workload calls at startup.
- **Root rotation / cross-signing** — overlapping trust bundles so a
  root can be retired without a flag day.

**Where the runnable core attaches.** The substrate already consumes
keys through the `IssuerTrustStore`-shaped `Callable[[str, str], bytes]`
and verifies SVIDs against a root cert it is *handed*. A production
issuer swaps *how the cert and root are obtained* (an HSM-backed CA, a
SPIRE agent) without changing `verify_svid`, the admission policy, or the
transport. The Phase 3 `key_rotation` and `bootstrap_bundle` primitives
are the in-process half of the rotation/anchor-distribution story; the
custody half is the deployment.

**Why it's infrastructure.** Key custody is a hardware + operations
concern (HSMs, KMS IAM, attestation roots). The kernel can *use* a key
and *verify* a cert; it must never *hold* the root.

## 4. Membership and routing at scale

**What's already real.** `SwimMembership` (D6.3) is a genuine gossip
protocol; a multi-node cluster converges and detects failures. `Router`
(D6.5) forwards multi-hop, loop-safe and deny-by-default.

**What scale adds (documented deferrals, see `DEFERRED.md`).**
- **SWIM refinements** — indirect probing (ping-req via *k* relays) to
  suppress false positives under real packet loss; Lifeguard adaptive
  timeouts. v0 probes all non-dead peers each tick (O(N²)); production
  probes one random peer per period for O(N) load.
- **A real routing protocol** — v0 takes the `next_hop` table as input;
  a distance-vector or link-state protocol that *computes* routes from
  gossiped topology is the scale version. The *forwarding* security
  invariants hold regardless of how the table is computed.
- **Partition behavior** — split-brain detection and merge, which only
  manifests with real network partitions.

**Why it's out of v0 scope.** These need many real hosts, real loss, and
real partitions to test meaningfully — a loopback cluster cannot produce
them.

## 5. Bootstrap, discovery, and DoS at the edge

**What a deployment needs.**
- **Seed infrastructure** — stable, discoverable seed nodes (DNS
  seeds / a bootstrap service) so a fresh node has someone to gossip to.
- **Ingress DoS protection** — rate limiting and connection admission at
  the network edge *before* the handshake, so an attacker can't exhaust
  TLS-handshake CPU. (The substrate's `IdentityRateLimiter` runs
  *post-auth*; edge protection is *pre-auth* and lives in front.)
- **Observability** — metrics/tracing across the fleet (the hash-chained
  audit log is the per-node forensic record; fleet-wide aggregation is
  deployment).

**Where it attaches.** Seed lists feed `SwimMembership(seeds=...)`
directly. Post-auth rate limiting already exists
(`host_rate_limit_enforced_post_auth`); the edge layer sits in front of
the transport.

---

## Summary: runnable core vs. deployment frontier

| Concern | In-process (Phase 6, tested) | Deployment (this doc) |
|---|---|---|
| Wire encryption + peer auth | **mTLS 1.3 + SVID verify** (D6.1) | session-resumption tuning, cipher policy |
| Reachability | direct loopback | **NAT traversal: STUN/TURN/ICE, relays** |
| Membership | **gossip convergence + failure detection** (D6.3) | indirect probing, O(N) load, partitions |
| Routing | **multi-hop, loop-safe, deny-by-default** (D6.5) | route *computation* protocol |
| Connections | **pooled/keepalive/reconnect** (D6.7) | — (already operational) |
| Identity issuance | verify against a handed root | **HSM custody, SPIRE attestation, rotation ops** |
| Edge protection | post-auth rate limit | **pre-auth ingress DoS protection** |
| Observability | per-node hash-chained audit | fleet-wide metrics/tracing aggregation |

**The consistent pattern:** every deployment item attaches to the
substrate through an *existing seam* — the `Transport` ABC, the
`IssuerTrustStore` callable, the `SwimMembership(seeds=...)` list, the
`Router`'s `next_hop` resolver. Phase 6 built the security-bearing core
and the seams; a deployment supplies the infrastructure behind each seam
without reopening the kernel. That is the whole point of keeping security
in the signed envelope and the SVID, not in the wire.

## What this is not

This is a **reference map**, not a runnable claim and not an ops runbook
for a specific cloud. It exists so the next agent (and any operator)
knows precisely where the tested boundary ends and why — no item here is
presented as done. The full deferred/out-of-scope registry is
`DEFERRED.md`.
