# Security Policy

WalkieTalkie is a **security substrate**, so a clear disclosure path matters
more here than for most projects. This document says how to report a
vulnerability and what the project's security boundary currently is.

## Project maturity and boundary

Read this before assessing a finding — it shapes what counts as a vulnerability.

- The substrate is **pre-release** (version `0.0.1`, no tagged releases yet).
- The kernel and mesh are **[RUNNABLE]** and tested, but run over **loopback and
  localhost sockets**. That bounds scale and reachability, not the security
  properties — see the honesty model in [`README.md`](./README.md).
- The deployment layer (production PKI custody, NAT/STUN/TURN traversal, runtime
  sandboxing, image admission) is **[REFERENCE]** — documented and modelled, but
  **not yet implemented**. See [`DEFERRED.md`](./DEFERRED.md) and
  [`docs/deployment-networking.md`](./docs/deployment-networking.md).

A gap that the project already documents as an unbuilt [REFERENCE] deployment
control (for example, "there is no live NAT traversal") is a known limitation,
not a vulnerability. A flaw in a **[RUNNABLE]** control that lets it be bypassed
— envelope forgery/replay, capability escalation, admission bypass, identity
spoofing across the verified-transport boundary — is exactly what this policy is
for.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through GitHub's coordinated-disclosure channel:

1. Go to the repository's **Security** tab →
   **[Report a vulnerability](https://github.com/JoshuaRamirez/WalkieTalkie/security/advisories/new)**.
2. This opens a private security advisory visible only to you and the
   maintainers.

A good report includes:

- the affected component or file (e.g. `security-foundations/envelope/…`),
- which security property you believe is broken (confidentiality, integrity,
  authenticity, authorization, or auditability),
- a minimal reproduction — ideally a failing test in the style of the existing
  suites, since every enforced invariant is pinned by one,
- impact and any suggested remediation.

## What to expect

This is a small, research-stage project, so the process is best-effort rather
than a contractual SLA:

- **Acknowledgement** that the report was received.
- **Investigation**, and a private discussion of the finding and a fix.
- **Coordinated disclosure**: once a fix is ready (or the report is determined
  to be out of scope), the advisory is published with credit to the reporter
  unless anonymity is requested.

Please allow reasonable time for a fix before any public disclosure.

## Scope

**In scope** — the substrate's own [RUNNABLE] code: the envelope kernel, the
capability/policy layer, and the mesh (transport, mTLS, membership, routing).

**Out of scope**

- Deployment-layer controls that are documented as unbuilt [REFERENCE] work.
- Vulnerabilities in third-party dependencies (report those upstream; if a
  dependency pin here forces a vulnerable version, that pin *is* in scope).
- Findings that require attacker capabilities the threat model already assumes
  as trusted (e.g. local root on the same host, which the loopback boundary
  explicitly does not defend against).

The threat classes the substrate is built against are enumerated in
[`docs/threat-model.md`](./docs/threat-model.md) and
[`SECURITY_FIRST_P2P_MCP_PLAN.md`](./SECURITY_FIRST_P2P_MCP_PLAN.md#1-threat-model-first-non-negotiable).
