"""Runtime trust tiers (Phase 5 Track D, D5.6). [REFERENCE]

The vision's Layer E ("Runtime and Environment Hardening") defines
runtime trust tiers, each declaring "allowed syscalls, writable
filesystem paths, outbound network policy, secret access scope":

    - Strict: for high-risk tools and low-trust peers
    - Standard: for ordinary trusted services
    - Limited-trust: for narrowly scoped workloads

This module is the **declarative model** for those tiers — a
:class:`RuntimeProfile` that an operator attaches to a workload and a
sandbox runtime consumes. The three vision tiers ship as built-in
profiles (:func:`strict_profile`, :func:`standard_profile`,
:func:`limited_trust_profile`) that operators use as-is or narrow.

ENFORCEMENT BOUNDARY (read this):
---------------------------------
This is **[REFERENCE]**, not enforcement. A `RuntimeProfile` is a
data structure describing constraints; it does NOT confine anything
by itself. Actual confinement requires deployment infrastructure the
substrate does not and cannot provide in-process:

- syscall filtering → a kernel + seccomp-BPF (the D2 generator emits
  the profile the kernel loads).
- filesystem confinement → a container runtime / mount namespaces.
- egress control → a network policy engine / firewall.
- secret scoping → a secrets manager (Vault-style) honoring the scope.

The value here is that the constraints are **declared, versioned,
type-checked, and testable** in the substrate, so the enforcement
layer has a single authoritative source instead of scattered ad-hoc
config. The D2 slice turns a profile into a real seccomp document a
kernel can load; loading it is the operator's runtime.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum


class RuntimeProfileError(ValueError):
    """Raised when a runtime profile violates v0 invariants."""


class TrustTier(StrEnum):
    STRICT = "strict"
    STANDARD = "standard"
    LIMITED_TRUST = "limited_trust"


class EgressPolicy(StrEnum):
    """Outbound network posture. DENY_ALL is the vision's default
    ("Disable outbound network by default")."""

    DENY_ALL = "deny_all"
    ALLOWLIST = "allowlist"
    ALLOW_ALL = "allow_all"


@dataclass(frozen=True)
class RuntimeProfile:
    """Declarative runtime constraints for one workload / trust tier.

    Fields mirror the vision's per-tier definition:
    - ``allowed_syscalls`` — the seccomp allowlist (names, e.g.
      ``"read"``, ``"write"``). Empty means "the generator's minimal
      base set only" (see D2).
    - ``writable_paths`` — filesystem paths the workload may write.
      Everything else is read-only / denied.
    - ``egress`` — the outbound network posture; ``egress_allowlist``
      names the permitted hosts when ``egress == ALLOWLIST``.
    - ``secret_scopes`` — the secret paths/labels this workload may
      read (least privilege).
    """

    tier: TrustTier
    allowed_syscalls: frozenset[str] = field(default_factory=frozenset)
    writable_paths: frozenset[str] = field(default_factory=frozenset)
    egress: EgressPolicy = EgressPolicy.DENY_ALL
    egress_allowlist: frozenset[str] = field(default_factory=frozenset)
    secret_scopes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.tier, TrustTier):
            raise RuntimeProfileError(f"tier must be a TrustTier: {self.tier!r}")
        for name, value in (
            ("allowed_syscalls", self.allowed_syscalls),
            ("writable_paths", self.writable_paths),
            ("egress_allowlist", self.egress_allowlist),
            ("secret_scopes", self.secret_scopes),
        ):
            if not isinstance(value, frozenset):
                raise RuntimeProfileError(f"{name} must be a frozenset")
            for item in value:
                if not isinstance(item, str) or not item:
                    raise RuntimeProfileError(
                        f"{name} entries must be non-empty strings"
                    )
        if not isinstance(self.egress, EgressPolicy):
            raise RuntimeProfileError(
                f"egress must be an EgressPolicy: {self.egress!r}"
            )
        if self.egress is EgressPolicy.ALLOWLIST and not self.egress_allowlist:
            raise RuntimeProfileError(
                "egress=ALLOWLIST requires a non-empty egress_allowlist"
            )
        if self.egress is not EgressPolicy.ALLOWLIST and self.egress_allowlist:
            raise RuntimeProfileError(
                "egress_allowlist is only meaningful when egress=ALLOWLIST"
            )


# A minimal syscall base every tier needs just to run. The strict
# tier adds nothing; higher-trust tiers add more.
_BASE_SYSCALLS = frozenset(
    {"read", "write", "close", "exit", "exit_group", "brk", "mmap", "munmap"}
)


def strict_profile(*, secret_scopes: frozenset[str] = frozenset()) -> RuntimeProfile:
    """High-risk tools / low-trust peers: deny-all egress, no writable
    paths beyond a scratch tmp, minimal syscalls."""
    return RuntimeProfile(
        tier=TrustTier.STRICT,
        allowed_syscalls=_BASE_SYSCALLS,
        writable_paths=frozenset({"/tmp"}),
        egress=EgressPolicy.DENY_ALL,
        secret_scopes=secret_scopes,
    )


def standard_profile(
    *,
    egress_allowlist: frozenset[str],
    writable_paths: frozenset[str] = frozenset({"/tmp", "/var/run/app"}),
    secret_scopes: frozenset[str] = frozenset(),
) -> RuntimeProfile:
    """Ordinary trusted services: egress allowlist, a couple of
    writable paths, a broader syscall set."""
    return RuntimeProfile(
        tier=TrustTier.STANDARD,
        allowed_syscalls=_BASE_SYSCALLS
        | {"openat", "fstat", "lseek", "poll", "futex", "socket", "connect"},
        writable_paths=writable_paths,
        egress=EgressPolicy.ALLOWLIST,
        egress_allowlist=egress_allowlist,
        secret_scopes=secret_scopes,
    )


def limited_trust_profile(
    *,
    allowed_syscalls: frozenset[str],
    secret_scopes: frozenset[str] = frozenset(),
) -> RuntimeProfile:
    """Narrowly scoped workloads: the operator names the exact syscall
    set, deny-all egress, no writable paths."""
    return RuntimeProfile(
        tier=TrustTier.LIMITED_TRUST,
        allowed_syscalls=_BASE_SYSCALLS | allowed_syscalls,
        writable_paths=frozenset(),
        egress=EgressPolicy.DENY_ALL,
        secret_scopes=secret_scopes,
    )


# --- Seccomp generation (Phase 5 Track D, D5.6) ---------------------------
#
# A :class:`RuntimeProfile`'s ``allowed_syscalls`` is the source of truth
# for the seccomp allowlist. :func:`generate_seccomp` renders it into the
# OCI runtime-spec / Docker seccomp document a kernel actually loads:
# deny-by-default (``SCMP_ACT_ERRNO``), an explicit architecture list, and
# one allow-rule naming every permitted syscall. This is still [REFERENCE]
# — the substrate emits the document; a container runtime loads it.

# The architectures a generated profile applies to. x86_64 hosts run 64-bit,
# 32-bit, and x32 ABIs; naming all three prevents an attacker from evading
# the filter by invoking a syscall through a different ABI.
_SECCOMP_ARCHITECTURES = (
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32",
)

# Deny-by-default: a syscall not on the allowlist returns EPERM rather than
# killing the process, matching Docker's default posture. ERRNO (not KILL)
# keeps a mis-scoped profile debuggable instead of silently crashing.
_SECCOMP_DEFAULT_ACTION = "SCMP_ACT_ERRNO"
_SECCOMP_ALLOW_ACTION = "SCMP_ACT_ALLOW"


def generate_seccomp(profile: RuntimeProfile) -> dict:
    """Render a profile's syscall allowlist as an OCI seccomp document.

    The returned dict is the exact shape ``runc``/Docker load via
    ``--security-opt seccomp=<file>``: a deny-by-default ``defaultAction``,
    the target ``architectures``, and a single ``syscalls`` allow-rule
    listing every permitted name in sorted (deterministic) order.

    An empty allowlist yields a document with an empty allow-rule — a
    profile that denies *every* syscall. That is a valid, if unusable,
    kernel document; callers that want a runnable workload put a base set
    on the profile (the built-in profiles do, via ``_BASE_SYSCALLS``).
    """
    if not isinstance(profile, RuntimeProfile):
        raise RuntimeProfileError(
            f"generate_seccomp expects a RuntimeProfile: {profile!r}"
        )
    return {
        "defaultAction": _SECCOMP_DEFAULT_ACTION,
        "architectures": list(_SECCOMP_ARCHITECTURES),
        "syscalls": [
            {
                "names": sorted(profile.allowed_syscalls),
                "action": _SECCOMP_ALLOW_ACTION,
            }
        ],
    }


def seccomp_to_json(profile: RuntimeProfile) -> str:
    """Serialize :func:`generate_seccomp` as a stable JSON string (sorted
    keys, no incidental whitespace) suitable for writing to a file the
    container runtime loads."""
    return json.dumps(generate_seccomp(profile), sort_keys=True, separators=(",", ":"))
