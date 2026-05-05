"""Capability token v0 — issuer side.

The :class:`CapabilityIssuer` mints ``wt-cap+jwt`` tokens that the validator
in :mod:`capability_token` accepts. Pairs of (issuer, validator) are
intentionally separate modules: an issuer holds a private signing key while a
validator only consults a public-key trust store.

A real production deployment will wrap this class with an HTTP/RPC issuance
*API*, request authentication, audit, and rate limiting. v0 only covers the
in-process minting library — enough to let tests, the test-vector regen
script, and any future demo dispatcher mint deterministic tokens.

Out of scope for v0
-------------------
- Issuance API surface (HTTP / RPC / mTLS-bound).
- Per-request authorization for *who can ask for which scope*.
- Token issuance log / accountability trail (will reuse :class:`AuditSink`).
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from capability_token import EXPECTED_ALG, EXPECTED_TYP
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from verify_envelope import (
    HEX_SHA256_RE,
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_uuidv7(*, now: datetime | None = None, rand_bytes: bytes | None = None) -> str:
    """Generate a RFC 9562 UUIDv7. Suitable for jti.

    ``rand_bytes`` is a 10-byte randomness source; defaults to ``os.urandom``.
    Tests that need determinism can pass an explicit value.
    """
    when = now or datetime.now(UTC)
    millis = int(when.timestamp() * 1000) & ((1 << 48) - 1)
    rb = rand_bytes if rand_bytes is not None else os.urandom(10)
    if len(rb) != 10:
        raise ValueError("rand_bytes must be exactly 10 bytes")
    rand_a = int.from_bytes(rb[:2], "big") & 0x0FFF
    rand_b = int.from_bytes(rb[2:10], "big") & ((1 << 62) - 1)
    msb = (millis << 16) | (0x7 << 12) | rand_a
    lsb = (0b10 << 62) | rand_b
    hex_str = f"{msb:016x}{lsb:016x}"
    return (
        f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
        f"{hex_str[16:20]}-{hex_str[20:32]}"
    )


@dataclass
class CapabilityIssuer:
    """Mints wt-cap+jwt capability tokens.

    Construction validates ``iss`` and ``kid`` against the same regexes the
    validator uses, so a misconfigured issuer fails immediately rather than
    minting tokens that every consumer will reject.
    """

    iss: str
    kid: str
    signing_key: Ed25519PrivateKey
    default_ttl: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    clock_skew: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    def __post_init__(self) -> None:
        if not isinstance(self.iss, str) or not SPIFFE_ID_RE.match(self.iss):
            raise ValueError(f"invalid iss: {self.iss!r}")
        if not isinstance(self.kid, str) or not KID_RE.match(self.kid):
            raise ValueError(f"invalid kid: {self.kid!r}")
        if self.default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive")
        if self.clock_skew < timedelta(0):
            raise ValueError("clock_skew must be non-negative")

    def issue(
        self,
        *,
        sub: str,
        aud: str,
        scope: str,
        envelope_digest: str,
        jti: str | None = None,
        ttl: timedelta | None = None,
        now: datetime | None = None,
    ) -> str:
        if not isinstance(sub, str) or not SPIFFE_ID_RE.match(sub):
            raise ValueError(f"invalid sub: {sub!r}")
        if not isinstance(aud, str) or not SPIFFE_ID_RE.match(aud):
            raise ValueError(f"invalid aud: {aud!r}")
        if not isinstance(scope, str) or not scope:
            raise ValueError("scope must be a non-empty string")
        if not isinstance(envelope_digest, str) or not HEX_SHA256_RE.match(envelope_digest):
            raise ValueError(f"invalid envelope_digest: {envelope_digest!r}")

        effective_ttl = ttl if ttl is not None else self.default_ttl
        if effective_ttl <= timedelta(0):
            raise ValueError("ttl must be positive")

        when = (now or datetime.now(UTC)).astimezone(UTC)
        iat_dt = when - self.clock_skew
        exp_dt = iat_dt + effective_ttl
        iat = int(iat_dt.timestamp())
        nbf = iat
        exp = int(exp_dt.timestamp())

        if jti is None:
            jti = generate_uuidv7(now=when)
        elif not isinstance(jti, str) or not UUID_V7_RE.match(jti):
            raise ValueError(f"invalid jti: {jti!r}")

        header = {"alg": EXPECTED_ALG, "typ": EXPECTED_TYP, "kid": self.kid}
        payload = {
            "iss": self.iss,
            "sub": sub,
            "aud": aud,
            "scope": scope,
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "jti": jti,
            "cnf": {"envelope_digest": envelope_digest},
        }

        h = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = _b64u(self.signing_key.sign((h + "." + p).encode("ascii")))
        return f"{h}.{p}.{sig}"
