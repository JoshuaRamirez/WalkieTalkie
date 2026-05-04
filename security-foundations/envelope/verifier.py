"""Verifier facade — bound dependencies for repeated verification calls.

The :class:`Verifier` dataclass holds the trust stores, replay cache, audit
sink, and verification config so callers don't pass seven keyword arguments
on every request. Two methods:

- :meth:`Verifier.verify` — raises :class:`EnvelopeVerificationError` on any
  failure and returns the validated :class:`CapabilityClaims` on success.
- :meth:`Verifier.try_verify` — never raises. Returns a
  :class:`VerificationResult` with ``ok``, ``reason``, and ``claims``.

Use ``verify`` when an exception is the right control flow (e.g., a request
handler that propagates 4xx/5xx). Use ``try_verify`` when the caller wants to
inspect the rejection reason without an exception.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from audit import AuditSink
from verify_envelope import (
    DEFAULT_CONFIG,
    EnvelopeVerificationError,
    ReplayCache,
    VerificationConfig,
    verify_envelope,
)

if TYPE_CHECKING:
    from capability_token import CapabilityClaims


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str
    claims: CapabilityClaims | None


@dataclass(frozen=True)
class Verifier:
    key_lookup: Callable[[str], bytes]
    issuer_lookup: Callable[[str, str], bytes]
    replay_cache: ReplayCache
    config: VerificationConfig = DEFAULT_CONFIG
    audit_sink: AuditSink | None = None

    def verify(self, envelope: dict, *, now: datetime | None = None) -> CapabilityClaims:
        return verify_envelope(
            envelope,
            key_lookup=self.key_lookup,
            issuer_lookup=self.issuer_lookup,
            replay_cache=self.replay_cache,
            config=self.config,
            now=now,
            audit_sink=self.audit_sink,
        )

    def try_verify(self, envelope: dict, *, now: datetime | None = None) -> VerificationResult:
        try:
            claims = self.verify(envelope, now=now)
        except EnvelopeVerificationError as exc:
            return VerificationResult(ok=False, reason=str(exc), claims=None)
        return VerificationResult(ok=True, reason="ok", claims=claims)
