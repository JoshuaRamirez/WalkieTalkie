"""Output scanning v0 (Phase 2 Track C C1).

Closes the deterministic-patterns half of C1 ("Output Scanning"):

- "Deterministic secret patterns + ML classifiers." — v0 ships the
  deterministic side. ML classifiers are explicitly deferred; the
  :class:`ScanResult` shape is designed so a future ML-based scanner
  can append additional :class:`ScanMatch` entries without breaking
  consumers.
- "Risk score assigned to every outbound artifact." — every
  :func:`scan` call returns a :class:`ScanResult` whose
  :attr:`ScanResult.risk` is the most-severe match's severity (or
  :class:`RiskLevel.NONE` for clean output).

A :class:`PatternRegistry` carries a closed tuple of
:class:`SecretPattern` records (name + regex + severity). The
:func:`scan` function feeds a text artifact through every pattern and
returns the union of matches plus the aggregate risk.

Patterns are deliberately conservative: every entry has a
characteristic prefix / structure that makes false positives rare.
v0 ships the patterns most likely to leak through a multi-agent
workload: cloud provider keys, generic PEM private-key blocks, JWTs,
and the API-key formats of common LLM / git providers. Operators can
build their own registry via :func:`PatternRegistry.from_patterns`
or extend the built-in one with :meth:`PatternRegistry.extend`.

Redaction
---------
:meth:`ScanResult.redact` returns a copy of the scanned text with
every match replaced by ``[REDACTED:<pattern_name>]``. Overlapping
matches are resolved deterministically: an earlier-starting match
wins; among ties, the higher-severity wins. Redaction is bytewise
on the input string — no normalization is performed.

Out of scope for v0
-------------------
- ML / classifier-based detection. The shape carries severity already;
  adding ``ScanMatch(source="ml-pii", ...)`` later is non-breaking.
- Structured artifact awareness (JSON / YAML / source-tree parsing).
  v0 scans raw text. Callers that want to scan structured data should
  serialize it first.
- Per-callsite allowlists. v0's ``PatternRegistry`` is a closed set;
  ignore-rules would belong in C2 (policy-adaptive egress).
- Reversible tokenization for review workflows. v0 only redacts; the
  C3 reviewer slice will decide whether to retain originals under a
  separate key.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum


class OutputScanningError(ValueError):
    """Raised when scanner inputs violate v0 invariants."""


class RiskLevel(StrEnum):
    """Aggregate / per-match risk levels in increasing severity."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_RISK_RANK = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def is_more_severe(a: RiskLevel, b: RiskLevel) -> bool:
    """``True`` iff ``a`` is strictly more severe than ``b``."""
    return _RISK_RANK[a] > _RISK_RANK[b]


def _max_risk(levels: Iterable[RiskLevel]) -> RiskLevel:
    best = RiskLevel.NONE
    for level in levels:
        if _RISK_RANK[level] > _RISK_RANK[best]:
            best = level
    return best


@dataclass(frozen=True)
class SecretPattern:
    """One named regex with an associated severity."""

    name: str
    regex: re.Pattern[str]
    severity: RiskLevel

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise OutputScanningError("name must be a non-empty string")
        if not isinstance(self.regex, re.Pattern):
            raise OutputScanningError(
                f"regex must be a compiled re.Pattern: {self.regex!r}"
            )
        if not isinstance(self.severity, RiskLevel):
            raise OutputScanningError(
                f"severity must be a RiskLevel: {self.severity!r}"
            )
        if self.severity is RiskLevel.NONE:
            raise OutputScanningError(
                "severity=NONE is reserved for clean ScanResults"
            )


# --- Built-in patterns ---
#
# Every pattern is deliberately anchored on a characteristic prefix or
# delimiter so false positives in routine prose are rare. Severity
# tiers:
#   CRITICAL — long-lived credentials with broad blast radius
#               (cloud root, private keys).
#   HIGH     — provider-issued bearer tokens that are still
#               authenticator-grade (LLM API keys, GitHub tokens).
#   MEDIUM   — short-lived bearer tokens (JWTs) or session credentials.
#   LOW      — reserved (no v0 patterns at this tier; the slot exists
#               so future ML classifiers have somewhere to land
#               low-confidence hits).

BUILTIN_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        name="aws_access_key_id",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity=RiskLevel.CRITICAL,
    ),
    SecretPattern(
        name="pem_private_key",
        regex=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----"
        ),
        severity=RiskLevel.CRITICAL,
    ),
    SecretPattern(
        name="anthropic_api_key",
        regex=re.compile(r"\bsk-ant-(?:api|admin|sid)[0-9A-Za-z_-]{20,}\b"),
        severity=RiskLevel.HIGH,
    ),
    SecretPattern(
        # OpenAI legacy/project keys (sk-proj-..., sk-svcacct-..., sk-...).
        # Anchored on "sk-" + a non-anthropic discriminator so we don't
        # double-fire with the anthropic pattern above.
        name="openai_api_key",
        regex=re.compile(
            r"\bsk-(?!ant-)(?:proj-|svcacct-)?[0-9A-Za-z_-]{32,}\b"
        ),
        severity=RiskLevel.HIGH,
    ),
    SecretPattern(
        name="github_personal_token",
        regex=re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),
        severity=RiskLevel.HIGH,
    ),
    SecretPattern(
        name="github_fine_grained_pat",
        regex=re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"),
        severity=RiskLevel.HIGH,
    ),
    SecretPattern(
        name="stripe_live_secret_key",
        regex=re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
        severity=RiskLevel.HIGH,
    ),
    SecretPattern(
        # RFC 7519 JWT shape: 3 base64url segments separated by dots.
        # Conservative on segment length (≥10) to keep prose noise low.
        name="jwt_token",
        regex=re.compile(
            r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"
        ),
        severity=RiskLevel.MEDIUM,
    ),
)


@dataclass(frozen=True)
class PatternRegistry:
    """An immutable set of patterns, queried by :func:`scan`."""

    patterns: tuple[SecretPattern, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.patterns, tuple):
            raise OutputScanningError("patterns must be a tuple")
        seen: set[str] = set()
        for index, p in enumerate(self.patterns):
            if not isinstance(p, SecretPattern):
                raise OutputScanningError(
                    f"patterns[{index}] must be a SecretPattern"
                )
            if p.name in seen:
                raise OutputScanningError(
                    f"duplicate pattern name: {p.name!r}"
                )
            seen.add(p.name)

    @classmethod
    def builtin(cls) -> PatternRegistry:
        """Return a registry seeded with v0's built-in patterns."""
        return cls(patterns=BUILTIN_PATTERNS)

    @classmethod
    def from_patterns(cls, patterns: Iterable[SecretPattern]) -> PatternRegistry:
        return cls(patterns=tuple(patterns))

    def extend(self, extra: Iterable[SecretPattern]) -> PatternRegistry:
        """Return a new registry with ``extra`` patterns appended."""
        return PatternRegistry(patterns=(*self.patterns, *tuple(extra)))


@dataclass(frozen=True)
class ScanMatch:
    """One detection: which pattern, where, and how severe."""

    pattern_name: str
    severity: RiskLevel
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise OutputScanningError(
                f"invalid match span: ({self.start}, {self.end})"
            )


@dataclass(frozen=True)
class ScanResult:
    """The complete output of one :func:`scan` call."""

    text: str
    matches: tuple[ScanMatch, ...] = field(default_factory=tuple)

    @property
    def risk(self) -> RiskLevel:
        if not self.matches:
            return RiskLevel.NONE
        return _max_risk(m.severity for m in self.matches)

    @property
    def is_clean(self) -> bool:
        return not self.matches

    def redact(self) -> str:
        """Return ``self.text`` with every match replaced by a tag.

        Resolution for overlapping matches: earlier ``start`` wins;
        among ties, the more-severe match wins; among further ties, the
        longer match wins. The remaining matches are skipped.
        """
        if not self.matches:
            return self.text

        ordered = sorted(
            self.matches,
            key=lambda m: (
                m.start,
                -_RISK_RANK[m.severity],
                -(m.end - m.start),
            ),
        )
        chunks: list[str] = []
        cursor = 0
        for m in ordered:
            if m.start < cursor:
                continue
            chunks.append(self.text[cursor : m.start])
            chunks.append(f"[REDACTED:{m.pattern_name}]")
            cursor = m.end
        chunks.append(self.text[cursor:])
        return "".join(chunks)


def scan(text: str, *, registry: PatternRegistry | None = None) -> ScanResult:
    """Scan ``text`` against ``registry`` (default: :func:`PatternRegistry.builtin`).

    Returns every detection — overlap resolution happens at redaction
    time. The order of :attr:`ScanResult.matches` is the order patterns
    appear in the registry, then by match position within each pattern.
    """
    if not isinstance(text, str):
        raise OutputScanningError("text must be a string")
    reg = registry if registry is not None else PatternRegistry.builtin()

    matches: list[ScanMatch] = []
    for pattern in reg.patterns:
        for m in pattern.regex.finditer(text):
            matches.append(
                ScanMatch(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    start=m.start(),
                    end=m.end(),
                )
            )
    return ScanResult(text=text, matches=tuple(matches))
