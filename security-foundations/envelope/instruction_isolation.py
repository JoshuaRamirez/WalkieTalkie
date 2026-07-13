"""Instruction isolation v0 (Phase 2 Track D D1).

Closes D1 ("Instruction Isolation"):

- "Treat peer/tool outputs as untrusted data channel."
- "Ensure model cannot treat arbitrary external data as control
  instructions."

The v0 primitive is a typed prompt-assembly path that segregates four
content channels (SYSTEM / USER / TOOL / RETRIEVED) and labels each
segment as :class:`Trust.TRUSTED` or :class:`Trust.UNTRUSTED`. The
assembler:

1. Refuses to admit a segment whose channel/trust pairing violates
   the isolation invariants. Specifically:
   - ``SYSTEM`` segments MUST be ``TRUSTED`` (you cannot inject
     untrusted system instructions; if the segment is not under your
     control, it is by definition not SYSTEM).
   - ``USER`` segments MUST be ``UNTRUSTED`` (user input is the
     canonical injection vector).
   - ``RETRIEVED`` segments MUST be ``UNTRUSTED`` (retrieved data is
     the other canonical injection vector).
   - ``TOOL`` segments default to ``UNTRUSTED``; a caller may declare
     a tool segment ``TRUSTED`` only by attaching a non-empty
     ``signature_ref`` — an opaque upstream proof token (typically an
     envelope ``message_id`` whose payload digest has already been
     verified). That implements "tool outputs treated as untrusted
     unless signed".

2. Renders an :class:`IsolatedPrompt` whose ``text`` wraps every
   non-SYSTEM segment in an explicit data frame keyed off a fresh
   nonce. The fence has the form
   ``<<wt-nonce:CHANNEL source="LABEL" trust="TRUSTED|UNTRUSTED">>...<<wt-nonce:end>>``
   and every ``<`` ``>`` ``&`` character inside the wrapped text is
   HTML-escaped so a malicious payload cannot smuggle a synthetic
   closing fence. The system prompt is expected to instruct the model
   to treat anything inside any ``<<wt-…>>`` fence as inert data.

3. Emits an :class:`IsolatedPrompt.audit_log` — a tuple of
   :class:`AuditEntry` records (one per segment) listing channel,
   source_label, trust, and signature_ref. That's the audit-side
   counterpart to the rendered prompt and answers, after the fact,
   "what trust level did each chunk arrive with?".

The fence-nonce makes the framing robust against payloads that
literally write ``<<wt-nonce:end>>``: the assembler picks a nonce that
does not appear in any segment text, and content escaping prevents an
attacker from constructing the exact nonce themselves.

Out of scope for v0
-------------------
- A baked-in system prompt template. The assembler returns a
  structured string; the operator writes the system prompt that tells
  the model how to read it.
- Per-channel transformations (e.g. summarization, redaction). The
  caller is expected to have already applied B3 prompt-assembly
  minimization and C1 output scanning where appropriate.
- Multi-turn conversation framing. v0 produces a single-prompt
  assembly; multi-turn isolation is the caller's responsibility.
- Cryptographic verification of ``signature_ref``. The assembler
  takes it as an opaque token attesting that the caller verified the
  upstream envelope; binding the ref to an actual envelope is a
  higher-level coordination concern.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum


class InstructionIsolationError(ValueError):
    """Raised when isolation invariants are violated."""


class ContentChannel(StrEnum):
    SYSTEM = "system"
    USER = "user"
    TOOL = "tool"
    RETRIEVED = "retrieved"


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


_HTML_ESCAPES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
)


def _escape(text: str) -> str:
    for raw, esc in _HTML_ESCAPES:
        text = text.replace(raw, esc)
    return text


@dataclass(frozen=True)
class ContentSegment:
    """One labeled chunk submitted to :func:`assemble_isolated_prompt`."""

    channel: ContentChannel
    source_label: str
    trust: Trust
    text: str
    signature_ref: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.channel, ContentChannel):
            raise InstructionIsolationError(
                f"channel must be a ContentChannel: {self.channel!r}"
            )
        if not isinstance(self.trust, Trust):
            raise InstructionIsolationError(
                f"trust must be a Trust: {self.trust!r}"
            )
        if not isinstance(self.source_label, str) or not self.source_label:
            raise InstructionIsolationError(
                "source_label must be a non-empty string"
            )
        if not isinstance(self.text, str):
            raise InstructionIsolationError("text must be a string")
        if not isinstance(self.signature_ref, str):
            raise InstructionIsolationError("signature_ref must be a string")

        if self.channel is ContentChannel.SYSTEM and self.trust is not Trust.TRUSTED:
            raise InstructionIsolationError(
                "SYSTEM segments must be TRUSTED — untrusted system "
                "instructions are not admissible"
            )
        if self.channel is ContentChannel.USER and self.trust is not Trust.UNTRUSTED:
            raise InstructionIsolationError(
                "USER segments must be UNTRUSTED — user input is the "
                "canonical injection vector"
            )
        if (
            self.channel is ContentChannel.RETRIEVED
            and self.trust is not Trust.UNTRUSTED
        ):
            raise InstructionIsolationError(
                "RETRIEVED segments must be UNTRUSTED — retrieved data "
                "is an external content channel"
            )
        if (
            self.channel is ContentChannel.TOOL
            and self.trust is Trust.TRUSTED
            and not self.signature_ref
        ):
            raise InstructionIsolationError(
                "TOOL segments may only be TRUSTED when signature_ref is "
                "non-empty — tool outputs are untrusted unless signed"
            )


@dataclass(frozen=True)
class AuditEntry:
    """One row of the audit-side counterpart to the rendered prompt."""

    channel: ContentChannel
    source_label: str
    trust: Trust
    signature_ref: str


@dataclass(frozen=True)
class IsolatedPrompt:
    text: str
    nonce: str
    audit_log: tuple[AuditEntry, ...] = field(default_factory=tuple)


_FENCE_PREFIX = "wt-iso"


def _fresh_nonce(*, segments: Iterable[ContentSegment], rng: secrets.SystemRandom | None = None) -> str:
    """Pick a fresh 96-bit nonce.

    Segment text is HTML-escaped before insertion, so an adversary
    cannot inject a literal fence regardless of nonce — the nonce's
    job is to make the fence shape unpredictable to the adversary
    when the operator's system prompt instructs the model to honor
    only the literal fences the assembler emitted.
    """
    rng = rng or secrets.SystemRandom()
    return f"{rng.getrandbits(96):024x}"


def assemble_isolated_prompt(
    segments: Iterable[ContentSegment],
    *,
    nonce: str | None = None,
) -> IsolatedPrompt:
    """Render an isolation-aware prompt + per-segment audit log.

    SYSTEM segments are emitted as-is (still labeled in the audit log).
    Every other segment is wrapped in a fenced block whose open / close
    markers depend on ``nonce`` and include the channel, source, and
    trust level for the model to see. Segment text is HTML-escaped to
    prevent fence injection.

    ``nonce`` may be supplied for deterministic output (e.g. unit
    tests); it must be a non-empty string that does not appear inside
    any segment's text.
    """
    seg_list = list(segments)
    for index, seg in enumerate(seg_list):
        if not isinstance(seg, ContentSegment):
            raise InstructionIsolationError(
                f"segments[{index}] must be a ContentSegment"
            )

    if nonce is None:
        chosen_nonce = _fresh_nonce(segments=seg_list)
    else:
        if not isinstance(nonce, str) or not nonce:
            raise InstructionIsolationError(
                "nonce must be a non-empty string when supplied"
            )
        chosen_nonce = nonce

    chunks: list[str] = []
    audit: list[AuditEntry] = []
    for seg in seg_list:
        audit.append(
            AuditEntry(
                channel=seg.channel,
                source_label=seg.source_label,
                trust=seg.trust,
                signature_ref=seg.signature_ref,
            )
        )

        if seg.channel is ContentChannel.SYSTEM:
            chunks.append(seg.text)
            continue

        open_marker = (
            f"<<{_FENCE_PREFIX}:{chosen_nonce}:{seg.channel.value} "
            f"source=\"{_escape(seg.source_label)}\" "
            f"trust=\"{seg.trust.value}\">>"
        )
        close_marker = f"<<{_FENCE_PREFIX}:{chosen_nonce}:end>>"
        chunks.append(open_marker)
        chunks.append(_escape(seg.text))
        chunks.append(close_marker)

    return IsolatedPrompt(
        text="\n".join(chunks),
        nonce=chosen_nonce,
        audit_log=tuple(audit),
    )
