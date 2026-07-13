"""Prompt assembly minimization v0 (Phase 2 Track B B3).

Closes B3 ("Prompt Assembly Minimization"):

- "Least-sensitive-first context composition."
- "Max context sensitivity budget per action class."

The :class:`PromptAssembler` consumes a list of candidate
:class:`PromptCandidate` records (each pairs a :class:`ClassifiedData`
with a human-readable source label and the raw context text), filters
them against an :class:`ActionBudget`, and returns a
:class:`PromptContext`.

Two invariants are enforced:

1. **Budget ceiling.** An :class:`ActionBudget` carries a
   ``max_class`` for the action being composed. Any candidate whose
   ``data.data_class`` is *more restrictive* than ``max_class`` is
   dropped before composition. The result records how many items were
   dropped, by class, so operators can spot a workload routinely
   over-asking for restricted context.

2. **Least-sensitive-first ordering.** Items that pass the ceiling are
   sorted by their :class:`DataClass` rank (PUBLIC → RESTRICTED). Ties
   break on ``source_label`` for deterministic output.

The output :class:`PromptContext` carries, for each included item:

- ``source_label`` — the operator-supplied origin tag (e.g.
  ``"kb:doc-42"``). Used in audit logs.
- ``data_class`` — the sensitivity label.
- ``trust_label`` — the trust-domain component of the first lineage
  tag's ``actor_iss``. Lets downstream logs answer "what tenant did
  this chunk come from?" without re-walking the lineage.
- ``text`` — the actual context bytes.

The combination of ``source_label`` + ``data_class`` + ``trust_label``
on every included item is what the acceptance criterion calls "prompt
assembly logs include source sensitivity and trust labels". The
assembler itself never writes to disk — emission of an audit event for
the composition is a downstream concern, identical to how retrieval-
policy decisions are audited at the call site.

Out of scope for v0
-------------------
- Token-count budgets / model-specific tokenizers. v0 carries a per-
  action ``max_items`` budget only.
- Per-item redaction (B3 stops at inclusion vs. exclusion; column-level
  redaction would be a downstream transform).
- Multi-action composition. ``compose()`` answers exactly one
  ``ActionBudget`` per call; mixing multiple actions in one prompt is
  the caller's responsibility.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from audit_query import trust_domain_of
from data_classification import (
    ClassifiedData,
    DataClass,
    is_more_restrictive,
)


class PromptAssemblyError(ValueError):
    """Raised when assembly inputs violate v0 invariants."""


_DATA_CLASS_RANK = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.RESTRICTED: 3,
}


@dataclass(frozen=True)
class ActionBudget:
    """Per-action ceiling on context sensitivity and size.

    ``action`` is a free-form purpose-of-use string — operators are
    encouraged to use the same vocabulary they pass to the retrieval
    policy so the two checks compose. The assembler does not interpret
    ``action`` beyond echoing it into :class:`PromptContext` for
    logging.
    """

    action: str
    max_class: DataClass
    max_items: int

    def __post_init__(self) -> None:
        if not isinstance(self.action, str) or not self.action:
            raise PromptAssemblyError("action must be a non-empty string")
        if not isinstance(self.max_class, DataClass):
            raise PromptAssemblyError(
                f"max_class must be a DataClass: {self.max_class!r}"
            )
        if not isinstance(self.max_items, int) or self.max_items < 1:
            raise PromptAssemblyError(
                f"max_items must be a positive int: {self.max_items!r}"
            )


@dataclass(frozen=True)
class PromptCandidate:
    """One candidate context chunk submitted to the assembler.

    ``source_label`` is opaque to the assembler — it's an operator-side
    handle that ends up in audit records. ``text`` carries the actual
    bytes that would be spliced into the prompt; the assembler never
    inspects its contents.
    """

    source_label: str
    data: ClassifiedData
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_label, str) or not self.source_label:
            raise PromptAssemblyError("source_label must be a non-empty string")
        if not isinstance(self.data, ClassifiedData):
            raise PromptAssemblyError("data must be a ClassifiedData instance")
        if not isinstance(self.text, str):
            raise PromptAssemblyError("text must be a string")


@dataclass(frozen=True)
class IncludedItem:
    """One chunk that made it into the assembled prompt."""

    source_label: str
    data_class: DataClass
    trust_label: str
    text: str


@dataclass(frozen=True)
class DroppedItem:
    """One chunk dropped before composition, with the reason recorded."""

    source_label: str
    data_class: DataClass
    reason_code: str  # "class_exceeds_budget" | "items_over_budget"


@dataclass(frozen=True)
class PromptContext:
    """The assembler's output: ordered chunks + a drop log."""

    action: str
    max_class: DataClass
    items: tuple[IncludedItem, ...]
    dropped: tuple[DroppedItem, ...] = field(default_factory=tuple)

    @property
    def realized_max_class(self) -> DataClass:
        """The most-restrictive class actually included.

        Returns :class:`DataClass.PUBLIC` when no items were included —
        callers should also check :attr:`items` to disambiguate "empty"
        from "all PUBLIC".
        """
        if not self.items:
            return DataClass.PUBLIC
        return max(
            (item.data_class for item in self.items),
            key=_DATA_CLASS_RANK.__getitem__,
        )


def compose(
    candidates: Iterable[PromptCandidate],
    *,
    budget: ActionBudget,
) -> PromptContext:
    """Compose candidates into a budget-respecting :class:`PromptContext`.

    Steps:

    1. Drop every candidate whose ``data.data_class`` is strictly more
       restrictive than ``budget.max_class``.
    2. Sort survivors by ``DataClass`` rank ascending, then by
       ``source_label`` for tie-break determinism.
    3. Take at most ``budget.max_items`` survivors; the rest go on the
       drop log with ``reason_code="items_over_budget"``.
    4. Attach a ``trust_label`` derived from the first lineage tag's
       ``actor_iss`` for downstream audit logging.
    """
    candidates_list = list(candidates)
    for index, c in enumerate(candidates_list):
        if not isinstance(c, PromptCandidate):
            raise PromptAssemblyError(
                f"candidates[{index}] must be a PromptCandidate"
            )

    kept: list[PromptCandidate] = []
    dropped: list[DroppedItem] = []
    for c in candidates_list:
        if is_more_restrictive(c.data.data_class, budget.max_class):
            dropped.append(
                DroppedItem(
                    source_label=c.source_label,
                    data_class=c.data.data_class,
                    reason_code="class_exceeds_budget",
                )
            )
        else:
            kept.append(c)

    kept.sort(
        key=lambda c: (_DATA_CLASS_RANK[c.data.data_class], c.source_label)
    )

    included_slice = kept[: budget.max_items]
    overflow_slice = kept[budget.max_items :]
    for c in overflow_slice:
        dropped.append(
            DroppedItem(
                source_label=c.source_label,
                data_class=c.data.data_class,
                reason_code="items_over_budget",
            )
        )

    items = tuple(
        IncludedItem(
            source_label=c.source_label,
            data_class=c.data.data_class,
            trust_label=trust_domain_of(c.data.lineage[0].actor_iss) or "",
            text=c.text,
        )
        for c in included_slice
    )

    return PromptContext(
        action=budget.action,
        max_class=budget.max_class,
        items=items,
        dropped=tuple(dropped),
    )
