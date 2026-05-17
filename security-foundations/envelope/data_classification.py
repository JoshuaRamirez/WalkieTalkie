"""Data classification + lineage v0 (Phase 2 Track B B1).

Closes the first half of B1 ("Class labels (public/internal/confidential/
restricted)") and the second half ("Metadata binding and immutable lineage
tags").

Every piece of data that crosses an ingress boundary gets wrapped in a
:class:`ClassifiedData` record: a `data_digest` (sha256 of the actual
bytes), a :class:`DataClass` label, an immutable tuple of
:class:`LineageTag` entries, and an immutable key/value metadata bag.

Derivation rules (the v0 non-escalation invariant for data):

- :func:`derive` produces a child :class:`ClassifiedData` whose class is
  **at least as restrictive** as the parent's. Demotion (e.g. confidential
  → public) is rejected — that's the data-side equivalent of the
  delegation non-escalation rule.
- :func:`combine` builds a child whose class is the *max* (most
  restrictive) of all parents.
- Both extend the lineage chain with a new :class:`LineageTag` whose
  ``parent_digest`` field commits to the parent's ``chain_hash`` — so any
  future verifier can re-derive the chain hashes and detect tampering.

Out of scope for v0
-------------------
- Class label downgrading via human-review workflow (Track C C3 concern).
- Cryptographic signing of lineage tags (today the lineage is integrity-
  protected only by chain hashing; signing comes when actor_iss/kid are
  consumed by a verifier, expected in B2).
- Per-class encryption-at-rest. v0 only carries the label; storage is
  the operator's concern.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

import jcs
from verify_envelope import HEX_SHA256_RE, KID_RE, SPIFFE_ID_RE


class DataClass(StrEnum):
    """Class labels in increasing order of restriction.

    The ``int`` order on ``_RANK`` defines "more restrictive" — operators
    SHOULD compare via :func:`is_more_restrictive` rather than relying on
    enum iteration order.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


_RANK = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL: 1,
    DataClass.CONFIDENTIAL: 2,
    DataClass.RESTRICTED: 3,
}


class DataClassificationError(ValueError):
    """Raised when a classification or derivation breaks the lineage rules."""


def is_more_restrictive(a: DataClass, b: DataClass) -> bool:
    """``True`` iff ``a`` is strictly more restrictive than ``b``."""
    return _RANK[a] > _RANK[b]


def max_class(klasses: Iterable[DataClass]) -> DataClass:
    """Return the most restrictive class from ``klasses`` (non-empty)."""
    ks = list(klasses)
    if not ks:
        raise DataClassificationError("max_class requires at least one class")
    return max(ks, key=_RANK.__getitem__)


@dataclass(frozen=True)
class LineageTag:
    """One step in the chain of custody for a piece of classified data.

    ``parent_digest`` commits to the parent's :func:`chain_hash` — if a
    future verifier walks the lineage, it re-derives the chain hashes and
    rejects anything that doesn't match.
    """

    actor_iss: str
    actor_kid: str
    operation: str
    timestamp: str  # RFC 3339 with explicit timezone
    parent_digest: str  # hex sha256; "0" * 64 for first-touch ingest

    def __post_init__(self) -> None:
        if not isinstance(self.actor_iss, str) or not SPIFFE_ID_RE.match(self.actor_iss):
            raise DataClassificationError(f"invalid actor_iss: {self.actor_iss!r}")
        if not isinstance(self.actor_kid, str) or not KID_RE.match(self.actor_kid):
            raise DataClassificationError(f"invalid actor_kid: {self.actor_kid!r}")
        if not isinstance(self.operation, str) or not self.operation:
            raise DataClassificationError("operation must be a non-empty string")
        if not isinstance(self.timestamp, str) or not self.timestamp:
            raise DataClassificationError("timestamp must be a non-empty string")
        if not isinstance(self.parent_digest, str) or not HEX_SHA256_RE.match(self.parent_digest):
            raise DataClassificationError(
                f"parent_digest must be hex sha256: {self.parent_digest!r}"
            )

    def to_dict(self) -> dict:
        return {
            "actor_iss": self.actor_iss,
            "actor_kid": self.actor_kid,
            "operation": self.operation,
            "timestamp": self.timestamp,
            "parent_digest": self.parent_digest,
        }


_GENESIS_PARENT_DIGEST = "0" * 64


@dataclass(frozen=True)
class ClassifiedData:
    """An immutable wrapper around a data digest + class + lineage chain.

    The actual data bytes are *not* carried here; only their sha256 digest.
    That keeps :class:`ClassifiedData` cheap to pass around and serializable
    without inadvertently propagating large or sensitive payloads.
    """

    data_digest: str
    data_class: DataClass
    lineage: tuple[LineageTag, ...]
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.data_digest, str) or not HEX_SHA256_RE.match(self.data_digest):
            raise DataClassificationError(
                f"data_digest must be hex sha256: {self.data_digest!r}"
            )
        if not isinstance(self.data_class, DataClass):
            raise DataClassificationError(
                f"data_class must be a DataClass: {self.data_class!r}"
            )
        if not isinstance(self.lineage, tuple):
            raise DataClassificationError("lineage must be a tuple")
        if not self.lineage:
            raise DataClassificationError("lineage must be non-empty")
        for index, tag in enumerate(self.lineage):
            if not isinstance(tag, LineageTag):
                raise DataClassificationError(
                    f"lineage[{index}] must be a LineageTag"
                )
        if not isinstance(self.metadata, tuple):
            raise DataClassificationError("metadata must be a tuple of (key, value) pairs")
        seen_keys: set[str] = set()
        for index, kv in enumerate(self.metadata):
            if not isinstance(kv, tuple) or len(kv) != 2:
                raise DataClassificationError(
                    f"metadata[{index}] must be a (key, value) tuple"
                )
            k, v = kv
            if not isinstance(k, str) or not k:
                raise DataClassificationError(
                    f"metadata[{index}] key must be a non-empty string"
                )
            if not isinstance(v, str):
                raise DataClassificationError(
                    f"metadata[{index}] value must be a string"
                )
            if k in seen_keys:
                raise DataClassificationError(f"duplicate metadata key: {k!r}")
            seen_keys.add(k)

    @property
    def chain_hash(self) -> str:
        """Stable hex sha256 over the data + class + lineage + metadata.

        Used as ``parent_digest`` when this record is consumed as input to
        a derived record. Bit-stable across processes (computed via JCS).
        """
        body = {
            "data_digest": self.data_digest,
            "data_class": self.data_class.value,
            "lineage": [tag.to_dict() for tag in self.lineage],
            "metadata": [list(kv) for kv in self.metadata],
        }
        return hashlib.sha256(jcs.canonicalize(body)).hexdigest()


def _rfc3339(now: datetime | None) -> str:
    when = (now or datetime.now(UTC)).astimezone(UTC)
    return when.isoformat().replace("+00:00", "Z")


def classify(
    *,
    data_digest: str,
    data_class: DataClass,
    actor_iss: str,
    actor_kid: str,
    operation: str = "ingest",
    metadata: Iterable[tuple[str, str]] = (),
    now: datetime | None = None,
) -> ClassifiedData:
    """First-touch classification at ingress.

    The lineage chain starts with a single tag whose ``parent_digest`` is
    the genesis sentinel (64 zeros).
    """
    tag = LineageTag(
        actor_iss=actor_iss,
        actor_kid=actor_kid,
        operation=operation,
        timestamp=_rfc3339(now),
        parent_digest=_GENESIS_PARENT_DIGEST,
    )
    return ClassifiedData(
        data_digest=data_digest,
        data_class=data_class,
        lineage=(tag,),
        metadata=tuple(metadata),
    )


def derive(
    parent: ClassifiedData,
    *,
    data_digest: str,
    actor_iss: str,
    actor_kid: str,
    operation: str,
    new_class: DataClass | None = None,
    metadata: Iterable[tuple[str, str]] | None = None,
    now: datetime | None = None,
) -> ClassifiedData:
    """Produce a derived :class:`ClassifiedData`.

    ``new_class`` may *promote* the class (more restrictive) but never
    demote it. ``None`` keeps the parent's class.
    """
    if new_class is None:
        effective_class = parent.data_class
    elif is_more_restrictive(parent.data_class, new_class):
        raise DataClassificationError(
            f"cannot demote data class: parent={parent.data_class.value}, "
            f"requested={new_class.value}"
        )
    else:
        effective_class = new_class

    tag = LineageTag(
        actor_iss=actor_iss,
        actor_kid=actor_kid,
        operation=operation,
        timestamp=_rfc3339(now),
        parent_digest=parent.chain_hash,
    )
    return ClassifiedData(
        data_digest=data_digest,
        data_class=effective_class,
        lineage=(*parent.lineage, tag),
        metadata=tuple(metadata) if metadata is not None else parent.metadata,
    )


def combine(
    parents: Iterable[ClassifiedData],
    *,
    data_digest: str,
    actor_iss: str,
    actor_kid: str,
    operation: str,
    metadata: Iterable[tuple[str, str]] = (),
    now: datetime | None = None,
) -> ClassifiedData:
    """Combine multiple parents into one classified record.

    The result's class is the maximum (most restrictive) over the parents'
    classes. The result's lineage is the concatenation of every parent's
    lineage followed by a single new tag whose ``parent_digest`` covers
    the *combined* chain hash of all parents (committed in sorted order
    so the result is reproducible across implementations).
    """
    parents_list = list(parents)
    if not parents_list:
        raise DataClassificationError("combine requires at least one parent")
    effective_class = max_class(p.data_class for p in parents_list)

    parent_hashes = sorted(p.chain_hash for p in parents_list)
    combined = hashlib.sha256("\n".join(parent_hashes).encode("utf-8")).hexdigest()

    tag = LineageTag(
        actor_iss=actor_iss,
        actor_kid=actor_kid,
        operation=operation,
        timestamp=_rfc3339(now),
        parent_digest=combined,
    )
    lineage: list[LineageTag] = []
    for parent in parents_list:
        lineage.extend(parent.lineage)
    lineage.append(tag)

    return ClassifiedData(
        data_digest=data_digest,
        data_class=effective_class,
        lineage=tuple(lineage),
        metadata=tuple(metadata),
    )
