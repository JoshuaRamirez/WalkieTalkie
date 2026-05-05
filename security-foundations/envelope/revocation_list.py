"""Capability token revocation v0.

Closes the second sub-bullet of Phase 1 D1.3 ("Capability revocation API +
cache invalidation channel") and the "revoked" arm of Phase 1 Track C C2
("Reject expired, out-of-scope, wrong-audience, or revoked tokens"). v0 is
local-process only — the *cache invalidation channel* is deliberately
deferred until a transport choice exists.

A :class:`RevocationList` is consulted by the capability validator with the
token's ``jti``. Returning ``True`` from :meth:`is_revoked` causes
:func:`capability_token.verify_capability_token` to reject the token with
``capability token: revoked``.

Two implementations:

- :class:`InMemoryRevocationList` — set-backed, useful for tests and short-
  lived workloads.
- :class:`FileBackedRevocationList` — append-only JSONL log of revocations.
  ``revoke()`` appends a line; ``is_revoked()`` reads the file. The optional
  :meth:`FileBackedRevocationList.integrity_hash` returns a sha256 over the
  sorted, deduplicated jti set so operators can compare against a known-good
  baseline.

Out of scope for v0
-------------------
- Distributed cache invalidation (D1.3 explicitly mentions this; a transport
  choice precedes it).
- Revocation issuance API surface (HTTP/RPC).
- Per-revocation authorization (who can revoke what).
- Time-bounded revocation (a token is either revoked or not; no
  ``revoked_until``).
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from verify_envelope import UUID_V7_RE


class RevocationList(ABC):
    """Yes/no check for a capability token's ``jti``."""

    @abstractmethod
    def is_revoked(self, jti: str) -> bool:
        ...


class InMemoryRevocationList(RevocationList):
    def __init__(self, jtis: Iterable[str] = ()) -> None:
        self._jtis: set[str] = set()
        for jti in jtis:
            self.revoke(jti)

    def revoke(self, jti: str, *, reason: str = "") -> None:
        if not isinstance(jti, str) or not UUID_V7_RE.match(jti):
            raise ValueError(f"invalid jti: {jti!r}")
        # ``reason`` is accepted for API symmetry with the file-backed
        # implementation but not stored in v0; revocation reasons live in the
        # audit trail when callers wire one up.
        del reason
        self._jtis.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._jtis


class FileBackedRevocationList(RevocationList):
    """Append-only JSONL revocation log.

    Each line is::

        {"jti": "<uuidv7>", "revoked_at": "<RFC3339>", "reason": "<free text>"}

    Duplicate revocations are tolerated (the same jti listed twice has the same
    effect as listed once). ``is_revoked()`` rebuilds the set from disk on each
    call, so changes by another process are picked up; for higher-throughput
    deployments swap in an in-process cache once the cache invalidation channel
    lands (D1.3 follow-up).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.touch(exist_ok=True)

    def revoke(self, jti: str, *, reason: str = "", now: datetime | None = None) -> None:
        if not isinstance(jti, str) or not UUID_V7_RE.match(jti):
            raise ValueError(f"invalid jti: {jti!r}")
        if not isinstance(reason, str):
            raise ValueError("reason must be a string")
        ts = (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
        record = {"jti": jti, "revoked_at": ts, "reason": reason}
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")

    def _load(self) -> set[str]:
        revoked: set[str] = set()
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"corrupt revocation file (unparseable line): {self._path}"
                    ) from exc
                jti = record.get("jti")
                if not isinstance(jti, str):
                    raise ValueError(
                        f"corrupt revocation file (missing/invalid jti): {self._path}"
                    )
                revoked.add(jti)
        return revoked

    def is_revoked(self, jti: str) -> bool:
        return jti in self._load()

    def integrity_hash(self) -> str:
        """sha256 over the sorted, deduplicated revoked-jti set.

        Operators can checkpoint this hash and re-compute later to detect any
        change to the revocation set. Insertion order does not affect the hash;
        only the final membership matters.
        """
        revoked = sorted(self._load())
        canonical = "\n".join(revoked).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
