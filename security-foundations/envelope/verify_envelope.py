"""Reference envelope verification utilities for Phase 0 bootstrap."""

from __future__ import annotations

import base64
import hashlib
import re
import sqlite3
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import jcs

from .audit import AuditSink
from .deny_reason import DenyReason

if TYPE_CHECKING:
    from .capability_token import CapabilityClaims
    from .revocation_list import RevocationList
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

UUID_V7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SPIFFE_ID_RE = re.compile(r"^spiffe://[a-zA-Z0-9._/-]+$")
NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{16,256}$")
KID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
HEX_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

ALLOWED_ALGORITHMS = {"Ed25519"}

class EnvelopeVerificationError(ValueError):
    """Raised when envelope verification fails.

    Carries an optional :class:`~deny_reason.DenyReason` for machine-readable
    matching alongside the human message. Sites that pre-date the deny-reason
    contract may construct without ``reason``; ``reason_code`` then returns
    the empty string. New raise sites MUST pass a ``DenyReason``.
    """

    def __init__(self, message: str, *, reason: DenyReason | None = None) -> None:
        super().__init__(message)
        self.reason = reason

    @property
    def reason_code(self) -> str:
        return self.reason.value if self.reason is not None else ""

@dataclass(frozen=True)
class VerificationConfig:
    max_clock_skew: timedelta = timedelta(seconds=60)
    max_envelope_ttl: timedelta = timedelta(minutes=5)
    max_capability_ttl: timedelta = timedelta(minutes=5)
    # Structural bound on inbound JSON. Canonicalization (:mod:`jcs`) and
    # hashing recurse over the envelope, so an attacker-supplied nesting
    # depth near CPython's recursion limit turns a few kilobytes of wire
    # bytes into a stack exhaustion. The verifier rejects over-deep
    # envelopes *before* touching them. 64 is far above any real MCP
    # payload and far below the interpreter's limit.
    max_json_depth: int = 64

DEFAULT_CONFIG = VerificationConfig()

class ReplayCache(ABC):
    """Minimal replay cache interface.

    **All three methods are abstract, including** :meth:`mark_if_new`.
    That is deliberate, and it is the whole security contract of this
    class: replay rejection is the one invariant that *requires*
    atomicity, and **there is no correct generic default**.

    The tempting default —::

        def mark_if_new(self, sender, nonce, ttl):
            if self.seen(sender, nonce):
                return False
            self.mark(sender, nonce, ttl)
            return True

    — is a check-then-act race. Two callers handling the same nonce both
    observe "not seen", both mark, and both are told they were first, so
    the replay is accepted. On a purely local dict the window is a few
    bytecodes and CPython's GIL usually hides it. But the reason to
    implement a custom cache at all is a *shared* backend (Redis, a SQL
    table) for cross-process or cross-node deployment — and there
    ``seen`` is a network round trip, which widens the window to
    milliseconds and releases the GIL besides. Measured against a
    2 ms-RTT backend: **32 of 32 concurrent callers accepted the same
    nonce.** The replay defense was simply absent.

    Supplying a lock in this base class would be worse than supplying
    nothing: a local lock serializes threads in one process while doing
    nothing across the processes that motivated the shared backend, so
    it would look fixed and still admit replays.

    So each backend must implement atomicity in its own terms —
    ``INSERT OR IGNORE`` + ``rowcount`` (see :class:`SQLiteReplayCache`),
    a held lock around check-and-set (see :class:`InMemoryReplayCache`),
    Redis ``SET NX``, ``INSERT ... ON CONFLICT DO NOTHING``. Forcing the
    method to be written makes that a decision rather than an omission;
    a partial implementation now fails loudly at construction instead of
    silently accepting replays under load.

    :meth:`mark_if_new` is what :func:`verify_envelope` calls; ``seen``
    and ``mark`` exist for inspection and for tests.
    """

    @abstractmethod
    def seen(self, sender: str, nonce: str) -> bool:
        ...

    @abstractmethod
    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        ...

    @abstractmethod
    def mark_if_new(self, sender: str, nonce: str, ttl: timedelta) -> bool:
        """Atomically reserve ``nonce`` for ``sender``.

        Returns True if the nonce was new and is now reserved, False if it
        was already present (a replay). Implementations MUST make the
        check-and-reserve a single atomic operation against their backend
        — concurrent callers racing the same nonce must yield exactly one
        True.
        """
        ...

class InMemoryReplayCache(ReplayCache):
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def _purge(self, now: datetime) -> None:
        expired = [k for k, v in self._entries.items() if v <= now]
        for key in expired:
            del self._entries[key]

    def seen(self, sender: str, nonce: str) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            self._purge(now)
            return (sender, nonce) in self._entries

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        now = datetime.now(UTC)
        with self._lock:
            self._entries[(sender, nonce)] = now + ttl

    def mark_if_new(self, sender: str, nonce: str, ttl: timedelta) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            self._purge(now)
            key = (sender, nonce)
            if key in self._entries:
                return False
            self._entries[key] = now + ttl
            return True

class SQLiteReplayCache(ReplayCache):
    """SQLite-backed replay cache for cross-process nonce replay protection."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    sender TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (sender, nonce)
                )
                """
            )

    @staticmethod
    def _now_epoch() -> int:
        return int(datetime.now(UTC).timestamp())

    def _purge(self, conn: sqlite3.Connection) -> None:
        conn.execute("DELETE FROM replay_nonces WHERE expires_at <= ?", (self._now_epoch(),))

    def seen(self, sender: str, nonce: str) -> bool:
        with self._connect() as conn:
            self._purge(conn)
            row = conn.execute(
                "SELECT 1 FROM replay_nonces WHERE sender = ? AND nonce = ?",
                (sender, nonce),
            ).fetchone()
            return row is not None

    def mark(self, sender: str, nonce: str, ttl: timedelta) -> None:
        expires_at = self._now_epoch() + max(0, int(ttl.total_seconds()))
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO replay_nonces(sender, nonce, expires_at) VALUES (?, ?, ?)",
                (sender, nonce, expires_at),
            )

    def mark_if_new(self, sender: str, nonce: str, ttl: timedelta) -> bool:
        expires_at = self._now_epoch() + max(0, int(ttl.total_seconds()))
        with self._connect() as conn:
            self._purge(conn)
            cur = conn.execute(
                "INSERT OR IGNORE INTO replay_nonces(sender, nonce, expires_at) VALUES (?, ?, ?)",
                (sender, nonce, expires_at),
            )
            return cur.rowcount == 1

def parse_rfc3339(value: str) -> datetime:
    if not isinstance(value, str):
        raise EnvelopeVerificationError(
            "timestamp must be a string", reason=DenyReason.INVALID_TIMESTAMP
        )
    candidate = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise EnvelopeVerificationError(
            "invalid timestamp format", reason=DenyReason.INVALID_TIMESTAMP
        ) from exc
    if dt.tzinfo is None:
        raise EnvelopeVerificationError(
            "timestamp must include timezone", reason=DenyReason.INVALID_TIMESTAMP
        )
    return dt.astimezone(UTC)

AUDIT_FIELD_MAX_LEN = 256

def audit_safe(value: Any, *, max_len: int = AUDIT_FIELD_MAX_LEN) -> str:
    """Coerce an unvalidated envelope field into something safe to audit.

    The audit context is read straight off the inbound envelope *before*
    validation — it has to be, since a denial needs to name the message it
    denied. So these values are arbitrary attacker-controlled JSON, and the
    audit sink JCS-canonicalizes what it is handed in order to hash it.

    Two ways that bites, both reachable from the wire:

    - A non-canonicalizable value (``json.loads`` accepts a bare ``NaN`` by
      default, so ``{"sender_spiffe_id": NaN}`` parses) makes the sink raise
      *while recording the denial* — the foreign exception escapes the deny
      handler and no event is written. The exact failure this module exists
      to prevent, one layer up.
    - An unbounded string bloats every downstream audit record.

    Non-strings become a type marker rather than their repr: the point is to
    record *that* the field was malformed without copying attacker bytes
    into the forensic log.
    """
    if not isinstance(value, str):
        return f"<non-string:{type(value).__name__}>"
    if len(value) > max_len:
        return value[:max_len] + "…<truncated>"
    return value

def check_json_depth(value: Any, max_depth: int) -> None:
    """Reject structures nested deeper than ``max_depth``.

    Walked with an explicit stack rather than recursion: a recursive depth
    checker would itself blow the stack on exactly the input it exists to
    reject, which is the bug and not the fix.

    Raises :class:`EnvelopeVerificationError` with
    :attr:`DenyReason.ENVELOPE_TOO_DEEP` on the first node past the bound.
    """
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if not isinstance(node, (dict, list)):
            continue
        if depth > max_depth:
            raise EnvelopeVerificationError(
                f"json nesting exceeds maximum depth of {max_depth}",
                reason=DenyReason.ENVELOPE_TOO_DEEP,
            )
        # Push only containers. Scalars cannot deepen the nesting, and
        # queueing one tuple per scalar would make auxiliary memory
        # proportional to *breadth*: a wide array of compact integers turns
        # a few MB of frame into hundreds of MB of transient tuples — a
        # memory-exhaustion DoS inside the check meant to prevent one.
        children = node.values() if isinstance(node, dict) else node
        stack.extend(
            (child, depth + 1)
            for child in children
            if isinstance(child, (dict, list))
        )

def _canonical_json(value: Any) -> bytes:
    """Canonicalize to JCS bytes, converting encoder failures into denials.

    :mod:`jcs` raises bare ``TypeError``/``ValueError`` for values outside
    the JSON data model (``set``, ``bytes``, ``NaN``, ``Infinity``). Those
    reach this function whenever a caller hands the verifier a dict it did
    not decode from JSON itself, and an uncaught ``TypeError`` escapes the
    verifier's deny path — no ``DenyReason``, no audit event. Fail closed
    instead.
    """
    try:
        return jcs.canonicalize(value)
    except EnvelopeVerificationError:
        raise
    except RecursionError as exc:
        raise EnvelopeVerificationError(
            "json nesting exceeds canonicalization limit",
            reason=DenyReason.ENVELOPE_TOO_DEEP,
        ) from exc
    except Exception as exc:
        raise EnvelopeVerificationError(
            f"value is not canonicalizable JSON: {type(exc).__name__}",
            reason=DenyReason.ENVELOPE_NOT_CANONICALIZABLE,
        ) from exc

def _digest_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()

def canonicalize_envelope_for_signing(envelope: dict[str, Any]) -> bytes:
    if "signature" not in envelope:
        raise EnvelopeVerificationError(
            "missing signature", reason=DenyReason.MISSING_SIGNATURE
        )
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    return _canonical_json(unsigned)

def decode_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnvelopeVerificationError(
            "signature must be non-empty base64url",
            reason=DenyReason.SIGNATURE_ENCODING_INVALID,
        )
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise EnvelopeVerificationError(
            "invalid signature encoding", reason=DenyReason.SIGNATURE_ENCODING_INVALID
        ) from exc

def load_ed25519_public_key(public_key_pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise EnvelopeVerificationError(
            "invalid public key", reason=DenyReason.INVALID_PUBLIC_KEY
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EnvelopeVerificationError(
            "invalid public key", reason=DenyReason.INVALID_PUBLIC_KEY
        )
    return key

def _verify_ed25519_signature(signing_input: bytes, signature: str, public_key_pem: bytes) -> bool:
    sig_bytes = decode_base64url(signature)
    key = load_ed25519_public_key(public_key_pem)
    try:
        key.verify(sig_bytes, signing_input)
    except InvalidSignature:
        return False
    return True

def _validate_static_fields(envelope: dict[str, Any]) -> None:
    # Every field below is matched against a regex or a membership test,
    # both of which raise (``TypeError``) on a non-``str`` rather than
    # returning False. The envelope is attacker-controlled JSON, so a
    # non-``str`` here is an expected input, not an internal error: check
    # the type first and deny with the field's own reason code.
    if envelope["version"] != "v0":
        raise EnvelopeVerificationError(
            "unsupported version", reason=DenyReason.UNSUPPORTED_VERSION
        )

    if not isinstance(envelope["message_id"], str) or not UUID_V7_RE.match(
        envelope["message_id"]
    ):
        raise EnvelopeVerificationError(
            "message_id must be UUIDv7", reason=DenyReason.INVALID_MESSAGE_ID
        )

    if not isinstance(envelope["sender_spiffe_id"], str) or not SPIFFE_ID_RE.match(
        envelope["sender_spiffe_id"]
    ):
        raise EnvelopeVerificationError(
            "invalid sender_spiffe_id", reason=DenyReason.INVALID_SENDER_SPIFFE_ID
        )

    if not isinstance(envelope["recipient_spiffe_id"], str) or not SPIFFE_ID_RE.match(
        envelope["recipient_spiffe_id"]
    ):
        raise EnvelopeVerificationError(
            "invalid recipient_spiffe_id", reason=DenyReason.INVALID_RECIPIENT_SPIFFE_ID
        )

    if not isinstance(envelope["nonce"], str) or not NONCE_RE.match(envelope["nonce"]):
        raise EnvelopeVerificationError(
            "invalid nonce format", reason=DenyReason.INVALID_NONCE
        )

    if not isinstance(envelope["kid"], str) or not KID_RE.match(envelope["kid"]):
        raise EnvelopeVerificationError(
            "invalid kid format", reason=DenyReason.INVALID_KID
        )

    if not isinstance(envelope["payload_digest"], str) or not HEX_SHA256_RE.match(
        envelope["payload_digest"]
    ):
        raise EnvelopeVerificationError(
            "payload_digest must be hex sha256",
            reason=DenyReason.INVALID_PAYLOAD_DIGEST,
        )

    # ``x in <set>`` hashes x; an unhashable ``alg`` (list/dict) raises
    # TypeError instead of failing the membership test.
    if not isinstance(envelope["alg"], str) or envelope["alg"] not in ALLOWED_ALGORITHMS:
        raise EnvelopeVerificationError(
            "algorithm not allowed", reason=DenyReason.DISALLOWED_ALGORITHM
        )

def verify_envelope(
    envelope: dict[str, Any],
    *,
    key_lookup: Callable[[str], bytes],
    issuer_lookup: Callable[[str, str], bytes],
    replay_cache: ReplayCache,
    config: VerificationConfig = DEFAULT_CONFIG,
    now: datetime | None = None,
    audit_sink: AuditSink | None = None,
    revocation_list: RevocationList | None = None,
) -> CapabilityClaims:
    # Deferred to avoid circular import (capability_token imports from this module).
    from .capability_token import verify_capability_token

    _raw = envelope if isinstance(envelope, dict) else {}
    audit_ctx = {
        "message_id": audit_safe(_raw.get("message_id", "")),
        "sender": audit_safe(_raw.get("sender_spiffe_id", "")),
        "recipient": audit_safe(_raw.get("recipient_spiffe_id", "")),
        "envelope_kid": audit_safe(_raw.get("kid", "")),
        "issuer_iss": "",
        "issuer_kid": "",
    }

    def _record(**fields: Any) -> None:
        """Emit one audit event, converting sink failures into denials.

        A sink that raises (disk full, permissions) must not leak its own
        exception type out of ``verify_envelope`` — that would reopen the
        partial-deny-path hole from the other end, since ``_record`` is
        called from inside the deny handlers themselves.

        Fail *closed*: an allow that could not be audited is downgraded to a
        denial, because an unaudited allow is precisely what the hash-chained
        log exists to make impossible. In the deny path the outcome is
        already a denial; surfacing AUDIT_SINK_FAILURE there deliberately
        supersedes the original reason code, since a broken audit sink is the
        more urgent operational fact (the original stays chained).
        """
        if audit_sink is None:
            return
        try:
            audit_sink.record(**fields)
        except Exception as exc:
            raise EnvelopeVerificationError(
                f"audit sink failed: {type(exc).__name__}",
                reason=DenyReason.AUDIT_SINK_FAILURE,
            ) from exc

    def _emit(outcome: str, reason: str, *, reason_code: str = "") -> None:
        _record(
            event_type="envelope.verify",
            outcome=outcome,
            reason=reason,
            reason_code=reason_code,
            artifact_version="envelope/v0",
            **audit_ctx,
        )

    def _emit_cap(
        outcome: str,
        reason: str,
        *,
        reason_code: str = "",
        cap_iss: str = "",
        cap_kid: str = "",
    ) -> None:
        _record(
            event_type="capability.verify",
            outcome=outcome,
            reason=reason,
            reason_code=reason_code,
            artifact_version="wt-cap+jwt",
            message_id=audit_ctx["message_id"],
            sender=audit_ctx["sender"],
            recipient=audit_ctx["recipient"],
            envelope_kid=audit_ctx["envelope_kid"],
            issuer_iss=cap_iss,
            issuer_kid=cap_kid,
        )

    try:
        if not isinstance(envelope, dict):
            raise EnvelopeVerificationError(
                "envelope must be a JSON object",
                reason=DenyReason.ENVELOPE_NOT_OBJECT,
            )

        # Structural bound first: everything downstream (canonicalization,
        # hashing, signing input) recurses over this object.
        check_json_depth(envelope, config.max_json_depth)

        required = {
            "version",
            "message_id",
            "sender_spiffe_id",
            "recipient_spiffe_id",
            "issued_at",
            "expires_at",
            "nonce",
            "capability_token",
            "purpose_of_use",
            "kid",
            "alg",
            "payload",
            "payload_digest",
            "signature",
        }

        missing = sorted(required - set(envelope))
        if missing:
            raise EnvelopeVerificationError(
                f"missing required fields: {','.join(missing)}",
                reason=DenyReason.MISSING_REQUIRED_FIELD,
            )

        _validate_static_fields(envelope)

        issued_at = parse_rfc3339(envelope["issued_at"])
        expires_at = parse_rfc3339(envelope["expires_at"])
        current = now.astimezone(UTC) if now else datetime.now(UTC)

        if issued_at - current > config.max_clock_skew:
            raise EnvelopeVerificationError(
                "issued_at in future beyond skew", reason=DenyReason.ISSUED_AT_IN_FUTURE
            )
        if current - expires_at > config.max_clock_skew:
            raise EnvelopeVerificationError(
                "envelope expired", reason=DenyReason.ENVELOPE_EXPIRED
            )
        if expires_at <= issued_at:
            raise EnvelopeVerificationError(
                "invalid validity window", reason=DenyReason.INVALID_VALIDITY_WINDOW
            )
        if expires_at - issued_at > config.max_envelope_ttl:
            raise EnvelopeVerificationError(
                "envelope ttl exceeds maximum",
                reason=DenyReason.ENVELOPE_TTL_EXCEEDED,
            )

        computed_digest = _digest_payload(envelope["payload"])
        if computed_digest != envelope["payload_digest"]:
            raise EnvelopeVerificationError(
                "payload digest mismatch", reason=DenyReason.PAYLOAD_DIGEST_MISMATCH
            )

        signing_input = canonicalize_envelope_for_signing(envelope)
        public_key_pem = key_lookup(envelope["kid"])

        if envelope["alg"] == "Ed25519" and not _verify_ed25519_signature(
            signing_input,
            envelope["signature"],
            public_key_pem,
        ):
            raise EnvelopeVerificationError(
                "signature invalid", reason=DenyReason.SIGNATURE_INVALID
            )

        try:
            claims = verify_capability_token(
                envelope["capability_token"],
                envelope=envelope,
                issuer_lookup=issuer_lookup,
                current=current,
                max_clock_skew=config.max_clock_skew,
                max_capability_ttl=config.max_capability_ttl,
                revocation_list=revocation_list,
            )
        except EnvelopeVerificationError as cap_exc:
            _emit_cap("deny", str(cap_exc), reason_code=cap_exc.reason_code)
            raise
        _emit_cap(
            "allow", "ok",
            reason_code="ok",
            cap_iss=claims.iss,
            cap_kid=claims.issuer_kid,
        )
        audit_ctx["issuer_iss"] = claims.iss
        audit_ctx["issuer_kid"] = claims.issuer_kid

        sender = envelope["sender_spiffe_id"]
        nonce = envelope["nonce"]
        ttl = max(expires_at - current, timedelta(seconds=0))
        if not replay_cache.mark_if_new(sender, nonce, ttl):
            raise EnvelopeVerificationError(
                "replay detected", reason=DenyReason.REPLAY_DETECTED
            )
    except EnvelopeVerificationError as exc:
        _emit("deny", str(exc), reason_code=exc.reason_code)
        raise
    except Exception as exc:
        # Fail-closed backstop. Anything that reaches here is a path the
        # verifier did not anticipate — a malformed field type it has no
        # explicit guard for, a ``key_lookup``/``replay_cache`` callback
        # that raised, a bug. Letting it propagate as its native type
        # would (a) escape every caller's ``except
        # EnvelopeVerificationError`` handler and (b) skip the deny audit
        # event, so a malformed-envelope probe would leave no forensic
        # trace. Deny is the safe direction; the original exception stays
        # chained for debugging and its type lands in the audit reason.
        detail = f"verifier internal error: {type(exc).__name__}"
        _emit("deny", detail, reason_code=DenyReason.VERIFIER_INTERNAL_ERROR.value)
        raise EnvelopeVerificationError(
            detail, reason=DenyReason.VERIFIER_INTERNAL_ERROR
        ) from exc

    _emit("allow", "ok", reason_code="ok")
    return claims
