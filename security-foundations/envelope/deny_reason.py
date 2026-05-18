"""Stable taxonomy of capability/envelope denial reasons.

Closes Phase 1 Track B B3 ("Deterministic Error Contracts: Security-deny
responses are machine-readable and auditable. No ambiguous errors that could
cause insecure fallback").

Each :class:`DenyReason` value is a short, snake_case identifier suitable for
matching in client code, log queries, and incident playbooks. The free-form
exception message remains for human readers; the enum value is the
machine-readable counterpart and is also embedded in audit events as
``reason_code``.

**Stability contract.** Identifiers, once shipped, are never renamed or
repurposed. New denial paths get new identifiers; deprecated ones can be
retired but their string form is reserved.

**Coverage.** Every ``raise EnvelopeVerificationError(...)`` site in
:mod:`verify_envelope`, :mod:`capability_token`, :mod:`trust_store`, and
:mod:`issuer_trust_store` carries a ``DenyReason``. The
``test_every_raise_carries_reason`` test in :mod:`test_deny_reason`
asserts this invariant.
"""

from __future__ import annotations

from enum import StrEnum


class DenyReason(StrEnum):
    # --- Envelope structure ---
    MISSING_REQUIRED_FIELD = "missing_required_field"
    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_MESSAGE_ID = "invalid_message_id"
    INVALID_SENDER_SPIFFE_ID = "invalid_sender_spiffe_id"
    INVALID_RECIPIENT_SPIFFE_ID = "invalid_recipient_spiffe_id"
    INVALID_NONCE = "invalid_nonce"
    INVALID_KID = "invalid_kid"
    INVALID_PAYLOAD_DIGEST = "invalid_payload_digest"
    DISALLOWED_ALGORITHM = "disallowed_algorithm"

    # --- Time window (envelope) ---
    INVALID_TIMESTAMP = "invalid_timestamp"
    ISSUED_AT_IN_FUTURE = "issued_at_in_future"
    ENVELOPE_EXPIRED = "envelope_expired"
    INVALID_VALIDITY_WINDOW = "invalid_validity_window"
    ENVELOPE_TTL_EXCEEDED = "envelope_ttl_exceeded"

    # --- Crypto (envelope) ---
    PAYLOAD_DIGEST_MISMATCH = "payload_digest_mismatch"
    MISSING_SIGNATURE = "missing_signature"
    SIGNATURE_ENCODING_INVALID = "signature_encoding_invalid"
    INVALID_PUBLIC_KEY = "invalid_public_key"
    SIGNATURE_INVALID = "signature_invalid"

    # --- Trust store / lookup ---
    UNKNOWN_KID = "unknown_kid"
    KEY_EXPIRED = "key_expired"
    UNKNOWN_ISSUER_KEY = "unknown_issuer_key"
    ISSUER_KEY_EXPIRED = "issuer_key_expired"

    # --- Capability token: structure ---
    CAP_MISSING = "capability_missing"
    CAP_OVERSIZED = "capability_oversized"
    CAP_MALFORMED = "capability_malformed"
    CAP_WRONG_ALG = "capability_wrong_alg"
    CAP_WRONG_TYP = "capability_wrong_typ"
    CAP_INVALID_KID = "capability_invalid_kid"
    CAP_MISSING_CLAIM = "capability_missing_claim"
    CAP_INVALID_CLAIM = "capability_invalid_claim"

    # --- Capability token: envelope binding ---
    CAP_SUB_MISMATCH = "capability_sub_mismatch"
    CAP_AUD_MISMATCH = "capability_aud_mismatch"
    CAP_SCOPE_MISMATCH = "capability_scope_mismatch"
    CAP_DIGEST_MISMATCH = "capability_digest_mismatch"

    # --- Capability token: time / state ---
    CAP_IAT_AFTER_NBF = "capability_iat_after_nbf"
    CAP_NOT_YET_VALID = "capability_not_yet_valid"
    CAP_EXPIRED = "capability_expired"
    CAP_INVALID_VALIDITY_WINDOW = "capability_invalid_validity_window"
    CAP_TTL_EXCEEDED = "capability_ttl_exceeded"
    CAP_SIGNATURE_INVALID = "capability_signature_invalid"
    CAP_REVOKED = "capability_revoked"

    # --- Replay / rate limiting ---
    REPLAY_DETECTED = "replay_detected"
    RATE_LIMITED = "rate_limited"

    # --- Discovery ---
    DISCOVERY_MALFORMED = "discovery_malformed"
    DISCOVERY_EXPIRED = "discovery_expired"
    DISCOVERY_SIGNATURE_INVALID = "discovery_signature_invalid"
    DISCOVERY_UNKNOWN_ISSUER = "discovery_unknown_issuer"

    # --- Admission ---
    ADMISSION_WORKLOAD_NOT_ALLOWED = "admission_workload_not_allowed"
    ADMISSION_VERSION_INCOMPATIBLE = "admission_version_incompatible"

    # --- Delegation (Phase 2 Track A) ---
    DELEGATION_MALFORMED = "delegation_malformed"
    DELEGATION_EXPIRED = "delegation_expired"
    DELEGATION_SIGNATURE_INVALID = "delegation_signature_invalid"
    DELEGATION_UNKNOWN_ISSUER = "delegation_unknown_issuer"
    DELEGATION_DEPTH_EXCEEDED = "delegation_depth_exceeded"
    DELEGATION_PARENT_MISMATCH = "delegation_parent_mismatch"
    DELEGATION_SCOPE_ESCALATION = "delegation_scope_escalation"
    DELEGATION_AUDIENCE_DRIFT = "delegation_audience_drift"
    DELEGATION_TTL_ESCALATION = "delegation_ttl_escalation"

    # --- Retrieval / context firewall (Phase 2 Track B) ---
    RETRIEVAL_CROSS_TENANT = "retrieval_cross_tenant"
    RETRIEVAL_CLASS_EXCEEDS_RULE = "retrieval_class_exceeds_rule"
    RETRIEVAL_NO_RULE_MATCH = "retrieval_no_rule_match"
