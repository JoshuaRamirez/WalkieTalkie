"""Alerting policies layered on top of the audit checkpoint stream.

Closes Phase 1 Track D D3 ("Alerting"):

- "Thresholds for repeated validation failures per identity" — tracked from
  ``envelope.verify`` deny events keyed on ``sender``.
- "Thresholds for abnormal capability issuance volume" — tracked from
  ``capability.issue`` allow events keyed on ``sender`` (the cap token's
  ``sub``, i.e., the identity being granted authority).

Design
------
- :class:`AlertingPolicy` consumes :class:`audit.AuditEvent` and returns zero
  or more :class:`Alert` instances per event.
- :class:`ThresholdAlertingPolicy` is the default implementation: per-identity
  sliding windows + a fixed count threshold per alert kind.
- :class:`AlertingAuditSink` is an :class:`audit.AuditSink` decorator. It
  forwards every event to an inner sink (preserving the hash chain) and then
  feeds the same event to an :class:`AlertingPolicy`. Alerts are dispatched
  through a caller-supplied ``on_alert`` callable so v0 stays transport-
  agnostic — operators can wire it to PagerDuty, Slack, syslog, or stdout.

Out of scope for v0
-------------------
- Cross-process / distributed sliding-window state. v0 is single-process.
- Persistent alert state across restarts.
- De-duplication windows (an alert can re-fire as soon as the bucket refills).
- Cross-tenant attempt detection (Phase 1 Track D D2 queryability concern).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from audit import AuditEvent, AuditSink
from verify_envelope import parse_rfc3339

REPEATED_VALIDATION_FAILURE = "repeated_validation_failure"
ABNORMAL_ISSUANCE_VOLUME = "abnormal_issuance_volume"


@dataclass(frozen=True)
class Alert:
    """One alert occurrence. Caller's ``on_alert`` decides how to dispatch."""

    kind: str
    identity: str
    count: int
    window_seconds: int
    triggered_at: datetime


class AlertingPolicy(ABC):
    @abstractmethod
    def observe(self, event: AuditEvent) -> list[Alert]:
        """Called after each event. Return any alerts the event triggers."""


@dataclass
class ThresholdAlertingPolicy(AlertingPolicy):
    """Per-identity sliding-window count thresholds.

    Each tracked event_type maintains a per-identity ``deque`` of timestamps;
    events older than ``window`` are evicted on each observation. When a
    bucket reaches its threshold the alert fires and the bucket is cleared
    so the alert does not re-fire on every subsequent event in the same
    window.
    """

    window: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    repeated_deny_threshold: int = 10
    issuance_volume_threshold: int = 100

    _deny_buckets: dict[str, deque[datetime]] = field(default_factory=dict, init=False, repr=False)
    _issuance_buckets: dict[str, deque[datetime]] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.window <= timedelta(0):
            raise ValueError("window must be positive")
        if self.repeated_deny_threshold < 1:
            raise ValueError("repeated_deny_threshold must be >= 1")
        if self.issuance_volume_threshold < 1:
            raise ValueError("issuance_volume_threshold must be >= 1")

    def observe(self, event: AuditEvent) -> list[Alert]:
        if not event.timestamp:
            return []
        ts = parse_rfc3339(event.timestamp)
        cutoff = ts - self.window
        alerts: list[Alert] = []

        if (
            event.event_type == "envelope.verify"
            and event.outcome == "deny"
            and event.sender
        ):
            bucket = self._deny_buckets.setdefault(event.sender, deque())
            self._purge(bucket, cutoff)
            bucket.append(ts)
            if len(bucket) >= self.repeated_deny_threshold:
                alerts.append(
                    Alert(
                        kind=REPEATED_VALIDATION_FAILURE,
                        identity=event.sender,
                        count=len(bucket),
                        window_seconds=int(self.window.total_seconds()),
                        triggered_at=ts,
                    )
                )
                bucket.clear()

        if (
            event.event_type == "capability.issue"
            and event.outcome == "allow"
            and event.sender
        ):
            bucket = self._issuance_buckets.setdefault(event.sender, deque())
            self._purge(bucket, cutoff)
            bucket.append(ts)
            if len(bucket) >= self.issuance_volume_threshold:
                alerts.append(
                    Alert(
                        kind=ABNORMAL_ISSUANCE_VOLUME,
                        identity=event.sender,
                        count=len(bucket),
                        window_seconds=int(self.window.total_seconds()),
                        triggered_at=ts,
                    )
                )
                bucket.clear()

        return alerts

    @staticmethod
    def _purge(bucket: deque[datetime], cutoff: datetime) -> None:
        while bucket and bucket[0] < cutoff:
            bucket.popleft()


class AlertingAuditSink(AuditSink):
    """Decorator: forwards events to ``inner`` and feeds them to ``policy``.

    Hash-chain integrity is preserved because all writes happen on the inner
    sink. ``tail_hash`` delegates so the chain extends through whatever
    persistence the inner sink uses (in-memory, JSONL, future backends).
    """

    def __init__(
        self,
        inner: AuditSink,
        *,
        policy: AlertingPolicy,
        on_alert: Callable[[Alert], None],
    ) -> None:
        self._inner = inner
        self._policy = policy
        self._on_alert = on_alert

    def tail_hash(self) -> str:
        return self._inner.tail_hash()

    def _append(self, event: AuditEvent) -> None:
        self._inner._append(event)
        for alert in self._policy.observe(event):
            self._on_alert(alert)
