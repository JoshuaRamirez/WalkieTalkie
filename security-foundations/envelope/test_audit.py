import json
import pathlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import (
    GENESIS_PREV_HASH,
    AuditChainError,
    AuditEvent,
    InMemoryAuditSink,
    JsonlAuditSink,
    verify_chain,
)


def _record(sink, **overrides):
    base = dict(
        event_type="envelope.verify",
        outcome="allow",
        reason="ok",
        message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
        sender="spiffe://mesh/ns-a/service-a",
        recipient="spiffe://mesh/ns-b/service-b",
        envelope_kid="dev-kid-1",
        issuer_iss="spiffe://mesh/cap-issuer-1",
        issuer_kid="issuer-kid-1",
        timestamp=datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC),
    )
    base.update(overrides)
    return sink.record(**base)


class InMemorySinkTests(unittest.TestCase):
    def test_first_event_uses_genesis_prev_hash(self):
        sink = InMemoryAuditSink()
        event = _record(sink)
        self.assertEqual(event.prev_hash, GENESIS_PREV_HASH)
        self.assertNotEqual(event.this_hash, GENESIS_PREV_HASH)

    def test_subsequent_event_chains_to_previous(self):
        sink = InMemoryAuditSink()
        first = _record(sink, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1")
        second = _record(sink, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2")
        self.assertEqual(second.prev_hash, first.this_hash)

    def test_chain_verifies(self):
        sink = InMemoryAuditSink()
        for i in range(5):
            _record(sink, message_id=f"0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c{i}")
        verify_chain(sink.events)  # does not raise

    def test_invalid_outcome_rejected(self):
        sink = InMemoryAuditSink()
        with self.assertRaises(ValueError):
            _record(sink, outcome="maybe")

    def test_tampered_event_detected(self):
        sink = InMemoryAuditSink()
        _record(sink, reason="ok")
        events = list(sink.events)
        # Mutate the recorded reason without recomputing the hash.
        events[0] = AuditEvent(**{**events[0].to_dict(), "reason": "tampered"})
        with self.assertRaisesRegex(AuditChainError, "this_hash mismatch"):
            verify_chain(events)

    def test_inserted_event_breaks_chain(self):
        sink = InMemoryAuditSink()
        _record(sink, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1")
        _record(sink, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2")
        events = list(sink.events)
        # Re-mint a "fake" middle event that copies the second's prev_hash.
        forged = AuditEvent(**{
            **events[1].to_dict(),
            "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c9",
        })
        events.insert(1, forged)
        with self.assertRaises(AuditChainError):
            verify_chain(events)


class JsonlSinkTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            for i in range(3):
                _record(sink, message_id=f"0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c{i}")
            events = sink.read_all()
            self.assertEqual(len(events), 3)
            verify_chain(events)

    def test_tail_hash_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "audit.jsonl"
            sink_a = JsonlAuditSink(path)
            first = _record(sink_a, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1")

            sink_b = JsonlAuditSink(path)
            self.assertEqual(sink_b.tail_hash(), first.this_hash)
            second = _record(sink_b, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2")
            self.assertEqual(second.prev_hash, first.this_hash)

            verify_chain(JsonlAuditSink(path).read_all())

    def test_tampered_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "audit.jsonl"
            sink = JsonlAuditSink(path)
            _record(sink, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1")
            _record(sink, message_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2")

            # Edit the first line to lie about its outcome.
            lines = path.read_text().splitlines()
            first = json.loads(lines[0])
            first["outcome"] = "deny"
            lines[0] = json.dumps(first, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n")

            with self.assertRaises(AuditChainError):
                verify_chain(JsonlAuditSink(path).read_all())


if __name__ == "__main__":
    unittest.main()
