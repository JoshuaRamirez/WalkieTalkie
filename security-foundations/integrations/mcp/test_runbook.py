"""Phase 4 D4.4 runbook artifact tests.

A short CI gate that prevents the runbook (``example/README.md``)
from drifting away from the files it references. If a future agent
deletes ``gen_keys.py`` or ``sample-audit.jsonl`` without updating
the README, this test fails fast.

We do NOT re-run the generator scripts here — that would slow CI
and add cross-process state. We just check the artifacts exist and
the audit-log skeleton looks right.
"""

import json
import pathlib
import sys
import unittest

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "envelope")
)

from audit import AuditEvent, verify_chain  # noqa: E402

_EXAMPLE_DIR = pathlib.Path(__file__).resolve().parent / "example"


class RunbookArtifactsTests(unittest.TestCase):
    def test_readme_exists(self):
        self.assertTrue(
            (_EXAMPLE_DIR / "README.md").is_file(),
            "Phase 4 D4.4 runbook README is missing",
        )

    def test_gen_keys_script_exists(self):
        self.assertTrue((_EXAMPLE_DIR / "gen_keys.py").is_file())

    def test_sample_audit_exists(self):
        self.assertTrue((_EXAMPLE_DIR / "sample-audit.jsonl").is_file())


class SampleAuditChainTests(unittest.TestCase):
    """The shipped sample audit must hash-validate, otherwise an
    operator following the runbook will look at a broken example."""

    def test_chain_hash_validates(self):
        events = []
        for line in (_EXAMPLE_DIR / "sample-audit.jsonl").read_text().splitlines():
            data = json.loads(line)
            events.append(
                AuditEvent(
                    timestamp=data["timestamp"],
                    event_type=data["event_type"],
                    outcome=data["outcome"],
                    reason=data["reason"],
                    message_id=data.get("message_id", ""),
                    sender=data.get("sender", ""),
                    recipient=data.get("recipient", ""),
                    envelope_kid=data.get("envelope_kid", ""),
                    issuer_iss=data.get("issuer_iss", ""),
                    issuer_kid=data.get("issuer_kid", ""),
                    prev_hash=data["prev_hash"],
                    this_hash=data["this_hash"],
                    reason_code=data.get("reason_code", ""),
                    artifact_version=data.get("artifact_version", ""),
                )
            )
        # Raises AuditChainError on tampering / drift.
        verify_chain(events)

    def test_sample_audit_covers_happy_path_event_sequence(self):
        events = []
        for line in (_EXAMPLE_DIR / "sample-audit.jsonl").read_text().splitlines():
            events.append(json.loads(line))
        types = [e["event_type"] for e in events]
        # The runbook README documents this sequence; if it drifts,
        # update both the README and this test in the same commit.
        for required in ("capability.issue", "envelope.verify", "tool.gate",
                         "egress.evaluate"):
            self.assertIn(required, types)


if __name__ == "__main__":
    unittest.main()
