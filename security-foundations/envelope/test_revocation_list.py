import json
import pathlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from revocation_list import FileBackedRevocationList, InMemoryRevocationList

_VALID_JTI_1 = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1"
_VALID_JTI_2 = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2"


class InMemoryRevocationListTests(unittest.TestCase):
    def test_unknown_jti_not_revoked(self):
        rl = InMemoryRevocationList()
        self.assertFalse(rl.is_revoked(_VALID_JTI_1))

    def test_revoked_jti_is_revoked(self):
        rl = InMemoryRevocationList()
        rl.revoke(_VALID_JTI_1)
        self.assertTrue(rl.is_revoked(_VALID_JTI_1))
        self.assertFalse(rl.is_revoked(_VALID_JTI_2))

    def test_seed_constructor(self):
        rl = InMemoryRevocationList([_VALID_JTI_1, _VALID_JTI_2])
        self.assertTrue(rl.is_revoked(_VALID_JTI_1))
        self.assertTrue(rl.is_revoked(_VALID_JTI_2))

    def test_invalid_jti_rejected(self):
        rl = InMemoryRevocationList()
        for bad in ("", "not-a-uuid", "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c"):
            with self.subTest(jti=bad):
                with self.assertRaisesRegex(ValueError, "invalid jti"):
                    rl.revoke(bad)

    def test_double_revoke_idempotent(self):
        rl = InMemoryRevocationList()
        rl.revoke(_VALID_JTI_1)
        rl.revoke(_VALID_JTI_1)
        self.assertTrue(rl.is_revoked(_VALID_JTI_1))


class FileBackedRevocationListTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rev.jsonl"
            rl = FileBackedRevocationList(path)
            rl.revoke(_VALID_JTI_1, reason="leaked")

            self.assertTrue(rl.is_revoked(_VALID_JTI_1))
            self.assertFalse(rl.is_revoked(_VALID_JTI_2))

            # Persists across instances.
            rl2 = FileBackedRevocationList(path)
            self.assertTrue(rl2.is_revoked(_VALID_JTI_1))

    def test_record_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rev.jsonl"
            rl = FileBackedRevocationList(path)
            rl.revoke(_VALID_JTI_1, reason="leaked", now=datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC))

            line = path.read_text().strip()
            record = json.loads(line)
            self.assertEqual(record["jti"], _VALID_JTI_1)
            self.assertEqual(record["reason"], "leaked")
            self.assertEqual(record["revoked_at"], "2026-04-14T12:00:00Z")

    def test_invalid_jti_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rev.jsonl"
            rl = FileBackedRevocationList(path)
            with self.assertRaisesRegex(ValueError, "invalid jti"):
                rl.revoke("not-a-uuid")
            # File must still be empty/parseable.
            self.assertEqual(path.read_text(), "")

    def test_corrupt_line_rejected_at_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rev.jsonl"
            rl = FileBackedRevocationList(path)
            rl.revoke(_VALID_JTI_1)
            with path.open("a") as f:
                f.write("not json\n")
            with self.assertRaisesRegex(ValueError, "corrupt revocation file"):
                rl.is_revoked(_VALID_JTI_2)

    def test_integrity_hash_changes_after_revoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rev.jsonl"
            rl = FileBackedRevocationList(path)
            empty = rl.integrity_hash()

            rl.revoke(_VALID_JTI_1)
            after_one = rl.integrity_hash()
            self.assertNotEqual(empty, after_one)

            rl.revoke(_VALID_JTI_2)
            after_two = rl.integrity_hash()
            self.assertNotEqual(after_one, after_two)

    def test_integrity_hash_invariant_under_duplicate_entries(self):
        # Same set of revocations → same hash regardless of how many times
        # each jti was appended or in what order.
        with tempfile.TemporaryDirectory() as tmp:
            path_a = pathlib.Path(tmp) / "a.jsonl"
            path_b = pathlib.Path(tmp) / "b.jsonl"

            rl_a = FileBackedRevocationList(path_a)
            rl_a.revoke(_VALID_JTI_1)
            rl_a.revoke(_VALID_JTI_2)

            rl_b = FileBackedRevocationList(path_b)
            rl_b.revoke(_VALID_JTI_2)
            rl_b.revoke(_VALID_JTI_1)
            rl_b.revoke(_VALID_JTI_1)  # duplicate

            self.assertEqual(rl_a.integrity_hash(), rl_b.integrity_hash())


if __name__ == "__main__":
    unittest.main()
