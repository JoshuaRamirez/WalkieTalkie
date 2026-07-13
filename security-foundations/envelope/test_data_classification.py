"""Tests for data classification + lineage (Phase 2 Track B B1)."""

import hashlib
import pathlib
import sys
import unittest
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from data_classification import (
    ClassifiedData,
    DataClass,
    DataClassificationError,
    LineageTag,
    classify,
    combine,
    derive,
    is_more_restrictive,
    max_class,
)

_ACTOR = "spiffe://mesh.example/ns-a/svc"
_KID = "actor-kid-a"
_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_DIGEST_A = hashlib.sha256(b"a").hexdigest()
_DIGEST_B = hashlib.sha256(b"b").hexdigest()
_DIGEST_C = hashlib.sha256(b"c").hexdigest()


class DataClassOrderingTests(unittest.TestCase):
    def test_more_restrictive_chain(self):
        self.assertTrue(is_more_restrictive(DataClass.RESTRICTED, DataClass.CONFIDENTIAL))
        self.assertTrue(is_more_restrictive(DataClass.CONFIDENTIAL, DataClass.INTERNAL))
        self.assertTrue(is_more_restrictive(DataClass.INTERNAL, DataClass.PUBLIC))
        self.assertFalse(is_more_restrictive(DataClass.PUBLIC, DataClass.PUBLIC))
        self.assertFalse(is_more_restrictive(DataClass.INTERNAL, DataClass.CONFIDENTIAL))

    def test_max_class(self):
        self.assertEqual(
            max_class([DataClass.PUBLIC, DataClass.CONFIDENTIAL, DataClass.INTERNAL]),
            DataClass.CONFIDENTIAL,
        )
        self.assertEqual(max_class([DataClass.PUBLIC]), DataClass.PUBLIC)

    def test_max_class_empty_rejected(self):
        with self.assertRaisesRegex(DataClassificationError, "at least one"):
            max_class([])


class LineageTagValidationTests(unittest.TestCase):
    def _valid_kwargs(self, **overrides) -> dict:
        kwargs = dict(
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="ingest",
            timestamp="2026-04-14T12:00:00Z",
            parent_digest="0" * 64,
        )
        kwargs.update(overrides)
        return kwargs

    def test_constructs_with_valid_inputs(self):
        LineageTag(**self._valid_kwargs())

    def test_invalid_actor_iss(self):
        with self.assertRaisesRegex(DataClassificationError, "actor_iss"):
            LineageTag(**self._valid_kwargs(actor_iss="not-spiffe"))

    def test_invalid_actor_kid(self):
        with self.assertRaisesRegex(DataClassificationError, "actor_kid"):
            LineageTag(**self._valid_kwargs(actor_kid="bad kid"))

    def test_empty_operation(self):
        with self.assertRaisesRegex(DataClassificationError, "operation"):
            LineageTag(**self._valid_kwargs(operation=""))

    def test_non_hex_parent_digest(self):
        with self.assertRaisesRegex(DataClassificationError, "parent_digest"):
            LineageTag(**self._valid_kwargs(parent_digest="not-hex"))


class ClassifyTests(unittest.TestCase):
    def test_classify_produces_single_link_lineage(self):
        cd = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.CONFIDENTIAL,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        self.assertEqual(cd.data_class, DataClass.CONFIDENTIAL)
        self.assertEqual(len(cd.lineage), 1)
        self.assertEqual(cd.lineage[0].parent_digest, "0" * 64)
        self.assertEqual(cd.lineage[0].operation, "ingest")

    def test_classified_data_is_immutable(self):
        cd = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.PUBLIC,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        with self.assertRaises(FrozenInstanceError):
            cd.data_class = DataClass.RESTRICTED  # type: ignore[misc]

    def test_metadata_round_trip(self):
        cd = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.INTERNAL,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            metadata=(("source", "user-upload"), ("tenant", "acme")),
            now=_NOW,
        )
        self.assertEqual(
            cd.metadata, (("source", "user-upload"), ("tenant", "acme"))
        )

    def test_metadata_duplicate_key_rejected(self):
        with self.assertRaisesRegex(DataClassificationError, "duplicate metadata"):
            classify(
                data_digest=_DIGEST_A,
                data_class=DataClass.INTERNAL,
                actor_iss=_ACTOR,
                actor_kid=_KID,
                metadata=(("source", "a"), ("source", "b")),
                now=_NOW,
            )


class DeriveTests(unittest.TestCase):
    def setUp(self):
        self.parent = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.CONFIDENTIAL,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )

    def test_derive_inherits_class(self):
        child = derive(
            self.parent,
            data_digest=_DIGEST_B,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="transform",
            now=_NOW,
        )
        self.assertEqual(child.data_class, DataClass.CONFIDENTIAL)
        self.assertEqual(len(child.lineage), 2)

    def test_derive_appends_lineage_with_parent_hash(self):
        child = derive(
            self.parent,
            data_digest=_DIGEST_B,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="transform",
            now=_NOW,
        )
        self.assertEqual(child.lineage[-1].parent_digest, self.parent.chain_hash)

    def test_derive_can_promote_class(self):
        child = derive(
            self.parent,
            data_digest=_DIGEST_B,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="enrich",
            new_class=DataClass.RESTRICTED,
            now=_NOW,
        )
        self.assertEqual(child.data_class, DataClass.RESTRICTED)

    def test_derive_cannot_demote_class(self):
        with self.assertRaisesRegex(DataClassificationError, "demote"):
            derive(
                self.parent,
                data_digest=_DIGEST_B,
                actor_iss=_ACTOR,
                actor_kid=_KID,
                operation="redact",
                new_class=DataClass.PUBLIC,
                now=_NOW,
            )

    def test_chain_hash_is_deterministic(self):
        cd1 = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.PUBLIC,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        cd2 = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.PUBLIC,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        self.assertEqual(cd1.chain_hash, cd2.chain_hash)

    def test_chain_hash_differs_for_different_inputs(self):
        cd1 = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.PUBLIC,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        cd2 = classify(
            data_digest=_DIGEST_B,
            data_class=DataClass.PUBLIC,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        self.assertNotEqual(cd1.chain_hash, cd2.chain_hash)


class CombineTests(unittest.TestCase):
    def setUp(self):
        self.pub = classify(
            data_digest=_DIGEST_A,
            data_class=DataClass.PUBLIC,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )
        self.conf = classify(
            data_digest=_DIGEST_B,
            data_class=DataClass.CONFIDENTIAL,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            now=_NOW,
        )

    def test_combine_takes_max_class(self):
        merged = combine(
            [self.pub, self.conf],
            data_digest=_DIGEST_C,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="merge",
            now=_NOW,
        )
        self.assertEqual(merged.data_class, DataClass.CONFIDENTIAL)

    def test_combine_concatenates_lineage(self):
        merged = combine(
            [self.pub, self.conf],
            data_digest=_DIGEST_C,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="merge",
            now=_NOW,
        )
        # 1 (pub) + 1 (conf) + 1 (merge tag) = 3
        self.assertEqual(len(merged.lineage), 3)
        # New tag's parent_digest commits to the combined parent hashes.
        expected = hashlib.sha256(
            "\n".join(sorted([self.pub.chain_hash, self.conf.chain_hash])).encode()
        ).hexdigest()
        self.assertEqual(merged.lineage[-1].parent_digest, expected)

    def test_combine_empty_rejected(self):
        with self.assertRaisesRegex(DataClassificationError, "at least one parent"):
            combine(
                [],
                data_digest=_DIGEST_C,
                actor_iss=_ACTOR,
                actor_kid=_KID,
                operation="merge",
                now=_NOW,
            )

    def test_combine_is_order_independent_for_class(self):
        merged_ab = combine(
            [self.pub, self.conf],
            data_digest=_DIGEST_C,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="merge",
            now=_NOW,
        )
        merged_ba = combine(
            [self.conf, self.pub],
            data_digest=_DIGEST_C,
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="merge",
            now=_NOW,
        )
        # Same class (max), same parent_digest (sorted hashes), even if
        # lineage tuple order differs.
        self.assertEqual(merged_ab.data_class, merged_ba.data_class)
        self.assertEqual(
            merged_ab.lineage[-1].parent_digest,
            merged_ba.lineage[-1].parent_digest,
        )


class ClassifiedDataValidationTests(unittest.TestCase):
    def _tag(self) -> LineageTag:
        return LineageTag(
            actor_iss=_ACTOR,
            actor_kid=_KID,
            operation="ingest",
            timestamp="2026-04-14T12:00:00Z",
            parent_digest="0" * 64,
        )

    def test_empty_lineage_rejected(self):
        with self.assertRaisesRegex(DataClassificationError, "lineage must be non-empty"):
            ClassifiedData(
                data_digest=_DIGEST_A,
                data_class=DataClass.PUBLIC,
                lineage=(),
            )

    def test_non_hex_digest_rejected(self):
        with self.assertRaisesRegex(DataClassificationError, "data_digest"):
            ClassifiedData(
                data_digest="nope",
                data_class=DataClass.PUBLIC,
                lineage=(self._tag(),),
            )

    def test_bad_metadata_shape_rejected(self):
        with self.assertRaisesRegex(DataClassificationError, "metadata"):
            ClassifiedData(
                data_digest=_DIGEST_A,
                data_class=DataClass.PUBLIC,
                lineage=(self._tag(),),
                metadata=(("only-one-element",),),  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
