"""Source/specification preservation, not a substitute for measured WP proofs."""
import json
import os
from pathlib import Path
import re
import unittest

from fragma.provenance import check_target, extract_function


ROOT = Path(__file__).resolve().parents[1]
PILOT = json.loads((ROOT / "config/s390-targets.json").read_text())


class S390ByteAnnotationTests(unittest.TestCase):
    def setUp(self):
        self.original = (ROOT / "s390/annotated/unaligned.acsl.c").read_text()
        self.verified = (ROOT / "s390/annotated/unaligned.verified.c").read_text()

    def test_all_c_declarators_and_bodies_are_unchanged(self):
        names = {
            "__get_unaligned_be24", "__get_unaligned_le24",
            "__put_unaligned_be24", "__put_unaligned_le24",
            "__get_unaligned_be48", "__put_unaligned_be48",
            "fragma_roundtrip_be24", "fragma_roundtrip_le24",
            "fragma_roundtrip_be48",
        }
        for name in names:
            with self.subTest(function=name):
                self.assertEqual(extract_function(self.original, name).tokens,
                                 extract_function(self.verified, name).tokens)

    def test_independent_false_calibration_remains_separate(self):
        self.assertIn("void fragma_byte_order_calibration", self.original)
        self.assertIn("assert byte_order_REFUTED", self.original)
        self.assertNotIn("void fragma_byte_order_calibration", self.verified)
        self.assertNotIn("assert byte_order_REFUTED", self.verified)

    def test_domains_and_postconditions_are_not_weakened(self):
        def contracts(text):
            return [" ".join(block.split()) for block in
                    re.findall(r"/\*@(.+?)\*/", text, flags=re.S)
                    if not block.lstrip().startswith("assert ")]
        self.assertEqual(contracts(self.original), contracts(self.verified))

    def test_new_annotations_are_assertions_not_assumed_lemmas(self):
        assertions = re.findall(r"/\*@\s*assert\s+(\w+):", self.verified)
        for name in ("decode_decompose_low", "decode_decompose_middle",
                     "extracted_high", "extracted_middle", "extracted_low",
                     "decompose_low", "decompose_middle", "decompose_high"):
            self.assertEqual(assertions.count(name), 2, name)
        # Strip ordinary comments before checking ACSL constructs. Documentation
        # may explain why an axiom/admission would not be an acceptable proof.
        annotations = "\n".join(re.findall(r"/\*@(.+?)\*/", self.verified, re.S))
        self.assertNotRegex(annotations, r"\b(?:axiom|axiomatic|admit|assumes)\b")
        strategy = (ROOT / "s390/annotated/byteproof.h").read_text()
        strategy_annotations = "\n".join(re.findall(r"/\*@(.+?)\*/", strategy, re.S))
        self.assertNotRegex(strategy_annotations, r"\b(?:axiom|axiomatic|admit|assumes)\b")

    def test_new_harness_still_passes_pinned_source_gate(self):
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))
        if not (kernel / ".git").exists():
            self.skipTest("set FRAGMA_KERNEL_TREE for pinned-source integration checks")
        for original in PILOT["targets"]:
            if original["id"] not in {"s390.unaligned24", "s390.unaligned48"}:
                continue
            target = {**original, "harness": "s390/annotated/unaligned.verified.c"}
            result = check_target(target, kernel, PILOT["kernel_revision"], ROOT)
            self.assertTrue(result["passed"], result["errors"])


if __name__ == "__main__":
    unittest.main()
