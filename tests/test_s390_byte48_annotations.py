"""48-bit annotation preservation; actual proof completion remains measured."""
import json
import os
from pathlib import Path
import re
import unittest

from fragma.provenance import check_target, extract_function


ROOT = Path(__file__).resolve().parents[1]


class S390Byte48AnnotationTests(unittest.TestCase):
    def setUp(self):
        self.original = (ROOT / "s390/annotated/unaligned.acsl.c").read_text()
        self.verified = (ROOT / "s390/annotated/unaligned48.verified.c").read_text()

    def test_all_helpers_and_witness_c_tokens_are_unchanged(self):
        for name in ("__get_unaligned_be24", "__get_unaligned_le24",
                     "__put_unaligned_be24", "__put_unaligned_le24",
                     "__get_unaligned_be48", "__put_unaligned_be48",
                     "fragma_roundtrip_be24", "fragma_roundtrip_le24",
                     "fragma_roundtrip_be48"):
            with self.subTest(function=name):
                self.assertEqual(extract_function(self.original, name).tokens,
                                 extract_function(self.verified, name).tokens)

    def test_exact_original_domains_and_contracts_are_preserved(self):
        def contracts(text):
            return [" ".join(block.split()) for block in
                    re.findall(r"/\*@(.+?)\*/", text, flags=re.S)
                    if not block.lstrip().startswith("assert ")]
        self.assertEqual(contracts(self.original), contracts(self.verified))

    def test_intermediate_facts_are_assertions_not_admissions(self):
        names = re.findall(r"/\*@\s*assert\s+(\w+):", self.verified)
        for prefix, count in (("decompose_48_", 6), ("decode_decompose_48_", 5),
                              ("extracted_48_byte_", 6), ("roundtrip_decompose_48_", 6)):
            for index in range(count):
                self.assertEqual(names.count(prefix + str(index)), 1)
        for path in ("s390/annotated/unaligned48.verified.c", "s390/annotated/byteproof64.h"):
            annotations = "\n".join(re.findall(r"/\*@(.+?)\*/", (ROOT / path).read_text(), re.S))
            self.assertNotRegex(annotations, r"\b(?:axiom|axiomatic|admit|assumes)\b")

    def test_independent_calibration_is_not_a_hidden_proof_caller(self):
        self.assertIn("void fragma_byte_order_calibration", self.original)
        self.assertIn("assert byte_order_REFUTED", self.original)
        self.assertNotIn("void fragma_byte_order_calibration", self.verified)
        self.assertNotIn("assert byte_order_REFUTED", self.verified)

    def test_new_harness_passes_the_pinned_source_gate(self):
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))
        if not (kernel / ".git").exists():
            self.skipTest("set FRAGMA_KERNEL_TREE for pinned-source integration checks")
        manifest = json.loads((ROOT / "config/s390-targets.json").read_text())
        original = next(t for t in manifest["targets"] if t["id"] == "s390.unaligned48")
        target = {**original, "harness": "s390/annotated/unaligned48.verified.c"}
        result = check_target(target, kernel, manifest["kernel_revision"], ROOT)
        self.assertTrue(result["passed"], result["errors"])


if __name__ == "__main__":
    unittest.main()
