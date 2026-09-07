"""Inventory/source tests for benign, explicitly negative spec calibration.

These tests never convert a solver's ambiguous status into defect evidence.
Set FRAGMA_STRING_SENSITIVITY_RESULTS to additionally inspect a fresh raw run.
"""

import json
import os
from pathlib import Path
import re
import unittest

from fragma.provenance import check_target, extract_function
from fragma.report import named_assertions
from fragma.sources import sha256


ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "config/string-sensitivity-targets.json").read_text())


class StringSensitivityTests(unittest.TestCase):
    def test_calibrations_do_not_count_as_new_proved_kernel_functions(self):
        self.assertEqual(len(CONFIG["targets"]), 8)
        for target in CONFIG["targets"]:
            with self.subTest(target=target["id"]):
                self.assertEqual(target["role"], "calibration")
                self.assertEqual(target["analysis"], "eva")
                self.assertEqual(target["claims"], [])
                self.assertEqual(target["profile"], "x86_64-gcc")
                self.assertTrue(set(target["functions"]) <= {"strlcat", "strnchr"})
                self.assertEqual(len(target["expected_invalid"]), 1)
                self.assertTrue(target["expected_invalid"][0].endswith("_REFUTED"))
                self.assertGreaterEqual(len(target["required_properties"]), 3)

    def test_named_positive_and_negative_locations_are_unique(self):
        driver = ROOT / "harness/string_sensitivity.c"
        source = driver.read_text()
        names = named_assertions([driver])
        self.assertEqual(len(names), len(set(names.values())))
        expected = {name for target in CONFIG["targets"]
                    for name in target["required_properties"]}
        self.assertEqual(set(names.values()), expected)
        for target in CONFIG["targets"]:
            self.assertTrue(extract_function(source, target["entry"]).tokens)
            negative = target["expected_invalid"][0]
            negative_line = next(line for (_, line), name in names.items() if name == negative)
            for name in target["required_properties"]:
                if name != negative:
                    positive_line = next(line for (_, line), value in names.items() if value == name)
                    self.assertLess(positive_line, negative_line)
        self.assertNotRegex(source, r"\bassert\s+\w+\s*:\s*(?:\\true|1)\s*;")

    def test_independent_model_does_not_import_strong_quantified_contracts(self):
        specs = (ROOT / "harness/specs.sensitivity.h").read_text()
        self.assertNotIn("fragma_cstring", specs)
        self.assertNotIn("fragma_scan_readable", specs)
        self.assertNotRegex(specs, r"\baxiom(?:atic)?\b")
        for target in CONFIG["targets"]:
            self.assertEqual(target["harness"], "harness/string_calibration.c")
            self.assertEqual(target["specs"], "harness/specs.sensitivity.h")
            self.assertFalse(target["eva_auto_builtins"])
            self.assertEqual(target["eva_builtins"], ["memcpy:Frama_C_memcpy"])
            reference = target["specification_reference"]
            self.assertEqual(reference["harness"], "annotated/string.verified.c")
            reference_source = (ROOT / reference["harness"]).read_text()
            for name in target["tested_contract_properties"]:
                label = name.removeprefix(target["functions"][0] + "_")
                self.assertRegex(reference_source, r"\b" + re.escape(label) + r"\s*:")

    def test_assumptions_have_reviewable_local_inputs(self):
        ledger = {entry["id"]: entry for entry in CONFIG["assumptions"]}
        for target in CONFIG["targets"]:
            for name in target["assumptions"]:
                self.assertIn(name, ledger)
                for filename in ledger[name]["files"] + ledger[name]["review_evidence"]:
                    self.assertTrue((ROOT / filename).is_file(), filename)
                self.assertFalse(ledger[name]["implementation_proved"])

    def test_entire_calibration_translation_unit_matches_pinned_kernel(self):
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))
        if not (kernel / ".git").exists():
            self.skipTest("set FRAGMA_KERNEL_TREE for pinned-source integration")
        target = {**CONFIG["targets"][0], "functions": ["strlcat", "strnchr", "strlen"]}
        gate = check_target(target, kernel, CONFIG["kernel_revision"], ROOT)
        self.assertTrue(gate["passed"], gate["errors"])
        self.assertTrue(all(item["declaration_prefix_equal"] for item in gate["functions"]))

    def test_optional_fresh_evidence_remains_explicitly_incomplete(self):
        supplied = os.environ.get("FRAGMA_STRING_SENSITIVITY_RESULTS")
        if not supplied:
            self.skipTest("set FRAGMA_STRING_SENSITIVITY_RESULTS for raw-run checks")
        output = Path(supplied)
        summary = json.loads((output / "summary.json").read_text())
        self.assertFalse(summary["accepted"])
        self.assertEqual(summary["changed_inputs"], [])
        for filename, digest in json.loads((output / "input-hashes.json").read_text()).items():
            self.assertEqual(sha256(ROOT / filename), digest, filename)
        for target in CONFIG["targets"]:
            evidence = json.loads((output / target["entry"] / "receipt.json").read_text())
            self.assertTrue(evidence["source_gate"]["passed"])
            self.assertEqual(evidence["analysis"]["returncode"], 0)
            self.assertEqual(evidence["changed_inputs"], [])
            statuses = evidence["named_properties"]
            for name in target["required_properties"]:
                expected = "Invalid or unreachable" if name in target["expected_invalid"] else "Valid"
                self.assertEqual(statuses[name], expected, (target["id"], name))


if __name__ == "__main__":
    unittest.main()
