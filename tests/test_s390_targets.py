"""Pilot inventory checks; proof success remains a measured suite outcome."""

import json
import os
from pathlib import Path
import unittest

from fragma.provenance import check_target, extract_function


ROOT = Path(__file__).resolve().parents[1]
PILOT = json.loads((ROOT / "config/s390-targets.json").read_text())


class S390PilotTests(unittest.TestCase):
    def test_kernel_inventory_excludes_witnesses(self):
        functions = {(target["source"], name) for target in PILOT["targets"]
                     if target["role"] == "proof" for name in target["functions"]}
        self.assertEqual(len(functions), 7)
        self.assertTrue(any(source.startswith("arch/s390/") for source, _ in functions))
        self.assertTrue(all(not name.startswith("fragma_") for _, name in functions))

    def test_source_functions_and_analysis_witnesses_exist_once(self):
        for target in PILOT["targets"]:
            with self.subTest(target=target["id"]):
                source = (ROOT / target["harness"]).read_text()
                for name in target.get("analysis_functions", target["functions"]):
                    self.assertTrue(extract_function(source, name).tokens)
                if target["analysis"] == "wp":
                    selected = target.get("analysis_functions", target["functions"])
                    self.assertTrue(set(target["functions"]).issubset(selected))
                    self.assertNotIn("fragma_byte_order_calibration", selected)
                    self.assertTrue(any("_ensures_" in p for p in target["required_properties"]))

    def test_assumptions_and_model_fixture_are_explicit(self):
        assumptions = {entry["id"]: entry for entry in PILOT["assumptions"]}
        for target in PILOT["targets"]:
            with self.subTest(target=target["id"]):
                self.assertTrue((ROOT / target["kernel_model_check"]).is_file())
                for name in target["assumptions"]:
                    self.assertIn(name, assumptions)
                    self.assertTrue(assumptions[name]["kernel_files"])
                    for path in assumptions[name]["files"]:
                        self.assertTrue((ROOT / path).is_file(), path)

    def test_false_calibration_is_separate_and_explicit(self):
        calibrations = [target for target in PILOT["targets"] if target["role"] == "calibration"]
        self.assertEqual(len(calibrations), 1)
        calibration = calibrations[0]
        self.assertEqual(calibration["analysis"], "eva")
        self.assertEqual(calibration["expected_invalid"], ["byte_order_REFUTED"])
        self.assertIn("decoded_be24", calibration["required_properties"])
        source = (ROOT / calibration["harness"]).read_text()
        self.assertTrue(extract_function(source, calibration["entry"]).tokens)

    def test_all_kernel_functions_match_pinned_sources(self):
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))
        if not (kernel / ".git").exists():
            self.skipTest("set FRAGMA_KERNEL_TREE to run pinned-source integration checks")
        for target in PILOT["targets"]:
            with self.subTest(target=target["id"]):
                result = check_target(target, kernel, PILOT["kernel_revision"], ROOT)
                self.assertTrue(result["passed"], result["errors"])
                self.assertEqual(len(result["functions"]), len(target["functions"]))


if __name__ == "__main__":
    unittest.main()
