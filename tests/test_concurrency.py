import csv
import json
from pathlib import Path
import tempfile
import unittest

from fragma import concurrency


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyTests(unittest.TestCase):
    def test_manifest_matches_all_fixture_assertions(self):
        manifest = concurrency.load_manifest(ROOT)
        self.assertEqual(manifest["provider"]["expected_version"], "33.0 (Arsenic)")
        self.assertEqual(len(manifest["cases"]), 9)
        self.assertEqual(
            {case["outcome_kind"] for case in manifest["cases"]},
            {"valid_calibration", "possible_race", "false_property", "model_gap",
             "valid_synthetic_exclusion", "unsupported"},
        )

    def test_report_parser_maps_line_to_named_assertion_and_tracks_assumptions(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "fixture.c"
            source.write_text("int main(void) {\n/*@ assert expected: 1; */\n}\n")
            report = directory / "report.csv"
            with report.open("w", newline="") as stream:
                writer = csv.writer(stream, delimiter="\t")
                writer.writerow(["directory", "file", "line", "function",
                                 "property kind", "status", "property"])
                writer.writerow(["x", "model.h", 1, "model", "assigns clause",
                                 "Considered valid", "assigns x"])
                writer.writerow(["x", "fixture.c", 2, "main", "user assertion",
                                 "Invalid or unreachable", "0 = 1"])
            value = concurrency.parse_report_csv(report, source)
            self.assertEqual(value["assertions"], {"expected": "invalid"})
            self.assertEqual(value["considered_valid_assumptions"], 1)

    def test_race_parser_uses_final_section_and_distinguishes_protection(self):
        text = """[mt] Possible read/write data races:
  none
[mt] Shared memory: nothing
[mt] Possible read/write data races:
  shared:
    read by main, unprotected
[mt] Possible write/write data races:
  shared:
    write by main, protected by lock
[mt] Shared memory: shared
"""
        value = concurrency.parse_race_sections(text)
        self.assertTrue(value["read_write"]["reported"])
        self.assertTrue(value["read_write"]["unprotected"])
        self.assertTrue(value["write_write"]["reported"])
        self.assertFalse(value["write_write"]["unprotected"])

    def test_report_parser_rejects_assertion_from_another_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "fixture.c"
            source.write_text("/*@ assert expected: 1; */\n")
            report = directory / "report.csv"
            with report.open("w", newline="") as stream:
                writer = csv.writer(stream, delimiter="\t")
                writer.writerow(["directory", "file", "line", "function",
                                 "property kind", "status", "property"])
                writer.writerow(["x", "other.c", 1, "main", "user assertion",
                                 "Valid", "1"])
            with self.assertRaisesRegex(concurrency.ConcurrencyError,
                                        "another file"):
                concurrency.parse_report_csv(report, source)

    def test_negative_control_requires_exact_expected_class(self):
        case = {
            "expected_exit": 0,
            "report_expected": True,
            "expected_assertions": {"bad": "invalid"},
            "expected_unprotected_races": {"read_write": False, "write_write": False},
            "required_diagnostics": ["bad"],
            "forbidden_diagnostics": ["unsupported"],
        }
        diagnostics = concurrency.parse_diagnostics("bad\n")
        report = {"assertions": {"bad": "valid"}}
        checks = concurrency.evaluate_case(case, 0, False, report, diagnostics, "bad\n")
        self.assertFalse(all(check["passed"] for check in checks))
        assertion = next(check for check in checks if check["name"] == "assertions")
        self.assertEqual(assertion["actual"], {"bad": "valid"})

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(concurrency.ConcurrencyError, "already exists"):
                concurrency.run_c0(ROOT, Path(temporary))


if __name__ == "__main__":
    unittest.main()
