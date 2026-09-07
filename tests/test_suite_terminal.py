"""Unsuccessful setup is still a dated, complete inventory of selected cases."""

from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma import suite


ROOT = Path(__file__).resolve().parents[1]


class TerminalSuiteTests(unittest.TestCase):
    def test_setup_exceptions_do_not_leave_a_running_receipt(self):
        for operation in ("prepare_environment", "inventory"):
            for error in (OSError("test read error"), ValueError("test malformed lock")):
                with self.subTest(operation=operation, error=type(error).__name__), \
                        tempfile.TemporaryDirectory(prefix="fragma setup exception ") as temporary:
                    output = Path(temporary) / "run"
                    with patch("fragma.suite.toolchain.prepare_environment", return_value={}), \
                            patch("fragma.suite.toolchain.inventory", return_value={"ok": True}), \
                            patch("fragma.suite.toolchain." + operation, side_effect=error), \
                            patch("fragma.suite.profiles.validate_profile", side_effect=AssertionError("must not check profiles")), \
                            patch("fragma.suite.execute_target", side_effect=AssertionError("must not analyze")):
                        result = suite.run_suite(ROOT, ROOT, ids=["string.strnchr"],
                            suites=[], profile_ids=[], output=output)
                    self.assertEqual(result["status"], "preflight-failed")
                    self.assertIs(result["accepted"], False)
                    self.assertIn("completed_at", result)
                    self.assertEqual(result["counts"], {"preflight-blocked": 1})
                    self.assertEqual(json.loads((output / "summary.json").read_text()), result)
                    self.assertTrue((output / "SUMMARY.md").is_file())
                    self.assertEqual(json.loads((output / "toolchain.json").read_text())["error_type"],
                                     type(error).__name__)

    def test_preflight_failure_is_finalized_without_running_profiles_or_analyzers(self):
        with tempfile.TemporaryDirectory(prefix="fragma failed preflight ") as temporary:
            output = Path(temporary) / "run"
            with patch("fragma.suite.toolchain.prepare_environment", return_value={}), \
                    patch("fragma.suite.toolchain.inventory", return_value={
                        "ok": False, "issues": ["test-only missing prover"]}), \
                    patch("fragma.suite.profiles.validate_profile", side_effect=AssertionError("must not check profiles")), \
                    patch("fragma.suite.execute_target", side_effect=AssertionError("must not analyze")):
                result = suite.run_suite(ROOT, ROOT, ids=["string.strnchr", "string.strlcat"],
                    suites=[], profile_ids=[], output=output)
            self.assertEqual(result["status"], "preflight-failed")
            self.assertIs(result["accepted"], False)
            started = datetime.fromisoformat(result["started_at"])
            completed = datetime.fromisoformat(result["completed_at"])
            self.assertIsNotNone(completed.tzinfo)
            self.assertGreaterEqual(completed, started)
            self.assertEqual([row["target"]["id"] for row in result["targets"]], result["selected_targets"])
            self.assertEqual(result["counts"], {"preflight-blocked": 2})
            for row in result["targets"]:
                self.assertEqual(row["status"], "preflight-blocked")
                self.assertIs(row["accepted"], False)
                self.assertIs(row["evaluation"]["verified"], False)
                retained = json.loads((output / row["target"]["id"] / "result.json").read_text())
                self.assertEqual(retained, row)
            self.assertEqual(json.loads((output / "summary.json").read_text()), result)
            markdown = (output / "SUMMARY.md").read_text()
            self.assertIn("preflight-failed", markdown)
            self.assertIn("preflight-blocked", markdown)


if __name__ == "__main__":
    unittest.main()
