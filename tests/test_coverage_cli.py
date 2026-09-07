"""Coverage generation is explicit reporting, never proof execution."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma.__main__ import main


class CoverageCliTests(unittest.TestCase):
    def test_explicit_receipts_are_forwarded_and_incomplete_inventory_is_reportable(self):
        matrix = {"counts": {"registered_targets": 22,
                              "unique_kernel_functions_with_current_accepted_variant": 0}}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "coverage"
            with patch("fragma.coverage.generate_matrix", return_value=matrix) as generate, \
                    patch("fragma.coverage.render_markdown", return_value="dated incomplete inventory\n"), \
                    patch("fragma.suite.run_suite", side_effect=AssertionError("must not analyze")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["coverage", "--summary", "run-a/summary.json",
                    "--summary", "run-b/summary.json", "--profile-evidence", "model/profile.json",
                    "--output", str(output)]), 0)
            self.assertEqual(generate.call_args.args[1], [Path("run-a/summary.json"), Path("run-b/summary.json")])
            self.assertEqual(generate.call_args.kwargs["profile_paths"], [Path("model/profile.json")])
            self.assertEqual(json.loads((output / "coverage.json").read_text()), matrix)
            self.assertEqual((output / "coverage.md").read_text(), "dated incomplete inventory\n")

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            marker = output / "keep.txt"
            marker.write_text("original")
            with patch("fragma.coverage.generate_matrix", side_effect=AssertionError("must not regenerate")), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(["coverage", "--output", str(output)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(marker.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
