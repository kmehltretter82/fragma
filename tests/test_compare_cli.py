import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma.__main__ import main, replay_roots


class CompareCliTests(unittest.TestCase):
    def test_explicit_role_overrides_and_duplicate_rejection(self):
        self.assertEqual(replay_roots(["project=/tmp/relocated", "switch=/tmp/tools"], Path("/project")),
                         {"project": "/tmp/relocated", "switch": "/tmp/tools"})
        for values in (["project=/tmp/a", "project=/tmp/b"], ["missing-equals"], ["role="]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                replay_roots(values, Path("/project"))

    def test_comparison_does_not_need_current_registry_or_run_analysis(self):
        for passed in (True, False):
            with self.subTest(passed=passed), patch("fragma.replay.build_replay_view", return_value={}) as view, \
                    patch("fragma.replay.compare_replays", return_value={"replay_passed": passed}), \
                    patch("fragma.suite.load_registry", side_effect=AssertionError("must not load registry")), \
                    patch("fragma.suite.run_suite", side_effect=AssertionError("must not analyze")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["compare", "left/summary.json", "right/summary.json"]), 0 if passed else 1)
                self.assertEqual(view.call_count, 2)

    def test_existing_comparison_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "comparison.json"
            output.write_text("keep this evidence")
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main(["compare", "left", "right", "--output", str(output)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(output.read_text(), "keep this evidence")


if __name__ == "__main__":
    unittest.main()
