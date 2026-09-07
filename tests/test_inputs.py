"""Analyzer audit streams and solver-process lifecycle checks."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from fragma.inputs import audit_inputs, run_recorded
from fragma.sources import SourceError


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "result"
        (self.output / "tmp").mkdir(parents=True)
        self.source = self.root / "helper.c"
        self.source.write_text("int helper(void) { return 1; }\n")
        self.data = {"sources": {str(self.source): hashlib.md5(self.source.read_bytes(), usedforsecurity=False).hexdigest()}}
        (self.output / "audit.json").write_text(json.dumps(self.data))
        self.stream = self.output / "tmp/helper.c123.i456.pp"
        self.stream.write_text(self.source.read_text())

    def audit(self, target=None):
        with patch("fragma.inputs.input_receipts", return_value=[]):
            return audit_inputs(self.root, self.root, "a" * 40, {}, self.output,
                                {"cwd": str(self.root)}, target or {"harness": "helper.c"})

    def test_retains_actual_acsl_preprocessed_stream(self):
        result = self.audit()
        self.assertEqual(result["parsed_streams"][0]["source"], "helper.c")
        self.assertEqual(result["parsed_streams"][0]["absolute_path"], str(self.stream))

    def test_dependency_file_is_not_actual_parsed_c(self):
        self.stream.unlink()
        (self.output / "tmp/helper.c123.i").write_text("helper.o: helper.c\n")
        with self.assertRaisesRegex(SourceError, "actual Frama-C .pp"):
            self.audit()

    def test_nonobject_json_has_durable_source_error(self):
        for value in ([], None, "text"):
            with self.subTest(value=value):
                (self.output / "audit.json").write_text(json.dumps(value))
                with self.assertRaisesRegex(SourceError, "JSON object"):
                    self.audit()

    def test_changed_analyzer_observed_input_rejected(self):
        self.source.write_text("int helper(void) { return 2; }\n")
        with self.assertRaisesRegex(SourceError, "consumed source changed"):
            self.audit()

    def test_driver_must_be_in_analyzer_audit(self):
        (self.root / "driver.c").write_text("int main(void) { return 0; }\n")
        with self.assertRaisesRegex(SourceError, "declared driver"):
            self.audit({"harness": "helper.c", "driver": "driver.c"})


class ProcessTests(unittest.TestCase):
    def test_timeout_cleans_process_group_after_leader_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            process = Mock(pid=12345)
            process.wait.side_effect = [subprocess.TimeoutExpired("frama-c", 1), 0, 0]
            with patch("fragma.inputs.subprocess.Popen", return_value=process) as start, patch("fragma.inputs.os.killpg") as kill:
                result = run_recorded(["frama-c"], cwd=directory, env=dict(os.environ),
                                      log=directory / "run.log", timeout=1)
            self.assertTrue(start.call_args.kwargs["start_new_session"])
            self.assertTrue(result["timed_out"])
            self.assertIsNone(result["returncode"])
            self.assertEqual([call.args for call in kill.call_args_list],
                             [(12345, signal.SIGTERM), (12345, signal.SIGKILL)])

    def test_cancellation_cleans_children_and_propagates(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            process = Mock(pid=12345)
            process.wait.side_effect = [KeyboardInterrupt(), -9]
            with patch("fragma.inputs.subprocess.Popen", return_value=process), patch("fragma.inputs.os.killpg") as kill:
                with self.assertRaises(KeyboardInterrupt):
                    run_recorded(["frama-c"], cwd=directory, env=dict(os.environ),
                                 log=directory / "run.log", timeout=1)
            kill.assert_called_once_with(12345, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
