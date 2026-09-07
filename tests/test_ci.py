"""CI runs actual registry selections and cannot turn incomplete output green."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci import check


class FakeRunner:
    def __init__(self, case="passed"):
        self.case = case
        self.calls = []

    def __call__(self, argv, *, cwd, env, log, timeout=None):
        self.calls.append({"argv": argv, "cwd": cwd, "env": env, "timeout": timeout})
        log.write_text("retained simulated command output\n")
        result = {"argv": argv, "cwd": str(cwd), "log": str(log),
                  "returncode": 0, "timed_out": False, "log_sha256": check.checksum(log)}
        if "unittest" in argv:
            if self.case == "unit-failed":
                result["returncode"] = 1
            if self.case == "unit-bool-return":
                result["returncode"] = False
            return result
        if self.case == "launch-error":
            raise OSError("simulated launch failure")
        if self.case == "missing-summary":
            return result
        output = Path(argv[argv.index("--output") + 1])
        output.mkdir()
        suites = [argv[index + 1] for index, arg in enumerate(argv) if arg == "--suite"]
        revision, targets, _ = check.suite.load_registry(check.ROOT)
        selected = check.suite.select_targets(targets, ids=[], suites=suites, profile_ids=[])
        records = []
        for target in selected:
            status = "passed" if target["role"] == "proof" else "calibration-passed"
            records.append({"target": target, "accepted": True, "status": status,
                "evaluation": {"target_id": target["id"], "accepted": True, "status": status,
                    "local_policy_passed": True, "issues": [], "verified": target["role"] == "proof",
                    **{key: target[key] for key in ("profile", "source", "role", "analysis")}}})
        summary = {"schema_version": 1, "revision": revision, "status": "passed", "accepted": True,
                   "output": str(output), "selected_targets": [target["id"] for target in selected],
                   "targets": records, "counts": dict(check.Counter(row["status"] for row in records)),
                   "started_at": "2026-09-06T00:00:00+00:00", "completed_at": "2026-09-06T00:01:00+00:00",
                   "analysis_limits": check.suite.analysis_limits(int(argv[argv.index("--timeout") + 1]),
                       int(argv[argv.index("--jobs") + 1]), int(argv[argv.index("--wall-timeout") + 1]))}
        if self.case == "incomplete-zero":
            summary.update(status="incomplete", accepted=False)
        elif self.case == "wrong-selection":
            summary["selected_targets"].pop()
            summary["targets"].pop()
        elif self.case == "duplicate-target":
            summary["targets"][-1] = copy.deepcopy(summary["targets"][0])
        elif self.case == "unaccepted-target":
            summary["targets"][0]["accepted"] = False
        elif self.case == "missing-completed":
            summary.pop("completed_at")
        elif self.case == "bad-schema":
            summary["schema_version"] = True
        elif self.case == "bad-counts":
            summary["counts"] = {"passed": True}
        elif self.case == "unaccepted-evaluation":
            summary["targets"][0]["evaluation"]["local_policy_passed"] = False
        elif self.case.startswith("wrong-evaluation-"):
            field = self.case.removeprefix("wrong-evaluation-")
            summary["targets"][0]["evaluation"][field] = "different"
        elif self.case == "proof-unverified":
            next(row for row in records if row["target"]["role"] == "proof")["evaluation"]["verified"] = False
        elif self.case == "calibration-verified":
            next(row for row in records if row["target"]["role"] == "calibration")["evaluation"]["verified"] = True
        elif self.case == "verified-bool-confusion":
            next(row for row in records if row["target"]["role"] == "proof")["evaluation"]["verified"] = 1
        elif self.case == "wrong-limits":
            summary["analysis_limits"]["solver_timeout_seconds"] += 1
        elif self.case == "limits-bool-confusion":
            summary["analysis_limits"]["jobs"] = True
        elif self.case == "suite-failed":
            summary.update(status="incomplete", accepted=False)
            result["returncode"] = 1
        for record in summary["targets"]:
            directory = output / record["target"]["id"]
            directory.mkdir(exist_ok=True)
            (directory / "result.json").write_text(json.dumps(record))
        if self.case == "child-mismatch":
            first = output / summary["targets"][0]["target"]["id"] / "result.json"
            first.write_text("{}")
        encoded = json.dumps(summary)
        if self.case == "duplicate-json":
            encoded = encoded.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
        if self.case == "nonfinite-json":
            encoded = encoded[:-1] + ', "extra": 1e999}'
        (output / "summary.json").write_text(encoded)
        return result


class CiTests(unittest.TestCase):
    def invoke(self, output, runner, extra=()):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return check.main(["--output", str(output), "--kernel", str(check.ROOT), *extra], runner=runner)

    def test_modes_select_real_registry_including_known_legacy_cases(self):
        for mode in check.MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="fragma ci ") as temporary:
                output = Path(temporary) / "run"
                runner = FakeRunner()
                self.assertEqual(self.invoke(output, runner, ["--mode", mode]), 0)
                self.assertEqual(len(runner.calls), 2)
                argv = runner.calls[1]["argv"]
                self.assertEqual([argv[index + 1] for index, arg in enumerate(argv) if arg == "--suite"], check.MODES[mode])
                record = check.strict_json(output / "ci.json")
                self.assertIs(record["accepted"], True)
                self.assertEqual(record["changed_inputs"], [])
                self.assertIn(str(Path(check.__file__).resolve()), record["inputs"])
                self.assertIs(record["baseline_updated"], False)
                self.assertIs(record["native_execution"], False)
                if mode in ("core", "all"):
                    self.assertTrue({"string.strnchr", "string.strlcat", "calibration.strlcat.naive.wp",
                                     "calibration.strlcat.naive.eva"} <= set(record["selected_targets"]))

    def test_zero_exit_cannot_hide_missing_incomplete_or_contradictory_results(self):
        cases = ["incomplete-zero", "missing-summary", "wrong-selection", "duplicate-target",
                 "unaccepted-target", "missing-completed", "bad-schema", "bad-counts",
                 "unaccepted-evaluation", "child-mismatch", "duplicate-json", "nonfinite-json",
                 "proof-unverified", "calibration-verified", "verified-bool-confusion", "wrong-limits",
                 "limits-bool-confusion", *["wrong-evaluation-" + field for field in ("profile", "source", "role", "analysis")]]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="fragma ci fail ") as temporary:
                output = Path(temporary) / "run"
                self.assertEqual(self.invoke(output, FakeRunner(case)), 1)
                record = check.strict_json(output / "ci.json")
                self.assertIs(record["accepted"], False)
                self.assertEqual(record["status"], "failed")
                self.assertTrue(record["issues"])
                self.assertIn("completed_at", record)
                self.assertTrue((output / "unit-tests.log").is_file())
                self.assertTrue((output / "suite.log").is_file())

    def test_unit_failure_prevents_suite_and_retains_terminal_receipt(self):
        for case in ("unit-failed", "unit-bool-return"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "run"
                runner = FakeRunner(case)
                self.assertEqual(self.invoke(output, runner), 1)
                self.assertEqual(len(runner.calls), 1)
                self.assertFalse((output / "suite").exists())
                self.assertTrue((output / "unit-tests.log").is_file())
                self.assertEqual(check.strict_json(output / "ci.json")["status"], "failed")

    def test_suite_failure_and_launch_error_keep_logs_and_terminal_receipt(self):
        for case in ("suite-failed", "launch-error"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "run"
                self.assertEqual(self.invoke(output, FakeRunner(case)), 1)
                record = check.strict_json(output / "ci.json")
                self.assertEqual(record["status"], "failed")
                self.assertIn("completed_at", record)
                self.assertIn("retained", (output / "suite.log").read_text())
                if case == "suite-failed":
                    self.assertTrue((output / "suite/summary.json").is_file())
                    self.assertIn("suite_summary", record)

    def test_existing_output_and_symlink_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for name in ("run", "linked"):
                output = parent / name
                if name == "run":
                    output.mkdir()
                    (output / "keep").write_text("original")
                else:
                    output.symlink_to(parent / "absent")
                runner = FakeRunner()
                self.assertEqual(self.invoke(output, runner), 2)
                self.assertEqual(runner.calls, [])
            self.assertEqual((parent / "run/keep").read_text(), "original")
            self.assertFalse((parent / "absent").exists())

    def test_numeric_limits_and_unknown_flags_rejected_before_execution(self):
        cases = [["--timeout", "0"], ["--timeout", "3601"], ["--jobs", "0"], ["--jobs", "257"],
                 ["--wall-timeout", "0"], ["--wall-timeout", "86401"], ["--timeout", "1;id"],
                 ["--mode", "passing-only"], ["--target", "string.verified.strnchr"]]
        for extra in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "run"
                runner = FakeRunner()
                try:
                    code = self.invoke(output, runner, extra)
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2)
                self.assertEqual(runner.calls, [])
                self.assertFalse(output.exists())

    def test_relative_paths_spaces_prefix_and_receipt_repetition_are_argv_safe(self):
        with tempfile.TemporaryDirectory(prefix="fragma ci path ") as temporary:
            base = Path(temporary)
            (base / "kernel tree").mkdir()
            for name in ("native one.json", "native ; harmless.json"):
                (base / name).write_text("{}")
            runner = FakeRunner()
            with contextlib.chdir(base), patch.dict(os.environ, {
                    "FRAGMA_TOOLCHAIN_PREFIX": "prefix dir", "FRAGMA_CI_TEST_SECRET": "not-in-receipts"}), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = check.main(["--output", "run with spaces", "--kernel", "kernel tree",
                    "--native-evidence", "native one.json", "--native-evidence", "native ; harmless.json",
                    "--timeout", "1", "--wall-timeout", "600", "--jobs", "2"], runner=runner)
            self.assertEqual(code, 0)
            argv = runner.calls[-1]["argv"]
            self.assertIn(str(base / "kernel tree"), argv)
            self.assertIn(str(base / "native ; harmless.json"), argv)
            self.assertEqual(argv.count("--native-evidence"), 2)
            self.assertEqual(runner.calls[-1]["cwd"], check.ROOT)
            self.assertEqual(runner.calls[-1]["env"]["FRAGMA_TOOLCHAIN_PREFIX"], str(base / "prefix dir"))
            self.assertNotIn("not-in-receipts", (base / "run with spaces/ci.json").read_text())

    def test_input_changes_and_new_inputs_fail_even_after_complete_child_pass(self):
        for final in ({"self": "different"}, {"self": "same", "new_test": "new"}):
            with self.subTest(final=final), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "run"
                with patch.object(check, "snapshot_inputs", side_effect=[{"self": "same"}, final]):
                    self.assertEqual(self.invoke(output, FakeRunner()), 1)
                record = check.strict_json(output / "ci.json")
                self.assertTrue(record["changed_inputs"])
                self.assertIs(record["accepted"], False)

    def test_actual_command_runner_keeps_failure_output_without_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            argv = [check.sys.executable, "-c", "import sys; print('retained failure'); sys.exit(3)"]
            record = check.run_command(argv, cwd=base, env=dict(os.environ), log=base / "failure.log", timeout=10)
            self.assertEqual(record["returncode"], 3)
            self.assertFalse(record["timed_out"])
            self.assertIn("retained failure", (base / "failure.log").read_text())
            self.assertEqual(record["log_sha256"], check.checksum(base / "failure.log"))

    def test_actual_timeout_reaps_the_direct_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            argv = [check.sys.executable, "-c", "import os, signal; print(os.getpid(), flush=True); signal.pause()"]
            record = check.run_command(argv, cwd=base, env=dict(os.environ), log=base / "timeout.log", timeout=0.2)
            self.assertEqual(record["returncode"], 124)
            self.assertTrue(record["timed_out"])
            self.assertEqual(record["cleanup_scope"], "direct-child-process-group")
            pid = int((base / "timeout.log").read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_interruption_is_recorded_and_cleans_only_direct_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with patch.object(check.subprocess, "Popen") as launch, patch.object(check.os, "killpg") as kill:
                launch.return_value.pid = 98765
                launch.return_value.wait.side_effect = [KeyboardInterrupt(), -15]
                record = check.run_command(["not-executed"], cwd=base, env={}, log=base / "interrupted.log")
            self.assertEqual(record["returncode"], 130)
            self.assertTrue(record["interrupted"])
            self.assertFalse(record["timed_out"])
            kill.assert_called_once_with(98765, check.signal.SIGTERM)
            self.assertTrue((base / "interrupted.log").is_file())


if __name__ == "__main__":
    unittest.main()
