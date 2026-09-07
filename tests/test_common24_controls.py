"""Pure/mock common24 compiler controls; retained diagnostics are read-only."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma import common24_controls as controls
from fragma import inputs
from fragma.sources import sha256
from tests import test_common24_calibration_context as context_fixtures


class ControlsTests(unittest.TestCase):
    def setUp(self):
        # Reuse the complete temporary input/model/Git fixture, not a success
        # mock for the provider context or genuine positive-gate validator.
        self.fixture = context_fixtures.SyntheticContextTests("test_genuine_fixture_reconstructs_artifacts_and_git_dependencies")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.positive = self.fixture.validate_gate()
        self.output = self.fixture.output / "compiler-controls"
        self.calls = []
        self.effect = None

    def arguments(self):
        f = self.fixture
        return (f.root, f.kernel, f.target, f.model, f.build, f.binding, self.positive)

    def context(self):
        return controls.context(*self.arguments(), self.output)

    @staticmethod
    def diagnostics(name, fixture, *, excerpts=False):
        lines = []
        for line, message in controls.DIAGNOSTICS[name]:
            lines.append(f'{fixture}:{line}:1: error: static assertion failed: "{message}"')
            if excerpts:
                lines += [f" {line:4} | _Static_assert(synthetic_expression,", "      | ^~~~~~~~~~~~~~"]
        return "\n".join(lines) + "\n"

    def mock_compiler(self, argv, *, cwd, env, log, stdout_file, timeout):
        name = log.name.removesuffix(".stderr")
        self.assertIn(name, controls.NAMES)
        self.assertEqual(argv[0], str(self.fixture.compiler))
        self.assertEqual(cwd, self.fixture.build_path)
        self.assertEqual(env, controls.compiler_environment(self.output))
        self.assertIn("-c", argv)
        self.assertEqual(Path(argv[argv.index("-c") + 1]), self.fixture.root / controls.frontend_policy.FIXTURE)
        self.calls.append({"argv": list(argv), "cwd": cwd, "env": dict(env), "timeout": timeout})
        stdout_file.write_text("")
        log.write_text(self.diagnostics(name, self.fixture.root / controls.frontend_policy.FIXTURE, excerpts=True))
        row = {"argv": list(argv), "cwd": str(cwd), "returncode": 1, "timed_out": False,
            "seconds": 0.01, "log": str(log), "log_sha256": sha256(log)}
        if self.effect:
            self.effect(name, row, log, stdout_file)
        return row

    def run_controls(self):
        with patch.object(inputs, "run_recorded", side_effect=self.mock_compiler):
            return controls.run(*self.arguments(), self.output)

    def validate(self):
        return controls.validate(*self.arguments(), self.output / "receipt.json")

    def read_receipt(self):
        return json.loads((self.output / "receipt.json").read_text())

    def write_receipt(self, value):
        (self.output / "receipt.json").write_text(json.dumps(value))

    def test_exact_two_command_plan_and_distinct_single_selectors(self):
        f = self.fixture
        for variant, selected in (("no-instrument", 1), ("patchable-entry-0", 2)):
            target = copy.deepcopy(f.target); target["frontend_policy"]["variant"] = variant
            context = self.context(); context["selector"] = controls.frontend_policy.cpp_arguments(target)
            plan = controls.command_plan(context, target, self.output)
            self.assertEqual([item["name"] for item in plan], list(controls.NAMES))
            for item, selector in zip(plan, (selected, 3 - selected), strict=True):
                self.assertEqual([arg for arg in item["argv"] if controls.frontend_policy.MACRO in arg],
                                 ["-DFRAGMA_COMMON24_INLINE_POLICY=" + str(selector)])
                self.assertEqual(item["argv"].count("-c"), 1)
                self.assertEqual(item["argv"].count("-o"), 1)
                self.assertNotIn("-E", item["argv"])
            self.assertIn("-DFRAGMA_COMMON24_EXPECT_U32=unsigned long", plan[0]["argv"])
            self.assertFalse(any("EXPECT_U32" in arg for arg in plan[1]["argv"]))

    def test_success_reconstructs_positive_gate_and_returns_only_negative_observations(self):
        before = copy.deepcopy(self.arguments()[2:])
        observed = self.run_controls()
        self.assertEqual(observed["status"], controls.CHECKED)
        self.assertEqual(observed["commands_checked"], 2)
        self.assertEqual([row["observed_errors"] for row in observed["controls"]], [5, 1])
        self.assertEqual(observed["positive_gate_sha256"], self.positive["record_sha256"])
        self.assertEqual(observed["boundary"], controls.BOUNDARY)
        self.assertIsNone(observed["boundary"]["architecture_level_awarded"])
        self.assertFalse(observed["boundary"]["native_executed"])
        self.assertFalse(observed["boundary"]["analyzer_executed"])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.read_receipt()["artifacts"]), 4)
        self.assertEqual(before, self.arguments()[2:])
        self.assertEqual(observed, self.validate())

    def test_diagnostics_require_exact_order_source_location_and_no_extra_errors(self):
        fixture = self.fixture.root / controls.frontend_policy.FIXTURE
        command = {"returncode": 1, "timed_out": False}
        for name in controls.NAMES:
            good = self.diagnostics(name, fixture, excerpts=True)
            controls.validate_diagnostics(name, fixture, command, good, "", False)
            bad = ["", good + good, good.replace(str(fixture), "/other/fixture.c"),
                good.replace(":1: error:", ":2: error:"), good.replace("static assertion failed", "unrelated failure"),
                good + "cc1: warning: unrelated\n", good + "cc1: fatal error: unrelated\n",
                good + "unexpected continuation\n", "\x1b[0m" + good, "\x00" + good, good.replace("\n", "\r\n")]
            if name == "wrong-type":
                bad += ["\n".join(reversed(self.diagnostics(name, fixture).splitlines())) + "\n"]
            for text in bad:
                with self.subTest(name=name, text=text[:40]), self.assertRaises(ValueError):
                    controls.validate_diagnostics(name, fixture, command, text, "", False)

    def test_exit_stdout_timeout_object_and_bool_metadata_fail_closed(self):
        fixture = self.fixture.root / controls.frontend_policy.FIXTURE
        good = self.diagnostics("wrong-inline", fixture)
        for code, timeout, stdout, obj in ((0, False, "", False), (True, False, "", False),
            (None, True, "", False), (1, True, "", False), (1, 0, "", False),
            (1, False, "\n", False), (1, False, "", True)):
            with self.subTest(values=(code, timeout, stdout, obj)), self.assertRaises(ValueError):
                controls.validate_diagnostics("wrong-inline", fixture,
                    {"returncode": code, "timed_out": timeout}, good, stdout, obj)

    def test_current_positive_gate_context_and_artifact_identity_are_mandatory(self):
        for mutate in (lambda g: g.update(record_sha256="bad"), lambda g: g["inputs"].pop(),
                       lambda g: g["artifacts"][0].update(sha256="0" * 64),
                       lambda g: g["fixture"].update(sha256="0" * 64),
                       lambda g: g["object_identity"].update(byte_order="big")):
            gate = copy.deepcopy(self.positive); mutate(gate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                controls.context(*self.arguments()[:-1], gate, self.output)
        changed = copy.deepcopy(self.fixture.binding); changed["model_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            controls.context(*self.arguments()[:5], changed, self.positive, self.output)

    def test_source_header_and_positive_diagnostics_changes_reject_before_compiling(self):
        log = self.fixture.output / "kernel-model.log"; log.write_text("unexpected positive diagnostic\n")
        observed = self.run_controls()
        self.assertEqual(observed["status"], "error")
        self.assertEqual(self.calls, [])
        self.assertIsNotNone(self.read_receipt()["error"])

    def test_positive_special_or_symlinked_artifacts_reject_before_hashing(self):
        log = self.fixture.output / "kernel-model.log"; saved = log.with_name("saved-log")
        log.rename(saved); log.symlink_to(saved)
        with self.assertRaises(ValueError):
            self.context()

    def test_nonmatching_current_genuine_dependencies_reject(self):
        self.fixture.git_blobs["include/linux/types.h"] = b"changed Git types\n"
        with self.assertRaises(ValueError):
            self.context()

    def test_existing_directory_bad_namespace_and_invalid_timeout_do_not_execute(self):
        self.output.mkdir()
        for output, timeout in ((self.output, 60), (self.fixture.root, 60),
                                (self.fixture.output / "other", 60), (self.output, True), (self.output, 0)):
            with self.subTest(output=output, timeout=timeout), self.assertRaises(ValueError):
                controls.run(*self.arguments(), output, timeout=timeout)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.calls, [])

    def test_saved_environment_budget_identity_intents_and_commands_cannot_be_forged(self):
        self.assertEqual(self.run_controls()["status"], controls.CHECKED)
        original = self.read_receipt()
        mutations = [lambda d: d["environment"].update(CPATH="/unexpected"),
            lambda d: d["environment"].update(TMPDIR="/other"), lambda d: d.update(timeout=True),
            lambda d: d.update(timeout=59), lambda d: d["intents"].pop(), lambda d: d["commands"].pop(),
            lambda d: d["plan"][0]["argv"].append("-DOVERRIDE=1"),
            lambda d: d["commands"][0].update(returncode=0),
            lambda d: d["commands"][0].update(seconds=float("nan")),
            lambda d: d["context"].update(binding_sha256="0" * 64),
            lambda d: d.update(initial_inputs=[]), lambda d: d.update(artifacts=[]),
            lambda d: d.update(boundary={**controls.BOUNDARY, "runtime_reachability": True})]
        for mutate in mutations:
            changed = copy.deepcopy(original); mutate(changed); self.write_receipt(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate()
        self.write_receipt(original)

    def test_rehashed_extra_diagnostic_is_rejected_not_just_hash_checked(self):
        self.run_controls(); saved = self.read_receipt()
        path = self.output / "wrong-type.stderr"; path.write_text(path.read_text() + "cc1: error: extra\n")
        for row in saved["artifacts"]:
            if row["absolute_path"] == str(path): row["sha256"] = sha256(path)
        saved["commands"][0]["stderr"]["sha256"] = sha256(path)
        saved["commands"][0]["log_sha256"] = sha256(path); self.write_receipt(saved)
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_raw_stream_or_unexpected_object_is_not_success(self):
        self.run_controls()
        (self.output / "wrong-type.o").write_bytes(b"inert unexpected object artifact")
        with self.assertRaises(ValueError):
            self.validate()
        (self.output / "wrong-type.o").unlink(); (self.output / "wrong-inline.stdout").unlink()
        with self.assertRaises(ValueError):
            self.validate()

    def test_failed_compiler_retains_intent_command_logs_and_error_receipt(self):
        def effect(name, row, log, stdout):
            row["returncode"] = 0
        self.effect = effect
        observed = self.run_controls(); saved = self.read_receipt()
        self.assertEqual(observed["status"], "error")
        self.assertEqual(len(saved["intents"]), 1)
        self.assertEqual(len(saved["commands"]), 1)
        self.assertEqual(saved["commands"][0]["returncode"], 0)
        self.assertEqual(len(saved["artifacts"]), 2)
        self.assertIsNotNone(saved["completed_at"])

    def test_missing_stream_keeps_returned_command_metadata(self):
        self.effect = lambda name, row, log, stdout: stdout.unlink()
        self.assertEqual(self.run_controls()["status"], "error")
        saved = self.read_receipt()
        self.assertEqual(len(saved["commands"]), 1)
        self.assertEqual(saved["commands"][0]["returncode"], 1)
        self.assertEqual(len(saved["intents"]), 1)

    def test_interruption_retains_partial_terminal_receipt_and_rethrows(self):
        def effect(name, row, log, stdout):
            if name == "wrong-inline": raise KeyboardInterrupt()
        self.effect = effect
        with self.assertRaises(KeyboardInterrupt):
            self.run_controls()
        saved = self.read_receipt()
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(len(saved["intents"]), 2)
        self.assertEqual(len(saved["commands"]), 1)
        self.assertEqual(len(saved["artifacts"]), 4)
        self.assertIsNotNone(saved["completed_at"])

    def test_during_run_input_drift_remains_error(self):
        def effect(name, row, log, stdout):
            if name == "wrong-type": self.fixture.generated.write_text("#define CONFIG_DRIFT 1\n")
        self.effect = effect
        self.assertEqual(self.run_controls()["status"], "error")
        self.assertTrue(self.read_receipt()["input_drift"])


@unittest.skipUnless(os.environ.get("FRAGMA_COMMON24_CONTROLS_READBACK"),
                     "optional explicitly selected retained fixture-control diagnostics")
class RetainedDiagnosticsTests(unittest.TestCase):
    def test_all_six_retained_diagnostic_streams_without_execution(self):
        base = Path(os.environ["FRAGMA_COMMON24_CONTROLS_READBACK"]).resolve()
        fixture = base.parent / "kernel-model-check.c"
        before = {}
        for profile in ("arm-gcc", "powerpc32-gcc", "m68k-gcc"):
            for name in controls.NAMES:
                stem = base / profile / ("reject-" + name)
                stderr = stem.with_suffix(".stderr"); stdout = stem.with_suffix(".stdout")
                before[str(stderr)] = sha256(stderr); before[str(stdout)] = sha256(stdout)
                controls.validate_diagnostics(name, fixture, {"returncode": 1, "timed_out": False},
                                              stderr.read_text(), stdout.read_text(), False)
        self.assertEqual(before, {path: sha256(Path(path)) for path in before})


if __name__ == "__main__":
    unittest.main()
