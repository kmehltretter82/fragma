"""Pure compiler-calibration tests; subprocess execution is always mocked."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma import common24_calibration as MOD
from fragma import common24_controls as CONTROLS

ROOT = Path(__file__).resolve().parents[1]


def expanded_assertions(offset=0):
    """Inert compiler-transport fixture with real declaration/call structure."""
    rows = ["void fragma_common24_compiler_calibration(void) {"]
    for index, case in enumerate(MOD.CASES, offset):
        symbol = "__compiletime_assert_" + str(index)
        rows.append('__attribute__((__noreturn__)) extern void ' + symbol
            + '(void) __attribute__((__error__("fragma common24 " "' + case + '")));'
            + ' if (0) ' + symbol + '();')
    return "\n".join([*rows, "}"])


def policy_target(policy):
    return {"frontend_policy": policy, "input_mode": "standalone",
            "role": "proof", "analysis": "wp",
            "source": "include/linux/unaligned.h", "harness": MOD.frontend_policy.HARNESS,
            "kernel_model_check": MOD.frontend_policy.FIXTURE}


class CalibrationTests(unittest.TestCase):
    def test_permanent_source_and_exact22_case_inventory(self):
        self.assertEqual(MOD.sha(ROOT / "common/annotated/compiler-calibration.c"),
                         "84a5ffce5e314761a57769837f13550323d4bfbaa7e9126cecf70a029fac157d")
        self.assertEqual(MOD.CASES, (
            "decode_be", "decode_le", "store_be_0", "store_be_1", "store_be_2",
            "store_le_0", "store_le_1", "store_le_2", "roundtrip_be", "roundtrip_le",
            "maximum_be_0", "maximum_be_1", "maximum_be_2", "maximum_roundtrip",
            "discarded_le_0", "discarded_le_1", "discarded_le_2", "discarded_roundtrip",
            "memory_0", "memory_1", "memory_2", "memory_3"))

    def test_closed_calibration_setting(self):
        expected = {"kind": "common24-fixed22", "source": "common/annotated/compiler-calibration.c"}
        target = policy_target({"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"})
        target.update(functions=list(MOD.HELPERS), compiler_calibration=expected)
        self.assertEqual(MOD.identity(target), expected)
        self.assertIsNone(MOD.identity({}))
        for setting in (None, True, {}, {**expected, "kind": "native"},
                        {**expected, "extra": True}, {**expected, "source": "other.c"},
                        {**expected, "source": "common/annotated/./compiler-calibration.c"},
                        {**expected, "source": str(ROOT / expected["source"])},
                        {**expected, "source": "common/annotated/../annotated/compiler-calibration.c"}):
            with self.subTest(setting=setting), self.assertRaises(MOD.CalibrationError):
                MOD.identity({**target, "compiler_calibration": setting})

    def test_closed_environment_is_reconstructible(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "calibration"
            self.assertEqual(MOD.compiler_environment(output), {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(output)})
            with patch.dict(os.environ, {"LD_PRELOAD": "/unreviewed.so", "CPATH": "/unreviewed"}):
                self.assertEqual(MOD.compiler_environment(output), {
                    "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(output)})

    def test_setting_cannot_expand_beyond_exact_common24_wp_scope(self):
        target = policy_target({"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"})
        target.update(functions=list(MOD.HELPERS), compiler_calibration={
            "kind": "common24-fixed22", "source": "common/annotated/compiler-calibration.c"})
        for change in ({"role": "calibration"}, {"analysis": "eva"},
                       {"functions": list(MOD.HELPERS)[:-1]},
                       {"functions": list(reversed(MOD.HELPERS))},
                       {"functions": [*MOD.HELPERS, "fragma_roundtrip_be24"]},
                       {"source": "include/linux/other.h"}, {"input_mode": "translation-unit"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                MOD.identity({**target, **change})

    def test_policy_mapping(self):
        for variant, number in (("no-instrument", 1), ("patchable-entry-0", 2)):
            self.assertEqual(MOD.frontend_options(policy_target({
                "schema_version": 1, "kind": "common24-inline", "variant": variant})),
                ["-DFRAGMA_COMMON24_INLINE_POLICY=" + str(number)])

    def test_policy_fail_closed(self):
        baseline = {"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"}
        for value in (None, {}, {**baseline, "fallback": True}, {**baseline, "schema_version": True},
                      {**baseline, "variant": "s390"}, {**baseline, "kind": "arbitrary-cpp"}):
            with self.subTest(value=value), self.assertRaises(MOD.CalibrationError):
                MOD.frontend_options(policy_target(value))

    def test_bool_not_integer_identity(self):
        self.assertFalse(MOD.same({"v": 1}, {"v": True}))

    def test_exact_compile_only_command_plan(self):
        binding = {"base_argv": ["/usr/bin/target-gcc", "-O2", "-nostdinc"],
                   "source": "/workspace/calibration.c", "big_endian": True}
        plan = MOD.command_plan(binding, "/workspace/new-evidence")
        self.assertEqual(len(plan), 25)
        self.assertEqual([name for name, argv in plan], ["positive", "macros", "preprocess"]
                         + ["wrong-" + case for case in MOD.CASES])
        for i, (name, argv) in enumerate(plan):
            self.assertEqual(argv[:3], binding["base_argv"])
            self.assertEqual(argv.count("-DFRAGMA_COMMON24_EXPECT_BIG_ENDIAN=1"), 1)
            self.assertEqual(argv.count("/workspace/calibration.c"), 1)
            self.assertTrue("-c" in argv or "-E" in argv)
            if i >= 3:
                self.assertIn("-DFRAGMA_COMMON24_WRONG_CASE=" + str(i - 2), argv)

    def test_genuine_gate_selector_is_explicit(self):
        binding = {"base_argv": ["/usr/bin/target-gcc", "-O2"], "fixture": "/workspace/fixture.c",
                   "frontend_options": ["-DFRAGMA_COMMON24_INLINE_POLICY=2"]}
        argv = MOD.expected_gate_argv(binding, "/workspace/gate")
        self.assertEqual(argv[:3], ["/usr/bin/target-gcc", "-O2", "-DFRAGMA_COMMON24_INLINE_POLICY=2"])
        self.assertIn("/workspace/fixture.c", argv)
        self.assertNotIn("-DFRAGMA_COMMON24_INLINE_POLICY=1", argv)

    def test_selector_free_legacy_gate_rejected_before_file_reads(self):
        binding = {"base_argv": ["/usr/bin/target-gcc", "-O2"], "fixture": "/workspace/fixture.c",
                   "frontend_options": ["-DFRAGMA_COMMON24_INLINE_POLICY=2"], "cwd": "/workspace/build"}
        argv = MOD.expected_gate_argv(binding, "/workspace/gate")
        argv.remove("-DFRAGMA_COMMON24_INLINE_POLICY=2")
        with self.assertRaises(MOD.CalibrationError):
            MOD.validate_gate(Path("/workspace"), Path("/kernel"), binding, {},
                              {"argv": argv, "cwd": binding["cwd"]}, Path("/workspace/gate"))

    def test_command_plan_requires_boolean_byte_order(self):
        for value in (None, 0, 1, "big"):
            with self.subTest(value=value), self.assertRaises(MOD.CalibrationError):
                MOD.command_plan({"big_endian": value}, "/workspace/new-evidence")

    def test_no_native_or_architecture_award(self):
        for field in ("native_executed", "analyzer_executed", "runtime_reachability",
                      "full_domain_proof", "ambiguous_eva_corroboration"):
            self.assertIs(MOD.BOUNDARY[field], False)
        self.assertIsNone(MOD.BOUNDARY["architecture_level_awarded"])

    def test_compiler_envelope_cannot_enter_native_routing(self):
        from fragma import suite
        target = {"id": "common.unaligned24.arm", "role": "calibration", "analysis": "eva"}
        envelope = {"schema_version": 1, "kind": MOD.KIND, "status": MOD.STATUS, "boundary": dict(MOD.BOUNDARY),
                    "cases": [{"target_id": target["id"]}]}
        with self.assertRaisesRegex(suite.SuiteError, "native calibration evidence kind"):
            suite.select_native_targets(envelope, [target])
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(suite.SuiteError, "native calibration evidence kind"):
                suite.validate_native_evidence(Path(directory), Path(directory), target,
                                               "a" * 40, {}, {}, receipt)

    def test_intended_diagnostic(self):
        MOD.validate_wrong("decode_be", {"returncode": 1, "timed_out": False}, self.error(), "", False,
                           symbol="__compiletime_assert_0")

    def test_exact_clang_diagnostic_and_expansion_chain(self):
        source = "/workspace/common/annotated/compiler-calibration.c"
        command = {"returncode": 1, "timed_out": False,
                   "argv": ["clang", "-c", source, "-o", "wrong.o"]}
        error = (f"{source}:46:2: error: call to '__compiletime_assert_0' declared "
                 "with 'error' attribute: fragma common24 decode_be\n")
        notes = "".join(
            f"fixture-{index}.h:1:1: note: {message}\n   1 | synthetic\n      | ^~~~\n"
            for index, message in enumerate(MOD.CLANG_NOTE_MESSAGES))
        good = error + notes + "1 error generated.\n"
        MOD.validate_wrong("decode_be", command, good, "", False,
                           symbol="__compiletime_assert_0", compiler_family="clang")
        for bad in (
                good.replace(":46:2: error:", ":47:2: error:", 1),
                good.replace("with 'error' attribute", "with attribute error", 1),
                good.replace(MOD.CLANG_NOTE_MESSAGES[0], "expanded from another macro", 1),
                good.replace("1 error generated.", "2 errors generated."),
                good + "unexpected continuation\n"):
            with self.subTest(bad=bad[:60]), self.assertRaises(MOD.CalibrationError):
                MOD.validate_wrong("decode_be", command, bad, "", False,
                                   symbol="__compiletime_assert_0", compiler_family="clang")
        with self.assertRaises(MOD.CalibrationError):
            MOD.validate_wrong("decode_be", command, good, "", False,
                               symbol="__compiletime_assert_0", compiler_family="unknown")

    @staticmethod
    def error():
        return "fixture.c:1:1: error: call to '__compiletime_assert_0' declared with attribute error: fragma common24 decode_be\n"

    def test_negative_rejects_extras(self):
        for extra in (self.error(), "gcc: error: unrelated\n", "gcc: warning: unrelated\n",
                      "gcc: fatal error: unrelated\n", "\x1b[31m", "\x00"):
            with self.subTest(extra=extra), self.assertRaises(MOD.CalibrationError):
                MOD.validate_wrong("decode_be", {"returncode": 1, "timed_out": False}, self.error() + extra, "", False,
                                   symbol="__compiletime_assert_0")

    def test_negative_rejects_wrong_missing_error(self):
        for error in ("", self.error().replace("decode_be", "decode_le"), self.error().replace("assert_0", "assert_1")):
            with self.subTest(error=error), self.assertRaises(MOD.CalibrationError):
                MOD.validate_wrong("decode_be", {"returncode": 1, "timed_out": False}, error, "", False,
                                   symbol="__compiletime_assert_0")

    def test_negative_rejects_return_timeout_stdout_object(self):
        for code, timeout, stdout, obj in ((0, False, "", False), (True, False, "", False),
                (None, True, "", False), (1, True, "", False), (1, 0, "", False),
                (1, False, " ", False), (1, False, "\n", False), (1, False, "", True)):
            with self.subTest(values=(code, timeout, stdout, obj)), self.assertRaises(MOD.CalibrationError):
                MOD.validate_wrong("decode_be", {"returncode": code, "timed_out": timeout}, self.error(), stdout, obj,
                                   symbol="__compiletime_assert_0")

    @unittest.skipUnless(os.environ.get("FRAGMA_COMMON24_READBACK"), "optional explicitly selected retained controls")
    def test_retained_compiler_outputs_read_only(self):
        directory = Path(os.environ["FRAGMA_COMMON24_READBACK"]).resolve()
        index = json.loads((directory / "index.json").read_text())
        before = {str(directory / "index.json"): MOD.sha(directory / "index.json")}
        count = 0
        for row in index["profiles"]:
            receipt_path = directory / row["profile"] / "receipt.json"
            before[str(receipt_path)] = MOD.sha(receipt_path)
            receipt = json.loads(receipt_path.read_text())
            fixture = json.loads(Path(receipt["fixture"]["path"]).read_text())
            binding = {"base_argv": receipt["original_command_without_outputs"],
                       "source": receipt["source"]["path"], "cwd": receipt["build"]["path"],
                       "big_endian": receipt["expected_big_endian"],
                       "frontend_options": ["-DFRAGMA_COMMON24_INLINE_POLICY=" + str(fixture["inline_policy"])]}
            variant = next(name for name, value in MOD.frontend_policy.VARIANTS.items()
                           if value[0] == fixture["inline_policy"])
            binding["frontend_target"] = policy_target({"schema_version": 1, "kind": "common24-inline", "variant": variant})
            MOD.validate_commands(binding, receipt_path.parent, receipt["commands"])
            expanded = (receipt_path.parent / "preprocess.stdout").read_text()
            symbols = MOD.assertion_symbols(expanded)
            macros = (receipt_path.parent / "macros.stdout").read_text()
            genuine = (Path(receipt["build"]["source"]) / "include/linux/unaligned.h").read_text()
            MOD.validate_expansion(binding, expanded, macros, genuine)
            with self.assertRaises(MOD.CalibrationError):
                MOD.validate_expansion({**binding, "frontend_options": []}, expanded, macros, genuine)
            changed = copy.deepcopy(receipt["commands"])
            changed[-1]["argv"].append("-DFRAGMA_COMMON24_WRONG_CASE=0")
            with self.assertRaises(MOD.CalibrationError):
                MOD.validate_commands(binding, receipt_path.parent, changed)
            with self.assertRaises(MOD.CalibrationError):
                MOD.validate_commands(binding, receipt_path.parent, receipt["commands"][:-1])
            for case, command in zip(MOD.CASES, receipt["commands"][3:], strict=True):
                MOD.validate_wrong(case, command, Path(command["stderr"]["path"]).read_text(),
                    Path(command["stdout"]["path"]).read_text(),
                    (receipt_path.parent / ("wrong-" + case + ".o")).exists(), symbol=symbols[case])
                count += 1
        self.assertEqual(count, 66)
        self.assertEqual(before, {path: MOD.sha(path) for path in before})


class OrchestrationTests(unittest.TestCase):
    """Mock compiler/context and sibling-control authentication, not their semantics."""
    def setUp(self):
        from tests.test_frontend_policy import fixture_elf
        from tests.test_elf import calibration_elf
        process_guard = patch("subprocess.Popen", side_effect=AssertionError("unmocked subprocess is forbidden"))
        process_guard.start()
        self.addCleanup(process_guard.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "calibration"
        self.gate_output = self.root / "gate"
        self.gate_output.mkdir()
        self.target = policy_target({"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"})
        self.target.update(id="common.unaligned24.arm", profile="mock", functions=list(MOD.HELPERS), compiler_calibration={
            "kind": "common24-fixed22", "source": "common/annotated/compiler-calibration.c"})
        self.model = {"machdep": {"checked_fields": {"sizeof_ptr": 4, "little_endian": True}}}
        self.build = {"source": str(self.root / "kernel-source")}
        self.header = Path(self.build["source"]) / "include/linux/unaligned.h"
        self.header.parent.mkdir(parents=True)
        functions = []
        for name in MOD.HELPERS:
            functions.append("static inline " + ("u32 " + name + "(const u8 *p) { return p[0]; }"
                if name.startswith("__get") else "void " + name + "(const u32 val, u8 *p) { *p = val; }"))
        self.header.write_text("\n".join(functions))
        self.source = self.root / "common/annotated/compiler-calibration.c"
        self.source.parent.mkdir(parents=True)
        # Exact reviewed 22-case source copied only into the isolated unit fixture.
        original = ROOT / "common/annotated/compiler-calibration.c"
        self.source.write_bytes(original.read_bytes())
        self.assertEqual(MOD.sha(self.source), MOD.SOURCE_SHA256)
        self.fixture = self.root / MOD.frontend_policy.FIXTURE
        self.fixture.parent.mkdir(parents=True, exist_ok=True)
        self.fixture.write_text("/* mocked genuine fixture context */\n")
        self.elf = fixture_elf(self.target["frontend_policy"])
        self.positive_elf = calibration_elf()
        for name, data in (("kernel-model.o", self.elf), ("kernel-model.log", b""), ("model-headers.d", b"fragma: fixture\n")):
            (self.gate_output / name).write_bytes(data)
        self.gate = {"test": "mocked-shared-gate"}
        self.gate_observation = {"record_sha256": MOD.digest(self.gate),
            "artifacts": [MOD.record(path) for path in sorted(self.gate_output.iterdir())],
            "inputs": [MOD.record(self.fixture)], "fixture": MOD.record(self.fixture),
            "object_identity": MOD.frontend_policy.fixture_object(self.elf, self.target, self.model)}
        self.binding = {"schema_version": 1, "profile": "mock", "revision": "a" * 40,
            "target_sha256": MOD.digest(self.target), "model_sha256": MOD.digest(self.model),
            "source": str(self.source), "fixture": str(self.fixture), "base_argv": ["/mock-compiler", "-O2"],
            "cwd": str(self.root), "frontend_options": MOD.frontend_options(self.target),
            "frontend_target": self.target, "big_endian": False,
            "tracked_inputs": [MOD.record(self.source), MOD.record(self.header)]}
        required_headers = [self.header.with_name(name) for name in ("types.h", "build_bug.h")]
        for header in required_headers:
            header.write_text("/* synthetic dependency identity */\n")
        self.consumed = [MOD.record(path) for path in (self.source, self.header, *required_headers)]
        attrs = "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))"
        self.expanded = self.header.read_text().replace("inline", attrs)
        self.expanded += "\n" + expanded_assertions()
        self.macros = "#define __OPTIMIZE__ 1\n#define __compiletime_error(msg) __attribute__((__error__(msg)))\n#define FRAGMA_COMMON24_WRONG_CASE 0\n"
        self.failure = None
        self.drift = False
        self.controls_failure = False
        self.controls_observation = None
        for method, replacement in (("context", self.binding), ("validate_gate", self.gate_observation)):
            patcher = patch.object(MOD, method, return_value=replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(MOD.inputs, "input_receipts", return_value=self.consumed)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(MOD.inputs, "run_recorded", side_effect=self.compiler)
        self.compiler_mock = patcher.start()
        self.addCleanup(patcher.stop)
        for method, handler in (("run", self.run_controls), ("validate", self.validate_controls)):
            patcher = patch.object(CONTROLS, method, side_effect=handler)
            setattr(self, "controls_" + method + "_mock", patcher.start())
            self.addCleanup(patcher.stop)

    def run_controls(self, root, kernel, target, model, build, binding, gate, output, *, timeout=60):
        self.assertEqual([root, kernel, target, model, build, binding, gate, timeout],
                         [self.root, self.root, self.target, self.model, self.build,
                          self.binding, self.gate_observation, 60])
        self.assertEqual(Path(output), self.output.parent / "compiler-controls")
        Path(output).mkdir()
        receipt = Path(output) / "receipt.json"
        receipt.write_text('{"mocked_sibling_controls": true}\n')
        self.controls_observation = {
            "schema_version": 1, "kind": CONTROLS.KIND,
            "status": "error" if self.controls_failure else CONTROLS.CHECKED,
            "receipt": MOD.record(receipt), "commands_checked": 2,
            "positive_gate_sha256": gate["record_sha256"],
            "controls": [{"name": name} for name in CONTROLS.NAMES],
            "boundary": dict(CONTROLS.BOUNDARY), "tracked_files": [MOD.record(receipt)]}
        return copy.deepcopy(self.controls_observation)

    def validate_controls(self, root, kernel, target, model, build, binding, gate, receipt, *, timeout=60):
        self.assertEqual([root, kernel, target, model, build, binding, gate, timeout],
                         [self.root, self.root, self.target, self.model, self.build,
                          self.binding, self.gate_observation, 60])
        self.assertEqual(Path(receipt), self.output.parent / "compiler-controls/receipt.json")
        self.assertIsNotNone(self.controls_observation)
        return copy.deepcopy(self.controls_observation)

    def compiler(self, argv, *, cwd, env, log, stdout_file, timeout):
        self.assertEqual(env, MOD.compiler_environment(self.output))
        name = log.name.removesuffix(".stderr")
        log.write_text("")
        stdout_file.write_text("")
        code, timed_out = 0, False
        if name == "positive":
            (self.output / "positive.o").write_bytes(self.positive_elf)
            (self.output / "positive.d").write_text("fragma: " + " ".join(row["absolute_path"] for row in self.consumed) + "\n")
        elif name == "macros":
            stdout_file.write_text(self.macros)
        elif name == "preprocess":
            stdout_file.write_text(self.expanded)
        else:
            case = name.removeprefix("wrong-")
            code = 1
            log.write_text("fixture.c:1:1: error: call to '__compiletime_assert_" + str(MOD.CASES.index(case))
                + "' declared with attribute error: fragma common24 " + case + "\n")
        if self.failure == name:
            code, timed_out = None, True
        if self.failure == "interrupt" and name == "macros":
            raise KeyboardInterrupt("mock cancellation")
        if self.drift and name == "wrong-memory_3":
            self.source.write_text("changed input")
        return {"argv": list(argv), "cwd": str(cwd), "returncode": code, "timed_out": timed_out,
                "seconds": 0.01, "log": str(log), "log_sha256": MOD.sha(log)}

    def run_calibration(self):
        return MOD.run(self.root, self.target, self.model, self.build, self.root, "a" * 40,
            self.output, MOD.compiler_environment(self.output), kernel_model_gate=self.gate,
            kernel_model_output=self.gate_output)

    def validate_calibration(self):
        return MOD.validate(self.root, self.target, self.model, self.build, self.root, "a" * 40,
            self.output / "receipt.json", kernel_model_gate=self.gate, kernel_model_output=self.gate_output)

    def receipt(self):
        return MOD.read_json(self.output / "receipt.json")

    def change_receipt(self, change):
        saved = self.receipt()
        change(saved)
        MOD._write(self.output / "receipt.json", saved)

    def test_exact25_mock_roundtrip_has52_artifacts_and_no_proof_or_native_award(self):
        result = self.run_calibration()
        self.assertEqual(result["status"], MOD.STATUS)
        self.assertEqual(self.compiler_mock.call_count, 25)
        self.assertEqual(result["artifact_count"], 52)
        self.assertEqual(result["cases_checked"], list(MOD.CASES))
        self.assertEqual(result["boundary"], MOD.BOUNDARY)
        self.assertEqual(result["fixture_controls"], self.controls_observation)
        self.assertEqual(self.controls_run_mock.call_count, 1)
        self.assertEqual(self.controls_validate_mock.call_count, 1)
        for key in ("accepted", "verified", "native_executed", "reached", "corroborated", "remaining"):
            self.assertNotIn(key, result)
        self.assertEqual(self.validate_calibration(), result)

    def test_timeout_preserves_command_and_partial_artifacts(self):
        self.failure = "wrong-decode_be"
        self.assertEqual(self.run_calibration()["status"], "error")
        saved = self.receipt()
        self.assertEqual(len(saved["commands"]), 4)
        self.assertEqual(len(saved["intents"]), 4)
        self.assertTrue(saved["commands"][-1]["timed_out"])
        self.assertTrue(saved["artifacts"])
        with self.assertRaises(MOD.CalibrationError):
            self.validate_calibration()

    def test_interruption_retains_intent_and_terminal_status(self):
        self.failure = "interrupt"
        with self.assertRaises(KeyboardInterrupt):
            self.run_calibration()
        saved = self.receipt()
        self.assertEqual(saved["status"], "interrupted")
        self.assertEqual(len(saved["commands"]), 1)
        self.assertEqual(len(saved["intents"]), 2)
        self.assertIsNotNone(saved["completed_at"])
        self.assertTrue(any(row["absolute_path"].endswith("macros.stdout") for row in saved["artifacts"]))

    def test_final_drift_blocks_compiler_calibration_success(self):
        self.drift = True
        self.assertEqual(self.run_calibration()["status"], "error")
        self.assertTrue(self.receipt()["input_drift"])

    def test_inline_fixture_cannot_substitute_for_positive_definition(self):
        self.positive_elf = self.elf
        self.assertEqual(self.run_calibration()["status"], "error")
        saved = self.receipt()
        self.assertEqual(len(saved["commands"]), 25)
        self.assertIsNotNone(saved["error"])
        self.assertEqual(saved["boundary"], MOD.BOUNDARY)

    def test_failed_sibling_control_blocks_core_compiler_commands(self):
        self.controls_failure = True
        self.assertEqual(self.run_calibration()["status"], "error")
        self.compiler_mock.assert_not_called()
        saved = self.receipt()
        self.assertEqual(saved["commands"], [])
        self.assertEqual(saved["fixture_controls"]["status"], "error")
        self.assertIsNotNone(saved["completed_at"])
        with self.assertRaises(MOD.CalibrationError):
            self.validate_calibration()

    def test_changed_sibling_control_envelope_or_receipt_blocks_revalidation(self):
        self.assertEqual(self.run_calibration()["status"], MOD.STATUS)
        saved = self.receipt()
        changed = copy.deepcopy(saved)
        changed["fixture_controls"]["positive_gate_sha256"] = "0" * 64
        MOD._write(self.output / "receipt.json", changed)
        with self.assertRaisesRegex(MOD.CalibrationError, "fixture controls"):
            self.validate_calibration()
        changed = copy.deepcopy(saved)
        receipt = Path(changed["fixture_controls"]["receipt"]["absolute_path"])
        receipt.write_text('{"mocked_sibling_controls": "changed"}\n')
        for record in [changed["fixture_controls"]["receipt"],
                       *changed["fixture_controls"]["tracked_files"],
                       *changed["initial_inputs"], *changed["final_inputs"]]:
            if record["absolute_path"] == str(receipt):
                record["sha256"] = MOD.sha(receipt)
        MOD._write(self.output / "receipt.json", changed)
        with self.assertRaisesRegex(MOD.CalibrationError, "fixture controls"):
            self.validate_calibration()

    def test_conflicting_consumed_hash_cannot_bypass_terminal_recording(self):
        self.consumed[0]["sha256"] = "0" * 64
        self.assertEqual(self.run_calibration()["status"], "error")
        saved = self.receipt()
        self.assertTrue(saved["finalization_errors"])
        self.assertIsNone(saved["final_inputs"])
        self.assertTrue(saved["input_drift"])
        self.assertEqual(len(saved["commands"]), 25)

    def test_preflight_and_readback_failure_preserve_distinct_progress(self):
        with patch.object(MOD, "context", side_effect=MOD.CalibrationError("mock preflight")):
            self.assertEqual(self.run_calibration()["status"], "error")
        self.assertEqual(self.receipt()["commands"], [])
        self.output = self.root / "second"
        # Mapping is well formed, but genuine helper bodies are absent; this
        # distinct readback gate still runs after all compiler observations.
        self.expanded = expanded_assertions()
        self.assertEqual(self.run_calibration()["status"], "error")
        self.assertEqual(len(self.receipt()["commands"]), 25)
        self.assertEqual(len(self.receipt()["artifacts"]), 52)

    def test_bad_positive_symbol_inventory_stops_before_any_negative_command(self):
        self.expanded = "bad expanded inventory"
        self.assertEqual(self.run_calibration()["status"], "error")
        saved = self.receipt()
        self.assertEqual([row["name"] for row in saved["commands"]], ["positive", "macros", "preprocess"])
        self.assertEqual([row["name"] for row in saved["intents"]], ["positive", "macros", "preprocess"])
        self.assertEqual(len(saved["artifacts"]), 8)
        self.assertIsNotNone(saved["completed_at"])
        self.assertIsNotNone(saved["error"])

    def test_validator_never_calls_compiler(self):
        self.run_calibration()
        self.compiler_mock.reset_mock()
        self.assertEqual(self.validate_calibration()["status"], MOD.STATUS)
        self.compiler_mock.assert_not_called()

    def test_run_rejects_environment_overrides_before_compiler(self):
        environment = MOD.compiler_environment(self.output)
        changes = ({**environment, "LD_PRELOAD": "/unreviewed.so"},
                   {**environment, "CPATH": "/unreviewed"},
                   {**environment, "PATH": "/unreviewed:/usr/bin:/bin"},
                   {**environment, "LC_ALL": "fr_FR.UTF-8"},
                   {**environment, "TZ": "Europe/Paris"},
                   {**environment, "TMPDIR": str(self.root)},
                   {key: value for key, value in environment.items() if key != "TZ"},
                   {**environment, "TZ": True}, None)
        for env in changes:
            with self.subTest(env=env), self.assertRaisesRegex(MOD.CalibrationError, "environment"):
                MOD.run(self.root, self.target, self.model, self.build, self.root, "a" * 40,
                        self.output, env, kernel_model_gate=self.gate, kernel_model_output=self.gate_output)
            self.compiler_mock.assert_not_called()
            self.assertFalse(self.output.exists())

    def test_validator_reconstructs_environment_even_with_recomputed_hash(self):
        self.assertEqual(self.run_calibration()["status"], MOD.STATUS)
        saved = self.receipt()
        self.assertEqual(saved["environment"], MOD.environment_identity(self.output))
        updates = ({"LD_PRELOAD": "/unreviewed.so"}, {"CPATH": "/unreviewed"},
                   {"PATH": "/unreviewed:/usr/bin:/bin"}, {"TMPDIR": str(self.root)},
                   {"LC_ALL": "fr_FR.UTF-8"}, {"TZ": "Europe/Paris"})
        for update in updates:
            with self.subTest(update=update):
                changed = copy.deepcopy(saved)
                changed["environment"]["values"].update(update)
                changed["environment"]["sha256"] = MOD.digest(changed["environment"]["values"])
                MOD._write(self.output / "receipt.json", changed)
                with self.assertRaisesRegex(MOD.CalibrationError, "environment policy"):
                    self.validate_calibration()
        for change in (lambda env: env.update(schema_version=True),
                       lambda env: env.update(policy="unreviewed"),
                       lambda env: env.update(sha256="0" * 64),
                       lambda env: env.update(extra=True),
                       lambda env: env.pop("values")):
            changed = copy.deepcopy(saved)
            change(changed["environment"])
            MOD._write(self.output / "receipt.json", changed)
            with self.assertRaisesRegex(MOD.CalibrationError, "environment policy"):
                self.validate_calibration()

    def test_each_command_mutation_rejected_by_independent_plan(self):
        self.run_calibration()
        saved = self.receipt()
        for index in range(25):
            with self.subTest(index=index):
                changed = copy.deepcopy(saved)
                changed["commands"][index]["argv"].append("-DUNREVIEWED=1")
                MOD._write(self.output / "receipt.json", changed)
                with self.assertRaises(MOD.CalibrationError):
                    self.validate_calibration()

    def test_receipt_cannot_choose_subset_of_required_artifacts_or_inputs(self):
        self.run_calibration()
        saved = self.receipt()
        for field in ("artifacts", "initial_inputs", "consumed_inputs", "final_inputs", "intents", "commands"):
            with self.subTest(field=field):
                changed = copy.deepcopy(saved)
                changed[field] = changed[field][:-1]
                MOD._write(self.output / "receipt.json", changed)
                with self.assertRaises((MOD.CalibrationError, ValueError)):
                    self.validate_calibration()

    def test_extra_file_symlink_and_missing_artifact_rejected(self):
        self.run_calibration()
        extra = self.output / "unexpected"
        extra.write_text("extra")
        with self.assertRaises(MOD.CalibrationError):
            self.validate_calibration()
        extra.unlink()
        extra.symlink_to(self.output / "missing")
        with self.assertRaises(MOD.CalibrationError):
            self.validate_calibration()
        extra.unlink()
        (self.output / "wrong-memory_3.stdout").unlink()
        with self.assertRaises((MOD.CalibrationError, OSError)):
            self.validate_calibration()

    def test_nonregular_extra_and_expected_stream_rejected_before_hashing(self):
        self.run_calibration()
        extra = self.output / "unexpected-fifo"
        os.mkfifo(extra)
        with self.assertRaisesRegex(MOD.CalibrationError, "non-regular"):
            self.validate_calibration()
        extra.unlink()
        expected = self.output / "macros.stdout"
        expected.unlink()
        os.mkfifo(expected)
        with self.assertRaisesRegex(MOD.CalibrationError, "non-regular"):
            self.validate_calibration()

    def test_malformed_or_wrong_kind_boundary_context_and_object_rejected(self):
        self.run_calibration()
        saved = self.receipt()
        changes = (lambda r: r.update(schema_version=True),
                   lambda r: r.update(kind="fragma-native-spec-sensitivity"),
                   lambda r: r.update(status="native-corroborated"),
                   lambda r: r["boundary"].update(runtime_reachability=True),
                   lambda r: r.update(model={}), lambda r: r.update(extra="field"),
                   lambda r: r.update(gate_sha256="0" * 64),
                   lambda r: r.update(positive_object={}))
        for change in changes:
            changed = copy.deepcopy(saved)
            change(changed)
            MOD._write(self.output / "receipt.json", changed)
            with self.assertRaises((MOD.CalibrationError, ValueError)):
                self.validate_calibration()
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}'):
            (self.output / "receipt.json").write_text(text)
            with self.assertRaises(ValueError):
                self.validate_calibration()


if __name__ == "__main__":
    unittest.main()
