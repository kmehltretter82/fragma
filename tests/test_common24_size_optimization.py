"""Closed genuine -O2/-Os policy; no compiler/analyzer/native execution.

Real context/readback validators operate on full temporary receipts. Existing
synthetic transports emit inert bytes only; subprocess execution is forbidden.
These tests are policy regressions, not architecture acceptance evidence.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from fragma import common24_calibration as calibration, common24_controls as controls
from fragma import frontend_policy, inputs, provenance
from tests import test_common24_calibration_context as context_fixtures
from tests import test_common24_calibration_readback as readback_fixtures
from tests.test_common24_calibration import expanded_assertions


ROOT = Path(__file__).resolve().parents[1]


def forbidden(*args, **kwargs):
    raise AssertionError("real compiler/analyzer/native/subprocess execution forbidden")


def macros(*, size=None, optimize="1"):
    return ("#define __OPTIMIZE__ " + optimize + "\n"
        + ("" if size is None else "#define __OPTIMIZE_SIZE__ " + size + "\n")
        + "#define __compiletime_error(msg) __attribute__((__error__(msg)))\n"
        + "#define FRAGMA_COMMON24_WRONG_CASE 0\n")


class OptimizationModeTests(unittest.TestCase):
    def test_only_exact_sole_supported_modes_and_no_mutation(self):
        for mode in ("-O2", "-Os"):
            argv = ["/inert compiler", "-m64", mode, "-I", "/headers with spaces", "-nostdinc"]
            before = list(argv)
            self.assertEqual(calibration.optimization_mode(argv), mode)
            self.assertEqual(argv, before)

    def test_duplicate_competing_absent_and_unsupported_modes_reject(self):
        cases = [[], ["-O2", "-Os"], ["-Os", "-O2"], ["-O2", "-O2"], ["-Os", "-Os"]]
        unsupported = ("-O", "-O0", "-O1", "-O3", "-Og", "-Oz", "-Ofast", "-O02", "-O4", "-Osize")
        cases += [[flag] for flag in unsupported]
        cases += [["-O2", flag] for flag in unsupported]
        for flags in cases:
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                calibration.optimization_mode(["/inert compiler", *flags, "-nostdinc"])


class GenuineOptimizationContextTests(unittest.TestCase):
    def setUp(self):
        self.fixture = context_fixtures.SyntheticContextTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.original_entry = copy.deepcopy(self.fixture.entry)
        self.original_model = copy.deepcopy(self.fixture.model)

    def rebind(self, flags):
        fixture = self.fixture
        fixture.entry = copy.deepcopy(self.original_entry)
        fixture.entry["arguments"] = [arg for arg in fixture.entry["arguments"] if not arg.startswith("-O")]
        fixture.entry["arguments"][1:1] = flags
        fixture.save_build()
        model = copy.deepcopy(self.original_model)
        model["build"]["matched_commands"] = [copy.deepcopy(fixture.entry)]
        model["build"]["build_receipt_sha256"] = fixture.build["receipt_sha256"]
        return model

    def test_both_genuine_modes_preserved_in_all_28_planned_commands(self):
        fixture = self.fixture
        for mode in ("-O2", "-Os"):
            model = self.rebind([mode])
            before = copy.deepcopy((fixture.target, model, fixture.build, fixture.entry))
            binding = fixture.context(model=model)
            base = inputs.command_without_outputs(fixture.entry)
            self.assertEqual(binding["base_argv"], base)
            self.assertEqual(calibration.optimization_mode(binding["base_argv"]), mode)
            argv_binding = {"base_argv": base, "fixture": binding["fixture"],
                            "selector": binding["frontend_options"]}
            plan = [calibration.expected_gate_argv(binding, fixture.output)]
            plan += [row["argv"] for row in controls.command_plan(
                argv_binding, fixture.target, fixture.output / "compiler-controls")]
            plan += [argv for _, argv in calibration.command_plan(
                binding, fixture.output / "compiler-calibration")]
            self.assertEqual(len(plan), 28)
            for argv in plan:
                self.assertEqual(argv[:len(base)], base)
                self.assertEqual([arg for arg in argv if arg.startswith("-O")], [mode])
                self.assertTrue("-c" in argv or "-E" in argv)
            self.assertEqual(before, (fixture.target, model, fixture.build, fixture.entry))

    def test_rebound_genuine_but_unsupported_or_contradictory_flags_reject(self):
        for flags in ([], ["-O2", "-Os"], ["-Os", "-Os"], ["-Os", "-O"],
                      ["-O02"], ["-Og"], ["-Oz"], ["-Ofast"]):
            model = self.rebind(flags)
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.fixture.context(model=model)

    def test_genuine_command_change_cannot_borrow_old_model_command(self):
        self.rebind(["-Os"])
        with self.assertRaisesRegex(ValueError, "command not bound"):
            self.fixture.context(model=self.original_model)

    def test_joined_and_split_optimization_macro_overrides_reject(self):
        for macro in ("__OPTIMIZE__", "__OPTIMIZE_SIZE__"):
            for operation in ("-D", "-U"):
                for operand in (macro, macro + "=1", macro + "(x)=1"):
                    for extra in ([operation + operand], [operation, operand]):
                        model = self.rebind(["-Os", *extra])
                        with self.subTest(extra=extra), self.assertRaises(ValueError):
                            self.fixture.context(model=model)


class OptimizationExpansionTests(unittest.TestCase):
    def setUp(self):
        for patcher in (patch.object(subprocess, "Popen", side_effect=forbidden),
                        patch.object(subprocess, "run", side_effect=forbidden),
                        patch.object(inputs, "run_recorded", side_effect=forbidden)):
            patcher.start()
            self.addCleanup(patcher.stop)
        _, targets = context_fixtures.configured_targets()
        self.target = next(target for target in targets if target["profile"] == "arm-gcc")
        harness = (ROOT / frontend_policy.HARNESS).read_text()
        functions = [provenance.extract_function(harness, name) for name in calibration.HELPERS]
        self.header = "\n".join(" ".join([*function.declaration_prefix, *function.tokens])
                                for function in functions)
        self.expanded = "\n".join(" ".join([
            *frontend_policy.expected_prefix(self.target, function.name), *function.tokens])
            for function in functions) + "\n" + expanded_assertions(offset=2)

    def binding(self, mode):
        return {"base_argv": ["/inert compiler", mode, "-nostdinc"],
                "frontend_target": self.target,
                "frontend_options": calibration.frontend_options(self.target)}

    def check(self, mode, macro_text):
        return calibration.validate_expansion(self.binding(mode), self.expanded, macro_text, self.header)

    def test_exact_macro_agreement_passes_both_modes_without_source_changes(self):
        before = (self.expanded, self.header, copy.deepcopy(self.target))
        self.check("-O2", macros())
        self.check("-Os", macros(size="1"))
        self.assertEqual(before, (self.expanded, self.header, self.target))

    def test_size_macro_must_be_absent_for_o2_and_exact_one_for_os(self):
        cases = [("-O2", macros(size="1")), ("-O2", macros(size="0")),
                 ("-Os", macros()), ("-Os", macros(size="0")),
                 ("-Os", macros(size="2")), ("-Os", macros(size="(1)")),
                 ("-Os", macros(size="1") + "#define __OPTIMIZE_SIZE__ 1\n")]
        for mode, text in cases:
            with self.subTest(mode=mode, text=text), self.assertRaises(ValueError):
                self.check(mode, text)

    def test_optimize_macro_required_exactly_once_under_both_modes(self):
        for mode, size in (("-O2", None), ("-Os", "1")):
            valid = macros(size=size)
            cases = [macros(size=size, optimize=value) for value in ("0", "2", "(1)", "")]
            cases += [valid.replace("#define __OPTIMIZE__ 1\n", ""),
                      valid + "#define __OPTIMIZE__ 1\n"]
            for text in cases:
                with self.subTest(mode=mode, text=text), self.assertRaises(ValueError):
                    self.check(mode, text)

    def test_functionlike_malformed_and_hidden_duplicate_macro_definitions_reject(self):
        for macro in ("__OPTIMIZE__", "__OPTIMIZE_SIZE__"):
            for line in ("#define " + macro + "(x) 1\n", "#define " + macro + "\n",
                         "#define " + macro + "\t1\n", "#define " + macro + " 1 1\n"):
                with self.subTest(line=line), self.assertRaises(ValueError):
                    self.check("-Os", macros(size="1") + line)

    def test_similar_but_distinct_macro_identifiers_do_not_spoof_or_conflict(self):
        unrelated = "#define __OPTIMIZE_SIZE___OTHER 1\n#define __OPTIMIZE___OTHER 0\n"
        self.check("-O2", macros() + unrelated)
        self.check("-Os", macros(size="1") + unrelated)
        with self.assertRaises(ValueError):
            self.check("-Os", macros() + unrelated)

    def test_expansion_rederives_mode_not_an_untrusted_saved_label(self):
        binding = self.binding("-O2")
        binding["optimization_mode"] = "-Os"
        with self.assertRaises(ValueError):
            calibration.validate_expansion(binding, self.expanded, macros(size="1"), self.header)
        binding = self.binding("-Os")
        binding["base_argv"].append("-O2")
        with self.assertRaises(ValueError):
            calibration.validate_expansion(binding, self.expanded, macros(size="1"), self.header)


class OptimizationReadbackTests(unittest.TestCase):
    def test_rehashed_raw_size_macro_contradiction_is_rejected_by_real_provider(self):
        owner = readback_fixtures.ReadbackTests()
        self.addCleanup(owner.doCleanups)
        fixture = owner.make_fixture()
        receipt = fixture.calibration_output / "receipt.json"
        raw = calibration.read_json(receipt)
        stream = fixture.calibration_output / "macros.stdout"
        stream.write_text(stream.read_text() + "#define __OPTIMIZE_SIZE__ 1\n")
        raw["commands"][1]["stdout"]["sha256"] = calibration.sha(stream)
        for record in raw["artifacts"]:
            if record["absolute_path"] == str(stream):
                record["sha256"] = calibration.sha(stream)
        receipt.write_text(json.dumps(raw))
        # Hashes, streams, complete context, genuine gate and both controls are
        # authenticated normally; only semantic -O2/size-macro disagreement fails.
        with self.assertRaisesRegex(ValueError, "optimization|size macro"):
            calibration.validate(fixture.root, fixture.target, fixture.model, fixture.build,
                fixture.kernel, fixture.revision, receipt,
                kernel_model_gate=fixture.gate, kernel_model_output=fixture.output)


@unittest.skipUnless(os.environ.get("FRAGMA_COMMON24_SIZE_RECEIPTS"),
                     "optional JSON array of explicit x86/UML retained -Os receipts; read-only")
class RetainedSizeOptimizationTests(unittest.TestCase):
    def setUp(self):
        for patcher in (patch.object(subprocess, "Popen", side_effect=forbidden),
                        patch.object(subprocess, "run", side_effect=forbidden),
                        patch.object(inputs, "run_recorded", side_effect=forbidden)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.before = {}
        self.addCleanup(self.check_unchanged)

    def observe(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        actual = calibration.sha(path)
        if expected is not None:
            self.assertEqual(actual, expected)
        if str(path) in self.before:
            self.assertEqual(self.before[str(path)], actual)
        self.before[str(path)] = actual
        return path

    def check_unchanged(self):
        self.assertEqual(self.before, {name: calibration.sha(name) for name in self.before})

    def test_actual_size_commands_macros_and_full_positive_source_agree(self):
        paths = json.loads(os.environ["FRAGMA_COMMON24_SIZE_RECEIPTS"])
        self.assertIsInstance(paths, list)
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(isinstance(path, str) and Path(path).is_absolute() for path in paths))
        self.assertEqual(len(set(paths)), 2)
        seen = set()
        for name in paths:
            receipt_path = self.observe(name)
            self.assertEqual(receipt_path.name, "receipt.json")
            saved = calibration.read_json(receipt_path)
            self.assertEqual(saved["status"], calibration.RECORD_STATUS)
            self.assertIsNone(saved["error"])
            self.assertEqual(saved["input_drift"], [])
            profile = saved["target"]["profile"]
            self.assertNotIn(profile, seen)
            seen.add(profile)
            with self.subTest(profile=profile):
                binding = calibration.context(ROOT, saved["target"], saved["model"],
                    saved["build"], saved["revision"])
                for record in binding["tracked_inputs"]:
                    self.observe(record["absolute_path"], record["sha256"])
                # Current source/model/command semantics must match. This is not
                # old-provider reapproval: historical tracked-helper hashes and
                # saved acceptance envelopes are not silently upgraded.
                semantic = lambda value: {key: row for key, row in value.items() if key != "tracked_inputs"}
                self.assertEqual(semantic(binding), semantic(saved["binding"]))
                self.assertEqual(calibration.optimization_mode(binding["base_argv"]), "-Os")
                entry = inputs.compile_entry(saved["build"], "lib/string.c")
                self.assertIn(entry, saved["model"]["build"]["matched_commands"])
                self.assertEqual(binding["base_argv"], inputs.command_without_outputs(entry))
                output = receipt_path.parent
                self.assertEqual(saved["plan"], [{"name": key, "argv": argv}
                    for key, argv in calibration.command_plan(binding, output)])
                self.assertEqual(saved["artifacts"], calibration._artifacts(output))
                for record in saved["artifacts"]:
                    self.observe(record["absolute_path"], record["sha256"])
                self.assertEqual(len(saved["commands"]), 25)
                symbols = calibration.validate_commands(binding, output, saved["commands"])
                self.assertEqual(list(symbols), list(calibration.CASES))
                header = Path(saved["build"]["source"]) / "include/linux/unaligned.h"
                consumed = [row for row in saved["consumed_inputs"]
                            if row["absolute_path"] == str(header)]
                self.assertEqual(len(consumed), 1)
                self.observe(header, consumed[0]["sha256"])
                expanded = (output / "preprocess.stdout").read_text()
                raw_macros = (output / "macros.stdout").read_text()
                calibration.validate_expansion(binding, expanded, raw_macros, header.read_text())
                wrong_mode = copy.deepcopy(binding)
                wrong_mode["base_argv"] = ["-O2" if arg == "-Os" else arg
                                           for arg in wrong_mode["base_argv"]]
                with self.assertRaises(ValueError):
                    calibration.validate_commands(wrong_mode, output, saved["commands"])
                with self.assertRaises(ValueError):
                    calibration.validate_expansion(wrong_mode, expanded, raw_macros, header.read_text())
        self.assertEqual(seen, {"x86_64-gcc", "um-x86_64-gcc"})


if __name__ == "__main__":
    unittest.main()
