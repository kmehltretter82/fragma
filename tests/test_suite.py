"""Selection, command preservation, and missing-input regressions."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma.inputs import command_without_outputs, dependency_paths
from fragma.sources import SourceError
from fragma.suite import (SuiteError, analysis_limits, load_registry, select_native_targets, select_targets,
                         strategy_options, warnings_from_log)


ROOT = Path(__file__).resolve().parent.parent


class SuiteTests(unittest.TestCase):
    def test_wall_budget_is_independent_of_solver_attempt_budget(self):
        self.assertEqual(analysis_limits(1, 4, 600),
            {"wall_timeout_seconds": 600, "solver_timeout_seconds": 1, "jobs": 4})
        self.assertEqual(analysis_limits(5, 4, None)["wall_timeout_seconds"], 300)
        for values in ((True, 4, 600), (1, True, 600), (1, 4, True), (1, 4, 0),
                       (1, 4, 86401), (0, 4, 600), (1, 0, 600)):
            with self.subTest(values=values), self.assertRaises(SuiteError):
                analysis_limits(*values)

    def test_cli_forwards_independent_wall_budget(self):
        from fragma.__main__ import main
        with patch("fragma.__main__.suite.run_suite", return_value={
                "status": "passed", "output": "test-output", "accepted": True}) as run, \
                patch("builtins.print"):
            self.assertEqual(main(["run", "--target", "s390.unaligned24", "--timeout", "1",
                                   "--wall-timeout", "600"]), 0)
        self.assertEqual(run.call_args.kwargs["timeout"], 1)
        self.assertEqual(run.call_args.kwargs["wall_timeout"], 600)

    def test_registered_targets_and_assumptions_resolve(self):
        revision, targets, assumptions = load_registry(ROOT)
        self.assertEqual(len(revision), 40)
        self.assertIn("string.strnchr", targets)
        self.assertIn("s390.unaligned24", targets)
        self.assertIn("kernel-trap", assumptions)

    def test_missing_target_or_suite_never_means_everything(self):
        _, targets, _ = load_registry(ROOT)
        with self.assertRaises(SuiteError):
            select_targets(targets, ids=["does-not-exist"], suites=[], profile_ids=[])
        with self.assertRaises(SuiteError):
            select_targets(targets, ids=[], suites=["does-not-exist"], profile_ids=[])
        with self.assertRaises(SuiteError):
            select_targets(targets, ids=["string.strnchr"], suites=[], profile_ids=["s390x-gcc"])

    def test_calibration_selection_includes_independent_companion(self):
        _, targets, _ = load_registry(ROOT)
        selected = select_targets(targets, ids=["calibration.strlcat.naive.wp"],
                                  suites=[], profile_ids=[])
        self.assertEqual({target["id"] for target in selected},
            {"calibration.strlcat.naive.wp", "calibration.strlcat.naive.eva"})

    def test_registry_requires_exact_explained_companion_mapping(self):
        for changes in ({"companion_property_map": {}}, {"companion_mapping_reason": ""},
                        {"companion_property_map": {"strlcat_ensures_naive_no_truncation": "unrelated"}},
                        {"required_companion": "string.strnchr"}):
            def read_modified(path):
                value = json.loads(path.read_text())
                for target in value.get("targets", []):
                    if target["id"] == "calibration.strlcat.naive.wp":
                        target.update(changes)
                return value
            with self.subTest(changes=changes), patch("fragma.suite.read_json", side_effect=read_modified):
                with self.assertRaisesRegex(SuiteError, "companion mapping"):
                    load_registry(ROOT)

    def test_compiler_options_and_literal_arguments_preserved(self):
        entry = {"file": "/path with spaces/input.c", "arguments": [
            "gcc", "-std=gnu11", "-funsigned-char", "-fno-strict-overflow",
            "-I", "/headers with spaces", '-DNAME="$(literal);`value`"',
            "-Wp,-MMD,lib/.string.o.d", "-c", "/path with spaces/input.c",
            "-o", "out.o"]}
        self.assertEqual(command_without_outputs(entry), entry["arguments"][:7])

    def test_shell_operators_are_not_executed(self):
        with self.assertRaises(SourceError):
            command_without_outputs({"file": "x.c", "arguments": ["gcc", "x.c", ";", "false"]})

    def test_strategy_engine_and_actual_solver_assumptions_are_distinct(self):
        target = {"analysis": "wp", "wp_strategy": "fragma_scalar_math",
                  "wp_strategy_file": "s390/annotated/bitproof.h",
                  "wp_strategy_provers": ["alt-ergo", "z3"], "wp_auto_depth": 64,
                  "wp_smoke_timeout": 2}
        options, engine, assumptions = strategy_options(target, "alt-ergo")
        self.assertEqual(engine, "tip,alt-ergo,z3")
        self.assertEqual(assumptions, "alt-ergo,z3")
        self.assertIn("fragma_scalar_math", options)
        self.assertNotIn("-wp-no-rte", options)

    def test_strategy_configuration_rejects_incomplete_or_unbounded_settings(self):
        good = {"analysis": "wp", "wp_strategy": "scalar", "wp_strategy_file": "proof.h",
                "wp_strategy_provers": ["alt-ergo"]}
        for changes in ({"wp_strategy": "-wp-no-rte"}, {"analysis": "eva"},
                        {"wp_strategy_file": ""}, {"wp_strategy_provers": ["unlocked"]},
                        {"wp_strategy_provers": ["z3", "z3"]}, {"wp_auto_depth": 0},
                        {"wp_auto_depth": True}, {"wp_smoke_timeout": 61}):
            with self.subTest(changes=changes), self.assertRaises(SuiteError):
                strategy_options({**good, **changes}, "alt-ergo,z3")
        with self.assertRaises(SuiteError):
            strategy_options({"wp_strategy_file": "proof.h"}, "alt-ergo")

    def test_native_inventory_routing_never_selects_unrelated_or_proof_targets(self):
        selected = [{"id": "calibration", "role": "calibration", "analysis": "eva"}]
        receipt = {"kind": "fragma-native-spec-sensitivity", "cases": [{"target_id": "calibration"}]}
        self.assertEqual(select_native_targets(receipt, selected), {"calibration"})
        for changed in ({**receipt, "kind": "different"}, {**receipt, "cases": []},
                        {**receipt, "cases": receipt["cases"] * 2},
                        {**receipt, "cases": [{"target_id": "unrelated"}]},
                        {**receipt, "cases": [None]}):
            with self.subTest(receipt=changed), self.assertRaises(SuiteError):
                select_native_targets(changed, selected)
        with self.assertRaises(SuiteError):
            select_native_targets(receipt, [{**selected[0], "role": "proof"}])

    def test_dependency_paths_preserve_spaces_and_require_files(self):
        with tempfile.TemporaryDirectory(prefix="fragma dependencies ") as temporary:
            path = Path(temporary)
            header = path / "my header.h"
            header.write_text("#define X 1\n")
            dependency = path / "dep.d"
            dependency.write_text("fragma: my\\ header.h\n")
            self.assertEqual(dependency_paths(dependency, path), [header])
            dependency.write_text("fragma: missing.h\n")
            with self.assertRaises(SourceError):
                dependency_paths(dependency, path)

    def test_warnings_are_preserved_for_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "run.log"
            log.write_text("[wp] Warning: Missing RTE guards\n[kernel] Error: bad input\n")
            warnings = warnings_from_log(log)
            self.assertEqual(len(warnings), 2)
            self.assertEqual(warnings[1]["severity"], "error")

    def test_located_multiline_and_compiler_warnings_are_not_dropped(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "run.log"
            log.write_text("[kernel:attrs] /source with spaces/input.c:12: Warning: \n"
                           "  Ignoring an attribute.\n  More diagnostic details.\n"
                           "[wp] Normal progress\n"
                           "/temporary/input.c:22:9: warning: macro redefined\n"
                           "  22 | #define MACRO 1\n"
                           "[kernel] User Error: parser stopped\n")
            warnings = warnings_from_log(log)
            self.assertEqual(len(warnings), 3)
            self.assertEqual(warnings[0]["message"], "Ignoring an attribute. More diagnostic details.")
            self.assertEqual(warnings[0]["path"], "/source with spaces/input.c")
            self.assertEqual(warnings[0]["line"], 12)
            self.assertEqual(warnings[1]["message"], "macro redefined")
            self.assertEqual(warnings[1]["line"], 22)
            self.assertEqual(warnings[2]["severity"], "error")


if __name__ == "__main__":
    unittest.main()
