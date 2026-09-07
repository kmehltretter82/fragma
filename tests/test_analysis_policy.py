"""Closed analysis semantics and read-only diagnostic command regressions."""

import copy
import json
import os
from pathlib import Path
import unittest

from fragma import profiles, suite
from fragma import analysis_policy as policy


ROOT = Path(__file__).resolve().parents[1]
STAGE = Path(os.environ.get("FRAGMA_POINTER_AUDIT_RESULTS", ROOT / "build/pointer-formation-review"))


class CandidatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.analysis = copy.deepcopy(profiles.load_profiles(ROOT)["s390x-gcc"]["analysis"])
        self.analysis["runtime_checks"] = {"pointer_formation": "object-or-null"}
        self.revision, self.targets, _ = suite.load_registry(ROOT)
        self.target = copy.deepcopy(self.targets["calibration.s390.byte-order.eva"])
        self.target["analysis_pipeline"] = {"kind": "rte-eva"}

    def test_pointer_policy_is_not_stored_as_integer_arithmetic(self):
        before = copy.deepcopy(self.analysis)
        self.assertNotIn(policy.POINTER_FLAG, self.analysis["arithmetic_flags"])
        self.assertEqual([*policy.ARITHMETIC_FLAGS, policy.POINTER_FLAG], policy.analyzer_flags(self.analysis))
        self.assertEqual(before, self.analysis)

    def test_every_configured_profile_can_adopt_identical_explicit_policy(self):
        count = 0
        for profile in profiles.load_profiles(ROOT).values():
            if profile["status"] == "experimental":
                analysis = copy.deepcopy(profile["analysis"])
                analysis["runtime_checks"] = copy.deepcopy(policy.RUNTIME_CHECKS)
                self.assertEqual("Typed", policy.model_identity(analysis)["wp_model"])
                count += 1
        self.assertEqual(11, count)

    def test_missing_unknown_and_weakened_runtime_policies_fail(self):
        for value in (None, False, True, 0, {}, [], {"pointer_formation": False},
                      {"pointer_formation": "disabled"}, {"pointer_formation": "object-or-null", "alignment": False}):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.analysis)
                changed["runtime_checks"] = value
                with self.assertRaises(policy.AnalysisPolicyError):
                    policy.model_identity(changed)
        del self.analysis["runtime_checks"]
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.model_identity(self.analysis)

    def test_unknown_analysis_setting_and_arithmetic_injection_fail(self):
        changes = [lambda row: row.update(unknown_setting=True),
                   lambda row: row.update(wp_model="Bytes"),
                   lambda row: row["arithmetic_flags"].append(policy.POINTER_FLAG),
                   lambda row: row["arithmetic_flags"].append("-load-script=manual.ml"),
                   lambda row: row["arithmetic_flags"].pop(),
                   lambda row: row["arithmetic_flags"].reverse()]
        for mutate in changes:
            changed = copy.deepcopy(self.analysis)
            mutate(changed)
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.analyzer_flags(changed)

    def test_semantic_identity_binds_pointer_policy(self):
        identity = policy.model_identity(self.analysis)
        self.assertEqual({"wp_model", "arithmetic_flags", "runtime_checks"}, set(identity))
        identity["runtime_checks"]["pointer_formation"] = "disabled"
        self.assertEqual("object-or-null", self.analysis["runtime_checks"]["pointer_formation"])

    def test_model_calibration_checks_semantics_without_claiming_a_suite_pipeline(self):
        evidence = self.actual()
        argv = ["/not-executed/frama-c", *policy.analyzer_flags(self.analysis),
                "/fixture/calibration.c", "-eva", "-eva-slevel", "10"]
        checked = policy.validate_actual_model_policy(self.analysis, argv,
            evidence["analyzer_audit"]["parameters"])
        self.assertEqual("checked", checked["status"])
        self.assertNotIn("pipeline", checked)
        for audit in ({}, {"eva": {}}, {"eva": {"correctness-parameters": []}}):
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_model_policy(self.analysis, argv, audit)
        audit = copy.deepcopy(evidence["analyzer_audit"]["parameters"])
        audit["eva"]["correctness-parameters"][policy.POINTER_FLAG] = "false"
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.validate_actual_model_policy(self.analysis, argv, audit)

    def test_pipeline_cannot_choose_a_smaller_rte_function_set(self):
        expected = ["__get_unaligned_be24", "fragma_byte_order_calibration"]
        self.assertEqual(expected, policy.pipeline_identity(self.target)["rte_functions"])
        self.target["analysis_functions"] = ["__get_unaligned_be24", "another_witness"]
        self.assertEqual(["__get_unaligned_be24", "another_witness", "fragma_byte_order_calibration"],
                         policy.pipeline_identity(self.target)["rte_functions"])
        self.target["analysis_functions"] = ["another_witness"]
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.pipeline_identity(self.target)

    def test_unknown_pipeline_fields_kinds_and_function_selectors_fail(self):
        for value in (None, False, "rte-eva", {}, {"kind": "eva-wp"},
                      {"kind": "rte-eva", "functions": ["fragma_byte_order_calibration"]},
                      {"kind": "rte-eva", "arguments": []}):
            changed = copy.deepcopy(self.target)
            changed["analysis_pipeline"] = value
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.pipeline_identity(changed)
        for functions in ([], ["a", "a"], ["-main"], ["good,bad"], [False], [{}]):
            changed = copy.deepcopy(self.target)
            changed["functions"] = functions
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.pipeline_identity(changed)

    def test_rte_pipeline_is_not_accepted_as_a_wp_setting(self):
        target = copy.deepcopy(self.targets["s390.unaligned24"])
        target["analysis_pipeline"] = {"kind": "rte-eva"}
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.pipeline_identity(target)

    def test_existing_eva_builtin_semantics_are_preserved_and_bound(self):
        target = self.targets["calibration.string.truncation.eva"]
        identity = policy.pipeline_identity(target)
        self.assertEqual("eva", identity["kind"])
        self.assertEqual(["memcpy:Frama_C_memcpy"], identity["eva_builtins"])
        self.assertFalse(identity["eva_auto_builtins"])
        for value in (False, [False], [{}], ["memcpy"], ["a:b", "a:b"],
                      ["a:b", "a:c"], ["@default", "memcpy:Frama_C_memcpy"]):
            changed = copy.deepcopy(target)
            changed["eva_builtins"] = value
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.pipeline_identity(changed)
        for value in (None, 0, 1, "false"):
            changed = copy.deepcopy(target)
            changed["eva_auto_builtins"] = value
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.pipeline_identity(changed)

    def test_all_existing_target_pipelines_remain_explicitly_representable(self):
        for target in self.targets.values():
            policy.pipeline_identity(target)

    def actual(self, target=None):
        # Synthetic argv/audit fixture only: no executable is invoked.
        target = self.target if target is None else target
        pipeline = policy.pipeline_identity(target)
        overrides = ",".join(pipeline["eva_builtins"])
        builtin_options = [] if pipeline["eva_auto_builtins"] else ["-eva-no-builtins-auto"]
        if overrides:
            builtin_options += ["-eva-builtin", overrides]
        correctness = {flag.removeprefix("-no"): "false" for flag in policy.ARITHMETIC_FLAGS}
        correctness.update({policy.POINTER_FLAG: "true", "-main": target["entry"],
                            "-eva-builtin": "@default," + overrides if overrides else "",
                            "-eva-builtins-auto": "true" if pipeline["eva_auto_builtins"] else "false"})
        argv = ["/not-executed/frama-c", "-machdep", "/fixture/machine.yaml",
                *policy.analyzer_flags(self.analysis), "/fixture/harness.c",
                *policy.before_eva_options(target), "-eva", "-main", target["entry"],
                "-eva-slevel", "100", *builtin_options, "-then", "-report", "-report-absolute-path",
                "-report-csv", "/fixture/properties.tsv"]
        return {"analysis_command": {"argv": argv}, "analyzer_audit": {
            "parameters": {"eva": {"correctness-parameters": correctness}}}}

    def wp_fixture(self, name="s390.unaligned24"):
        target = self.targets[name]
        evidence = self.actual()
        evidence["target"] = target
        evidence["analysis_command"]["argv"] = ["/not-executed/frama-c", "-machdep", "/fixture/machine.yaml",
            *policy.analyzer_flags(self.analysis), "/fixture/harness.c", "-wp", "-wp-rte",
            "-wp-model", "Typed", "-wp-fct", ",".join(target.get("analysis_functions", target["functions"])),
            "-then", "-report", "-report-absolute-path", "-report-csv", "/fixture/properties.tsv"]
        return evidence

    def test_actual_s390_rte_eva_command_satisfies_candidate(self):
        evidence = self.actual()
        checked = policy.validate_actual_policy(self.analysis, self.target,
            evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])
        self.assertEqual("checked", checked["status"])
        self.assertEqual("rte-eva", checked["pipeline"]["kind"])

    def test_exact_builtin_audit_serialization_preserves_explicit_map(self):
        for kind in ("eva", "rte-eva"):
            for auto in (True, False):
                for mappings in ([], ["memcpy:Frama_C_memcpy"], ["b:B", "a:A"]):
                    with self.subTest(kind=kind, auto=auto, mappings=mappings):
                        target = copy.deepcopy(self.targets["calibration.string.truncation.eva"])
                        target.update(analysis_pipeline={"kind": kind}, eva_auto_builtins=auto,
                                      eva_builtins=mappings)
                        evidence = self.actual(target)
                        checked = policy.validate_actual_policy(self.analysis, target,
                            evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])
                        self.assertEqual(mappings, checked["pipeline"]["eva_builtins"])
                        self.assertEqual(auto, checked["pipeline"]["eva_auto_builtins"])

    def test_builtin_audit_rejects_noncanonical_categories_or_maps(self):
        target = self.targets["calibration.string.truncation.eva"]
        evidence = self.actual(target)
        for value in (None, False, [], "", "@default", "memcpy:Frama_C_memcpy",
                      "@default,@default,memcpy:Frama_C_memcpy", "@all,memcpy:Frama_C_memcpy",
                      "+@default,memcpy:Frama_C_memcpy", "@default,-memcpy:Frama_C_memcpy",
                      "@default,memcpy:Frama_C_memcpy,memcpy:Frama_C_memcpy",
                      "@default,memcpy:other", "@default,memcpy:Frama_C_memcpy,other:builtin",
                      " @default,memcpy:Frama_C_memcpy", "@default,memcpy:Frama_C_memcpy,"):
            with self.subTest(value=value), self.assertRaises(policy.AnalysisPolicyError):
                audit = copy.deepcopy(evidence["analyzer_audit"]["parameters"])
                audit["eva"]["correctness-parameters"]["-eva-builtin"] = value
                policy.validate_actual_policy(self.analysis, target, evidence["analysis_command"]["argv"], audit)
        empty = self.actual()
        empty["analyzer_audit"]["parameters"]["eva"]["correctness-parameters"]["-eva-builtin"] = "@default"
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.validate_actual_policy(self.analysis, self.target, empty["analysis_command"]["argv"],
                                          empty["analyzer_audit"]["parameters"])
        multiple = copy.deepcopy(target)
        multiple["eva_builtins"] = ["b:B", "a:A"]
        evidence = self.actual(multiple)
        evidence["analyzer_audit"]["parameters"]["eva"]["correctness-parameters"]["-eva-builtin"] = "@default,a:A,b:B"
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.validate_actual_policy(self.analysis, multiple, evidence["analysis_command"]["argv"],
                                          evidence["analyzer_audit"]["parameters"])

    def test_builtin_argv_rejects_aliases_duplicates_wrong_values_and_phases(self):
        for kind in ("eva", "rte-eva"):
            target = copy.deepcopy(self.targets["calibration.string.truncation.eva"])
            target["analysis_pipeline"] = {"kind": kind}
            evidence = self.actual(target)
            baseline = evidence["analysis_command"]["argv"]
            changes = [lambda argv: argv.remove("-eva-no-builtins-auto"),
                       lambda argv: argv.__setitem__(argv.index("-eva-builtin") + 1, "memcpy:other"),
                       lambda argv: argv.__delitem__(slice(argv.index("-eva-builtin"), argv.index("-eva-builtin") + 2)),
                       lambda argv: argv.__setitem__(argv.index("-eva-builtin"), "-val-builtin"),
                       lambda argv: argv.__setitem__(argv.index("-eva-no-builtins-auto"), "-val-no-builtins-auto"),
                       lambda argv: argv.__setitem__(argv.index("-eva-no-builtins-auto"), "-eva-builtins-auto=false")]
            for mutate in changes:
                argv = copy.deepcopy(baseline)
                mutate(argv)
                with self.subTest(kind=kind, argv=argv), self.assertRaises(policy.AnalysisPolicyError):
                    policy.validate_actual_policy(self.analysis, target, argv, evidence["analyzer_audit"]["parameters"])
            for extra in (["-eva-no-builtins-auto"], ["-eva-builtins-auto"],
                          ["-eva-builtin", "memcpy:Frama_C_memcpy"],
                          ["-eva-builtin=memcpy:Frama_C_memcpy"], ["-val-builtins-auto"],
                          ["-val-builtin=memcpy:Frama_C_memcpy"]):
                for index in (1, baseline.index("-eva"), len(baseline) - 5):
                    argv = [*baseline[:index], *extra, *baseline[index:]]
                    with self.subTest(kind=kind, extra=extra, index=index), self.assertRaises(policy.AnalysisPolicyError):
                        policy.validate_actual_policy(self.analysis, target, argv, evidence["analyzer_audit"]["parameters"])
            # Move the sole, otherwise correct controls into the earlier phase.
            argv = copy.deepcopy(baseline)
            start = argv.index("-eva-no-builtins-auto")
            controls = argv[start:start + 3]
            del argv[start:start + 3]
            argv[1:1] = controls
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, target, argv, evidence["analyzer_audit"]["parameters"])
        wp = self.wp_fixture()
        for extra in ("-eva-builtins-auto", "-eva-builtin=memcpy:Frama_C_memcpy", "-val-no-builtins-auto"):
            argv = wp["analysis_command"]["argv"]
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, wp["target"], [argv[0], extra, *argv[1:]],
                                              wp["analyzer_audit"]["parameters"])

    def test_actual_plain_eva_cannot_claim_explicit_rte_pipeline(self):
        evidence = self.actual()
        argv = evidence["analysis_command"]["argv"]
        del argv[argv.index("-rte"):argv.index("-eva")]
        with self.assertRaises(policy.AnalysisPolicyError):
            policy.validate_actual_policy(self.analysis, self.target,
                evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])

    def test_wrong_actual_flags_pipeline_or_final_audit_fail(self):
        baseline = self.actual()
        changes = [lambda argv: argv.remove(policy.POINTER_FLAG),
                   lambda argv: argv.append(policy.POINTER_FLAG),
                   lambda argv: argv.append("-no-warn-invalid-pointer"),
                   lambda argv: argv.append("-warn-invalid-pointer=false"),
                   lambda argv: argv.remove("-rte-no-use-eva-results"),
                   lambda argv: argv.remove("-then"),
                   lambda argv: argv.__setitem__(argv.index("-main") + 1, "different_entry"),
                   lambda argv: argv.__setitem__(argv.index("-eva-slevel") + 1, "1"),
                   lambda argv: argv.__setitem__(argv.index("-rte-select") + 1, self.target["entry"]),
                   lambda argv: argv.extend(["-then", "-eva"])]
        for mutate in changes:
            argv = copy.deepcopy(baseline["analysis_command"]["argv"])
            mutate(argv)
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, self.target, argv, baseline["analyzer_audit"]["parameters"])
        for key, value in ((policy.POINTER_FLAG, "false"), (policy.POINTER_FLAG, True),
                           ("-warn-signed-overflow", "true"), ("-main", "other_entry"),
                           ("-eva-builtins-auto", "false"), ("-eva-builtin", "helper:builtin")):
            audit = copy.deepcopy(baseline["analyzer_audit"]["parameters"])
            audit["eva"]["correctness-parameters"][key] = value
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, self.target, baseline["analysis_command"]["argv"], audit)

    def test_actual_pointer_checked_wp_commands_satisfy_candidate(self):
        for name in ("s390.unaligned24", "s390.unaligned48", "string.verified.strnchr", "string.verified.strlcat"):
            evidence = self.wp_fixture(name)
            checked = policy.validate_actual_policy(self.analysis, evidence["target"],
                evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])
            self.assertEqual("wp-rte", checked["pipeline"]["kind"])
            changed = copy.deepcopy(evidence["analysis_command"]["argv"])
            changed[changed.index("-wp-fct") + 1] = "omitted_helper_and_witness"
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, evidence["target"], changed,
                                              evidence["analyzer_audit"]["parameters"])

    def test_missing_duplicate_wrong_engines_and_wp_models_are_rejected(self):
        evidence = self.wp_fixture()
        changes = [lambda argv: argv.remove("-wp"),
                   lambda argv: argv.append("-wp"),
                   lambda argv: argv.append("-eva"),
                   lambda argv: argv.append("-no-wp"),
                   lambda argv: argv.append("-wp-no-rte"),
                   lambda argv: argv.__setitem__(argv.index("-wp-model") + 1, "Bytes"),
                   lambda argv: argv.remove("-wp-model"),
                   lambda argv: argv.extend(["-wp-model", "Typed"])]
        for mutate in changes:
            argv = copy.deepcopy(evidence["analysis_command"]["argv"])
            mutate(argv)
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, evidence["target"], argv,
                                              evidence["analyzer_audit"]["parameters"])
        for extra in ("-wp-model=Typed", "-wp-model=Bytes", "-wp=true", "-no-wp=true", "-eva=true"):
            with self.subTest(extra=extra), self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, evidence["target"],
                    [*evidence["analysis_command"]["argv"], extra], evidence["analyzer_audit"]["parameters"])
        for mutate in (lambda argv: argv.remove("-eva"), lambda argv: argv.append("-eva"),
                       lambda argv: argv.append("-wp"), lambda argv: argv.append("-no-eva"),
                       lambda argv: argv.extend(["-wp-model", "Typed"]),
                       lambda argv: argv.append("-eva=true"), lambda argv: argv.append("-rte=true")):
            eva = self.actual()
            argv = copy.deepcopy(eva["analysis_command"]["argv"])
            mutate(argv)
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, self.target, argv,
                                              eva["analyzer_audit"]["parameters"])

    def test_alternate_or_reordered_report_phases_are_rejected(self):
        for evidence, target in ((self.actual(), self.target), (self.wp_fixture(), self.targets["s390.unaligned24"])):
            baseline = evidence["analysis_command"]["argv"]
            for extra in ("-then-last", "-then-on=other", "-then-replace", "-then=other"):
                with self.subTest(extra=extra), self.assertRaises(policy.AnalysisPolicyError):
                    policy.validate_actual_policy(self.analysis, target, [*baseline[:-5], extra, *baseline[-5:]],
                                                  evidence["analyzer_audit"]["parameters"])
            engine = "-wp" if target["analysis"] == "wp" else "-eva"
            reordered = [arg for arg in baseline if arg != engine]
            reordered.insert(reordered.index("-report") + 1, engine)
            with self.assertRaises(policy.AnalysisPolicyError):
                policy.validate_actual_policy(self.analysis, target, reordered,
                                              evidence["analyzer_audit"]["parameters"])

    @unittest.skipUnless(os.environ.get("FRAGMA_POINTER_AUDIT_RESULTS"),
                         "supply explicit retained pointer-audit evidence")
    def test_retained_real_commands_and_audits(self):
        for directory, name in (("run-2", "s390.unaligned24"), ("run-2", "s390.unaligned48"),
                                ("run-3", "string.verified.strnchr"), ("run-3", "string.verified.strlcat")):
            evidence = json.loads((STAGE / directory / name / "result.json").read_text())
            checked = policy.validate_actual_policy(self.analysis, evidence["target"],
                evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])
            self.assertEqual("checked", checked["status"])
        evidence = json.loads((STAGE / "calibration-rte-2/receipt.json").read_text())
        checked = policy.validate_actual_policy(self.analysis, self.target,
            evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])
        self.assertEqual("rte-eva", checked["pipeline"]["kind"])

    @unittest.skipUnless(os.environ.get("FRAGMA_POINTER_BUILTIN_RESULTS"),
                         "supply explicit retained builtin-audit error evidence")
    def test_retained_eight_builtin_errors_are_understood_but_never_promoted(self):
        directory = Path(os.environ["FRAGMA_POINTER_BUILTIN_RESULTS"])
        summary_path = directory / "summary.json"
        summary_bytes = summary_path.read_bytes()
        summary = json.loads(summary_bytes)
        self.assertFalse(summary["accepted"])
        targets = [row for row in summary["targets"] if row["target"]["id"].startswith("calibration.string.")]
        self.assertEqual(8, len(targets))
        self.assertEqual(8, len({row["target"]["id"] for row in targets}))
        for recorded in targets:
            target = recorded["target"]
            with self.subTest(target=target["id"]):
                paths = [directory / target["id"] / name for name in ("result.json", "audit.json", "properties.tsv")]
                before = {path: path.read_bytes() for path in paths}
                evidence = json.loads(before[paths[0]])
                original = copy.deepcopy(evidence)
                self.assertEqual("tool-error", evidence["status"])
                self.assertFalse(evidence["accepted"])
                self.assertEqual("actual audited EVA builtin semantics differ", evidence["error"])
                self.assertNotIn("validated_analysis_policy", evidence)
                self.assertEqual(0, evidence["analysis_command"]["returncode"])
                self.assertEqual("passed", evidence["validated_native"]["status"])
                raw_audit = json.loads(before[paths[1]])
                self.assertEqual({key: value for key, value in raw_audit.items() if key != "sources"},
                                 evidence["analyzer_audit"]["parameters"])
                checked = policy.validate_actual_policy(summary["profiles"][target["profile"]]["analysis"], target,
                    evidence["analysis_command"]["argv"], evidence["analyzer_audit"]["parameters"])
                self.assertEqual("checked", checked["status"])
                self.assertEqual(["memcpy:Frama_C_memcpy"], checked["pipeline"]["eva_builtins"])
                self.assertFalse(checked["pipeline"]["eva_auto_builtins"])
                self.assertEqual(original, evidence)
                self.assertEqual(before, {path: path.read_bytes() for path in paths})
                self.assertEqual("tool-error", recorded["status"])
                self.assertFalse(recorded["accepted"])
        self.assertEqual(summary_bytes, summary_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
