import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma import analysis_policy
from fragma.replay import (POLICY, LEGACY_ASSERTION_MAPPERS, LEGACY_ANALYSIS_POLICIES,
                    LEGACY_ARITHMETIC_FLAGS, Mapper, ReplayError, RootBindings, analysis_limits,
                    analysis_policy_observation, assertion_predicate_starts,
                    build_replay_view, compare_replays, digest, goal_view,
                    normalize_linemarkers, property_view, strict_json, warning_view)


def view(instance, *, accepted=True):
    result = {"schema_version": 1, "policy": POLICY, "status": "comparable", "accepted": accepted,
        "inputs": {"targets": ["helper"], "source": "a" * 64, "compiler": "b" * 64},
        "execution": {"helper": {"analysis_limits": {"wall_timeout_seconds": 180, "solver_timeout_seconds": 3, "jobs": 1}}},
        "outcomes": {"accepted": accepted, "status": "passed" if accepted else "incomplete", "targets": {"helper": {"goals": [{"name": "post", "outcome": "valid"}], "warnings": []}}},
        "artifacts": {"/tmp/" + instance + "/summary.json": digest(instance)},
        "run_instance": {"directory": "/tmp/" + instance, "started_at": instance, "completed_at": instance,
                         "summary_sha256": digest(instance)}}
    refresh(result)
    return result


def refresh(result):
    for field, name in (("inputs", "input_id"), ("execution", "execution_id"), ("outcomes", "outcome_id"), ("artifacts", "evidence_id")):
        result[name] = digest(result[field])


class ReplayUnitTests(unittest.TestCase):
    def setUp(self):
        self.mapper = Mapper(RootBindings({"project": "/project", "switch": "/tool/switch"}), Path("/run/one"))

    def test_overflowing_json_numbers_are_rejected_even_without_nonfinite_spelling(self):
        for value in ('1e999', '-1e999', '{"nested": [1e999]}'):
            with self.subTest(value=value), self.assertRaises(ReplayError):
                strict_json(value)
        self.assertEqual(strict_json('{"finite": 1e20}'), {"finite": 1e20})

    def test_legacy_assertion_names_require_exact_recorded_parser_hash(self):
        for digest_value in LEGACY_ASSERTION_MAPPERS:
            self.assertFalse(assertion_predicate_starts({"/project/fragma/report.py": digest_value}, "/project"))
            self.assertTrue(assertion_predicate_starts({"/unrelated/report.py": digest_value}, "/project"))
        self.assertTrue(assertion_predicate_starts({}, "/project"))
        self.assertTrue(assertion_predicate_starts({"/project/fragma/report.py": "0" * 64}, "/project"))

    def test_explicit_roots_normalize_only_corresponding_locations(self):
        other = Mapper(RootBindings({"project": "/other", "switch": "/else/tool"}), Path("/run/two"))
        self.assertEqual(self.mapper.path("/project/src/x.c"), other.path("/other/src/x.c"))
        self.assertEqual(self.mapper.path("/run/one/profile/model.yaml"), other.path("/run/two/profile/model.yaml"))
        self.assertNotEqual(self.mapper.path("/unmapped/x.c"), other.path("/different/x.c"))
        self.assertNotEqual(self.mapper.path("/project/src/x.c"), self.mapper.path("/project/other/x.c"))

    def test_broad_duplicate_and_relative_roots_are_rejected(self):
        for roots in ({"project": "/"}, {"project": "relative"}, {"project": "/same", "switch": "/same"}, {"project": "/project", "run": "/run"}):
            with self.subTest(roots=roots), self.assertRaises(ReplayError):
                Mapper(RootBindings(roots), Path("/run"))

    def test_linemarker_mapping_never_changes_c_or_acsl_strings(self):
        text = '# 7 "/project/input.c" 1\nconst char *s = "/project/input.c";\n/*@ assert label: p == "/project/input.c"; */\n'
        normalized = normalize_linemarkers(text, self.mapper)
        self.assertTrue(normalized.startswith('# 7 "project:input.c" 1\n'))
        self.assertIn('const char *s = "/project/input.c"', normalized)
        self.assertIn('p == "/project/input.c"', normalized)
        self.assertNotEqual(digest(normalized), digest(normalize_linemarkers(text.replace('const char *s = "/project/input.c"', 'const char *s = "/else/input.c"'), self.mapper)))
        comment = '/*@\n# 7 "/project/input.c" 1\n*/\n'
        self.assertEqual(normalize_linemarkers(comment, self.mapper), comment)

    def test_generated_location_alias_requires_exact_bound_path(self):
        self.mapper.aliases["/run/one/tmp/ppannotabcdef.c"] = "generated:helper:ppannot.c:hash"
        warning = {"plugin": "compiler", "severity": "warning", "message": "macro redefined", "path": "/run/one/tmp/ppannotabcdef.c", "line": 7, "log_line": 20, "raw_lines": ["/run/one/tmp/ppannotabcdef.c:7: warning: macro redefined", " code"]}
        first = warning_view(warning, self.mapper)
        warning["log_line"] = 200
        self.assertEqual(first, warning_view(warning, self.mapper))
        warning["path"] = "/run/one/tmp/ppannotfedcba.c"
        self.assertNotEqual(first, warning_view(warning, self.mapper))

    def test_argument_order_and_opaque_define_values_remain_semantic(self):
        argv = ["/tool/switch/bin/frama-c", "-I/project/first", "-I/project/second", '-DPATH="/project/literal"']
        normalized = self.mapper.argv(argv)
        self.assertEqual(normalized[-1], argv[-1])
        changed = list(argv); changed[1:3] = reversed(changed[1:3])
        self.assertNotEqual(normalized, self.mapper.argv(changed))
        with self.assertRaises(ReplayError):
            self.mapper.argv(["compiler", "&&", "another"])

    def test_search_path_order_is_kept_and_bound_prefixes_are_normalized(self):
        paths = self.mapper.metadata({"PATH": "/tool/switch/bin:/usr/bin"})
        self.assertEqual(paths["PATH"], ["switch:bin", "absolute:/usr/bin"])
        self.assertNotEqual(paths, self.mapper.metadata({"PATH": "/usr/bin:/tool/switch/bin"}))

    def test_resource_parameters_are_explicit_execution_inputs(self):
        a = ["tool", "-wp", "-wp-timeout", "3", "-wp-par", "1"]
        b = ["tool", "-wp", "-wp-timeout", "8", "-wp-par", "2"]
        self.assertEqual(self.mapper.argv(a, omit_resources=True), self.mapper.argv(b, omit_resources=True))
        self.assertNotEqual(self.mapper.argv(a), self.mapper.argv(b))

    def test_timing_and_winning_prover_do_not_change_goal_identity(self):
        row = {"goal": "typed_post", "property": "post", "line": 8, "function": "helper", "smoke": False,
               "passed": True, "verdict": "valid", "outcome": "valid", "path": "/project/x.c", "solver_seconds": 0.1,
               "provers": [{"prover": "z3", "time": 0.1, "success": 1}]}
        first = goal_view(row, self.mapper)
        row.update(solver_seconds=5, provers=[{"prover": "alt-ergo", "time": 5, "success": 1}])
        self.assertEqual(first, goal_view(row, self.mapper))
        row["verdict"] = "timeout"
        self.assertNotEqual(first, goal_view(row, self.mapper))

    def test_ambiguous_property_tag_is_not_discarded(self):
        row = {"path": "/project/x.c", "line": 8, "function": "unselected", "kind": "precondition", "status": "Dead", "outcome": "unreachable", "property": "p", "names": []}
        first = property_view(row, self.mapper)
        row["exported_identity_ambiguous"] = True
        self.assertNotEqual(first, property_view(row, self.mapper))

    def test_two_distinct_successful_executions_can_agree(self):
        result = compare_replays(view("one"), view("two"))
        self.assertEqual(result["status"], "replay-passed")
        self.assertTrue(result["replay_passed"])

    def test_same_receipt_never_satisfies_two_run_requirement(self):
        original = view("one")
        result = compare_replays(original, copy.deepcopy(original))
        self.assertEqual(result["status"], "same-evidence")
        self.assertFalse(result["replay_passed"])

    def test_copied_receipt_timestamps_are_not_a_new_execution(self):
        left, right = view("one"), view("two")
        right["run_instance"].update(started_at="one", completed_at="one")
        self.assertEqual(compare_replays(left, right)["status"], "same-evidence")

    def test_changed_binary_or_review_invalidates_input_association(self):
        for field in ("compiler", "source", "review"):
            left, right = view("one"), view("two")
            right["inputs"][field] = "changed"; refresh(right)
            result = compare_replays(left, right)
            self.assertEqual(result["status"], "inputs-changed")
            self.assertTrue(result["outcomes_equal"])
            self.assertFalse(result["replay_passed"])

    def test_missing_or_changed_goals_and_warning_multiplicity_are_not_hidden(self):
        for mutation in ("missing-goal", "unknown-goal", "duplicate-warning"):
            left, right = view("one"), view("two")
            target = right["outcomes"]["targets"]["helper"]
            if mutation == "missing-goal": target["goals"] = []
            elif mutation == "unknown-goal": target["goals"][0]["outcome"] = "unknown"
            else: target["warnings"] = ["warning", "warning"]
            refresh(right)
            self.assertEqual(compare_replays(left, right)["status"], "outcomes-changed")

    def test_matching_incomplete_reports_never_pass(self):
        result = compare_replays(view("one", accepted=False), view("two", accepted=False))
        self.assertEqual(result["status"], "matching-incomplete")
        self.assertFalse(result["replay_passed"])

    def test_unavailable_legacy_limits_do_not_satisfy_clean_replay(self):
        left, right = view("one"), view("two")
        for item in (left, right): item["execution"]["helper"]["analysis_limits"] = None; refresh(item)
        self.assertEqual(compare_replays(left, right)["status"], "execution-limits-unavailable")

    def test_recorded_limits_must_match_summary_and_actual_wp_flags(self):
        limits = {"wall_timeout_seconds": 240, "solver_timeout_seconds": 3, "jobs": 2}
        evidence = {"target": {"analysis": "wp"}, "analysis_command": {"argv": ["tool", "-wp-timeout", "3", "-wp-par", "2"]}, "analysis_limits": limits}
        self.assertEqual(analysis_limits(evidence, {"analysis_limits": limits}, {}, "/project"), (limits, "recorded"))
        for change in ({**limits, "jobs": True}, {**limits, "solver_timeout_seconds": 9}, {**limits, "wall_timeout_seconds": 86401}):
            evidence["analysis_limits"] = change
            with self.assertRaises(ReplayError): analysis_limits(evidence, {"analysis_limits": change}, {}, "/project")

    def test_unrecognized_legacy_runner_never_gets_an_inferred_limit(self):
        evidence = {"target": {"analysis": "wp"}, "analysis_command": {"argv": ["tool", "-wp-timeout", "3", "-wp-par", "2"]}}
        self.assertEqual(analysis_limits(evidence, {}, {"/project/fragma/suite.py": "0" * 64}, "/project"), (None, "unavailable-in-legacy-receipt"))

    def test_forged_acceptance_schema_or_stale_digest_fails(self):
        for mutation in ("accepted", "schema", "digest", "empty-targets"):
            left, right = view("one"), view("two")
            if mutation == "accepted": right["outcomes"]["accepted"] = False; refresh(right)
            elif mutation == "schema": right["schema_version"] = True
            elif mutation == "digest": right["inputs"]["source"] = "other"
            else: right["inputs"]["targets"] = []; refresh(right)
            with self.subTest(mutation=mutation), self.assertRaises(ReplayError): compare_replays(left, right)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for text in ('{"accepted":false,"accepted":true}', '{"elapsed":NaN}', '{"elapsed":Infinity}'):
            with self.assertRaises(ReplayError): strict_json(text)


class ReplayAnalysisPolicyTests(unittest.TestCase):
    def fixture(self, *, kind="wp-rte", legacy=False):
        analysis = {"wp_model": "Typed", "arithmetic_flags": list(LEGACY_ARITHMETIC_FLAGS)}
        target = {"analysis": "wp" if kind == "wp-rte" else "eva", "functions": ["f"]}
        correctness = {flag.removeprefix("-no"): "false" for flag in LEGACY_ARITHMETIC_FLAGS}
        correctness["-warn-invalid-pointer"] = "false" if legacy else "true"
        argv = ["frama-c", *LEGACY_ARITHMETIC_FLAGS]
        if not legacy:
            analysis["runtime_checks"] = {"pointer_formation": "object-or-null"}
            argv.append("-warn-invalid-pointer")
        if kind == "wp-rte":
            argv.extend(["-wp", "-wp-rte", "-wp-model", "Typed", "-wp-fct", "f"])
        else:
            target["entry"] = "entry"
            correctness.update({"-main": "entry", "-eva-builtins-auto": "true", "-eva-builtin": ""})
            if kind == "rte-eva":
                target["analysis_pipeline"] = {"kind": kind}
                argv.extend(["-rte", "-rte-select", "f,entry", "-rte-no-use-eva-results", "-then"])
            argv.extend(["-eva", "-main", "entry", "-eva-slevel", "100"])
        argv.extend(["-then", "-report", "-report-absolute-path", "-report-csv", "/run/properties.tsv"])
        evidence = {"analysis_command": {"argv": argv},
                    "analyzer_audit": {"parameters": {"eva": {"correctness-parameters": correctness}}}}
        if not legacy:
            evidence["validated_analysis_policy"] = analysis_policy.validate_actual_policy(
                analysis, target, argv, evidence["analyzer_audit"]["parameters"])
        pair = sorted(LEGACY_ANALYSIS_POLICIES)[0]
        shared = {"/project/fragma/suite.py": pair[0], "/project/config/profiles.json": pair[1],
                  "/project/fragma/analysis_policy.py": "a" * 64}
        return {"analysis": analysis}, target, evidence, shared

    def observe(self, fixture):
        return analysis_policy_observation(*fixture, "/project")

    def test_current_policy_is_rederived_for_each_closed_pipeline(self):
        for kind in ("wp-rte", "eva", "rte-eva"):
            fixture = self.fixture(kind=kind)
            before = copy.deepcopy(fixture)
            result = self.observe(fixture)
            self.assertEqual(result["status"], "checked")
            self.assertEqual(result["actual_pointer_formation"], "true")
            self.assertEqual(result["pipeline"]["kind"], kind)
            self.assertEqual(before, fixture)

    def test_missing_forged_boolean_or_unknown_policy_envelopes_fail(self):
        for kind in ("missing", "null", "boolean", "schema-bool", "model", "pipeline", "extra", "unbound-code"):
            fixture = self.fixture()
            model, target, evidence, shared = fixture
            if kind == "missing": evidence.pop("validated_analysis_policy")
            elif kind == "null": evidence["validated_analysis_policy"] = None
            elif kind == "boolean": evidence["validated_analysis_policy"] = True
            elif kind == "schema-bool": evidence["validated_analysis_policy"]["schema_version"] = True
            elif kind == "model": model["analysis"]["runtime_checks"]["pointer_formation"] = "disabled"
            elif kind == "pipeline": evidence["validated_analysis_policy"]["pipeline"]["functions"] = ["other"]
            elif kind == "extra": evidence["validated_analysis_policy"]["unreviewed"] = True
            else: shared.pop("/project/fragma/analysis_policy.py")
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.observe(fixture)

    def test_actual_flags_audit_and_stage_mutations_are_not_hidden_by_checked_envelope(self):
        for kind in ("wp-rte", "eva", "rte-eva"):
            for mutation in ("missing-pointer", "opposing-pointer", "changed-arithmetic", "audit-false", "audit-bool", "new-pipeline", "alternate-stage"):
                fixture = self.fixture(kind=kind)
                _, target, evidence, _ = fixture
                argv = evidence["analysis_command"]["argv"]
                correctness = evidence["analyzer_audit"]["parameters"]["eva"]["correctness-parameters"]
                if mutation == "missing-pointer": argv.remove("-warn-invalid-pointer")
                elif mutation == "opposing-pointer": argv.insert(1, "-no-warn-invalid-pointer")
                elif mutation == "changed-arithmetic": argv.remove(LEGACY_ARITHMETIC_FLAGS[0])
                elif mutation == "audit-false": correctness["-warn-invalid-pointer"] = "false"
                elif mutation == "audit-bool": correctness["-warn-invalid-pointer"] = True
                elif mutation == "new-pipeline": target["analysis_pipeline"] = {"kind": "rte-eva" if kind != "rte-eva" else "eva"}
                else: argv.insert(1, "-then-last")
                with self.subTest(kind=kind, mutation=mutation), self.assertRaises(ValueError):
                    self.observe(fixture)

    def test_current_review_must_bind_the_same_actual_policy_and_pipeline(self):
        fixture = self.fixture()
        model, target, evidence, shared = fixture
        actual = evidence["validated_analysis_policy"]
        context = {"file_hashes": {"fragma/analysis_policy.py": shared["/project/fragma/analysis_policy.py"]},
                   "analysis": copy.deepcopy(actual["model"]), "analysis_pipeline": copy.deepcopy(actual["pipeline"])}
        target["review_context"] = copy.deepcopy(context)
        evidence["validated_review"] = {"review_context": copy.deepcopy(context)}
        self.assertEqual(self.observe(fixture)["status"], "checked")
        for mutation in ("missing-pointer", "different-pipeline", "wrong-module-hash", "target-disagrees"):
            changed = copy.deepcopy(fixture)
            review = changed[2]["validated_review"]["review_context"]
            if mutation == "missing-pointer": review["analysis"].pop("runtime_checks")
            elif mutation == "different-pipeline": review["analysis_pipeline"]["kind"] = "eva"
            elif mutation == "wrong-module-hash": review["file_hashes"]["fragma/analysis_policy.py"] = "b" * 64
            else: changed[1]["review_context"]["extra"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.observe(changed)

    def test_inspected_legacy_identity_preserves_observed_disabled_pointer_policy(self):
        for pair in LEGACY_ANALYSIS_POLICIES:
            for kind in ("wp-rte", "eva"):
                fixture = self.fixture(kind=kind, legacy=True)
                fixture[3].update({"/project/fragma/suite.py": pair[0], "/project/config/profiles.json": pair[1]})
                before = copy.deepcopy(fixture)
                actual = self.observe(fixture)
                self.assertEqual(actual["status"], "legacy-observed")
                self.assertIs(actual["current_policy"], False)
                self.assertEqual(actual["actual_pointer_formation"], "false")
                self.assertNotIn("runtime_checks", actual["model"])
                self.assertEqual(fixture, before)

    def test_ambiguous_legacy_identity_new_policy_or_changed_audit_cannot_upgrade(self):
        for mutation in ("runner", "profiles", "missing", "unrelated-path", "pipeline", "runtime", "new-envelope", "audit-true", "audit-missing", "command-true", "opposing-arithmetic", "new-phase"):
            fixture = self.fixture(legacy=True)
            model, target, evidence, shared = fixture
            argv = evidence["analysis_command"]["argv"]
            correctness = evidence["analyzer_audit"]["parameters"]["eva"]["correctness-parameters"]
            if mutation == "runner": shared["/project/fragma/suite.py"] = "0" * 64
            elif mutation == "profiles": shared["/project/config/profiles.json"] = "0" * 64
            elif mutation == "missing": shared.clear()
            elif mutation == "unrelated-path": shared["/other/fragma/suite.py"] = shared.pop("/project/fragma/suite.py")
            elif mutation == "pipeline": target["analysis_pipeline"] = {"kind": "wp-rte"}
            elif mutation == "runtime": model["analysis"]["runtime_checks"] = {"pointer_formation": "object-or-null"}
            elif mutation == "new-envelope": evidence["validated_analysis_policy"] = {"status": "checked"}
            elif mutation == "audit-true": correctness["-warn-invalid-pointer"] = "true"
            elif mutation == "audit-missing": correctness.pop("-warn-invalid-pointer")
            elif mutation == "command-true": argv.insert(1, "-warn-invalid-pointer")
            elif mutation == "opposing-arithmetic": argv.insert(1, "-warn-signed-overflow")
            else: argv.insert(1, "-then-last")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.observe(fixture)


class ReplayActualEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get("FRAGMA_REPLAY_PROJECT")
        if not supplied:
            raise unittest.SkipTest("set FRAGMA_REPLAY_PROJECT for retained real-run checks")
        cls.project = Path(supplied).resolve()
        cls.names = ["verified-strings-integrated-20260906", "verified-strings-clean-toolchain-20260906"]
        cls.roots, cls.views = [], []
        for name in cls.names:
            run = cls.project / "results" / name
            tools = json.loads((run / "toolchain.json").read_text())
            roots = RootBindings({"project": str(cls.project), "kernel": str(cls.project / "build/sources/linux-b9b3e33b70b71"),
                "build:x86_64-gcc": str(cls.project / "build/kernel/x86_64-gcc"),
                "switch": tools["environment"]["FRAGMA_SWITCH_PREFIX"], "native-prefix": tools["environment"]["FRAGMA_TOOLCHAIN_PREFIX"]})
            cls.roots.append(roots)
            cls.views.append(build_replay_view(run / "summary.json", roots=roots))

    def test_real_rebuilt_toolchain_agrees_on_outcomes_but_not_inputs(self):
        result = compare_replays(*self.views)
        self.assertEqual(result["status"], "inputs-changed")
        self.assertTrue(result["outcomes_equal"])
        self.assertTrue(result["execution_equal"])
        self.assertTrue(result["both_accepted"])
        self.assertFalse(result["replay_passed"])
        self.assertEqual(result["outcome_diffs"], [])
        self.assertFalse(result["current_analysis_policy_on_both"])
        for scope in result["analysis_policy_scope"]:
            self.assertEqual(set(scope.values()), {"legacy-observed"})

    def test_real_self_comparison_does_not_award_reproducibility(self):
        self.assertEqual(compare_replays(self.views[0], self.views[0])["status"], "same-evidence")

    def test_real_input_view_has_no_physical_output_location(self):
        for name, actual in zip(self.names, self.views):
            self.assertNotIn(str(self.project / "results" / name), json.dumps(actual["inputs"]))
            self.assertEqual(set(actual["limit_evidence"].values()), {"derived-from-pinned-legacy-runner"})

    def test_real_metadata_mutations_fail_without_rewriting_artifacts(self):
        run = self.project / "results" / self.names[0]
        summary_path = run / "summary.json"
        original = json.loads(summary_path.read_text())
        read_text = Path.read_text
        for mutation in ("missing-target", "profile-level", "goal-status", "warning-omission", "artifact-hash", "empty-inputs", "acceptance-bool", "suite-not-terminal", "duplicate-property", "smoke-consistency", "source-inventory", "summary-count"):
            changed = copy.deepcopy(original)
            target = changed["targets"][0]
            if mutation == "missing-target": changed["targets"].pop()
            elif mutation == "profile-level": changed["profiles"]["x86_64-gcc"]["level"] = "L0"
            elif mutation == "goal-status": target["goals"][-1]["verdict"] = "timeout"
            elif mutation == "warning-omission": target["warnings"].pop()
            elif mutation == "artifact-hash": target["analyzer_audit"]["parsed_streams"][0]["sha256"] = "0" * 64
            elif mutation == "empty-inputs": target["integrity_inputs"] = []
            elif mutation == "acceptance-bool": target["evaluation"]["accepted"] = 1
            elif mutation == "suite-not-terminal": changed["status"] = "running"
            elif mutation == "duplicate-property": target["properties"].append(copy.deepcopy(target["properties"][0]))
            elif mutation == "smoke-consistency": target["evaluation"]["smoke"]["consistency_proved"] = True
            elif mutation == "source-inventory": target["analyzer_audit"]["inputs"].pop()
            else: changed["counts"]["passed"] = 999

            def intercepted(path, *args, **kwargs):
                if path == summary_path: return json.dumps(changed)
                if path == run / target["target"]["id"] / "result.json": return json.dumps(target)
                if path == run / "profile-x86_64-gcc/profile.json": return json.dumps(changed["profiles"]["x86_64-gcc"])
                return read_text(path, *args, **kwargs)

            with self.subTest(mutation=mutation), patch.object(Path, "read_text", intercepted), self.assertRaises(ReplayError):
                build_replay_view(summary_path, roots=self.roots[0])


if __name__ == "__main__":
    unittest.main()
