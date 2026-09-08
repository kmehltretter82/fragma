import copy
import json
from pathlib import Path
import tempfile
import unittest

from fragma.report import (ReportError, evaluate_target, finalize_companions,
                           named_assertions, parse_properties, parse_wp_report)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="fragma-report-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "fixture.c"
        self.source.write_text("int f(int x) {\n  /*@ assert ok: x > 0; */\n  return x;\n}\n")
        self.target = {"id": "target.f", "profile": "test-profile", "source": "lib/f.c",
                       "functions": ["f"], "role": "proof", "analysis": "wp",
                       "required_properties": ["f_assert_ok"], "claims": ["runtime-safety"]}

    def goal(self, *, prop="f_assert_ok", verdict="valid", smoke=False, passed=None, line=2, function="f"):
        return {"goal": "typed_" + prop, "property": prop, "file": str(self.source),
                "line": line, "function": function, "smoke": smoke,
                "passed": verdict != "valid" if smoke and passed is None else verdict == "valid" if passed is None else passed,
                "verdict": verdict, "provers": [{"prover": "qed", "time": 0.001, "success": int(verdict == "valid")}]}

    def prop(self, *, status="Valid", names=None, line=2, function="f"):
        return {"path": str(self.source), "file": "fixture.c", "directory": str(self.root),
                "line": line, "function": function, "kind": "user assertion",
                "status": status, "property": "x > 0", "names": names or ["ok", "f_assert_ok"]}

    def evaluate(self, goals=None, props=None, target=None, **kwargs):
        return evaluate_target(target or self.target, [self.goal()] if goals is None else goals,
                               [self.prop()] if props is None else props,
                               returncode=kwargs.get("returncode", 0), warnings=kwargs.get("warnings", []),
                               validated_review=kwargs.get("validated_review"))

    def review(self, *, smoke=None, warnings=(), trap=None):
        target = copy.deepcopy(self.target)
        metadata = {"file_hashes": {str(self.source): "b" * 64},
                    "review_evidence": [str(self.source)]}
        context = {"kernel_revision": "a" * 40, **copy.deepcopy(metadata)}
        smoke_records = []
        if smoke is not None:
            record = {field: smoke[field] for field in ("goal", "property", "function", "file", "line")}
            record.update(copy.deepcopy(metadata), reason="A separately reviewed branch is outside the selected valid domain.")
            if trap is not None:
                record["unreachable_property"] = {field: trap[field] for field in ("function", "line", "kind", "status", "property")}
                record["unreachable_property"]["file"] = trap["path"]
            smoke_records.append(record)
        warning_records = []
        for warning in warnings:
            record = {field: warning[field] for field in ("plugin", "severity", "message")}
            if warning.get("file") is not None:
                record.update(file=warning["file"], line=warning["line"])
            record.update(copy.deepcopy(metadata), reason="Exact selected operation and guard class reviewed independently.", functions=["f"])
            warning_records.append(record)
        target.update(review_context=context, reviewed_smoke=smoke_records, reviewed_warnings=warning_records)
        envelope = {"status": "passed", "target_id": target["id"], "profile": target["profile"],
                    "analysis": target["analysis"], "source_root": str(self.root),
                    "review_context": copy.deepcopy(context), "reviewed_smoke": copy.deepcopy(smoke_records),
                    "reviewed_warnings": copy.deepcopy(warning_records)}
        return target, envelope

    def dead_smoke(self):
        return self.goal(prop="f_wp_smoke_dead_code_s42", smoke=True, verdict="valid", passed=False)

    def report(self, text, suffix):
        path = self.root / ("report." + suffix)
        path.write_text(text)
        return path

    def test_valid_wp_and_consolidated_report(self):
        result = self.evaluate()
        self.assertTrue(result["accepted"])
        self.assertTrue(result["verified"])

    def test_exits_clause_is_matched_to_its_consolidated_postcondition(self):
        goal = self.goal(prop="f_exits", line=3)
        prop = {**self.prop(line=3), "kind": "postcondition", "property": r"\false", "names": []}
        result = self.evaluate(goals=[self.goal(), goal], props=[self.prop(), prop])
        self.assertTrue(result["accepted"])
        prop["status"] = "Partially proven"
        self.assertFalse(self.evaluate(goals=[self.goal(), goal], props=[self.prop(), prop])["accepted"])

    def test_missing_goal_array_fails(self):
        result = self.evaluate(goals=[])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["status"], "incomplete")

    def test_missing_properties_fails(self):
        self.assertFalse(self.evaluate(props=[])["accepted"])

    def test_missing_required_named_property_fails(self):
        result = self.evaluate(goals=[self.goal(prop="f_assert_unrelated")])
        self.assertFalse(result["accepted"])
        self.assertTrue(any(issue.get("property") == "f_assert_ok" for issue in result["issues"]))

    def test_missing_baseline_goal_fails(self):
        target = copy.deepcopy(self.target)
        target["required_goals"] = ["typed_f_assert_ok", "typed_f_loop_invariant_preserved"]
        self.assertFalse(self.evaluate(target=target)["accepted"])

    def test_function_without_goals_fails(self):
        target = copy.deepcopy(self.target)
        target["functions"].append("missing")
        self.assertFalse(self.evaluate(target=target)["accepted"])

    def test_unknown_function_in_report_fails(self):
        self.assertFalse(self.evaluate(goals=[self.goal(function="unrelated")])["accepted"])

    def test_unknown_or_empty_function_manifest_fails(self):
        for functions in ([], 1, None, "f"):
            with self.subTest(functions=functions):
                target = copy.deepcopy(self.target)
                target["functions"] = functions
                self.assertFalse(self.evaluate(target=target)["accepted"])

    def test_successful_process_is_not_a_proof(self):
        result = self.evaluate(goals=[self.goal(verdict="timeout")], props=[self.prop(status="Unknown")])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["counts"]["goals"], {"timeout": 1})

    def test_nonzero_process_fails_even_with_valid_goals(self):
        self.assertEqual(self.evaluate(returncode=2)["status"], "tool-error")

    def test_downstream_valid_wp_with_pending_hypothesis_is_incomplete(self):
        result = self.evaluate(props=[self.prop(status="Partially proven")])
        self.assertFalse(result["verified"])
        self.assertEqual(len(result["unresolved_dependencies"]), 1)

    def test_missing_consolidated_property_is_incomplete(self):
        self.assertFalse(self.evaluate(props=[self.prop(line=3)])["accepted"])

    def test_smoke_timeout_is_inconclusive(self):
        smoke = self.goal(prop="f_wp_smoke_default_requires", smoke=True, verdict="timeout", passed=True)
        result = self.evaluate(goals=[self.goal(), smoke])
        self.assertTrue(result["accepted"])
        self.assertEqual(result["smoke"]["inconclusive"], 1)
        self.assertFalse(result["smoke"]["consistency_proved"])

    def test_smoke_proof_is_inconsistency(self):
        smoke = self.goal(prop="f_wp_smoke_default_requires", smoke=True, verdict="valid", passed=False)
        result = self.evaluate(goals=[self.goal(), smoke])
        self.assertEqual(result["status"], "inconsistent")
        self.assertFalse(result["accepted"])

    def test_unreachable_invalidity_is_not_a_counterexample(self):
        target = copy.deepcopy(self.target)
        target.update(role="calibration", analysis="eva", entry="f", expected_invalid=["ok"], required_properties=["ok"])
        result = self.evaluate(goals=[], props=[self.prop(status="Invalid_but_dead")], target=target)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["confirmed_invalid_properties"], [])

    def test_expected_invalid_became_valid_requires_review(self):
        target = copy.deepcopy(self.target)
        target.update(role="calibration", analysis="eva", entry="f", expected_invalid=["ok"], required_properties=["ok"])
        self.assertEqual(self.evaluate(goals=[], target=target)["status"], "review-required")

    def test_expected_wp_uncertainty_needs_independent_refutation(self):
        target = copy.deepcopy(self.target)
        target.update(role="calibration", expected_unresolved=["f_assert_ok"], required_companion="calibration.eva",
                      companion_property_map={"f_assert_ok": "ok"},
                      companion_mapping_reason="The exact reached witness contradicts this specification.")
        result = self.evaluate(goals=[self.goal(verdict="timeout")], props=[self.prop(status="Unknown")], target=target)
        self.assertEqual(result["status"], "needs-companion")
        self.assertFalse(result["accepted"])
        missing = finalize_companions([result])[0]
        self.assertEqual(missing["status"], "incomplete")
        companion_target = copy.deepcopy(target)
        companion_target.update(id="calibration.eva", analysis="eva", entry="f", expected_invalid=["ok"], required_properties=["ok"])
        companion_target.pop("expected_unresolved")
        companion_target.pop("required_companion")
        companion_target.pop("companion_property_map")
        companion = self.evaluate(goals=[], props=[self.prop(status="Invalid")], target=companion_target)
        final = finalize_companions([result, companion])[0]
        self.assertTrue(final["accepted"])
        self.assertFalse(final["verified"])
        companion["accepted"] = False  # A source/model gate failed externally.
        self.assertFalse(finalize_companions([result, companion])[0]["accepted"])

    def test_timeout_cannot_satisfy_expected_invalid(self):
        target = copy.deepcopy(self.target)
        target.update(role="calibration", expected_invalid=["f_assert_ok"])
        self.assertFalse(self.evaluate(target=target, goals=[self.goal(verdict="timeout")], props=[self.prop(status="Unknown")])["accepted"])

    def test_expected_wp_failure_becoming_valid_requires_review(self):
        target = copy.deepcopy(self.target)
        target.update(role="calibration", expected_unresolved=["f_assert_ok"], required_companion="calibration.eva",
                      companion_property_map={"f_assert_ok": "ok"})
        self.assertEqual(self.evaluate(target=target)["status"], "review-required")

    def test_unrelated_companion_invalidity_never_refutes_expected_property(self):
        parent = {**self.target, "role": "calibration", "expected_unresolved": ["f_assert_ok"],
                  "required_companion": "calibration.eva", "companion_property_map": {"f_assert_ok": "ok"},
                  "companion_mapping_reason": "The exact reached witness contradicts this specification."}
        result = self.evaluate(target=parent, goals=[self.goal(verdict="timeout")], props=[self.prop(status="Unknown")])
        child = {**self.target, "id": "calibration.eva", "role": "calibration", "analysis": "eva", "entry": "f",
                 "expected_invalid": ["ok"], "required_properties": ["ok"]}
        companion = self.evaluate(target=child, goals=[], props=[self.prop(status="Invalid")])
        self.assertTrue(finalize_companions([result, companion])[0]["accepted"])
        for changes in ({"confirmed_invalid_properties": ["unrelated"]}, {"expected_invalid": ["unrelated"]},
                        {"functions": ["another_function"]}, {"profile": "another_profile"},
                        {"analysis": "wp"}, {"accepted": 1}, {"local_policy_passed": False}):
            with self.subTest(changes=changes):
                self.assertFalse(finalize_companions([result, {**companion, **changes}])[0]["accepted"])
        for mapping in ({}, {"wrong_parent": "ok"}, {"f_assert_ok": "unrelated"}, {"f_assert_ok": ""}):
            with self.subTest(mapping=mapping):
                self.assertFalse(finalize_companions([{**result, "companion_property_map": mapping}, companion])[0]["accepted"])
        for changes in ({"local_policy_passed": 1}, {"companion_mapping_reason": ""},
                        {"companion_mapping_reason": None}):
            with self.subTest(changes=changes):
                self.assertFalse(finalize_companions([{**result, **changes}, companion])[0]["accepted"])

    def test_expected_uncertainty_without_exact_mapping_is_incomplete(self):
        target = {**self.target, "role": "calibration", "expected_unresolved": ["f_assert_ok"],
                  "required_companion": "calibration.eva"}
        self.assertEqual(self.evaluate(target=target, goals=[self.goal(verdict="timeout")],
                                      props=[self.prop(status="Unknown")])["status"], "incomplete")

    def test_missing_rte_guards_blocks_runtime_safety_claim(self):
        self.assertFalse(self.evaluate(warnings=["[wp] Warning: Missing RTE guards"])["accepted"])

    def test_raw_review_fields_are_not_approval(self):
        smoke = self.dead_smoke()
        target, _ = self.review(smoke=smoke)
        result = self.evaluate(target=target, goals=[self.goal(), smoke])
        self.assertFalse(result["accepted"])
        self.assertTrue(any(item["kind"] == "review-required" for item in result["issues"]))

    def test_reviewed_dead_path_is_neither_consistency_nor_defect_evidence(self):
        smoke = self.dead_smoke()
        target, envelope = self.review(smoke=smoke)
        result = self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["smoke"]["inconsistent"], 1)
        self.assertEqual(result["smoke"]["reviewed_unreachable"], 1)
        self.assertFalse(result["smoke"]["consistency_proved"])
        self.assertFalse(result["reviewed_smoke"][0]["defect_evidence"])
        self.assertEqual(result["smoke"]["goals"][0]["verdict"], "valid")
        self.assertEqual(result["confirmed_invalid_properties"], [])

    def test_review_requires_passed_external_gate_and_matching_target(self):
        smoke = self.dead_smoke()
        target, original = self.review(smoke=smoke)
        for key, value in (("status", "failed"), ("target_id", "other"), ("profile", "other"),
                           ("analysis", "eva"), ("source_root", ".")):
            with self.subTest(field=key):
                envelope = copy.deepcopy(original)
                envelope[key] = value
                self.assertFalse(self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)["accepted"])

    def test_review_context_and_record_hashes_must_agree(self):
        smoke = self.dead_smoke()
        for mode in ("context-mismatch", "hash-mismatch", "missing-evidence", "missing-reason", "missing-context"):
            with self.subTest(mode=mode):
                target, envelope = self.review(smoke=smoke)
                if mode == "context-mismatch":
                    envelope["review_context"]["kernel_revision"] = "c" * 40
                elif mode == "missing-context":
                    envelope.pop("review_context")
                else:
                    for owner in (target, envelope):
                        record = owner["reviewed_smoke"][0]
                        if mode == "hash-mismatch":
                            record["file_hashes"][str(self.source)] = "c" * 64
                        elif mode == "missing-evidence":
                            record["review_evidence"] = []
                        else:
                            record["reason"] = " "
                self.assertFalse(self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)["accepted"])

    def test_smoke_review_matches_every_identity_field(self):
        smoke = self.dead_smoke()
        for field, value in (("goal", "other"), ("property", "f_wp_smoke_dead_code_s43"),
                             ("function", "other"), ("file", str(self.root / "other.c")), ("line", 3)):
            with self.subTest(field=field):
                target, envelope = self.review(smoke=smoke)
                for owner in (target, envelope):
                    owner["reviewed_smoke"][0][field] = value
                self.assertFalse(self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)["accepted"])

    def test_duplicate_smoke_review_is_rejected(self):
        smoke = self.dead_smoke()
        target, envelope = self.review(smoke=smoke)
        for owner in (target, envelope):
            owner["reviewed_smoke"].append(copy.deepcopy(owner["reviewed_smoke"][0]))
        self.assertFalse(self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)["accepted"])

    def test_stale_smoke_review_cannot_accept_inconclusive_result(self):
        smoke = self.dead_smoke()
        target, envelope = self.review(smoke=smoke)
        smoke.update(verdict="timeout", passed=True)
        result = self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["smoke"]["inconclusive"], 1)
        self.assertFalse(result["smoke"]["consistency_proved"])

    def test_default_precondition_smoke_cannot_be_waived(self):
        smoke = self.goal(prop="f_wp_smoke_default_requires", smoke=True, verdict="valid", passed=False)
        target, envelope = self.review(smoke=smoke)
        self.assertEqual(self.evaluate(target=target, goals=[self.goal(), smoke], validated_review=envelope)["status"], "inconsistent")

    def test_review_cannot_waive_smoke_tool_error_or_ordinary_failure(self):
        for mode in ("smoke-error", "ordinary-timeout", "pending-dependency"):
            with self.subTest(mode=mode):
                smoke = self.dead_smoke()
                target, envelope = self.review(smoke=smoke)
                ordinary, prop = self.goal(), self.prop()
                if mode == "smoke-error":
                    smoke.update(verdict="error", passed=False)
                elif mode == "ordinary-timeout":
                    ordinary = self.goal(verdict="timeout")
                    prop["status"] = "Unknown"
                else:
                    prop["status"] = "Partially proven"
                self.assertFalse(self.evaluate(target=target, goals=[ordinary, smoke], props=[prop], validated_review=envelope)["accepted"])

    def test_exact_unselected_false_trap_is_audited_only(self):
        smoke = self.goal(prop="trap_wp_smoke_dead_call_s42", smoke=True, verdict="valid", passed=False)
        trap = self.prop(status="Invalid or unreachable", function="trap", names=[])
        trap["property"] = r"\false"
        target, envelope = self.review(smoke=smoke, trap=trap)
        result = self.evaluate(target=target, goals=[self.goal(), smoke], props=[self.prop(), trap], validated_review=envelope)
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["reviewed_unreachable_properties"]), 1)
        self.assertFalse(result["reviewed_unreachable_properties"][0]["defect_evidence"])
        self.assertEqual(result["confirmed_invalid_properties"], [])

    def test_reviewed_false_trap_cannot_cover_selected_or_invalid_property(self):
        for mode in ("selected", "invalid", "elsewhere", "absent", "duplicate"):
            with self.subTest(mode=mode):
                smoke = self.goal(prop="trap_wp_smoke_dead_call_s42", smoke=True, verdict="valid", passed=False)
                trap = self.prop(status="Invalid or unreachable", function="trap")
                trap["property"] = r"\false"
                if mode == "selected":
                    smoke = self.goal(prop="f_wp_smoke_dead_call_s42", smoke=True, verdict="valid", passed=False)
                    trap["function"] = "f"
                elif mode == "invalid":
                    trap["status"] = "Invalid"
                elif mode == "elsewhere":
                    trap["line"] = 3
                target, envelope = self.review(smoke=smoke, trap=trap)
                props = [self.prop()] if mode == "absent" else [self.prop(), trap]
                if mode == "duplicate":
                    props.append(copy.deepcopy(trap))
                self.assertFalse(self.evaluate(target=target, goals=[self.goal(), smoke], props=props, validated_review=envelope)["accepted"])

    def test_exact_warning_review_is_retained_with_rationale(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Skipped RTE guards: unaligned pointers (not supported)"}
        target, envelope = self.review(warnings=[warning])
        result = self.evaluate(target=target, warnings=[warning], validated_review=envelope)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["warnings"], [warning])
        self.assertEqual(result["reviewed_warnings"][0]["review"]["reason"], envelope["reviewed_warnings"][0]["reason"])

    def test_warning_review_does_not_match_another_message_plugin_or_severity(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Unsupported diagnostic"}
        for field, value in (("plugin", "eva"), ("severity", "error"), ("message", "Unsupported diagnostic elsewhere")):
            with self.subTest(field=field):
                target, envelope = self.review(warnings=[warning])
                observed = {**warning, field: value}
                self.assertFalse(self.evaluate(target=target, warnings=[observed], validated_review=envelope)["accepted"])

    def test_warning_review_requires_exact_function_scope(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Unsupported diagnostic"}
        for functions in ([], ["other"], ["f", "other"], ["f", "f"]):
            with self.subTest(functions=functions):
                target, envelope = self.review(warnings=[warning])
                for owner in (target, envelope):
                    owner["reviewed_warnings"][0]["functions"] = functions
                self.assertFalse(self.evaluate(target=target, warnings=[warning], validated_review=envelope)["accepted"])

    def test_duplicate_or_stale_warning_reviews_fail(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Unsupported diagnostic"}
        for mode in ("duplicate-diagnostic", "duplicate-review", "stale"):
            with self.subTest(mode=mode):
                target, envelope = self.review(warnings=[warning])
                observed = [warning, copy.deepcopy(warning)] if mode == "duplicate-diagnostic" else [] if mode == "stale" else [warning]
                if mode == "duplicate-review":
                    for owner in (target, envelope):
                        owner["reviewed_warnings"].append(copy.deepcopy(owner["reviewed_warnings"][0]))
                self.assertFalse(self.evaluate(target=target, warnings=observed, validated_review=envelope)["accepted"])

    def test_located_warning_review_does_not_cover_another_location(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Unsupported diagnostic",
                   "file": str(self.source), "line": 2}
        target, envelope = self.review(warnings=[warning])
        self.assertTrue(self.evaluate(target=target, warnings=[warning], validated_review=envelope)["accepted"])
        self.assertFalse(self.evaluate(target=target, warnings=[{**warning, "line": 3}], validated_review=envelope)["accepted"])

    def test_global_warning_review_does_not_cover_a_located_diagnostic(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Unsupported diagnostic"}
        target, envelope = self.review(warnings=[warning])
        self.assertFalse(self.evaluate(target=target, warnings=[{**warning, "file": str(self.source), "line": 2}], validated_review=envelope)["accepted"])

    def test_missing_rte_guards_cannot_be_waived_alone(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Missing RTE guards"}
        target, envelope = self.review(warnings=[warning])
        self.assertFalse(self.evaluate(target=target, warnings=[warning], validated_review=envelope)["accepted"])

    def test_missing_rte_review_requires_all_observed_guard_diagnostics(self):
        missing = {"plugin": "wp", "severity": "warning", "message": "Missing RTE guards"}
        skipped = {"plugin": "wp", "severity": "warning", "message": "Skipped RTE guards: unaligned pointers (not supported)"}
        target, envelope = self.review(warnings=[missing, skipped])
        self.assertTrue(self.evaluate(target=target, warnings=[missing, skipped], validated_review=envelope)["accepted"])
        novel = {"plugin": "wp", "severity": "warning", "message": "Skipped RTE guards: new guard class"}
        self.assertFalse(self.evaluate(target=target, warnings=[missing, skipped, novel], validated_review=envelope)["accepted"])

    def test_review_cannot_waive_skipped_proof_goals(self):
        warning = {"plugin": "wp", "severity": "warning", "message": "Skipped goal f_assert_guard"}
        target, envelope = self.review(warnings=[warning])
        self.assertFalse(self.evaluate(target=target, warnings=[warning], validated_review=envelope)["accepted"])

    def test_malformed_warning_diagnostic_fails_closed(self):
        for warning in (None, 7, {"message": None, "severity": "warning"}, {"message": "bad", "severity": "other"}):
            with self.subTest(warning=warning):
                self.assertEqual(self.evaluate(warnings=[warning])["status"], "tool-error")

    def test_dead_property_status_never_confirms_invalidity(self):
        target = {**self.target, "analysis": "eva", "role": "calibration", "entry": "f",
                  "expected_invalid": ["ok"], "required_properties": ["ok"]}
        result = self.evaluate(target=target, goals=[], props=[self.prop(status="Dead")])
        self.assertFalse(result["accepted"])
        self.assertEqual(result["confirmed_invalid_properties"], [])

    def test_unknown_wp_verdict_is_rejected(self):
        path = self.report(json.dumps([self.goal(verdict="brand-new-verdict")]), "json")
        with self.assertRaisesRegex(ReportError, "Unknown WP verdict"):
            parse_wp_report(path)

    def test_duplicate_goal_is_rejected(self):
        path = self.report(json.dumps([self.goal(), self.goal()]), "json")
        with self.assertRaisesRegex(ReportError, "Duplicate"):
            parse_wp_report(path)

    def test_nonfinite_solver_time_is_rejected(self):
        goal = self.goal()
        goal["provers"][0]["time"] = float("nan")
        with self.assertRaisesRegex(ReportError, "elapsed time"):
            parse_wp_report(self.report(json.dumps([goal]), "json"))

    def test_valid_goal_without_successful_prover_is_rejected(self):
        goal = self.goal()
        goal["provers"][0]["success"] = 0
        with self.assertRaisesRegex(ReportError, "no successful prover"):
            parse_wp_report(self.report(json.dumps([goal]), "json"))

    def test_truncated_json_is_rejected(self):
        path = self.report('[{"goal":', "json")
        with self.assertRaises(ReportError):
            parse_wp_report(path)

    def test_empty_goal_report_is_rejected(self):
        path = self.report("[]", "json")
        with self.assertRaises(ReportError):
            parse_wp_report(path)

    def test_header_only_tsv_is_rejected(self):
        path = self.report("directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n", "csv")
        with self.assertRaisesRegex(ReportError, "only a header"):
            parse_properties(path)

    def test_tsv_assertion_names_are_mapped_from_exact_source_location(self):
        path = self.report("directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n" +
                           f"{self.root}\tfixture.c\t2\tf\tuser assertion\tValid\tx > 0\n", "csv")
        row = parse_properties(path, source_files=[self.source])[0]
        self.assertEqual(row["names"], ["ok", "f_assert_ok"])

    def test_tsv_unknown_status_is_rejected(self):
        path = self.report("directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n" +
                           f"{self.root}\tfixture.c\t2\tf\tuser assertion\tProbably valid\tx > 0\n", "csv")
        with self.assertRaisesRegex(ReportError, "Unknown property status"):
            parse_properties(path)

    def test_unselected_exporter_collision_is_retained_not_deduplicated(self):
        header = "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        selected = f"{self.root}\tfixture.c\t2\tf\tuser assertion\tValid\tx > 0\n"
        other = f"{self.root}\tfixture.c\t4\tg\tprecondition of memcpy\tDead\tx > 0\n"
        path = self.report(header + selected + other + other, "tsv")
        with self.assertRaisesRegex(ReportError, "Duplicate"):
            parse_properties(path)
        rows = parse_properties(path, source_files=[self.source], selected_functions=["f"])
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["report_row"] for row in rows[1:]], [3, 4])
        self.assertTrue(all(row["exported_identity_ambiguous"] for row in rows[1:]))
        result = self.evaluate(props=rows)
        self.assertTrue(result["accepted"])
        self.assertEqual(len(result["unselected_property_ambiguities"]), 2)

    def test_selected_identical_exporter_rows_are_aggregated_but_contradictions_fail(self):
        header = "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
        row = f"{self.root}\tfixture.c\t2\tf\tuser assertion\tValid\tx > 0\n"
        path = self.report(header + row + row, "tsv")
        rows = parse_properties(path, source_files=[self.source], selected_functions=["f"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["exported_occurrences"], [2, 3])
        self.assertEqual(rows[0]["exported_duplicate_count"], 2)
        result = self.evaluate(props=rows)
        self.assertTrue(result["accepted"], result)
        self.assertEqual(len(result["selected_property_duplicate_groups"]), 1)
        path.write_text(header + row + row.replace("Valid", "Unknown"))
        rows = parse_properties(path, source_files=[self.source], selected_functions=["f"])
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(item["exported_identity_ambiguous"] for item in rows))
        result = self.evaluate(props=rows)
        self.assertFalse(result["accepted"])
        self.assertEqual(len(result["selected_property_ambiguities"]), 2)
        with self.assertRaisesRegex(ReportError, "Duplicate"):
            parse_properties(path, selected_functions=["unrelated"])
        for scope in ([], "f", [None]):
            with self.subTest(scope=scope), self.assertRaises(ReportError):
                parse_properties(path, selected_functions=scope)

    def test_evaluator_rejects_selected_ambiguity_even_without_parser(self):
        self.assertFalse(self.evaluate(props=[self.prop(), self.prop()])["accepted"])
        row = {**self.prop(), "exported_identity_ambiguous": True}
        self.assertFalse(self.evaluate(props=[row])["accepted"])

    def test_assertion_mapping_ignores_c_string_contents(self):
        self.source.write_text('const char *s = "/*@ assert fake: 0; */";\n/*@ assert real: 1; */\n')
        self.assertEqual(named_assertions([self.source]), {(str(self.source), 2): "real"})

    def test_ambiguous_source_assertion_mapping_is_rejected(self):
        self.source.write_text("/*@ assert a: 1; assert b: 1; */\n")
        with self.assertRaisesRegex(ReportError, "Ambiguous"):
            named_assertions([self.source])


if __name__ == "__main__":
    unittest.main()
