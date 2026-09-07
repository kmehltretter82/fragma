"""Boundary tests for the explicit-evidence coverage inventory."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


from fragma import analysis_policy, coverage
REVISION = "b" * 40
DATE = "2026-09-06T01:00:00+00:00"
LATER = "2026-09-06T02:00:00+00:00"
CHECKED = "2026-09-06T03:00:00+00:00"


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="fragma coverage tests ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.analysis = {"wp_model": "Typed", "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS),
                         "runtime_checks": {"pointer_formation": "object-or-null"}}
        self.correctness = {flag.removeprefix("-no"): "false" for flag in analysis_policy.ARITHMETIC_FLAGS}
        self.correctness["-warn-invalid-pointer"] = "true"
        self.audit_parameters = {"eva": {"correctness-parameters": self.correctness}}
        self.profile = {"id": "p", "architecture": "s390", "abi": {"bits": 64},
                        "analysis": copy.deepcopy(self.analysis),
                        "status": "experimental", "kernel_revision": REVISION}
        self.target = {"id": "proof.f", "profile": "p", "role": "proof", "analysis": "wp",
            "source": "lib/f.c", "harness": "annotated/f.c", "functions": ["f"],
            "project_functions": ["roundtrip"], "claims": ["runtime-safety", "functional"],
            "caller_coverage": "unverified", "required_properties": ["f_ensures_value"]}
        self.targets = {self.target["id"]: self.target}
        self.profiles = {"p": self.profile}
        self.write("config/architectures.json", {"schema_version": 1, "kernel_revision": REVISION,
            "architectures": [{"id": "s390"}, {"id": "um"}]})
        self.write("config/targets.json", {"schema_version": 1})
        self.write("toolchain/assumptions.json", {"schema_version": 1})
        self.write("toolchain/lock.json", {"schema_version": 1})
        self.write("fragma/analysis_policy.py", "# synthetic test fixture identity\n")
        self.write("annotated/f.c", "/*@ ensures value: \\result == 1; */\nint f(void) { return 1; }\n")
        self.write("snapshot/lib/f.c", "int f(void) { return 1; }\n")
        self.write("profiles/calibration.c", "fixture\n")
        self.write("model.yaml", "model\n")
        self.write("generator.py", "generator\n")
        policy_audit = self.write("model-policy-audit.json", self.audit_parameters)
        model_argv = ["frama-c", *analysis_policy.analyzer_flags(self.analysis),
                      "-audit-prepare", str(policy_audit), "-eva", "-eva-slevel", "10"]
        model_policy = analysis_policy.validate_actual_model_policy(self.analysis, model_argv, self.audit_parameters)
        self.model = {"schema_version": 1, "profile_id": "p", "architecture": "s390",
            "kernel_revision": REVISION, "profile_sha256": coverage._digest(self.profile),
            "status": "passed", "level": "L1", "analysis": copy.deepcopy(self.analysis),
            "validated_model_policy": model_policy,
            "analysis_policy_audit": {"path": str(policy_audit), "sha256": coverage._Inputs.hash(policy_audit),
                                      "parameters": copy.deepcopy(self.audit_parameters)},
            "checks": [{"name": "eva-arithmetic-and-memory-byte-order", "status": "passed",
                        "details": {"command": model_argv, "exit_code": 0}},
                       {"name": "analysis-runtime-policy", "status": "passed", "details": model_policy}],
            "fixture_sha256": self.hash("profiles/calibration.c"),
            "generator": {"path": str(self.root / "generator.py"), "sha256": self.hash("generator.py")},
            "machdep": {"path": str(self.root / "model.yaml"), "sha256": self.hash("model.yaml")}}
        self.registry = patch.object(coverage.suite, "load_registry",
                                     side_effect=lambda root: (REVISION, self.targets, {}))
        self.profile_registry = patch.object(coverage.profiles, "load_profiles",
                                             side_effect=lambda root: self.profiles)
        self.registry.start()
        self.profile_registry.start()
        self.addCleanup(self.registry.stop)
        self.addCleanup(self.profile_registry.stop)

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)
        return path

    def hash(self, relative):
        return coverage._Inputs.hash(self.root / relative)

    def item(self, target=None):
        target = target or self.target
        return {"schema_version": 1, "target": copy.deepcopy(target), "status": "passed",
            "accepted": True, "evaluation": {"status": "passed", "accepted": True,
                "verified": True, "local_policy_passed": True},
            "provenance": {"passed": True, "source": {"path": target["source"],
                "kind": "git-blob", "revision": REVISION, "sha256": self.hash("snapshot/lib/f.c")}},
            "integrity_inputs": [{"absolute_path": str(self.root / relative), "sha256": self.hash(relative)}
                for relative in ("annotated/f.c", "snapshot/lib/f.c", "model.yaml")],
            "goals": [], "properties": [], "warnings": []}

    def make_run(self, name="old", date=DATE, items=None, selected=None):
        items = [self.item()] if items is None else items
        accepted = bool(items) and all(item.get("accepted") is True for item in items)
        value = {"schema_version": 1, "revision": REVISION, "status": "passed" if accepted else "incomplete",
            "accepted": accepted, "output": str(self.root / name), "started_at": DATE,
            "completed_at": date, "profiles": {"p": copy.deepcopy(self.model)},
            "selected_targets": selected or [item["target"]["id"] for item in items], "targets": items,
            "integrity_inputs": [{"absolute_path": str(path), "sha256": coverage._Inputs.hash(path)}
                for path in sorted([*self.root.glob("config/*.json"),
                                    self.root / "fragma/analysis_policy.py",
                                    self.root / "toolchain/assumptions.json", self.root / "toolchain/lock.json"])]}
        return self.write(name + "/summary.json", value)

    def matrix(self, paths, **kwargs):
        with patch.object(coverage, "_retained_target", return_value={"status": "passed", "artifacts": [],
                                                                   "analysis_policy": {"status": "checked"}}):
            return coverage.generate_matrix(self.root, paths, checked_at=CHECKED, **kwargs)

    def test_empty_evidence_preserves_roster_and_not_run_targets(self):
        matrix = self.matrix([])
        self.assertEqual(matrix["counts"]["architectures"], 2)
        self.assertEqual(matrix["architectures"][1]["state"], "planned")
        self.assertEqual(matrix["targets"][0]["state"], "not-run")
        self.assertEqual(matrix["counts"]["unique_kernel_functions"], 1)
        self.assertEqual(matrix["counts"]["project_witness_rows_excluded"], 1)
        self.assertIn("Contract-variant", coverage.render_markdown(matrix))

    def test_current_pass_has_no_implicit_termination_or_caller_proof(self):
        matrix = self.matrix([self.make_run()])
        self.assertEqual(matrix["targets"][0]["state"], "accepted-current")
        dims = matrix["functions"][0]["dimensions"]
        self.assertEqual(dims["functional"], "accepted-current")
        self.assertEqual(dims["termination"], "not-claimed")
        self.assertEqual(dims["caller-preconditions"], "unverified")
        self.assertEqual(matrix["profiles"][0]["current_dated_model_level"], "L1")
        self.assertEqual(matrix["profiles"][0]["architecture_level"], "not-assessed")

    def test_latest_failed_minimal_target_blocks_old_success_in_any_input_order(self):
        old = self.make_run()
        for status in ("profile-blocked", "error", "unsupported", "tool-error", "input-changed"):
            failed = {"target": copy.deepcopy(self.target), "status": status, "accepted": False,
                      "error": "kept raw"}
            newer = self.make_run("new-" + status, LATER, [failed])
            for paths in ([old, newer], [newer, old]):
                with self.subTest(status=status, paths=paths):
                    latest = self.matrix(paths)["targets"][0]
                    self.assertEqual(latest["state"], status)
                    self.assertFalse(latest["latest"]["current_verified"])
                    self.assertEqual(latest["latest"]["error"], "kept raw")
                    self.assertTrue(latest["history"][0]["reported_verified"])

    def test_missing_selected_target_is_not_produced_not_old_green(self):
        old = self.make_run()
        newer = self.make_run("missing", LATER, [], [self.target["id"]])
        self.assertEqual(self.matrix([old, newer])["targets"][0]["state"], "not-produced")

    def test_undated_preflight_failure_blocks_green_and_model_latest_level(self):
        old = self.make_run()
        failed = self.make_run("preflight", LATER, [], [self.target["id"]])
        data = json.loads(failed.read_text())
        data.pop("completed_at")
        data.update(status="preflight-failed", profiles={})
        self.write("preflight/summary.json", data)
        matrix = self.matrix([old, failed])
        self.assertFalse(matrix["targets"][0]["latest"]["current_verified"])
        self.assertIsNone(matrix["profiles"][0]["current_dated_model_level"])

    def test_stale_input_and_changed_target_binding_remain_historical(self):
        path = self.make_run()
        self.write("annotated/f.c", "changed source\n")
        matrix = self.matrix([path])
        self.assertEqual(matrix["targets"][0]["state"], "accepted-stale")
        self.assertTrue(matrix["targets"][0]["latest"]["stale_inputs"])
        self.assertEqual(matrix["counts"]["unique_kernel_functions_with_current_accepted_variant"], 0)
        self.target["claims"].append("termination")
        self.assertIn("target-definition-mismatch", self.matrix([path])["targets"][0]["latest"]["identity_issues"])

    def test_profile_and_source_revision_mismatches_block_current(self):
        for section, key, value in (("source", "revision", "a" * 40),
                                    ("source", "path", "lib/another.c"),
                                    ("model", "profile_sha256", "0" * 64)):
            path = self.make_run(section + key)
            data = json.loads(path.read_text())
            destination = data["profiles"]["p"] if section == "model" else data["targets"][0]["provenance"]["source"]
            destination[key] = value
            self.write(section + key + "/summary.json", data)
            with self.subTest(section=section, key=key):
                self.assertFalse(self.matrix([path])["targets"][0]["latest"]["current_verified"])

    def test_source_equal_tu_may_bind_original_snapshot_without_consuming_it(self):
        path = self.make_run()
        data = json.loads(path.read_text())
        data["profiles"]["p"]["build"] = {"source": str(self.root / "snapshot")}
        data["targets"][0]["integrity_inputs"] = [row for row in data["targets"][0]["integrity_inputs"]
            if not row["absolute_path"].endswith("/lib/f.c")]
        self.write("old/summary.json", data)
        matrix = self.matrix([path])
        self.assertTrue(matrix["targets"][0]["latest"]["current_verified"])
        self.assertEqual(matrix["targets"][0]["latest"]["source_content_check"]["status"], "passed")
        self.write("snapshot/lib/f.c", "different source")
        self.assertFalse(self.matrix([path])["targets"][0]["latest"]["current_verified"])

    def test_profile_without_successful_checks_cannot_support_current_proof(self):
        path = self.make_run()
        data = json.loads(path.read_text())
        data["profiles"]["p"]["checks"] = []
        self.write("old/summary.json", data)
        self.assertFalse(self.matrix([path])["targets"][0]["latest"]["current_verified"])

    def test_changed_manifest_and_retained_artifact_failures_stay_distinct(self):
        path = self.make_run()
        self.write("config/targets.json", {"schema_version": 1, "changed": True})
        row = self.matrix([path])["targets"][0]
        self.assertTrue(row["latest"]["stale_inputs"])
        with patch.object(coverage, "_retained_target", return_value={"status": "unavailable-or-mismatched", "artifacts": []}):
            matrix = coverage.generate_matrix(self.root, [path], checked_at=CHECKED)
        self.assertIn("retained-evidence-unavailable-or-mismatched", matrix["targets"][0]["latest"]["identity_issues"])

    def test_legacy_or_missing_policy_is_historical_never_current_coverage(self):
        path = self.make_run()
        for policy in ({}, {"status": "legacy-observed", "current_policy": False}, {"status": "unavailable"}):
            retained = {"status": "passed", "artifacts": [], "analysis_policy": policy}
            with patch.object(coverage, "_retained_target", return_value=retained):
                row = coverage.generate_matrix(self.root, [path], checked_at=CHECKED)["targets"][0]["latest"]
            with self.subTest(policy=policy):
                self.assertTrue(row["reported_accepted"])
                self.assertFalse(row["current_accepted"])
                self.assertIn("current-analysis-policy-unavailable-or-legacy", row["identity_issues"])

    def test_model_policy_is_rederived_not_a_passed_boolean(self):
        for mutation in ("missing-envelope", "boolean-envelope", "missing-runtime", "changed-runtime", "false-audit", "wrong-command", "missing-policy-check", "duplicate-eva"):
            path = self.make_run("model-" + mutation)
            data = json.loads(path.read_text())
            model = data["profiles"]["p"]
            if mutation == "missing-envelope": model.pop("validated_model_policy")
            elif mutation == "boolean-envelope": model["validated_model_policy"] = True
            elif mutation == "missing-runtime": model["analysis"].pop("runtime_checks")
            elif mutation == "changed-runtime": model["analysis"]["runtime_checks"]["pointer_formation"] = "disabled"
            elif mutation == "false-audit":
                model["analysis_policy_audit"]["parameters"]["eva"]["correctness-parameters"]["-warn-invalid-pointer"] = "false"
                audit = self.write("false-model-audit.json", model["analysis_policy_audit"]["parameters"])
                model["analysis_policy_audit"].update(path=str(audit), sha256=coverage._Inputs.hash(audit))
                argv = model["checks"][0]["details"]["command"]
                argv[argv.index("-audit-prepare") + 1] = str(audit)
            elif mutation == "wrong-command": model["checks"][0]["details"]["command"].remove("-warn-invalid-pointer")
            elif mutation == "missing-policy-check": model["checks"].pop()
            else: model["checks"].append(copy.deepcopy(model["checks"][0]))
            self.write(str(path.relative_to(self.root)), data)
            matrix = self.matrix([path])
            with self.subTest(mutation=mutation):
                self.assertFalse(matrix["targets"][0]["latest"]["current_accepted"])
                self.assertIsNone(matrix["profiles"][0]["current_dated_model_level"])

    def test_duplicate_variants_deduplicate_kernel_not_preconditions_or_claims(self):
        alternative = {**self.target, "id": "proof.variant", "claims": ["output-nul-termination"]}
        calibration = {**self.target, "id": "calibration", "role": "calibration", "functions": ["not_a_kernel_count"]}
        self.targets.update({alternative["id"]: alternative, calibration["id"]: calibration})
        matrix = self.matrix([self.make_run(items=[self.item(), self.item(alternative)])])
        self.assertEqual(matrix["counts"]["unique_kernel_functions"], 1)
        self.assertEqual(matrix["counts"]["unique_kernel_functions_with_current_accepted_variant"], 1)
        alternative_row = next(row for row in matrix["functions"] if row["target"] == "proof.variant")
        self.assertEqual(alternative_row["dimensions"]["termination"], "not-claimed")
        self.assertTrue(any(row["kind"] == "calibration" for row in matrix["functions"]))

    def test_equal_time_observations_are_ambiguous(self):
        matrix = self.matrix([self.make_run("a"), self.make_run("b")])
        self.assertEqual(matrix["targets"][0]["state"], "ambiguous-latest")
        self.assertFalse(matrix["targets"][0]["latest"]["current_verified"])
        self.assertIsNone(matrix["profiles"][0]["current_dated_model_level"])

    def test_latest_failed_model_not_replaced_by_old_or_undated_l1(self):
        old = self.make_run()
        failed = {"target": self.target, "status": "profile-blocked", "accepted": False}
        newer = self.make_run("new", LATER, [failed])
        data = json.loads(newer.read_text())
        data["profiles"]["p"].update(status="blocked", level="L0", checks=[])
        self.write("new/summary.json", data)
        standalone = self.write("profile.json", self.model)
        row = self.matrix([old, newer], profile_paths=[standalone])["profiles"][0]
        self.assertEqual(row["latest_dated_model"]["reported_status"], "blocked")
        self.assertIsNone(row["current_dated_model_level"])
        self.assertEqual(row["undated_model_observations"][0]["current_model_level"], "L1")

    def test_json_rejects_duplicate_nonfinite_and_boolean_schema(self):
        path = self.make_run()
        raw = path.read_text()
        for changed in (raw.replace('"schema_version": 1', '"schema_version": true', 1),
                        raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1),
                        raw.replace('"schema_version": 1', '"schema_version": 1, "bad": NaN', 1),
                        raw.replace('"schema_version": 1', '"schema_version": 1, "bad": [1e999]', 1)):
            self.write("bad/summary.json", changed)
            with self.subTest(changed=changed[:90]), self.assertRaises(coverage.CoverageError):
                self.matrix([self.root / "bad/summary.json"])

    def test_contradictory_verdicts_are_rejected(self):
        mutations = [("accepted", 1), ("status", "incomplete"),
                     ("evaluation.verified", False), ("evaluation.accepted", False),
                     ("evaluation.status", "error"), ("evaluation.local_policy_passed", False)]
        for key, value in mutations:
            item = self.item()
            if "." in key:
                item["evaluation"][key.split(".")[1]] = value
            else:
                item[key] = value
            with self.subTest(key=key), self.assertRaises(coverage.CoverageError):
                self.matrix([self.make_run(key, items=[item])])

    def test_nonterminal_future_and_duplicate_summaries_are_rejected(self):
        path = self.make_run()
        with self.assertRaises(coverage.CoverageError):
            self.matrix([path, path])
        with self.assertRaises(coverage.CoverageError):
            self.matrix([self.make_run("future", "2027-01-01T00:00:00Z")])
        data = json.loads(path.read_text())
        data["status"] = "running"
        self.write("old/summary.json", data)
        with self.assertRaises(coverage.CoverageError):
            self.matrix([path])

    def test_input_drift_during_generation_is_rejected(self):
        path = self.make_run()
        original = coverage._Inputs.finalize

        def changed(inputs):
            self.write("annotated/f.c", "changed mid-generation")
            return original(inputs)

        with patch.object(coverage._Inputs, "finalize", changed), self.assertRaises(coverage.CoverageError):
            self.matrix([path])

    def raw_fixture(self):
        item = self.item()
        path = self.make_run()
        directory = path.parent / self.target["id"]
        target_relative = str(directory.relative_to(self.root))
        self.write("old/profile-p/profile.json", self.model)
        log = self.write(target_relative + "/analysis.log", "[wp] Fixture complete\n")
        pp = self.write(target_relative + "/tmp/source.pp", "int f(void) { return 1; }\n")
        source = str(self.root / "annotated/f.c")
        audit = self.write(target_relative + "/audit.json", {"sources": {source: "0" * 32}, **self.audit_parameters})
        item["input"] = {"cwd": str(self.root)}
        item["analysis_command"] = {"returncode": 0, "timed_out": False,
            "argv": ["frama-c", *analysis_policy.analyzer_flags(self.analysis), "-wp", "-wp-rte",
                     "-wp-model", "Typed", "-wp-fct", "f", "-then", "-report",
                     "-report-absolute-path", "-report-csv", str(directory / "properties.tsv")],
            "log": str(log), "log_sha256": coverage._Inputs.hash(log)}
        pp_row = {"absolute_path": str(pp), "path": "tmp/source.pp", "sha256": coverage._Inputs.hash(pp)}
        item["analyzer_audit"] = {"path": str(audit), "sha256": coverage._Inputs.hash(audit),
            "parameters": copy.deepcopy(self.audit_parameters), "inputs": [{"absolute_path": source}],
            "retained_preprocessing": [pp_row],
            "parsed_streams": [{**pp_row, "source": "annotated/f.c"}]}
        item["validated_analysis_policy"] = analysis_policy.validate_actual_policy(
            self.analysis, item["target"], item["analysis_command"]["argv"], item["analyzer_audit"]["parameters"])
        wp = self.write(target_relative + "/wp.json", [{"goal": "typed_f_ensures_value",
            "property": "f_ensures_value", "file": source, "line": 1, "function": "f",
            "smoke": False, "passed": True, "verdict": "valid",
            "provers": [{"prover": "qed", "time": 0.0, "success": 1}], "proved": 1}])
        tsv = self.write(target_relative + "/properties.tsv",
            "directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
            + str(self.root / "annotated") + "\tf.c\t1\tf\tpostcondition\tValid\tvalue: \\result == 1\n")
        item["goals"] = coverage.report.parse_wp_report(wp)
        item["properties"] = coverage.report.parse_properties(tsv, source_files=[self.root / "annotated/f.c"],
                                                             source_root=self.root, selected_functions=["f"])
        self.write(target_relative + "/result.json", item)
        run = {"path": str(path), "data": json.loads(path.read_text())}
        return item, run, directory

    def test_retained_raw_evidence_validates_and_rejects_deleted_or_changed_artifacts(self):
        for kind in ("unchanged", "analysis.log", "audit.json", "wp.json", "properties.tsv", "tmp/source.pp"):
            item, run, directory = self.raw_fixture()
            if kind != "unchanged":
                (directory / kind).unlink()
            result = coverage._retained_target(self.root, item, run, coverage._Inputs())
            with self.subTest(kind=kind):
                self.assertEqual(result["status"], "passed" if kind == "unchanged" else "unavailable-or-mismatched")
        for kind in ("analysis.log", "audit.json", "wp.json", "properties.tsv", "tmp/source.pp"):
            item, run, directory = self.raw_fixture()
            path = directory / kind
            path.write_text(path.read_text().replace("Valid", "Unknown") + "changed\n")
            with self.subTest(changed=kind):
                self.assertEqual(coverage._retained_target(self.root, item, run, coverage._Inputs())["status"],
                                 "unavailable-or-mismatched")

    def test_actual_policy_envelope_command_audit_and_pipeline_are_all_checked(self):
        for mutation in ("missing", "boolean", "extra-field", "missing-pointer", "opposing-pointer", "function-selector", "rte-pipeline", "changed-raw-audit"):
            item, run, directory = self.raw_fixture()
            if mutation == "missing": item.pop("validated_analysis_policy")
            elif mutation == "boolean": item["validated_analysis_policy"] = True
            elif mutation == "extra-field": item["validated_analysis_policy"]["waive"] = True
            elif mutation == "missing-pointer": item["analysis_command"]["argv"].remove("-warn-invalid-pointer")
            elif mutation == "opposing-pointer": item["analysis_command"]["argv"].insert(1, "-no-warn-invalid-pointer")
            elif mutation == "function-selector":
                argv = item["analysis_command"]["argv"]
                argv[argv.index("-wp-fct") + 1] = "other_function"
            elif mutation == "rte-pipeline": item["target"]["analysis_pipeline"] = {"kind": "rte-eva"}
            else:
                audit = item["analyzer_audit"]
                audit["parameters"]["eva"]["correctness-parameters"]["-warn-invalid-pointer"] = "false"
                raw = json.loads((directory / "audit.json").read_text())
                raw.update(copy.deepcopy(audit["parameters"]))
                self.write(str((directory / "audit.json").relative_to(self.root)), raw)
                audit["sha256"] = coverage._Inputs.hash(directory / "audit.json")
            self.write(str((directory / "result.json").relative_to(self.root)), item)
            with self.subTest(mutation=mutation):
                result = coverage._retained_target(self.root, item, run, coverage._Inputs())
                self.assertEqual(result["status"], "unavailable-or-mismatched")


if __name__ == "__main__":
    unittest.main()
