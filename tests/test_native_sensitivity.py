"""Fail-closed checks for bounded, independently observed false specifications."""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma import analysis_policy, native_sensitivity as native
from fragma.native_sensitivity import (INSERTION, NativeError, render_driver,
                                       validate_events, validate_expression, validate_native_receipt)
from fragma.inputs import load_build
from fragma.sources import sha256


ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / "config/string-sensitivity-targets.json").read_text())["targets"]
MAPPING = json.loads((ROOT / "config/string-native-observations.json").read_text())
DRIVER = (ROOT / MAPPING["driver"]).read_text()


class NativeSensitivityTests(unittest.TestCase):
    def setUp(self):
        self.generated, self.properties = render_driver(DRIVER, TARGETS, MAPPING)

    def events(self, index=0):
        target, case = TARGETS[index], MAPPING["cases"][index]
        return [{"kind": "begin", "entry": target["entry"]}, copy.deepcopy(case["state"]),
                *[{"kind": "property", "name": row["name"], "observed": row["expected"],
                   "expected": row["expected"]} for row in self.properties[index]],
                {"kind": "normal-return", "entry": target["entry"]}]

    def validate(self, events, index=0, returncode=0, stderr=""):
        return validate_events("\n".join(json.dumps(event) for event in events),
                               TARGETS[index], MAPPING["cases"][index],
                               self.properties[index], returncode, stderr)

    def policy_model(self):
        return {"profile_id": "x86_64-gcc", "status": "passed", "level": "L1",
            "kernel_revision": MAPPING["kernel_revision"],
            "compiler": {"sha256": "a" * 64, "target": "x86_64-linux-gnu", "version": "fixture", "flags": []},
            "machdep": {"sha256": "b" * 64, "checked_fields": {}},
            "analysis": {"wp_model": "Typed", "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS),
                         "runtime_checks": {"pointer_formation": "object-or-null"}},
            "build": {key: "c" * 64 for key in ("config_sha256", "compilation_database_sha256",
                                               "autoconf_sha256", "build_receipt_sha256")}}

    def test_full_model_identity_rejects_missing_or_weakened_pointer_policy(self):
        model = self.policy_model()
        self.assertEqual(native.model_identity(model)["analysis"], model["analysis"])
        for runtime in (None, {}, {"pointer_formation": False}, {"pointer_formation": "disabled"},
                        {"pointer_formation": "object-or-null", "extra": True}):
            changed = copy.deepcopy(model)
            if runtime is None:
                changed["analysis"].pop("runtime_checks")
            else:
                changed["analysis"]["runtime_checks"] = runtime
            with self.subTest(runtime=runtime), self.assertRaises(ValueError):
                native.model_identity(changed)

    def test_analysis_binding_keeps_effective_pipeline_without_mutating_targets(self):
        model, targets = self.policy_model(), copy.deepcopy(TARGETS)
        bound = native.analysis_binding(model, targets)
        self.assertEqual(bound["model"], model["analysis"])
        self.assertEqual([row["target_id"] for row in bound["pipelines"]], [target["id"] for target in targets])
        self.assertEqual(bound["pipelines"][0]["pipeline"], analysis_policy.pipeline_identity(targets[0]))
        changed = copy.deepcopy(targets)
        changed[0]["analysis_pipeline"] = {"kind": "rte-eva"}
        self.assertNotEqual(native.analysis_binding(model, changed), bound)
        self.assertEqual(targets, TARGETS)
        for invalid in ([], None, [targets[0], targets[0]], [{**targets[0], "id": True}]):
            with self.assertRaises(NativeError):
                native.analysis_binding(model, invalid)

    def test_legacy_model_and_missing_or_changed_binding_fail_before_artifact_reads(self):
        model = self.policy_model()
        build = {"receipt_sha256": "c" * 64, "files": {}}
        path = (ROOT / "build/string-sensitivity/not-executed-policy-test/receipt.json").resolve()
        expected = {"schema_version": 1, "kind": "fragma-native-spec-sensitivity",
            "status": "native-corroborated", "corroborated": True, "kernel_revision": MAPPING["kernel_revision"],
            "profile_id": "x86_64-gcc", "issues": [], "changed_inputs": [], "verified_kernel_functions": [],
            "model": model, "build": build, "analysis_policy": native.analysis_binding(model, TARGETS),
            "host": {"machine": native.platform.machine(), "system": native.platform.system(),
                     "release": native.platform.release(), "byte_order": native.sys.byteorder}}
        mutations = [lambda row: row["model"]["analysis"].pop("runtime_checks"),
                     lambda row: row.pop("analysis_policy"),
                     lambda row: row["analysis_policy"].update(schema_version=True),
                     lambda row: row["analysis_policy"]["model"]["runtime_checks"].update(pointer_formation="disabled"),
                     lambda row: row["analysis_policy"]["pipelines"].pop(),
                     lambda row: row["analysis_policy"]["pipelines"][0]["pipeline"].update(kind="rte-eva")]
        original = Path.read_text
        for mutate in mutations:
            altered = copy.deepcopy(expected)
            mutate(altered)
            with self.subTest(mutation=mutations.index(mutate)), \
                    patch.object(Path, "read_text", lambda p, *a, **k: json.dumps(altered) if p == path else original(p, *a, **k)), \
                    patch.object(native.inputs, "run_recorded", side_effect=AssertionError("execution forbidden")), \
                    self.assertRaisesRegex(NativeError, "runtime-check policy|semantic/pipeline"):
                validate_native_receipt(ROOT, ROOT.parent / "linux", TARGETS[0], MAPPING["kernel_revision"], model, build, path)

    def test_insertions_preserve_original_driver_exactly(self):
        instrumented = self.generated.split("\n", 1)[1].split("\nint main(", 1)[0]
        self.assertEqual(INSERTION.sub("", instrumented), DRIVER)
        self.assertEqual(sum(len(rows) for rows in self.properties), 30)
        self.assertEqual(sum(row["expected"] for rows in self.properties for row in rows), 22)

    def test_changed_driver_requires_mapping_review(self):
        for changed in (DRIVER.replace("result == 6", "result == 5", 1),
                        DRIVER.replace("strlcat(dest, src, 5)", "strlcat(dest, src, 4)", 1),
                        DRIVER + "\n"):
            with self.subTest(change=changed[-60:]), self.assertRaises(NativeError):
                render_driver(changed, TARGETS, MAPPING)

    def test_missing_duplicate_or_reordered_properties_fail(self):
        for mutation in ("remove", "duplicate", "reorder"):
            targets = copy.deepcopy(TARGETS)
            names = targets[0]["required_properties"]
            if mutation == "remove":
                names.pop(0)
            elif mutation == "duplicate":
                names.insert(0, names[0])
            else:
                names[0], names[1] = names[1], names[0]
            with self.subTest(mutation=mutation), self.assertRaises(NativeError):
                render_driver(DRIVER, targets, MAPPING)

    def test_logical_validity_mapping_cannot_change_scope(self):
        for field, value in (("required_entry", TARGETS[0]["entry"]),
                             ("acsl", "\\valid_read(input + (0 .. 99))"),
                             ("c_expression", "system(0)")):
            mapping = copy.deepcopy(MAPPING)
            mapping["logical_mappings"][0][field] = value
            with self.subTest(field=field), self.assertRaises(NativeError):
                render_driver(DRIVER, TARGETS, mapping)

    def test_unused_logical_or_arbitrary_state_observer_fails(self):
        mapping = copy.deepcopy(MAPPING)
        mapping["logical_mappings"].append({**mapping["logical_mappings"][0], "name": "unused"})
        with self.assertRaises(NativeError):
            render_driver(DRIVER, TARGETS, mapping)
        mapping = copy.deepcopy(MAPPING)
        mapping["cases"][0]["state_call"] = "arbitrary_action();"
        with self.assertRaises(NativeError):
            render_driver(DRIVER, TARGETS, mapping)

    def test_observation_expressions_exclude_mutation_and_calls(self):
        for expression in ("result = 6", "dest[0]++", "system(0)", "result; exit(0)",
                           "sizeof(other_object)", "input += 1", "*(result = input)"):
            with self.subTest(expression=expression), self.assertRaises(NativeError):
                validate_expression(expression)

    def test_all_expected_native_observations_corroborate(self):
        for index in range(8):
            observed = self.validate(self.events(index), index)
            self.assertTrue(all(row["reached"] for row in observed))
            self.assertTrue(all(row["observed"] for row in observed[:-1]))
            self.assertIs(observed[-1]["observed"], False)

    def test_ordinary_process_failure_is_not_spec_refutation(self):
        for code in (1, 3, 64, -11, None, False, 0.0):
            with self.subTest(code=code), self.assertRaises(NativeError):
                self.validate(self.events(), returncode=code)
        with self.assertRaises(NativeError):
            self.validate(self.events(), stderr="runtime warning\n")

    def test_missing_reachability_or_normal_return_fails(self):
        events = self.events()
        for changed in ([], events[1:], events[:-1], events + [events[-1]], events[:2] + events[3:]):
            with self.subTest(length=len(changed)), self.assertRaises(NativeError):
                self.validate(changed)

    def test_wrong_positive_negative_name_or_state_fails(self):
        variants = []
        changed = self.events(); changed[2]["observed"] = False; variants.append(changed)
        changed = self.events(); changed[-2]["observed"] = True; variants.append(changed)
        changed = self.events(); changed[2]["name"] = "another_property"; variants.append(changed)
        changed = self.events(); changed[1]["dest"][0] = 100; variants.append(changed)
        for changed in variants:
            with self.subTest(events=changed[2]), self.assertRaises(NativeError):
                self.validate(changed)

    def test_json_type_confusion_and_duplicate_keys_fail(self):
        for field, value in (("result", 6.0), ("result", True)):
            changed = self.events(); changed[1][field] = value
            with self.assertRaises(NativeError):
                self.validate(changed)
        changed = self.events(); changed[1]["dest"][4] = False
        with self.assertRaises(NativeError):
            self.validate(changed)
        changed = self.events(); changed[-2]["observed"] = 0
        with self.assertRaises(NativeError):
            self.validate(changed)
        text = "\n".join(json.dumps(event) for event in self.events())
        for malformed in (text.replace('"result": 6', '"result": 6, "result": 6', 1),
                          text.replace('"result": 6', '"result": NaN', 1)):
            with self.assertRaises(NativeError):
                validate_events(malformed, TARGETS[0], MAPPING["cases"][0], self.properties[0], 0, "")

    def test_optional_actual_native_receipt_and_outputs(self):
        supplied = os.environ.get("FRAGMA_STRING_NATIVE_RESULTS")
        if not supplied:
            self.skipTest("set FRAGMA_STRING_NATIVE_RESULTS for fresh native evidence checks")
        output = Path(supplied)
        evidence = json.loads((output / "receipt.json").read_text())
        self.assertTrue(evidence["corroborated"], evidence["issues"])
        self.assertEqual(evidence["status"], "native-corroborated")
        self.assertEqual(evidence["verified_kernel_functions"], [])
        self.assertEqual(evidence["changed_inputs"], [])
        self.assertEqual(len(evidence["cases"]), 8)
        for item in evidence["bindings"] + evidence["tool_inputs"] + evidence["runtime_inputs"] + evidence["link_inputs"]:
            self.assertEqual(sha256(Path(item["path"])), item["sha256"], item["path"])
        for filename, digest in evidence["artifact_hashes"].items():
            self.assertEqual(sha256(output / filename), digest, filename)
        for index, case in enumerate(evidence["cases"]):
            stdout, stderr = case["process"]["stdout"], case["process"]["stderr"]
            observations = validate_events(Path(stdout["path"]).read_text(), TARGETS[index],
                MAPPING["cases"][index], self.properties[index], case["process"]["returncode"],
                Path(stderr["path"]).read_text())
            self.assertEqual(observations, case["properties"])

    def test_optional_validator_rechecks_current_inputs_and_rejects_tampering(self):
        supplied = os.environ.get("FRAGMA_STRING_NATIVE_RESULTS")
        if not supplied:
            self.skipTest("set FRAGMA_STRING_NATIVE_RESULTS for validator integration")
        output = Path(supplied).resolve()
        receipt = output / "receipt.json"
        evidence = json.loads(receipt.read_text())
        revision = MAPPING["kernel_revision"]
        model = json.loads(Path(evidence["profile_receipt"]["path"]).read_text())
        build = load_build(ROOT, "x86_64-gcc", revision)
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))

        def validate(target=TARGETS[0], actual_model=model):
            return validate_native_receipt(ROOT, kernel, target, revision, actual_model, build, receipt)

        for target in TARGETS:
            envelope = validate(target)
            self.assertEqual(envelope["status"], "passed")
            self.assertEqual(envelope["kind"], "native-specification-calibration")
            self.assertIs(envelope["properties"][-1]["observed"], False)
            self.assertTrue(envelope["tracked_files"])
            self.assertEqual(envelope["analysis_policy"], native.analysis_binding(model, TARGETS))
            self.assertIn(str(Path(analysis_policy.__file__).resolve()), [row["absolute_path"] for row in envelope["tracked_files"]])
        changed_target = copy.deepcopy(TARGETS[0]); changed_target["profile"] = "s390x-gcc"
        with self.assertRaises(NativeError):
            validate(changed_target)
        changed_model = copy.deepcopy(model); changed_model["machdep"]["sha256"] = "0" * 64
        with self.assertRaises(NativeError):
            validate(actual_model=changed_model)
        original_read = Path.read_text
        for mutation in ("nonboolean", "line", "binary", "hash", "missing", "command", "original-command",
                         "empty-kernel", "missing-tool", "host", "adapter-hash", "case-status", "closure",
                         "deviations", "metadata-type", "gate-boolean", "model-boolean",
                         "missing-pointer-policy", "weak-pointer-policy", "missing-policy-binding", "wrong-pipeline",
                         "missing-policy-helper", "changed-policy-helper"):
            changed = copy.deepcopy(evidence)
            if mutation == "nonboolean":
                changed["corroborated"] = 1
            elif mutation == "line":
                changed["cases"][0]["properties"][0]["line"] += 1
            elif mutation == "binary":
                changed["binary"]["path"] = str(ROOT / "wrong-binary")
            elif mutation == "hash":
                changed["artifact_hashes"]["case-0.stdout"] = "0" * 64
            elif mutation == "missing":
                changed["cases"].pop()
            elif mutation == "command":
                changed["commands"][4]["argv"].append("-fno-unsigned-char")
            elif mutation == "original-command":
                changed["original_compile_command"] = {}
            elif mutation == "empty-kernel":
                changed["kernel_inputs"] = []
            elif mutation == "missing-tool":
                changed["tool_inputs"].pop()
            elif mutation == "host":
                changed["host"]["machine"] = "s390x"
            elif mutation == "adapter-hash":
                changed["adapter"]["sha256"] = "0" * 64
            elif mutation == "case-status":
                changed["cases"][0]["status"] = "incomplete"
            elif mutation == "closure":
                changed["source_gate_before_compile"] = {}
            elif mutation == "deviations":
                changed["native_deviations"]["kernel_added_flags"] = []
            elif mutation == "metadata-type":
                changed["cases"][0]["state"]["result"] = 6.0
            elif mutation == "gate-boolean":
                changed["cases"][0]["source_gate"]["passed"] = 1
            elif mutation == "model-boolean":
                changed["model"]["machdep"]["checked_fields"]["little_endian"] = 1
            elif mutation == "missing-pointer-policy":
                changed["model"]["analysis"].pop("runtime_checks")
            elif mutation == "weak-pointer-policy":
                changed["model"]["analysis"]["runtime_checks"]["pointer_formation"] = "disabled"
            elif mutation == "missing-policy-binding":
                changed.pop("analysis_policy")
            elif mutation == "wrong-pipeline":
                changed["analysis_policy"]["pipelines"][0]["pipeline"]["kind"] = "rte-eva"
            elif mutation == "missing-policy-helper":
                changed["bindings"] = [row for row in changed["bindings"] if row["path"] != str(Path(analysis_policy.__file__).resolve())]
            elif mutation == "changed-policy-helper":
                next(row for row in changed["bindings"] if row["path"] == str(Path(analysis_policy.__file__).resolve()))["sha256"] = "0" * 64

            def intercepted(path, *args, **kwargs):
                return json.dumps(changed) if path == receipt else original_read(path, *args, **kwargs)

            with self.subTest(mutation=mutation), patch.object(Path, "read_text", intercepted), self.assertRaises(NativeError):
                validate()


if __name__ == "__main__":
    unittest.main()
