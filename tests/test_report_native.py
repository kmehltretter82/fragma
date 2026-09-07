"""Independent native evidence disambiguates only a reached false specification."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from fragma.report import evaluate_target


class NativeReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = {"id": "calibration.example", "profile": "checked-x86", "source": "lib/helper.c",
                       "driver": "driver.c", "functions": ["helper"], "entry": "driver",
                       "analysis": "eva", "role": "calibration", "claims": [],
                       "required_properties": ["positive", "false_spec"], "expected_invalid": ["false_spec"]}
        self.properties = [self.property("helper", "internal", 1, "Valid"),
                           self.property("driver", "positive", 3, "Valid"),
                           self.property("driver", "false_spec", 4, "Invalid or unreachable")]
        self.envelope = {"status": "passed", "kind": "native-specification-calibration",
                         "target_id": self.target["id"], "profile": self.target["profile"],
                         "source": self.target["source"], "entry": self.target["entry"],
                         "kernel_revision": "a" * 40, "source_root": str(self.root),
                         "target_sha256": hashlib.sha256(json.dumps(self.target, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                         "receipt": {"path": str(self.root / "native/receipt.json"), "sha256": "b" * 64},
                         "properties": [{"name": name, "file": "driver.c", "line": line,
                            "function": "driver", "acsl": expression, "native_expression": expression,
                            "expected": expected, "observed": expected, "reached": True}
                            for name, line, expression, expected in (("positive", 3, "result == 6", True),
                                                                     ("false_spec", 4, "result == 4", False))]}

    def property(self, function, name, line, status):
        return {"path": str(self.root / "driver.c"), "file": "driver.c", "line": line,
                "function": function, "kind": "user assertion", "status": status,
                "property": name, "names": [name]}

    def evaluate(self, envelope=True, **kwargs):
        return evaluate_target(kwargs.get("target", self.target), [], self.properties,
                               returncode=kwargs.get("returncode", 0), warnings=kwargs.get("warnings", []),
                               validated_native=self.envelope if envelope else None)

    def test_ambiguous_eva_alone_is_not_invalidity_evidence(self):
        result = self.evaluate(envelope=False)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["confirmed_invalid_properties"], [])

    def test_native_corroboration_keeps_raw_eva_status_and_never_proves_kernel(self):
        original = copy.deepcopy(self.properties)
        result = self.evaluate()
        self.assertTrue(result["accepted"], result["issues"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "calibration-passed")
        self.assertEqual(result["confirmed_invalid_properties"], ["false_spec"])
        self.assertEqual(result["counts"]["properties"]["unreachable"], 1)
        self.assertEqual(result["native_invalid_properties"][0]["property_record"]["status"], "Invalid or unreachable")
        self.assertFalse(result["native_invalid_properties"][0]["kernel_defect_evidence"])
        self.assertEqual(self.properties, original)

    def test_native_result_never_masks_failed_positive_or_internal_dependency(self):
        for index in (0, 1):
            old = self.properties[index]["status"]
            self.properties[index]["status"] = "Unknown"
            self.assertFalse(self.evaluate()["accepted"])
            self.properties[index]["status"] = old

    def test_native_cannot_replace_missing_unknown_valid_or_dead_negative(self):
        for status in ("Unknown", "Valid", "Dead", "Partially proven"):
            with self.subTest(status=status):
                self.properties[-1]["status"] = status
                self.assertFalse(self.evaluate()["accepted"])
        self.properties.pop()
        self.assertFalse(self.evaluate()["accepted"])

    def test_native_cannot_override_tool_error_or_unsupported_warning(self):
        self.assertFalse(self.evaluate(returncode=1)["accepted"])
        self.assertFalse(self.evaluate(warnings=[{"plugin": "eva", "severity": "unsupported", "message": "Unsupported operation"}])["accepted"])

    def test_mismatched_target_identity_rejected(self):
        for field, value in (("status", "unverified"), ("target_id", "different"), ("entry", "other"),
                             ("source", "lib/other.c"), ("profile", "other"), ("target_sha256", "c" * 64)):
            old = self.envelope[field]
            with self.subTest(field=field):
                self.envelope[field] = value
                self.assertFalse(self.evaluate()["accepted"])
            self.envelope[field] = old

    def test_missing_boolean_reachability_or_exact_assertion_identity_rejected(self):
        observation = self.envelope["properties"][-1]
        for field, value in (("observed", True), ("observed", 0), ("reached", False), ("reached", 1),
                             ("line", 5), ("file", "other.c"), ("function", "helper"),
                             ("acsl", ""), ("native_expression", "")):
            old = observation[field]
            with self.subTest(field=field, value=value):
                observation[field] = value
                self.assertFalse(self.evaluate()["accepted"])
            observation[field] = old

    def test_duplicate_or_incomplete_observation_lists_rejected(self):
        good = self.envelope["properties"]
        for rows in (good[:-1], [*good, good[-1]], list(reversed(good))):
            self.envelope["properties"] = rows
            self.assertFalse(self.evaluate()["accepted"])

    def test_unrelated_invalid_row_cannot_be_waived(self):
        self.properties.append(self.property("driver", "unrelated", 5, "Invalid or unreachable"))
        self.assertFalse(self.evaluate()["accepted"])

    def test_native_observations_cannot_certify_proof_role(self):
        self.assertFalse(self.evaluate(target={**self.target, "role": "proof"})["accepted"])

    def test_standalone_calibration_uses_exact_harness_assertion_source(self):
        self.target["harness"] = self.target.pop("driver")
        self.envelope["target_sha256"] = hashlib.sha256(json.dumps(
            self.target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        result = self.evaluate()
        self.assertTrue(result["accepted"], result["issues"])
        self.assertFalse(result["verified"])

    def test_declared_driver_cannot_fall_back_to_harness(self):
        self.target.update(harness="driver.c", driver="different-driver.c")
        self.envelope["target_sha256"] = hashlib.sha256(json.dumps(
            self.target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertFalse(self.evaluate()["accepted"])


if __name__ == "__main__":
    unittest.main()
