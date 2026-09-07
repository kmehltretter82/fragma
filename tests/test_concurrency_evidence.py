from pathlib import Path
import tempfile
import unittest

from fragma import concurrency_evidence


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyEvidenceTests(unittest.TestCase):
    def test_registries_cover_every_c0_case_and_required_dimension(self):
        models, targets, c0 = concurrency_evidence.load_registries(ROOT)
        self.assertEqual(len(models["models"]), 1)
        self.assertEqual(len(targets["targets"]), len(c0["cases"]))
        self.assertEqual(
            set(models["models"][0]["dimensions"]),
            concurrency_evidence.REQUIRED_DIMENSIONS,
        )
        self.assertFalse(any(target["kernel_scope"] for target in targets["targets"]))

    def test_identity_drift_is_dependency_specific(self):
        expected = {
            "core": {"sha256": "a", "size": 1},
            "pthread": {"sha256": "b", "size": 2},
            "interrupt": {"sha256": "c", "size": 3},
        }
        current = {
            **expected,
            "pthread": {"sha256": "changed", "size": 2},
        }
        self.assertEqual(
            concurrency_evidence.identity_drift(expected, current, ["core", "interrupt"]),
            [],
        )
        self.assertEqual(
            concurrency_evidence.identity_drift(expected, current, ["core", "pthread"]),
            ["pthread"],
        )

    def test_calibrated_or_partial_support_never_becomes_verification(self):
        models, targets, _ = concurrency_evidence.load_registries(ROOT)
        model = models["models"][0]
        target = next(item for item in targets["targets"] if item["id"] == "mutex")
        decision = concurrency_evidence.acceptance_decision(target, model, True)
        self.assertTrue(decision["calibration_accepted"])
        self.assertFalse(decision["verification_accepted"])
        self.assertIn("calibrated", {item["status"] for item in decision["blocking_support"]})

    def test_unsupported_join_remains_an_explicit_blocker(self):
        models, targets, _ = concurrency_evidence.load_registries(ROOT)
        model = models["models"][0]
        target = next(item for item in targets["targets"] if item["id"] == "join")
        decision = concurrency_evidence.acceptance_decision(target, model, True)
        self.assertIn(
            {"kind": "primitive", "name": "pthread_join", "status": "unsupported"},
            decision["blocking_support"],
        )

    def test_verification_requires_every_dependency_to_be_supported(self):
        target = {
            "evidence_kind": "verification",
            "required_dimensions": ["sequential"],
            "required_primitives": ["lock"],
        }
        model = {
            "dimensions": {"sequential": {"status": "supported"}},
            "primitive_models": {"lock": {"status": "supported"}},
        }
        self.assertTrue(
            concurrency_evidence.acceptance_decision(target, model, True)
            ["verification_accepted"]
        )
        model["primitive_models"]["lock"]["status"] = "not_assessed"
        self.assertFalse(
            concurrency_evidence.acceptance_decision(target, model, True)
            ["verification_accepted"]
        )

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(concurrency_evidence.ConcurrencyEvidenceError,
                                        "already exists"):
                concurrency_evidence.audit_c1(
                    ROOT, ROOT / "results/concurrency-c0-20260907-05",
                    Path(temporary),
                )


if __name__ == "__main__":
    unittest.main()
