"""Read-back wiring tests; mock inventories are not analyzer evidence."""

import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma import common24, integrity, replay, suite


ROOT = Path(__file__).resolve().parents[1]


class Common24ReadbackTests(unittest.TestCase):
    def setUp(self):
        _, targets, _ = suite.load_registry(ROOT)
        self.target = targets["common.unaligned24.arm"]
        self.source = common24.check_source(self.target,
            source_path=ROOT / self.target["harness"],
            source_text=(ROOT / self.target["harness"]).read_text(),
            strategy_text=(ROOT / self.target["wp_strategy_file"]).read_text())
        # The real exporter and every omission are exercised separately by
        # test_common24. Here the mock isolates caller identity/policy wiring.
        self.inventory = {"schema_version": 1, "inventory": common24.INVENTORY,
            "status": "complete", "ordinary_complete": True, "issues": [], "source": self.source}
        self.evaluation = {"accepted": False, "verified": False, "local_policy_passed": False,
                           "status": "unsupported", "issues": [{"kind": "unsupported", "message": "unreviewed warning"}]}
        self.evidence = {"common24_source": copy.deepcopy(self.source),
            "common24_inventory": copy.deepcopy(self.inventory),
            "integrity_inputs": [integrity.receipt(ROOT / self.target[field])
                                 for field in ("harness", "wp_strategy_file")],
            "validated_review": None}
        self.shared = {str(ROOT / "fragma/common24.py"): integrity.sha256(ROOT / "fragma/common24.py")}

    def observe(self):
        with patch.object(common24, "evaluate_inventory", return_value=self.inventory) as check:
            result = replay.common24_observation(ROOT, self.target, self.evidence,
                [{"raw": "all goal rows"}], [{"raw": "all property rows"}], self.evaluation, self.shared)
            self.assertEqual(check.call_args.args[1:3],
                             ([{"raw": "all goal rows"}], [{"raw": "all property rows"}]))
            self.assertEqual(check.call_args.kwargs["source_text"], (ROOT / self.target["harness"]).read_text())
            return result

    def test_complete_inventory_does_not_approve_generic_warnings(self):
        evaluation, observed = self.observe()
        self.assertEqual(evaluation, self.evaluation)
        self.assertFalse(evaluation["accepted"])
        self.assertEqual(observed, self.inventory)

    def test_missing_implementation_identity_is_not_backfilled(self):
        self.shared.clear()
        with self.assertRaisesRegex(replay.ReplayError, "implementation"):
            self.observe()

    def test_harness_and_strategy_bindings_must_match_current_read_bytes(self):
        for index in (0, 1):
            before = copy.deepcopy(self.evidence["integrity_inputs"])
            self.evidence["integrity_inputs"][index]["sha256"] = "0" * 64
            with self.subTest(index=index), self.assertRaisesRegex(replay.ReplayError, "source/strategy"):
                self.observe()
            self.evidence["integrity_inputs"] = before

    def test_saved_source_and_inventory_must_match_rederived_records(self):
        for field in ("common24_source", "common24_inventory"):
            before = copy.deepcopy(self.evidence[field])
            self.evidence[field]["schema_version"] = True
            with self.subTest(field=field), self.assertRaisesRegex(replay.ReplayError, "saved common24"):
                self.observe()
            self.evidence[field] = before

    def test_reviews_bind_inventory_implementation_too(self):
        self.evidence["validated_review"] = {"review_context": {"file_hashes": {"fragma/common24.py": "0" * 64}}}
        with self.assertRaisesRegex(replay.ReplayError, "review does not bind"):
            self.observe()

    def test_incomplete_inventory_blocks_otherwise_green_generic_evaluation(self):
        self.evaluation.update(accepted=True, verified=True, local_policy_passed=True, status="passed", issues=[])
        self.inventory.update(status="incomplete", ordinary_complete=False, issues=["missing required goal"])
        self.evidence["common24_inventory"] = copy.deepcopy(self.inventory)
        evaluation, _ = self.observe()
        self.assertEqual(evaluation["status"], "incomplete")
        self.assertFalse(evaluation["accepted"])
        self.assertFalse(evaluation["verified"])
        self.assertIn("missing required goal", evaluation["issues"][0]["inventory_issues"])

    def test_legacy_without_envelope_is_not_a_checked_common24_observation(self):
        result = replay.common24_observation(ROOT, {}, {}, [], [], self.evaluation, {})
        self.assertEqual(result, (self.evaluation, None))
        with self.assertRaisesRegex(replay.ReplayError, "no declared"):
            replay.common24_observation(ROOT, {}, self.evidence, [], [], self.evaluation, {})


if __name__ == "__main__":
    unittest.main()
