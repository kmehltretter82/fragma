"""Proof progress must not mistake tactical/smoke success for certification."""
import unittest

from s390.prove import progress


class S390ProofProgressTests(unittest.TestCase):
    def setUp(self):
        self.target = {"functions": ["helper"], "required_properties": ["exact"]}
        self.goals = [{"function": "helper", "property": "exact", "smoke": False,
                       "verdict": "valid", "passed": True}]
        self.properties = [{"function": "helper", "status": "Valid"}]

    def test_complete_local_proofs_still_do_not_certify_profile(self):
        result = progress(self.target, self.goals, self.properties)
        self.assertTrue(result["ordinary_complete"])
        self.assertFalse(result["certified"])

    def test_strategy_unknown_parent_is_not_success(self):
        self.goals[0].update(verdict="unknown", passed=False)
        self.assertFalse(progress(self.target, self.goals, self.properties)["ordinary_complete"])

    def test_missing_named_property_cannot_be_replaced_by_assigns(self):
        self.goals[0]["property"] = "assigns"
        result = progress(self.target, self.goals, self.properties)
        self.assertFalse(result["ordinary_complete"])
        self.assertEqual(result["missing_properties"], ["exact"])

    def test_conditional_callee_dependency_blocks_roundtrip_claim(self):
        self.properties[0]["status"] = "Unknown"
        self.assertFalse(progress(self.target, self.goals, self.properties)["ordinary_complete"])

    def test_smoke_timeout_is_not_an_ordinary_goal(self):
        self.goals[0].update(smoke=True, verdict="timeout", passed=True)
        self.assertFalse(progress(self.target, self.goals, self.properties)["ordinary_complete"])

    def test_missing_source_function_blocks_partial_group(self):
        self.target["functions"].append("other_helper")
        result = progress(self.target, self.goals, self.properties)
        self.assertFalse(result["ordinary_complete"])
        self.assertEqual(result["missing_functions"], ["other_helper"])


if __name__ == "__main__":
    unittest.main()
