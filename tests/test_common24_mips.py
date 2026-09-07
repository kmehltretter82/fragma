"""Registered MIPS32el common24 scope and review boundaries; no processes."""
import json
from pathlib import Path
import unittest

from fragma import analysis_policy, common24, common24_calibration
from fragma import frontend_policy, profiles, sources, suite


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config/common-byte-mips-targets.json"
TARGET_ID = "common.unaligned24.mips32el"
PROFILE = "mips32el-clang"
ASSUMPTIONS = {"common24-mips-types", "common24-mips-frontend"}
REVIEW = "common/REVIEW-MIPS32EL-20260907.md"


class MIPSCommon24Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.revision, cls.registry, cls.ledger = suite.load_registry(ROOT)
        cls.target = cls.registry[TARGET_ID]
        cls.profile = profiles.load_profiles(ROOT)[PROFILE]

    def test_one_exact_registered_target_and_no_cross_profile_inheritance(self):
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(manifest["kernel_revision"], self.revision)
        self.assertEqual([(row["id"], row["profile"])
                          for row in manifest["targets"]], [(TARGET_ID, PROFILE)])
        self.assertEqual({row["id"] for row in manifest["assumptions"]}, ASSUMPTIONS)
        old = set()
        for name in ("common-byte-targets.json", "common-byte-wave2-targets.json",
                     "common-byte-wave3-targets.json"):
            old.update(row["id"] for row in
                       json.loads((ROOT / "config" / name).read_text())["assumptions"])
        self.assertTrue(ASSUMPTIONS.isdisjoint(old))
        self.assertEqual(set(self.target["assumptions"]), ASSUMPTIONS)

    def test_target_is_the_closed_common24_wp_scope(self):
        common24.check_target(self.target)
        self.assertEqual(self.target["suite"], "extended")
        self.assertEqual(self.target["role"], "proof")
        self.assertEqual(self.target["analysis"], "wp")
        self.assertEqual(self.target["frontend_policy"], {
            "schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"})
        self.assertEqual(frontend_policy.cpp_arguments(self.target),
                         ["-DFRAGMA_COMMON24_INLINE_POLICY=1"])
        self.assertEqual(self.target["compiler_calibration"], {
            "kind": "common24-fixed22", "source": common24_calibration.SOURCE})
        self.assertIs(self.target["require_smoke"], True)
        self.assertEqual(self.target["reviewed_smoke"], [])

    def test_review_is_current_mips_only_and_explicitly_nonimplementation(self):
        for name in self.target["assumptions"]:
            row = self.ledger[name]
            self.assertEqual(row["review_status"], "reviewed-assumption")
            self.assertIs(row["implementation_proved"], False)
            self.assertEqual(row["reviewed_profiles"], [PROFILE])
            self.assertEqual(row["review_evidence"], [REVIEW,
                "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/result.json",
                "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/compiler-calibration/receipt.json",
                "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/compiler-controls/receipt.json"])
            self.assertIn("not a human approval", row["reviewed_by"])

    def test_review_context_matches_current_declared_policies_and_hashes(self):
        context = self.target["review_context"]
        self.assertEqual(context["kernel_revision"], self.revision)
        self.assertEqual(context["profile"], PROFILE)
        self.assertEqual(context["analysis"],
                         analysis_policy.model_identity(self.profile["analysis"]))
        self.assertEqual(context["analysis_pipeline"],
                         analysis_policy.pipeline_identity(self.target))
        self.assertEqual(context["compiler_calibration"],
                         common24_calibration.review_identity(self.target))
        self.assertEqual(context["preprocessing"]["frontend_policy"],
                         frontend_policy.identity(self.target))
        self.assertEqual(context["review_evidence"], [REVIEW,
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/result.json",
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/analysis.log",
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/audit.json",
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/wp.json",
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/properties.tsv",
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/compiler-calibration/receipt.json",
            "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/compiler-controls/receipt.json"])
        for filename in context["review_evidence"]:
            self.assertEqual(context["file_hashes"][filename],
                             sources.sha256(ROOT / filename))
        self.assertEqual(len([name for name in context["file_hashes"]
                              if name.endswith(".yaml")]), 1)

    def test_exact_five_warning_reviews_cover_all_selected_functions(self):
        reviews = self.target["reviewed_warnings"]
        self.assertEqual(len(reviews), 5)
        self.assertEqual({row["message"] for row in reviews}, {
            "Ignoring unknown attribute: __gnu_inline__",
            "Skipped RTE guards: unaligned pointers (\\aligned not supported)",
            "Skipped RTE guards: invalid function pointer calls (\\valid_function not supported)",
            "-wp-rte can annotate signed overflow because -warn-signed-overflow is not set",
            "Missing RTE guards",
        })
        expected = set(self.target["analysis_functions"])
        for row in reviews:
            self.assertEqual(set(row["functions"]), expected)
            self.assertEqual(row["severity"], "warning")
            self.assertEqual(row["review_evidence"], [REVIEW,
                "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/result.json",
                "build/common24-mips-l2-initial-20260907/run-7/common.unaligned24.mips32el/analysis.log"])
            self.assertIn("not a human approval", row["reviewed_by"])


if __name__ == "__main__":
    unittest.main()
