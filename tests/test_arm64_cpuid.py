"""Scoped ARM64 scalar review; functional/caller coverage is not inferred."""

import json
import os
from pathlib import Path
import unittest

from fragma import integrity, provenance, report, sources, suite

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "config/arm64-cpuid-targets.json").read_text())
TARGET = MANIFEST["targets"][0]


class Arm64CpuidTests(unittest.TestCase):
    def test_registered_once_with_original_identity_and_limited_claim(self):
        _, targets, assumptions = suite.load_registry(ROOT)
        self.assertEqual(targets["arm64.cpuid"], TARGET)
        self.assertEqual(sum(target["id"] == "arm64.cpuid" for target in targets.values()), 1)
        self.assertEqual(TARGET["claims"], ["runtime-safety"])
        self.assertEqual(TARGET["caller_coverage"], "historical-manual-review")
        self.assertEqual(TARGET["profile"], "arm64-gcc")
        self.assertEqual(TARGET["analysis"], "wp")
        self.assertEqual(TARGET["role"], "proof")
        self.assertNotIn("expected_invalid", TARGET)
        self.assertNotIn("expected_unresolved", TARGET)
        for name in TARGET["assumptions"]:
            self.assertEqual(assumptions[name]["review_status"], "reviewed-assumption")
            self.assertIs(assumptions[name]["implementation_proved"], False)

    def test_original_harness_and_complete_contract_domains_are_unchanged(self):
        harness = ROOT / TARGET["harness"]
        self.assertEqual(sources.sha256(harness),
                         "0642417abb3e112498f8779ca60bb9788409160a2669d7a28f297b8fab0bc41a")
        source = harness.read_text()
        self.assertEqual(source.count("requires width_pos:   width >= 1;"), 2)
        self.assertEqual(source.count("requires field_pos:   field >= 0;"), 2)
        self.assertEqual(source.count("requires fits:        field + width <= 64;"), 2)
        self.assertNotIn("width <= 32", source)

    def test_each_exact_scalar_body_has_no_calls_or_memory_access(self):
        source = (ROOT / TARGET["harness"]).read_text()
        self.assertEqual(len(TARGET["functions"]), 2)
        self.assertEqual(len(TARGET["required_properties"]), 2)
        for name in TARGET["functions"]:
            tokens = provenance.extract_function(source, name).tokens
            body = tokens[tokens.index("{") + 1:]
            self.assertEqual(body.count("return"), 1)
            self.assertFalse(set(body) & {"*", "[", "->", "for", "while", "goto", "asm"})
            self.assertEqual(TARGET["required_properties"].count(name + "_assigns"), 1)

    def test_real_header_fixture_keeps_exact_attributed_signatures(self):
        fixture = ROOT / TARGET["kernel_model_check"]
        self.assertEqual(sources.sha256(fixture),
                         "f8988e753cabcd7042a0a8fa5cfba748568a23e30209f29c2703837a1f438191")
        source = fixture.read_text()
        self.assertIn("#include <linux/types.h>", source)
        self.assertIn("#include <asm/cpufeature.h>", source)
        self.assertNotIn("typedef unsigned long long u64", source)
        for text in ("exact u64 substitution", "exact s64 substitution",
                     "actual signed helper signature", "actual unsigned helper signature",
                     "signed high-bit conversion", "s64 arithmetic right shift",
                     "signed return narrowing", "unsigned return narrowing",
                     "exact always-inline expansion", "exact const attribute expansion"):
            self.assertIn(text, source)
        self.assertIn("typedef int (*signed_field_fn)(u64, int, int) __attribute_const__;", source)

    def test_scoped_reviews_bind_current_inputs_and_do_not_waive_smoke(self):
        context = TARGET["review_context"]
        self.assertEqual(context["kernel_revision"], MANIFEST["kernel_revision"])
        self.assertEqual(context["profile"], TARGET["profile"])
        self.assertEqual(context["toolchain_lock_sha256"], sources.sha256(ROOT / "toolchain/lock.json"))
        self.assertEqual(TARGET["reviewed_smoke"], [])
        self.assertEqual(len(TARGET["reviewed_warnings"]), 4)
        for filename, expected in context["file_hashes"].items():
            self.assertEqual(sources.sha256(ROOT / filename), expected, filename)
        for warning in TARGET["reviewed_warnings"]:
            self.assertEqual(warning["functions"], TARGET["functions"])
            self.assertEqual(warning["file_hashes"], context["file_hashes"])
            self.assertEqual(warning["plugin"], "wp")
            self.assertEqual(warning["severity"], "warning")
            self.assertTrue(warning["reason"].strip())
            self.assertTrue(warning["review_evidence"])
        for assumption in MANIFEST["assumptions"]:
            self.assertTrue(assumption["kernel_files"])
            for name in assumption["files"] + assumption["review_evidence"]:
                self.assertTrue((ROOT / name).is_file(), name)

    def test_bodies_and_declarators_match_pinned_kernel(self):
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))
        if not (kernel / ".git").exists():
            self.skipTest("set FRAGMA_KERNEL_TREE for pinned-source integration")
        gate = provenance.check_target(TARGET, kernel, MANIFEST["kernel_revision"], ROOT)
        self.assertTrue(gate["passed"], gate["errors"])
        self.assertEqual(len(gate["functions"]), 2)
        self.assertTrue(all(not row["declaration_prefix_equal"] for row in gate["functions"]))

    @unittest.skipUnless(os.environ.get("FRAGMA_ARM64_CPUID_RESULTS"),
                         "supply a fresh integrated ARM64 cpuid target directory")
    def test_integrated_raw_proof_and_dependencies_pass_all_gates(self):
        directory = Path(os.environ["FRAGMA_ARM64_CPUID_RESULTS"])
        result = json.loads((directory / "result.json").read_text())
        self.assertEqual(result["target"], TARGET)
        self.assertEqual(result["status"], "passed")
        self.assertIs(result["accepted"], True)
        self.assertEqual(result["evaluation"]["counts"],
                         {"goals": {"valid": 6}, "properties": {"valid": 10}})
        self.assertEqual(result["evaluation"]["issues"], [])
        self.assertEqual(result["evaluation"]["unresolved_dependencies"], [])
        self.assertFalse(integrity.changed_files(result["integrity_inputs"]))
        goals = report.parse_wp_report(directory / "wp.json")
        self.assertEqual(len([goal for goal in goals if not goal["smoke"]]), 6)
        self.assertTrue(all(goal["verdict"] == "valid" for goal in goals if not goal["smoke"]))
        self.assertIs(result["evaluation"]["smoke"]["consistency_proved"], False)


if __name__ == "__main__":
    unittest.main()
