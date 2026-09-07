"""Seven encoder inventory/source gates; proof outcomes are measured separately."""
import json
import os
from pathlib import Path
import re
import unittest

from fragma.provenance import check_target, extract_function, tokenize
from fragma.sources import sha256

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "config/riscv-targets.json").read_text())
TARGET = MANIFEST["targets"][0]


class RiscvEncoderTests(unittest.TestCase):
    def test_exactly_seven_kernel_helpers_not_twelve(self):
        self.assertEqual(set(TARGET["functions"]), {"rv_" + kind + "_insn" for kind in ("r", "i", "s", "b", "u", "j", "amo")})
        self.assertEqual(len(TARGET["project_functions"]), 5)
        self.assertEqual(set(TARGET["analysis_functions"]), set(TARGET["functions"] + TARGET["project_functions"]))
        self.assertFalse(set(TARGET["functions"]) & set(TARGET["project_functions"]))

    def test_source_and_witness_definitions_are_unique(self):
        source = (ROOT / TARGET["harness"]).read_text()
        for name in TARGET["analysis_functions"]:
            self.assertTrue(extract_function(source, name).tokens)
        self.assertNotRegex(source, r"\baxiom(?:atic)?\b\s+[A-Za-z_]")

    def test_all_immediate_values_remain_in_contract_domain(self):
        source = (ROOT / TARGET["harness"]).read_text()
        requires = re.findall(r"\brequires\b[^;]*;", source)
        self.assertTrue(requires)
        self.assertTrue(all("imm" not in clause for clause in requires))
        self.assertIn("(imm11_0 & 4095)", source)
        self.assertIn("(imm31_12 & 1048575)", source)

    def test_assumptions_and_real_kernel_fixture_are_present(self):
        assumptions = {record["id"]: record for record in MANIFEST["assumptions"]}
        fixture = (ROOT / TARGET["kernel_model_check"]).read_text()
        for name in ("u8", "u16", "u32"):
            self.assertIn("__builtin_types_compatible_p(" + name, fixture)
        for name in TARGET["assumptions"]:
            record = assumptions[name]
            self.assertTrue(record["kernel_files"])
            for filename in record["files"] + record["review_evidence"]:
                self.assertTrue((ROOT / filename).is_file(), filename)

    def test_every_helper_has_required_functional_property(self):
        required = TARGET["required_properties"]
        self.assertEqual(len(required), len(set(required)))
        for name in TARGET["analysis_functions"]:
            self.assertTrue(any(prop.startswith(name + "_ensures_") for prop in required), name)
        self.assertEqual(TARGET["profile"], "riscv64-gcc")
        self.assertEqual(TARGET["role"], "proof")
        self.assertNotIn("expected_invalid", TARGET)
        self.assertNotIn("expected_unresolved", TARGET)

    def test_promoted_harness_preserves_all_original_contracts_and_c_tokens(self):
        original = (ROOT / "riscv/annotated/base-encoders.verified.c").read_text()
        promoted = (ROOT / TARGET["harness"]).read_text()
        include = '\n#include "encoder-fieldproof.h"\n'
        self.assertEqual(promoted, original + include)
        for name in TARGET["analysis_functions"]:
            self.assertEqual(extract_function(promoted, name), extract_function(original, name))

    def test_strategy_is_comment_only_checked_and_has_bounded_search(self):
        source = (ROOT / TARGET["wp_strategy_file"]).read_text()
        sentinel = "int fragma_strategy_token_sentinel;"
        self.assertEqual(tokenize(source + sentinel), tokenize(sentinel))
        self.assertNotRegex(source, r"\baxiom(?:atic)?\b\s+[A-Za-z_]")
        self.assertIn('\\tactic("Wp.bitwised", \\incontext((_ & _) == _)', source)
        self.assertIn('\\tactic("Wp.bitwised", \\incontext((_ >> _) == _)', source)
        self.assertIn('\\tactic("Wp.bittestrange"', source)
        self.assertNotIn('\\incontext(_ == _)', source)
        self.assertEqual(TARGET["wp_strategy_provers"], ["alt-ergo", "z3"])
        self.assertEqual(TARGET["wp_auto_depth"], 32)
        self.assertEqual(TARGET["wp_smoke_timeout"], 2)

    def test_exact_scoped_warning_reviews_preserve_smoke_uncertainty(self):
        self.assertEqual(TARGET["reviewed_smoke"], [])
        context = TARGET["review_context"]
        self.assertEqual(context["kernel_revision"], MANIFEST["kernel_revision"])
        self.assertEqual(context["profile"], TARGET["profile"])
        self.assertEqual(context["toolchain_lock_sha256"], sha256(ROOT / "toolchain/lock.json"))
        for filename, expected in context["file_hashes"].items():
            self.assertEqual(sha256(ROOT / filename), expected, filename)
        self.assertEqual(len(TARGET["reviewed_warnings"]), 5)
        for record in TARGET["reviewed_warnings"]:
            self.assertEqual(set(record["functions"]), set(TARGET["analysis_functions"]))
            self.assertEqual(record["severity"], "warning")
            self.assertTrue(record["reason"].strip())
            self.assertTrue(record["review_evidence"])
            for filename, expected in record["file_hashes"].items():
                self.assertEqual(context["file_hashes"][filename], expected)

    def test_all_six_direct_call_dependencies_are_selected(self):
        source = (ROOT / TARGET["harness"]).read_text()
        graph = {}
        for name in TARGET["analysis_functions"]:
            tokens = extract_function(source, name).tokens
            body = tokens[tokens.index("{") + 1:]
            graph[name] = {token for index, token in enumerate(body[:-1])
                           if token in TARGET["analysis_functions"] and body[index + 1] == "("}
        self.assertEqual(graph["rv_amo_insn"], {"rv_r_insn"})
        for kind in ("i", "s", "b", "u", "j"):
            self.assertEqual(graph["fragma_riscv_roundtrip_" + kind], {"rv_" + kind + "_insn"})
        self.assertEqual(sum(map(len, graph.values())), 6)

    @unittest.skipUnless(os.environ.get("FRAGMA_RISCV_PROOF_RESULTS"),
                         "supply the complete retained seven-encoder proof probe")
    def test_retained_complete_batch_has_all_named_properties_and_dependencies(self):
        from fragma.report import parse_properties, parse_wp_report
        directory = Path(os.environ["FRAGMA_RISCV_PROOF_RESULTS"])
        goals = parse_wp_report(directory / "goals.json")
        ordinary = [goal for goal in goals if not goal["smoke"]]
        properties = parse_properties(directory / "properties.tsv",
            source_files=[ROOT / "riscv/annotated/base-encoders.verified.c"],
            selected_functions=TARGET["analysis_functions"])
        selected = [row for row in properties if row["function"] in TARGET["analysis_functions"]]
        self.assertEqual(len(ordinary), 119)
        self.assertEqual(len(selected), 119)
        self.assertEqual({goal["function"] for goal in ordinary}, set(TARGET["analysis_functions"]))
        self.assertTrue(all(goal["verdict"] == "valid" for goal in ordinary))
        self.assertTrue(all(row["status"] == "Valid" for row in selected))
        self.assertEqual(len(TARGET["required_properties"]), 47)
        self.assertTrue(set(TARGET["required_properties"]) <= {goal["property"] for goal in ordinary})
        self.assertEqual({goal["verdict"] for goal in goals if goal["smoke"]}, {"timeout"})

    def test_all_seven_bodies_and_declarators_match_pinned_kernel(self):
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", ROOT.parent / "linux"))
        if not (kernel / ".git").exists():
            self.skipTest("set FRAGMA_KERNEL_TREE for pinned-source integration checks")
        result = check_target(TARGET, kernel, MANIFEST["kernel_revision"], ROOT)
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(len(result["functions"]), 7)


if __name__ == "__main__":
    unittest.main()
