"""Draft pure/read-only integration tests; no compiler/analyzer/native process.

Always-on tests read the permanent common source/manifest. Retained ARM32/m68k
reports additionally exercise the real exporter; all mutations are in-memory.
These optional observational fixtures normalize only the old, explicit selector
definition to a blank line, preserving every contract/body and report location.
They do not claim that the old run used the production prelude or passed policy.
"""
from __future__ import annotations

import copy
from pathlib import Path
import unittest

from fragma import replay, report, suite


from fragma import common24


class Common24RetainedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = next((parent for parent in Path(__file__).resolve().parents
                        if (parent / "fragma/report.py").is_file()), None)
        if project is None:
            raise unittest.SkipTest("project source unavailable")
        cls.fixtures = {}
        for name in ("arm-gcc", "m68k-gcc"):
            directory = project / "build/common-byte-analysis-work/wp-2" / name
            if not (directory / "receipt.json").is_file():
                raise unittest.SkipTest("optional completed common24 observations unavailable")
            receipt = replay.strict_json((directory / "receipt.json").read_text())
            if receipt.get("status") != "diagnostics-recorded":
                raise unittest.SkipTest("observation is not terminal")
            target = receipt["target"]
            source_path = Path(receipt["input"]["frama_input"])
            goals = report.parse_wp_report(directory / "wp.json")
            properties = report.parse_properties(directory / "properties.tsv", source_files=[source_path],
                source_root=Path(receipt["input"]["cwd"]), selected_functions=target["analysis_functions"])
            evaluation = report.evaluate_target(target, goals, properties, returncode=0,
                warnings=suite.warnings_from_log(directory / "analysis.log"),
                validated_review=None, validated_native=None)
            source_text = source_path.read_text()
            selector = "#define FRAGMA_COMMON24_INLINE_POLICY 1\n"
            if source_text.count(selector) != 1:
                raise AssertionError("retained diagnostic fixture no longer has its exact selector1 prelude")
            # Test-only normalization; the actual retained source is never edited.
            source_text = source_text.replace(selector, "\n", 1)
            cls.fixtures[name] = {"target": target, "goals": goals, "properties": properties,
                "evaluation": evaluation, "source_path": source_path,
                "source_text": source_text,
                "strategy_text": source_path.with_name("byteproof.h").read_text()}

    def setUp(self):
        self.data = copy.deepcopy(self.fixtures["arm-gcc"])

    def gate(self, data=None):
        return common24.evaluate_inventory(**(data or self.data))

    def test_both_real_profiles_close_without_support_or_consistency(self):
        for name, data in self.fixtures.items():
            with self.subTest(profile=name):
                actual = self.gate(data)
                self.assertTrue(actual["ordinary_complete"])
                self.assertEqual(actual["ordinary_counts"], {"valid": 94})
                self.assertEqual(actual["selected_property_counts"], {"Valid": 82})
                self.assertEqual(actual["smoke"]["verdict_counts"], {"timeout": 12})
                self.assertEqual(len(actual["source_assertions"]), 16)
                self.assertEqual(len(actual["source_guard_sites"]), 8)
                self.assertEqual(len(actual["direct_call_preconditions"]), 4)
                self.assertFalse(actual["certified"])
                self.assertFalse(actual["consistency_proved"])
                self.assertEqual(data["evaluation"]["status"], "unsupported")
                self.assertFalse(data["evaluation"]["accepted"])

    def test_every_single_goal_deletion_fails_including_smoke_and_assigns_splits(self):
        for index, goal in enumerate(self.data["goals"]):
            with self.subTest(goal=goal["goal"]):
                changed = dict(self.data, goals=self.data["goals"][:index] + self.data["goals"][index + 1:])
                self.assertFalse(self.gate(changed)["ordinary_complete"])

    def test_every_single_property_deletion_fails(self):
        for index, prop in enumerate(self.data["properties"]):
            with self.subTest(property=prop["property"], line=prop["line"]):
                changed = dict(self.data, properties=self.data["properties"][:index] + self.data["properties"][index + 1:])
                self.assertFalse(self.gate(changed)["ordinary_complete"])

    def test_source_contract_body_declaration_and_strategy_changes_fail(self):
        for old, new in (("val % 16777216", "val % 256"),
                         ("requires writable:", "requires writable: val < 256 &&"),
                         ("*p++ = val & 0xff;", "*p++ = 0;"),
                         ("static inline u32", "static u32"),
                         ("decode_decompose_low:", "changed_label:")):
            with self.subTest(change=old):
                changed = dict(self.data, source_text=self.data["source_text"].replace(old, new, 1))
                with self.assertRaises((common24.Common24Error, ValueError)):
                    self.gate(changed)
        changed = dict(self.data, strategy_text=self.data["strategy_text"] + "\n")
        with self.assertRaises(common24.Common24Error):
            self.gate(changed)

    def test_extra_function_or_annotation_fails(self):
        for extra in ("\nint extra(void) { return 0; }\n", "\n/*@ axiom unreviewed: \\false; */\n"):
            with self.subTest(extra=extra):
                changed = dict(self.data, source_text=self.data["source_text"] + extra)
                with self.assertRaises(common24.Common24Error):
                    self.gate(changed)

    def test_no_architecture_or_path_fallback_and_moved_prelude_is_supported(self):
        self.data["target"]["profile"] = "an-explicit-future-profile"
        new_path = "/another/project/common/annotated/unaligned24.verified.c"
        self.data["source_path"] = new_path
        self.data["source_text"] = "/* new prelude */\n" + self.data["source_text"]
        for row in self.data["goals"] + self.data["properties"]:
            row["path"] = new_path
            row["line"] += 1
        self.assertTrue(self.gate()["ordinary_complete"])

    def test_bad_ordinary_goal_cannot_be_masked_by_saved_evaluation(self):
        for mutation in ({"verdict": "unknown"}, {"passed": False},
                         {"function": "other"}, {"line": 999}, {"path": "/wrong.c"},
                         {"property": "wrong"}, {"goal": "wrong"}):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.data)
                next(row for row in changed["goals"] if not row["smoke"]).update(mutation)
                self.assertFalse(self.gate(changed)["ordinary_complete"])

    def test_malformed_verdict_or_boolean_never_enters_inventory(self):
        for mutation in ({"passed": 1}, {"verdict": "invented"}, {"smoke": 0}):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.data)
                changed["goals"][0].update(mutation)
                with self.assertRaises(common24.Common24Error):
                    self.gate(changed)

    def test_conditional_ambiguous_or_mislocated_rows_fail(self):
        for mutation in ({"status": "Considered valid"}, {"status": "Unknown"},
                         {"status": "Valid under hypotheses"}, {"exported_identity_ambiguous": True},
                         {"function": "other"}, {"line": 999}, {"path": "/wrong.c"}, {"kind": "other"}):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.data)
                changed["properties"][0].update(mutation)
                self.assertFalse(self.gate(changed)["ordinary_complete"])

    def test_duplicate_goal_property_and_missing_assertion_label_fail(self):
        changed = copy.deepcopy(self.data)
        changed["goals"].append(copy.deepcopy(changed["goals"][0]))
        self.assertFalse(self.gate(changed)["ordinary_complete"])
        changed = copy.deepcopy(self.data)
        changed["properties"].append(copy.deepcopy(changed["properties"][0]))
        self.assertFalse(self.gate(changed)["ordinary_complete"])
        changed = copy.deepcopy(self.data)
        next(row for row in changed["properties"] if row["kind"] == "user assertion")["names"] = []
        self.assertFalse(self.gate(changed)["ordinary_complete"])

    def test_exit_clause_must_be_false(self):
        next(row for row in self.data["properties"] if row["property"] == "\\false")["property"] = "\\true"
        self.assertFalse(self.gate()["ordinary_complete"])

    def test_runtime_guard_frame_termination_predicates_and_post_labels_are_checked(self):
        for kind in ("mem_access", "pointer_value", "shift", "assigns clause", "termination clause"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(self.data)
                next(row for row in changed["properties"] if row["kind"] == kind)["property"] = "\\false"
                self.assertFalse(self.gate(changed)["ordinary_complete"])
        changed = copy.deepcopy(self.data)
        next(row for row in changed["properties"] if "decoded_value" in row["names"])["names"] = []
        self.assertFalse(self.gate(changed)["ordinary_complete"])
        changed = copy.deepcopy(self.data)
        next(row for row in changed["properties"] if row["kind"].startswith("precondition of"))["names"] = []
        self.assertFalse(self.gate(changed)["ordinary_complete"])

    def test_smoke_identity_is_checked_but_timeout_never_means_consistency(self):
        changed = copy.deepcopy(self.data)
        changed["goals"][0]["goal"] = "typed_other_smoke"
        self.assertFalse(self.gate(changed)["ordinary_complete"])
        result = self.gate()
        self.assertEqual(result["smoke"]["verdict_counts"], {"timeout": 12})
        self.assertFalse(result["smoke"]["consistency_proved"])

    def test_missing_or_nonempty_dependency_inventory_never_defaults_to_closed(self):
        for field in ("unresolved_dependencies", "trusted_dependencies", "dependency_report_omissions"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.data)
                changed["evaluation"][field] = [{"reason": "unreviewed"}]
                self.assertFalse(self.gate(changed)["ordinary_complete"])
                del changed["evaluation"][field]
                with self.assertRaises(common24.Common24Error):
                    self.gate(changed)
        self.data["evaluation"]["issues"].append({"message": "WP property is missing from the consolidated dependency report"})
        self.assertFalse(self.gate()["ordinary_complete"])

    def test_target_cannot_drop_witness_property_or_add_kernel_function(self):
        for field in ("functions", "analysis_functions", "project_functions", "required_properties"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.data)
                changed["target"][field] = changed["target"][field][:-1]
                with self.assertRaises(common24.Common24Error):
                    self.gate(changed)


class Common24SourceTests(unittest.TestCase):
    """Always exercised from the permanent source tree, without saved results."""
    @classmethod
    def setUpClass(cls):
        cls.project = next(parent for parent in Path(__file__).resolve().parents
                           if (parent / "fragma/report.py").is_file())
        manifest = replay.strict_json((cls.project / "config/common-byte-targets.json").read_text())
        cls.targets = manifest["targets"]
        cls.source_path = cls.project / "common/annotated/unaligned24.verified.c"
        cls.source_text = cls.source_path.read_text()
        cls.strategy_text = (cls.project / "common/annotated/byteproof.h").read_text()

    def source_gate(self, text=None, strategy=None, target=None):
        return common24.check_source(target or self.targets[0], source_path=self.source_path,
            source_text=self.source_text if text is None else text,
            strategy_text=self.strategy_text if strategy is None else strategy)

    def test_every_permanent_common_target_uses_the_checked_source(self):
        self.assertEqual(len(self.targets), 3)
        for target in self.targets:
            with self.subTest(target=target["id"]):
                self.assertEqual(self.source_gate(target=target)["status"], "checked")
        moved = "/* extra comment */\n\n" + self.source_text + "\n/* trailing comment */\n"
        self.assertEqual(self.source_gate(moved)["status"], "checked")

    def test_type_macro_include_selector_between_function_and_tail_mutations_fail(self):
        changes = [
            self.source_text.replace("unsigned char u8", "unsigned short u8", 1),
            self.source_text.replace("unsigned int u32", "unsigned long u32", 1),
            self.source_text.replace("unsigned int u32", "signed int u32", 1),
            self.source_text.replace('"inline-policy.h"', '"unreviewed.h"', 1),
            self.source_text.replace('"byteproof.h"', '"other-proof.h"', 1),
            self.source_text.replace("#define inline FRAGMA_COMMON24_INLINE", "#define inline", 1),
            '#define integer unsigned\n' + self.source_text,
            '#define p fake\n' + self.source_text,
            '#define FRAGMA_COMMON24_INLINE_POLICY 1\n' + self.source_text,
            '#define FRAGMA_COMMON24_INLINE_POLICY 2\n' + self.source_text,
            self.source_text.replace("\n}\n", "\n}\n#define val 0\n", 1),
            self.source_text + "\n#undef inline\n",
            self.source_text + "\nint extra;\n",
        ]
        for index, text in enumerate(changes):
            with self.subTest(mutation=index):
                with self.assertRaises(common24.Common24Error):
                    self.source_gate(text)

    def test_contract_extra_annotation_and_strategy_mutations_fail(self):
        for text in (self.source_text.replace("val % 16777216", "val % 256", 1),
                     self.source_text + "\n/*@ axiom unsound: \\false; */\n"):
            with self.assertRaises(common24.Common24Error):
                self.source_gate(text)
        with self.assertRaises(common24.Common24Error):
            self.source_gate(strategy=self.strategy_text + "\n")

    def test_apply_policy_copies_and_only_blocks_acceptance(self):
        original = {"status": "unsupported", "accepted": False, "verified": False,
                    "local_policy_passed": False, "issues": [{"kind": "unsupported", "message": "warning"}]}
        complete = {"schema_version": 1, "inventory": common24.INVENTORY,
                    "status": "complete", "ordinary_complete": True, "issues": []}
        result = common24.apply_policy(original, complete)
        self.assertEqual(result, original)
        self.assertIsNot(result, original)
        result["issues"].append({"kind": "test"})
        self.assertEqual(len(original["issues"]), 1)
        passing = dict(original, status="passed", accepted=True, verified=True, local_policy_passed=True, issues=[])
        for inventory in (None, {}, {"ordinary_complete": True}, dict(complete, schema_version=True),
                          dict(complete, status="incomplete", ordinary_complete=False, issues=["missing goal"])):
            with self.subTest(inventory=inventory):
                result = common24.apply_policy(passing, inventory)
                self.assertEqual(result["status"], "incomplete")
                self.assertFalse(result["accepted"])
                self.assertFalse(result["verified"])
                self.assertFalse(result["local_policy_passed"])
                self.assertEqual(result["issues"][-1]["inventory"], common24.INVENTORY)
        self.assertTrue(passing["accepted"])


if __name__ == "__main__":
    unittest.main()
