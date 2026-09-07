"""Offline parser regressions; never run a compiler, analyzer or old main.

Read/hash-check the frozen private context-run-1 and replay only pure functions
in memory. This is not a new diagnostic run and does not rewrite its receipt.
"""

import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import unittest


BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
RUN = BASE / "context-run-1"
FROZEN_SHA = "37419daca86065f5586eca22ee917ae7fea430976092331e8528b92501427050"
SUCCESSOR_SHA = "ca315f499eff71d75a05d1a1100cdb8ae5a51fa8d119870c0f63e7d778b7d8a8"
OLD_SHA = "7ce09c8784d9d2c16dd29d98b024ad688d8653923200f43411c283be17ac6cf0"
RECEIPT_SHA = "6d71f4cfe091264d70d1bc49ad95b611eb3aaaeb1024c3efd7b351ec9d300e60"


def require(condition, message):
    if not condition:
        raise ValueError(message)


class ContextClassifierV2Tests(unittest.TestCase):
    @classmethod
    def read_verified(cls, path, expected_sha, expected_size=None):
        require(path.is_absolute() and path.resolve() == path and not path.is_symlink(),
                "Noncanonical/symlinked offline input")
        before = path.stat()
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 2 * 1024 * 1024,
                "Offline input is not a bounded regular file")
        data = path.read_bytes()
        after = path.stat()
        signature = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                 row.st_mtime_ns, row.st_ctime_ns)
        require(signature(before) == signature(after), "Offline input changed during read")
        require(hashlib.sha256(data).hexdigest() == expected_sha,
                "Offline input SHA mismatch: " + str(path))
        require(expected_size is None or len(data) == expected_size,
                "Offline input size mismatch")
        cls.input_hashes[path] = expected_sha
        return data

    @classmethod
    def load_definitions(cls, path, expected_sha):
        data = cls.read_verified(path, expected_sha)
        tree = ast.parse(data, filename=str(path))
        require(all(isinstance(node, ast.FunctionDef)
                    or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                        and type(node.value.value) is str) for node in tree.body),
                "Classifier has an import or other top-level execution")
        namespace = {"__name__": "fragma_offline_pure_classifier"}
        exec(compile(tree, str(path), "exec"), namespace)
        return namespace, tree

    @classmethod
    def setUpClass(cls):
        cls.input_hashes = {}
        cls.v1, cls.v1_tree = cls.load_definitions(BASE / "context_classifiers.py", FROZEN_SHA)
        cls.v2, cls.v2_tree = cls.load_definitions(BASE / "context_classifiers_v2.py", SUCCESSOR_SHA)
        old_path = ROOT / "build/hexagon-alignment-context-20260906/diagnose-v2.py"
        old_data = cls.read_verified(old_path, OLD_SHA)
        # Extract only the two fully reviewed pure witness parsers. No import,
        # old module setup, filesystem helper, subprocess helper or main runs.
        selected = [node for node in ast.parse(old_data).body
                    if isinstance(node, ast.FunctionDef)
                    and node.name in ("compiler_values", "analyzer_values")]
        require(len(selected) == 2, "Missing exact old witness parsers")
        old_namespace = {"re": re, "require": require, "SYMBOL": "fragma_alignment_witness"}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(old_path), "exec"), old_namespace)
        cls.old = SimpleNamespace(re=re, compiler_values=old_namespace["compiler_values"],
                                  analyzer_values=old_namespace["analyzer_values"])
        receipt_bytes = cls.read_verified(RUN / "receipt.json", RECEIPT_SHA)
        cls.receipt = json.loads(receipt_bytes)
        require(len(cls.receipt["commands"]) == 112
                and len(cls.receipt["comparisons"]) == 55, "Incomplete retained matrix")
        cls.rows = []
        for index, row in enumerate(cls.receipt["commands"], 1):
            directory = RUN / ("command-%03d" % index)
            require(row["cwd"] == str(directory), "Retained command cwd differs")
            if row["case"] is None:
                require(index in (1, 2), "Unexpected version row")
                continue
            result_record = cls.receipt["artifacts"][directory.name + "/result.json"]
            result = json.loads(cls.read_verified(directory / "result.json",
                                                 result_record["sha256"], result_record["size"]))
            require(result == {key: value for key, value in row.items()
                               if key not in ("classification", "preprocessing")},
                    "Raw result differs from retained command")
            observation_record = cls.receipt["artifacts"][directory.name + "/observation.json"]
            saved_observation = json.loads(cls.read_verified(directory / "observation.json",
                                                            observation_record["sha256"],
                                                            observation_record["size"]))
            require(saved_observation["classification"] == row["classification"],
                    "Retained observation differs from receipt")
            require(saved_observation.get("preprocessing") == row.get("preprocessing"),
                    "Retained preprocessing observation differs from receipt")
            raw = {}
            for name in ("stdout", "stderr", "printed.c"):
                record = row["artifacts"].get(name)
                if record is not None:
                    require(record["kind"] == "file", "Nonfile command text")
                    raw[name] = cls.read_verified(directory / name, record["sha256"],
                                                 record["size"]).decode("utf-8")
            cls.rows.append((index, row, raw))
        require(len(cls.rows) == 110, "Wrong paired observation count")
        cls.locals = [(index, row, raw) for index, row, raw in cls.rows
                      if row["tool"] == "analyzer" and row["case"]["fixture"] == "locals"
                      and row["returncode"] == 0]
        require([index for index, _, _ in cls.locals] == [54, 56, 58, 60],
                "Unexpected retained successful-local inventory")

    @classmethod
    def tearDownClass(cls):
        # Re-read every input used, including frozen helpers and all retained
        # result/observation/raw streams. These tests never write those files.
        for path, expected in list(cls.input_hashes.items()):
            cls.read_verified(path, expected)

    def observe(self, module, row, raw, printed=None, case=None, stdout=None):
        case = row["case"] if case is None else case
        stdout = raw["stdout"] if stdout is None else stdout
        if row["tool"] == "compiler":
            return module["compiler_observation"](self.old, row["returncode"], stdout,
                                                  raw["stderr"], case)
        return module["analyzer_observation"](
            self.old, row["returncode"], stdout, raw["stderr"],
            raw.get("printed.c") if printed is None else printed, case)

    def test_all_55_replay_only_four_local_observations_change(self):
        changed = []
        comparisons = []
        for offset in range(0, 110, 2):
            new_rows = []
            for index, row, raw in self.rows[offset:offset + 2]:
                prior = self.observe(self.v1, row, raw)
                self.assertEqual(prior, row["classification"])
                current = self.observe(self.v2, row, raw)
                if current != prior:
                    changed.append(index)
                    self.assertEqual(row["case"]["fixture"], "locals")
                    self.assertEqual(row["tool"], "analyzer")
                    self.assertEqual(prior["status"], "unclassified")
                    self.assertEqual(current["status"], "constant-witness-observed")
                new_rows.append({**row, "classification": current})
            self.assertEqual(new_rows[0]["tool"], "compiler")
            self.assertEqual(new_rows[1]["tool"], "analyzer")
            self.assertEqual(new_rows[0]["case"], new_rows[1]["case"])
            comparisons.append(self.v2["compare"](new_rows[0]["case"], *new_rows))
        self.assertEqual(changed, [54, 56, 58, 60])
        self.assertEqual(Counter(row["status"] for row in comparisons), {
            "constants-agree-not-support": 33,
            "named-rejections-correspond-not-support": 21,
            "rejection-category-mismatch": 1,
        })
        self.assertEqual(len(comparisons), 55)
        # Historical four-unresolved classifications remain historical.
        self.assertEqual(self.receipt["summary"]["unresolved-observation"], 4)

    def test_four_local_witnesses_match_retained_compiler_values(self):
        self.assertEqual([row["case"]["alignment"] for _, row, _ in self.locals],
                         [16, 2 ** 28, 2 ** 29, 2 ** 32])
        for index, row, raw in self.locals:
            with self.subTest(command=index):
                current = self.observe(self.v2, row, raw)
                compiler = self.receipt["commands"][index - 2]["classification"]
                self.assertEqual(current["values"], compiler["values"])
                self.assertEqual(current["witness_symbol"], "fragma_scope_fragma_alignment_witness")

    def test_malformed_or_wrong_named_local_witness_is_unclassified(self):
        _, row, raw = self.locals[0]
        printed = raw["printed.c"]
        symbol = "fragma_scope_fragma_alignment_witness"
        variants = {
            "wrong-name": printed.replace(symbol, "other_" + symbol),
            "old-global-name": printed.replace(symbol, "fragma_alignment_witness"),
            "non-static": printed.replace("static unsigned", "unsigned"),
            "non-const": printed.replace("long long const", "long long"),
            "signed-type": printed.replace("unsigned long long", "signed long long"),
            "wrong-width": printed.replace("unsigned long long", "unsigned long"),
            "wrong-length": printed.replace("witness[6]", "witness[5]"),
            "missing-length": printed.replace("witness[6]", "witness[]"),
            "missing-used": printed.replace(" __attribute__((\n  __used__))", ""),
            "other-used-spelling": printed.replace("__used__", "used"),
            "short-values": printed.replace("{4ULL, ", "{", 1),
            "extra-values": printed.replace("{4ULL, ", "{4ULL, 4ULL, ", 1),
            "nonconstant": printed.replace("{4ULL", "{fragma_c11_local", 1),
            "negative": printed.replace("{4ULL", "{-1ULL", 1),
            "wrong-suffix": printed.replace("{4ULL", "{4UL", 1),
            "leading-zero": printed.replace("{4ULL", "{04ULL", 1),
            "overflow": printed.replace("{4ULL", "{" + str(2 ** 64) + "ULL", 1),
            "unterminated": printed.replace("};\nvoid", "}\nvoid", 1),
        }
        for name, mutated in variants.items():
            with self.subTest(variant=name):
                self.assertNotEqual(mutated, printed)
                self.assertEqual(self.observe(self.v2, row, raw, printed=mutated)["status"],
                                 "unclassified")

    def test_extra_globals_functions_or_effects_are_unclassified(self):
        _, row, raw = self.locals[0]
        printed = raw["printed.c"]
        variants = {
            "duplicate-witness": printed + printed,
            "extra-global": printed + "int extra_global;\n",
            "extra-function": printed + "void extra_function(void) { return; }\n",
            "extra-prototype": "void other(void);\n" + printed,
            "wrong-function-name": printed.replace("fragma_scope(void)", "other_scope(void)"),
            "missing-prototype": printed.replace("void fragma_scope(void);\n\n", "", 1),
            "evaluated-local": printed.replace("  return;", "  fragma_c11_local = 7;\n  return;"),
            "wrong-c11-request": printed.replace("_Alignas(16)", "_Alignas(8)"),
            "wrong-gnu-request": printed.replace("__aligned__(16)", "__aligned__(8)"),
            "attribute-erasure": printed.replace(" __attribute__((__aligned__(16)))", ""),
            "trailing-comment": printed + "/* unrelated output */\n",
        }
        for name, mutated in variants.items():
            with self.subTest(variant=name):
                self.assertNotEqual(mutated, printed)
                self.assertEqual(self.observe(self.v2, row, raw, printed=mutated)["status"],
                                 "unclassified")

    def test_local_field_inventory_and_fixture_are_exact(self):
        _, row, raw = self.locals[0]
        cases = [
            {**row["case"], "fields": list(reversed(row["case"]["fields"]))},
            {**row["case"], "fields": row["case"]["fields"][:-1]},
            {**row["case"], "alignment": 2 ** 28},
            {**row["case"], "fixture": "combined-directives"},
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(self.observe(self.v2, row, raw, case=case)["status"], "unclassified")
        with self.assertRaises(ValueError):
            self.v2["_locals_analyzer_values"](
                self.old, raw["printed.c"], {**row["case"], "fixture": "combined-directives"})

    def test_witness_values_are_observed_not_replaced_with_expectations(self):
        index, row, raw = self.locals[0]
        compiler = self.receipt["commands"][index - 2]
        for value in (0, 5, 2 ** 64 - 1):
            with self.subTest(value=value):
                mutated = raw["printed.c"].replace("{4ULL", "{" + str(value) + "ULL", 1)
                observed = self.observe(self.v2, row, raw, printed=mutated)
                self.assertEqual(observed["status"], "constant-witness-observed")
                self.assertEqual(observed["values"]["c11_local_size"], value)
                compared = self.v2["compare"](row["case"], compiler, {**row, "classification": observed})
                self.assertEqual(compared["status"], "constant-mismatch")

    def test_stdout_extra_or_failure_stays_unclassified(self):
        _, row, raw = self.locals[0]
        variants = [raw["stdout"] + tail for tail in (
            "arbitrary extra output\n", "[kernel] Failure: internal failure\n",
            "[kernel] fatal error\n", "[kernel] exception\n", "\n")]
        variants += [raw["stdout"].replace("[kernel] Parsing", "[kernel] Unexpected Parsing"),
                     raw["stdout"].replace("Full preprocessing command:", "Other command:")]
        for stdout in variants:
            with self.subTest(stdout=stdout[-100:]):
                self.assertEqual(self.observe(self.v2, row, raw, stdout=stdout)["status"], "unclassified")

    def test_compound_missing_definition_mismatch_is_preserved(self):
        selected = [(row, raw) for _, row, raw in self.rows
                    if row["case"]["fixture"] == "c11-redeclaration-conflict"
                    and row["case"]["alignment"] == 2 ** 33]
        self.assertEqual(len(selected), 2)
        rows = [{**row, "classification": self.observe(self.v2, row, raw)} for row, raw in selected]
        compared = self.v2["compare"](rows[0]["case"], *rows)
        self.assertEqual(compared["status"], "rejection-category-mismatch")
        self.assertEqual(compared["compiler_rejection_classes"],
                         ["above-maximum", "missing-definition-alignas"])
        self.assertEqual(compared["analyzer_rejection_classes"], ["above-maximum"])
        self.assertEqual(compared["compiler_primary_count"], 2)
        self.assertEqual(compared["analyzer_primary_count"], 1)
        self.assertFalse(compared["all_independent_invalid_conditions_established"])

    def test_only_local_parser_and_its_dispatch_are_changed(self):
        old_functions = {node.name: node for node in self.v1_tree.body if isinstance(node, ast.FunctionDef)}
        new_functions = {node.name: node for node in self.v2_tree.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(set(new_functions) - set(old_functions), {"_locals_analyzer_values"})
        self.assertFalse(set(old_functions) - set(new_functions))
        for name in old_functions:
            if name != "analyzer_observation":
                with self.subTest(function=name):
                    self.assertEqual(ast.dump(old_functions[name]), ast.dump(new_functions[name]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
