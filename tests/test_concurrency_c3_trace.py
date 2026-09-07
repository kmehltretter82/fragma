from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c3_trace


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyC3TraceTests(unittest.TestCase):
    def test_manifest_accepts_one_narrow_x86_64_property(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        self.assertEqual(
            manifest["property"]["kind"],
            "kernel_release_acquire_publication_ordering",
        )
        self.assertEqual(manifest["profile"]["required_config"]["CONFIG_SMP"], "y")
        self.assertEqual(manifest["profile"]["required_config"]["CONFIG_KCSAN"], "n")
        self.assertEqual(len(manifest["model"]["cases"]), 2)
        positive, negative = manifest["model"]["cases"]
        self.assertIs(positive["verification_candidate"], True)
        self.assertEqual(positive["expected"]["observation"], "Never")
        self.assertEqual(positive["expected"]["flags"], [])
        self.assertIs(negative["verification_candidate"], False)
        self.assertEqual(negative["expected"]["observation"], "Sometimes")
        self.assertEqual(negative["expected"]["flags"], ["data-race"])

    def test_source_model_mapping_and_lifetime_checks_pass(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        checks, evidence = concurrency_c3_trace._semantic_checks(ROOT, manifest)
        self.assertTrue(all(check["passed"] for check in checks), checks)
        self.assertEqual(
            set(evidence["roles"]),
            {
                "producer_payload",
                "producer_publish",
                "consumer_observe",
                "consumer_payload",
            },
        )
        self.assertEqual(
            evidence["allocator_token_inventory"],
            [
                {"path": "kernel/trace/trace.c", "count": 1},
                {"path": "kernel/trace/trace_sched_switch.c", "count": 1},
            ],
        )

    def test_declared_source_and_model_hashes_are_current(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        identities = dict(manifest["kernel"]["source_identities"])
        model = manifest["model"]
        identities[model["ordered_path"]] = model["ordered_sha256"]
        identities[model["weakened_path"]] = model["weakened_sha256"]
        for name, expected in identities.items():
            with self.subTest(name=name):
                self.assertEqual(concurrency_c3_trace._sha256(ROOT / name), expected)

    def test_disassembly_block_is_exactly_function_scoped(self):
        text = (
            "0000000000000010 <first>:\n"
            "  10: mov token-a\n"
            "  14: mov token-b\n\n"
            "0000000000000020 <second>:\n"
            "  20: mov token-c\n"
        )
        block = concurrency_c3_trace._function_block(text, "first")
        self.assertIn("token-a", block)
        self.assertIn("token-b", block)
        self.assertNotIn("token-c", block)
        with self.assertRaisesRegex(
            concurrency_c3_trace.ConcurrencyC3TraceError, "omits function"
        ):
            concurrency_c3_trace._function_block(text, "absent")

    def test_symbol_parser_requires_local_objects(self):
        text = (
            "0000000000000018 l     O .bss\t0000000000000008 tgid_map\n"
            "0000000000000010 l     O .bss\t0000000000000008 tgid_map_max\n"
            "0000000000001000 g     F .text\t000000000000006f trace_alloc_tgid_map\n"
        )
        self.assertEqual(
            concurrency_c3_trace._symbols(text, {"tgid_map", "tgid_map_max"}),
            {
                "tgid_map": {
                    "section": ".bss",
                    "value": "0000000000000018",
                    "size": 8,
                },
                "tgid_map_max": {
                    "section": ".bss",
                    "value": "0000000000000010",
                    "size": 8,
                },
            },
        )

    def test_order_check_rejects_missing_and_reversed_events(self):
        self.assertTrue(concurrency_c3_trace._ordered("a xx b xx c", ["a", "b", "c"]))
        self.assertFalse(concurrency_c3_trace._ordered("a xx c xx b", ["a", "b", "c"]))
        self.assertFalse(concurrency_c3_trace._ordered("a xx b", ["a", "b", "c"]))

    def test_positive_cannot_be_promoted_without_clean_never_result(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][0]["expected"]["flags"] = ["data-race"]
        with mock.patch.object(
            concurrency_c3_trace, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_trace.ConcurrencyC3TraceError,
                "clean Never candidate",
            ):
                concurrency_c3_trace.load_manifest(ROOT)

    def test_negative_cannot_become_a_verification_candidate(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][1]["verification_candidate"] = True
        with mock.patch.object(
            concurrency_c3_trace, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_trace.ConcurrencyC3TraceError,
                "detecting data-race control",
            ):
                concurrency_c3_trace.load_manifest(ROOT)

    def test_model_conditions_cannot_diverge(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][1]["expected"]["condition"] = "exists (1:r0=0)"
        with mock.patch.object(
            concurrency_c3_trace, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_trace.ConcurrencyC3TraceError,
                "condition drift",
            ):
                concurrency_c3_trace.load_manifest(ROOT)

    def test_other_architecture_and_progress_exclusions_are_mandatory(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        for word in ("architecture", "progress"):
            changed = deepcopy(manifest)
            changed["property"]["exclusions"] = [
                item for item in changed["property"]["exclusions"]
                if word not in item.lower()
            ]
            with self.subTest(word=word), mock.patch.object(
                concurrency_c3_trace, "_strict_json", return_value=changed
            ):
                with self.assertRaisesRegex(
                    concurrency_c3_trace.ConcurrencyC3TraceError,
                    f"omits {word} exclusion",
                ):
                    concurrency_c3_trace.load_manifest(ROOT)

    def test_project_relative_escape_is_rejected(self):
        manifest = concurrency_c3_trace.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["profile"]["build_directory"] = "../outside"
        with mock.patch.object(
            concurrency_c3_trace, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_trace.ConcurrencyC3TraceError,
                "project-relative",
            ):
                concurrency_c3_trace.load_manifest(ROOT)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                concurrency_c3_trace.ConcurrencyC3TraceError,
                "already exists",
            ):
                concurrency_c3_trace.run_c3_trace(ROOT, Path(temporary))

    def test_boolean_timeout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with self.assertRaisesRegex(
                concurrency_c3_trace.ConcurrencyC3TraceError,
                "positive integer",
            ):
                concurrency_c3_trace.run_c3_trace(ROOT, output, True)


if __name__ == "__main__":
    unittest.main()
