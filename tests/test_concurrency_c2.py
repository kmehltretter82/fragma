from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c2


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyC2Tests(unittest.TestCase):
    def test_manifest_keeps_the_verification_scope_narrow(self):
        manifest = concurrency_c2.load_manifest(ROOT)
        self.assertEqual(manifest["kernel"]["required_config"]["CONFIG_SMP"], "n")
        self.assertEqual(
            manifest["model"]["verification_gate"]["primitive_models"]
            ["linux_once_mutex"]["status"],
            "supported",
        )
        self.assertFalse(
            manifest["model"]["verification_gate"]["primitive_models"]
            ["linux_once_mutex"]["empty_stub_allowed"])
        exclusions = " ".join(manifest["property"]["exclusions"])
        for excluded in ("exactly-once", "Interrupt", "SMP", "weak-memory", "RCU"):
            self.assertIn(excluded, exclusions)
        self.assertFalse(manifest["cases"][1]["verification_candidate"])

    def test_copied_kernel_function_tokens_are_identical(self):
        manifest = concurrency_c2.load_manifest(ROOT)
        kernel = (ROOT / manifest["kernel"]["source_root"] / "lib/once.c").read_text()
        fixture = (ROOT / manifest["model"]["fixture"]).read_text()
        for name in manifest["kernel"]["copied_functions"]:
            self.assertEqual(
                concurrency_c2.c_tokens(concurrency_c2.extract_function(kernel, name)),
                concurrency_c2.c_tokens(concurrency_c2.extract_function(fixture, name)),
            )

    def test_token_gate_detects_a_semantic_body_change(self):
        manifest = concurrency_c2.load_manifest(ROOT)
        fixture = (ROOT / manifest["model"]["fixture"]).read_text()
        body = concurrency_c2.extract_function(
            fixture, "__do_once_sleepable_start")
        changed = body.replace("if (*done)", "if (!*done)", 1)
        self.assertNotEqual(
            concurrency_c2.c_tokens(body), concurrency_c2.c_tokens(changed))

    def test_real_macro_preserves_start_callback_done_order(self):
        manifest = concurrency_c2.load_manifest(ROOT)
        caller = manifest["kernel"]["caller_contract"]
        macro = concurrency_c2.extract_macro(
            (ROOT / caller["file"]).read_text(), caller["macro"])
        tokens = concurrency_c2.c_tokens(macro)
        positions = concurrency_c2.ordered_token_positions(
            tokens, caller["ordered_calls"])
        self.assertEqual(positions, sorted(positions))

    def test_kconfig_parser_distinguishes_explicit_disabled_symbols(self):
        values = concurrency_c2.parse_kconfig(
            "CONFIG_ONE=y\n# CONFIG_TWO is not set\nCONFIG_THREE=m\n")
        self.assertEqual(values, {
            "CONFIG_ONE": "y", "CONFIG_TWO": "n", "CONFIG_THREE": "m"})

    def test_protection_parser_uses_the_final_fixpoint_summary(self):
        text = """[mt] Mutexes for concurrent accesses:
  modeled_done  unprotected
[mt] Detailed shared zones protections
[mt] Mutexes for concurrent accesses:
  modeled_done  protected by linux-once-mutex
[mt] Detailed shared zones protections
"""
        self.assertEqual(
            concurrency_c2.final_mutex_protection(
                text, "modeled_done", "linux-once-mutex"),
            "protected",
        )
        self.assertEqual(
            concurrency_c2.final_mutex_protection(
                text.replace("protected by linux-once-mutex", "unprotected"),
                "modeled_done", "linux-once-mutex"),
            "unprotected",
        )
        self.assertTrue(
            concurrency_c2.final_mutex_protection(
                text.replace("protected by linux-once-mutex",
                             "protected by (?)linux-once-mutex"),
                "modeled_done", "linux-once-mutex").startswith("other:"),
        )

    def test_empty_mutex_adapter_is_rejected(self):
        manifest = concurrency_c2.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["verification_gate"]["primitive_models"] \
            ["linux_once_mutex"]["empty_stub_allowed"] = True
        with mock.patch.object(concurrency_c2, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(concurrency_c2.ConcurrencyC2Error, "nonempty"):
                concurrency_c2.load_manifest(ROOT)

    def test_positive_assertion_inventory_cannot_be_weakened(self):
        manifest = concurrency_c2.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["property"]["accepted_assertions"].pop()
        changed["cases"][0]["expected_assertions"].pop(
            "c2_done_published_before_unlock")
        with mock.patch.object(concurrency_c2, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(concurrency_c2.ConcurrencyC2Error,
                                        "inventory is not exact"):
                concurrency_c2.load_manifest(ROOT)

        changed = deepcopy(manifest)
        changed["cases"][0]["expected_assertions"][
            "c2_done_published_before_unlock"] = "unknown"
        with mock.patch.object(concurrency_c2, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(concurrency_c2.ConcurrencyC2Error,
                                        "acceptance boundary"):
                concurrency_c2.load_manifest(ROOT)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(concurrency_c2.ConcurrencyC2Error,
                                        "already exists"):
                concurrency_c2.run_c2(ROOT, Path(temporary))


if __name__ == "__main__":
    unittest.main()
