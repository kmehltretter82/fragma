from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c2, concurrency_c2_irq


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyC2IrqTests(unittest.TestCase):
    def test_manifest_preserves_the_narrow_irq_boundary(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        profile = manifest["kernel"]["profile"]
        self.assertEqual(profile["required_config"]["CONFIG_SMP"], "y")
        self.assertEqual(profile["required_config"]["CONFIG_PREEMPT_RT"], "n")
        self.assertEqual(profile["required_config"]["CONFIG_HDQ_MASTER_OMAP"], "m")
        self.assertEqual(
            manifest["model"]["entry_adapter"]["automatic_handler_status"],
            "excluded_initialization_gap",
        )
        self.assertEqual(
            manifest["model"]["entry_adapter"]["automatic_handler_calibration"],
            "interrupt_registered_exclusion_gap",
        )
        exclusions = " ".join(manifest["property"]["exclusions"])
        for excluded in ("Whole-variable", "nesting", "Softirq", "PREEMPT_RT",
                         "weak-memory", "lifetime"):
            self.assertIn(excluded, exclusions)

    def test_copied_kernel_function_tokens_are_identical(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        kernel = (ROOT / manifest["kernel"]["source_root"] /
                  "drivers/w1/masters/omap_hdq.c").read_text()
        fixture = (ROOT / manifest["model"]["fixture"]).read_text()
        for name in manifest["kernel"]["copied_functions"]:
            self.assertEqual(
                concurrency_c2.c_tokens(
                    concurrency_c2_irq.extract_function(kernel, name)),
                concurrency_c2.c_tokens(
                    concurrency_c2_irq.extract_function(fixture, name)),
            )

    def test_function_extractor_skips_prototypes(self):
        source = (
            "unsigned long chosen(int value);\n"
            "static unsigned long chosen(int value)\n"
            "{\n"
            "  return (unsigned long)value;\n"
            "}\n"
        )
        body = concurrency_c2_irq.extract_function(source, "chosen")
        self.assertIn("return (unsigned long)value", body)
        self.assertNotIn("chosen(int value);", body)

    def test_token_gate_detects_a_driver_body_change(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        fixture = (ROOT / manifest["model"]["fixture"]).read_text()
        body = concurrency_c2_irq.extract_function(fixture, "hdq_isr")
        changed = body.replace("|= hdq_reg_in", "&= hdq_reg_in", 1)
        self.assertNotEqual(
            concurrency_c2.c_tokens(body), concurrency_c2.c_tokens(changed))

    def test_probe_and_configured_spin_semantics_are_source_bound(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        fixture = (ROOT / manifest["model"]["fixture"]).read_text()
        checks, provenance = concurrency_c2_irq._semantic_checks(
            ROOT, manifest, fixture)
        self.assertTrue(all(check["passed"] for check in checks), checks)
        self.assertEqual(set(provenance), {"hdq_reset_irqstatus", "hdq_isr"})
        self.assertTrue(all(item["identical"] for item in provenance.values()))

    def test_access_parser_uses_last_section_and_both_status_layouts(self):
        text = """[mt] Possible read/write data races:
  old:
    read by old at old.c:1, unprotected
[mt] Possible write/write data races:
  none
[mt] Possible read/write data races:
  modeled_hdq.hdq_irqstatus:
    read by modeled_irq_thread at concurrency/c2/omap_hdq_irq.c:154,
       protected by hdq-spinlock
    write by <main> at concurrency/c2/omap_hdq_irq.c:120, unprotected
[mt] Possible write/write data races:
  none
"""
        accesses = concurrency_c2_irq.parse_final_accesses(text)
        self.assertEqual(len(accesses), 2)
        self.assertEqual(accesses[0]["locks"], ["hdq-spinlock"])
        self.assertEqual(accesses[1]["locks"], [])
        self.assertNotIn("old", {item["object"] for item in accesses})

    def test_access_parser_rejects_unclassified_protection(self):
        text = """[mt] Possible read/write data races:
  object:
    read by worker at fixture.c:7,
[mt] Possible write/write data races:
  none
"""
        with self.assertRaisesRegex(
                concurrency_c2_irq.ConcurrencyC2IrqError, "unclassified"):
            concurrency_c2_irq.parse_final_accesses(text)

    def test_role_resolution_is_tied_to_unique_source_lines(self):
        source = "first = shared;\nshared |= 1;\n"
        roles = {
            "copy": {"object": "shared", "operation": "read",
                     "line_contains": "first = shared;"},
            "rmw_write": {"object": "shared", "operation": "write",
                          "line_contains": "shared |= 1;"},
        }
        accesses = [
            {"object": "shared", "operation": "read", "line_start": 1,
             "locks": ["lock"]},
            {"object": "shared", "operation": "write", "line_start": 2,
             "locks": ["lock"]},
        ]
        self.assertEqual(
            concurrency_c2_irq.resolve_access_roles(source, roles, accesses),
            {"copy": ["lock"], "rmw_write": ["lock"]},
        )
        with self.assertRaisesRegex(
                concurrency_c2_irq.ConcurrencyC2IrqError, "matched 0"):
            concurrency_c2_irq.resolve_access_roles(source, roles, accesses[:1])

    def test_model_dependency_lookup_does_not_depend_on_list_order(self):
        paths = ["model/other.ml", "model/mt_analysis_hooks.ml", "model/last.ml"]
        self.assertEqual(
            concurrency_c2_irq.unique_suffix_path(paths, "/mt_analysis_hooks.ml"),
            "model/mt_analysis_hooks.ml",
        )
        with self.assertRaisesRegex(
                concurrency_c2_irq.ConcurrencyC2IrqError, "found 0"):
            concurrency_c2_irq.unique_suffix_path(paths, "/missing.ml")

    def test_negative_control_cannot_be_promoted(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][1]["verification_candidate"] = True
        with mock.patch.object(
                concurrency_c2_irq, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(
                    concurrency_c2_irq.ConcurrencyC2IrqError,
                    "positive/control roles"):
                concurrency_c2_irq.load_manifest(ROOT)

    def test_remote_unlocked_read_cannot_be_hidden(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][2]["expected_access_locks"][
            "handler_post_unlock_read"] = ["hdq-spinlock"]
        with mock.patch.object(
                concurrency_c2_irq, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(
                    concurrency_c2_irq.ConcurrencyC2IrqError,
                    "unlocked handler read"):
                concurrency_c2_irq.load_manifest(ROOT)

    def test_empty_spinlock_adapter_is_rejected(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["verification_gate"]["primitive_models"] \
            ["linux_hdq_spinlock"]["empty_stub_allowed"] = True
        with mock.patch.object(
                concurrency_c2_irq, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(
                    concurrency_c2_irq.ConcurrencyC2IrqError, "nonempty"):
                concurrency_c2_irq.load_manifest(ROOT)

    def test_positive_critical_lock_inventory_cannot_be_weakened(self):
        manifest = concurrency_c2_irq.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][2]["expected_access_locks"][
            "handler_status_rmw_write"] = []
        with mock.patch.object(
                concurrency_c2_irq, "_strict_json", return_value=changed):
            with self.assertRaisesRegex(
                    concurrency_c2_irq.ConcurrencyC2IrqError, "lacks spinlock"):
                concurrency_c2_irq.load_manifest(ROOT)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                    concurrency_c2_irq.ConcurrencyC2IrqError, "already exists"):
                concurrency_c2_irq.run_c2_irq(ROOT, Path(temporary))


if __name__ == "__main__":
    unittest.main()
