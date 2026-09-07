from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c3_ipc_refcount


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyC3IpcRefcountTests(unittest.TestCase):
    def test_manifest_has_one_candidate_and_one_detecting_control(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        self.assertEqual(
            manifest["property"]["kind"],
            "kernel_refcount_final_put_vs_get_unless_zero",
        )
        self.assertEqual(manifest["property"]["initial_refcount"], 1)
        self.assertEqual(len(manifest["model"]["cases"]), 2)
        by_id = {case["id"]: case for case in manifest["model"]["cases"]}
        positive = by_id["refcount_put_get_positive"]
        negative = by_id["unconditional_resurrection_negative"]
        self.assertIs(positive["verification_candidate"], True)
        self.assertIs(negative["verification_candidate"], False)
        self.assertEqual(negative["control_for"], positive["id"])
        self.assertEqual(positive["expected"]["condition"],
                         negative["expected"]["condition"])
        self.assertEqual(positive["expected"]["observation"], "Never")
        self.assertEqual(positive["expected"]["positive"], 0)
        self.assertEqual(negative["expected"]["observation"], "Sometimes")
        self.assertGreater(negative["expected"]["positive"], 0)

    def test_configurations_are_explicit_and_no_install_step_exists(self):
        profiles = concurrency_c3_ipc_refcount.load_manifest(ROOT)["profiles"]
        self.assertEqual(
            [profile["id"] for profile in profiles],
            [
                "x86_64-ipc-refcount-c3",
                "arm64-ipc-refcount-c3",
                "riscv64-ipc-refcount-c3",
                "s390x-ipc-refcount-c3",
            ],
        )
        self.assertEqual(
            [profile["arch"] for profile in profiles],
            ["x86_64", "arm64", "riscv", "s390"],
        )
        self.assertEqual(profiles[0]["configuration"]["base_recipe"],
                         "x86_64_defconfig")
        self.assertTrue(all(
            profile["configuration"]["finalize_recipe"] == "olddefconfig"
            for profile in profiles
        ))
        self.assertTrue(all(
            profile["required_config"]["CONFIG_SYSVIPC"] == "y"
            for profile in profiles
        ))
        self.assertIsNone(profiles[0]["cross_compile"])
        self.assertTrue(all(
            profile["cross_compile"].startswith("/usr/bin/")
            for profile in profiles[1:]
        ))
        serialized = repr(profiles).lower()
        self.assertNotIn("sudo", serialized)
        self.assertNotIn("install", serialized)

    def test_each_profile_pins_native_atomic_disassembly(self):
        profiles = concurrency_c3_ipc_refcount.load_manifest(ROOT)["profiles"]
        tokens = {
            profile["id"]: " ".join(
                token
                for function in profile["configured_compile"]["functions"].values()
                for token in function["disassembly_order"]
            )
            for profile in profiles
        }
        self.assertIn("lock cmpxchg", tokens["x86_64-ipc-refcount-c3"])
        self.assertIn("cas\t", tokens["arm64-ipc-refcount-c3"])
        self.assertIn("ldxr\t", tokens["arm64-ipc-refcount-c3"])
        self.assertIn("amocas.w\t", tokens["riscv64-ipc-refcount-c3"])
        self.assertIn("lr.w\t", tokens["riscv64-ipc-refcount-c3"])
        self.assertIn("laa\t", tokens["s390x-ipc-refcount-c3"])
        self.assertIn("cs\t", tokens["s390x-ipc-refcount-c3"])

    def test_declared_source_and_model_hashes_are_current(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        identities = dict(manifest["kernel"]["source_identities"])
        for case in manifest["model"]["cases"]:
            identities[case["path"]] = case["sha256"]
        for name, expected in identities.items():
            with self.subTest(name=name):
                self.assertEqual(
                    concurrency_c3_ipc_refcount._sha256(ROOT / name), expected
                )

    def test_source_model_and_contract_checks_pass(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        checks, evidence = concurrency_c3_ipc_refcount._semantic_checks(
            ROOT, manifest
        )
        self.assertTrue(all(check["passed"] for check in checks), checks)
        self.assertEqual(evidence["source_get_count"], 1)
        self.assertEqual(evidence["source_put_count"], 1)
        self.assertEqual(evidence["source_destroy_count"], 1)
        self.assertEqual(evidence["positive_decrement_count"], 1)
        self.assertEqual(evidence["positive_get_count"], 1)
        self.assertEqual(evidence["negative_resurrection_count"], 1)

    def test_bounded_cas_argument_and_lifetime_boundaries_are_explicit(self):
        prop = concurrency_c3_ipc_refcount.load_manifest(ROOT)["property"]
        self.assertIn("initial value one", prop["model_argument"])
        self.assertIn("first compare/exchange", prop["model_argument"])
        self.assertIn("caller locking", prop["stability_argument"])
        excluded = " ".join(prop["exclusions"]).lower()
        for boundary in (
            "rcu grace", "allocator reuse", "third refcount update",
            "saturation", "architecture", "progress", "whole-kernel",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, excluded)

    def test_source_candidate_cannot_be_promoted_with_bad_witness(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][0]["expected"].update(
            marker="Ok", observation="Sometimes", positive=1, negative=1
        )
        with mock.patch.object(
            concurrency_c3_ipc_refcount, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "cannot satisfy its evidence role",
            ):
                concurrency_c3_ipc_refcount.load_manifest(ROOT)

    def test_unsafe_control_cannot_become_verification_candidate(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][1]["verification_candidate"] = True
        with mock.patch.object(
            concurrency_c3_ipc_refcount, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "cannot satisfy its evidence role",
            ):
                concurrency_c3_ipc_refcount.load_manifest(ROOT)

    def test_pair_condition_drift_is_rejected(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][1]["expected"]["condition"] = (
            "exists (0:released=0 /\\ 1:acquired=0)"
        )
        with mock.patch.object(
            concurrency_c3_ipc_refcount, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "condition drift",
            ):
                concurrency_c3_ipc_refcount.load_manifest(ROOT)

    def test_mandatory_stability_exclusion_cannot_be_removed(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["property"]["exclusions"] = [
            item for item in changed["property"]["exclusions"]
            if "caller-locking" not in item.lower()
        ]
        with mock.patch.object(
            concurrency_c3_ipc_refcount, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "caller-locking exclusion",
            ):
                concurrency_c3_ipc_refcount.load_manifest(ROOT)

    def test_function_symbol_parser_is_exact(self):
        text = (
            "0000000000000010 g     F .text\t0000000000000020 ipc_rcu_getref\n"
            "0000000000000030 g     F .text\t0000000000000040 ipc_rcu_putref\n"
        )
        self.assertEqual(
            concurrency_c3_ipc_refcount._function_symbols(
                text, {"ipc_rcu_getref", "ipc_rcu_putref"}
            ),
            {
                "ipc_rcu_getref": {
                    "section": ".text", "value": "0000000000000010", "size": 32,
                },
                "ipc_rcu_putref": {
                    "section": ".text", "value": "0000000000000030", "size": 64,
                },
            },
        )

    def test_build_directory_escape_is_rejected(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["profiles"][0]["build_directory"] = "../outside"
        with mock.patch.object(
            concurrency_c3_ipc_refcount, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "project-relative",
            ):
                concurrency_c3_ipc_refcount.load_manifest(ROOT)

    def test_profile_inventory_reordering_is_rejected(self):
        manifest = concurrency_c3_ipc_refcount.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["profiles"][1], changed["profiles"][2] = (
            changed["profiles"][2], changed["profiles"][1]
        )
        with mock.patch.object(
            concurrency_c3_ipc_refcount, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "profile inventory",
            ):
                concurrency_c3_ipc_refcount.load_manifest(ROOT)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "already exists",
            ):
                concurrency_c3_ipc_refcount.run_c3_ipc_refcount(
                    ROOT, Path(temporary)
                )

    def test_boolean_timeout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with self.assertRaisesRegex(
                concurrency_c3_ipc_refcount.ConcurrencyC3IpcRefcountError,
                "positive integer",
            ):
                concurrency_c3_ipc_refcount.run_c3_ipc_refcount(
                    ROOT, output, True
                )


if __name__ == "__main__":
    unittest.main()
