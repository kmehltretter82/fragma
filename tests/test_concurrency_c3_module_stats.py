from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c3_module_stats


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyC3ModuleStatsTests(unittest.TestCase):
    def test_manifest_has_one_source_property_and_two_detecting_pairs(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        self.assertEqual(
            manifest["property"]["kind"], "kernel_atomic_rmw_no_lost_update"
        )
        self.assertEqual(len(manifest["model"]["cases"]), 4)
        self.assertEqual(len(manifest["model"]["pairs"]), 2)
        by_id = {case["id"]: case for case in manifest["model"]["cases"]}
        self.assertIs(by_id["atomic_inc_positive"]["verification_candidate"], True)
        self.assertTrue(all(
            not case["verification_candidate"]
            for case_id, case in by_id.items()
            if case_id != "atomic_inc_positive"
        ))
        for pair in manifest["model"]["pairs"]:
            positive = by_id[pair["positive"]]["expected"]
            negative = by_id[pair["negative"]]["expected"]
            self.assertEqual(positive["condition"], negative["condition"])
            self.assertEqual(positive["observation"], "Never")
            self.assertEqual(positive["positive"], 0)
            self.assertEqual(negative["observation"], "Sometimes")
            self.assertGreater(negative["positive"], 0)

    def test_configuration_is_explicit_and_no_install_step_exists(self):
        profile = concurrency_c3_module_stats.load_manifest(ROOT)["profile"]
        self.assertEqual(profile["arch"], "x86_64")
        self.assertEqual(
            profile["configuration"]["enable"],
            ["DEBUG_FS", "MODULE_DEBUG", "MODULE_STATS"],
        )
        serialized = repr(profile).lower()
        self.assertNotIn("sudo", serialized)
        self.assertNotIn("install", serialized)

    def test_declared_source_model_and_config_tool_hashes_are_current(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        identities = dict(manifest["kernel"]["source_identities"])
        identities[manifest["profile"]["configuration"]["config_tool"]] = (
            manifest["profile"]["configuration"]["config_tool_sha256"]
        )
        for case in manifest["model"]["cases"]:
            identities[case["path"]] = case["sha256"]
        for name, expected in identities.items():
            with self.subTest(name=name):
                self.assertEqual(
                    concurrency_c3_module_stats._sha256(ROOT / name), expected
                )

    def test_source_model_and_contract_checks_pass(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        checks, evidence = concurrency_c3_module_stats._semantic_checks(
            ROOT, manifest
        )
        self.assertTrue(all(check["passed"] for check in checks), checks)
        self.assertEqual(evidence["source_update_count"], 1)
        self.assertEqual(evidence["model_update_count"], 2)
        self.assertEqual(
            evidence["definition_callsite_inventory"],
            [
                {"path": "kernel/module/main.c", "count": 1},
                {"path": "kernel/module/stats.c", "count": 1},
            ],
        )

    def test_witnesses_need_not_equal_distinct_states(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        by_id = {case["id"]: case for case in manifest["model"]["cases"]}
        atomic = by_id["atomic_inc_positive"]["expected"]
        split = by_id["split_once_negative"]["expected"]
        self.assertEqual(atomic["states"], 1)
        self.assertEqual(atomic["positive"] + atomic["negative"], 2)
        self.assertEqual(split["states"], 2)
        self.assertEqual(split["positive"] + split["negative"], 4)

    def test_source_candidate_cannot_be_promoted_with_bad_witness(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][0]["expected"].update(
            marker="Ok", observation="Sometimes", positive=1, negative=1
        )
        with mock.patch.object(
            concurrency_c3_module_stats, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                "cannot satisfy its evidence role",
            ):
                concurrency_c3_module_stats.load_manifest(ROOT)

    def test_weakened_control_cannot_become_verification_candidate(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][1]["verification_candidate"] = True
        with mock.patch.object(
            concurrency_c3_module_stats, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                "cannot satisfy its evidence role",
            ):
                concurrency_c3_module_stats.load_manifest(ROOT)

    def test_pair_condition_drift_is_rejected(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["model"]["cases"][1]["expected"]["condition"] = (
            "exists ([counter]=0)"
        )
        with mock.patch.object(
            concurrency_c3_module_stats, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                "condition drift",
            ):
                concurrency_c3_module_stats.load_manifest(ROOT)

    def test_architecture_and_progress_exclusions_are_mandatory(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        for word in ("architecture", "progress"):
            changed = deepcopy(manifest)
            changed["property"]["exclusions"] = [
                item
                for item in changed["property"]["exclusions"]
                if word not in item.lower()
            ]
            with self.subTest(word=word), mock.patch.object(
                concurrency_c3_module_stats, "_strict_json", return_value=changed
            ):
                with self.assertRaisesRegex(
                    concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                    f"omits {word} exclusion",
                ):
                    concurrency_c3_module_stats.load_manifest(ROOT)

    def test_build_directory_escape_is_rejected(self):
        manifest = concurrency_c3_module_stats.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["profile"]["build_directory"] = "../outside"
        with mock.patch.object(
            concurrency_c3_module_stats, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                "project-relative",
            ):
                concurrency_c3_module_stats.load_manifest(ROOT)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                "already exists",
            ):
                concurrency_c3_module_stats.run_c3_module_stats(
                    ROOT, Path(temporary)
                )

    def test_boolean_timeout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with self.assertRaisesRegex(
                concurrency_c3_module_stats.ConcurrencyC3ModuleStatsError,
                "positive integer",
            ):
                concurrency_c3_module_stats.run_c3_module_stats(
                    ROOT, output, True
                )


if __name__ == "__main__":
    unittest.main()
