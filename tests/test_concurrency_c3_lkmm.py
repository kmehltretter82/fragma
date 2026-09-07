from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c3_lkmm


ROOT = Path(__file__).resolve().parents[1]


def rendered_output(case):
    expected = case["expected"]
    states = "".join(f"state-{number};\n" for number in range(expected["states"]))
    flags = "".join(f"Flag {flag}\n" for flag in expected["flags"])
    return (
        f"Test {expected['test']} {expected['disposition']}\n"
        f"States {expected['states']}\n"
        f"{states}"
        f"{expected['marker']}\n"
        "Witnesses\n"
        f"Positive: {expected['positive']} Negative: {expected['negative']}\n"
        f"{flags}"
        f"Condition {expected['condition']}\n"
        f"Observation {expected['test']} {expected['observation']} "
        f"{expected['positive']} {expected['negative']}\n"
        f"Time {expected['test']} 0.01\n"
        f"Hash={expected['hash']}\n"
    )


class ConcurrencyC3LkmmTests(unittest.TestCase):
    def test_manifest_is_calibration_only_and_has_two_detecting_pairs(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        self.assertEqual(manifest["scope"]["evidence_kind"], "semantic_calibration")
        self.assertEqual(len(manifest["cases"]), 4)
        self.assertEqual(len(manifest["pairs"]), 2)
        by_id = {case["id"]: case for case in manifest["cases"]}
        for pair in manifest["pairs"]:
            weak = by_id[pair["weakened_control"]]
            ordered = by_id[pair["ordered_calibration"]]
            self.assertEqual(weak["expected"]["observation"], "Sometimes")
            self.assertGreater(weak["expected"]["positive"], 0)
            self.assertEqual(ordered["expected"]["observation"], "Never")
            self.assertEqual(ordered["expected"]["positive"], 0)
            self.assertEqual(
                weak["expected"]["condition"], ordered["expected"]["condition"]
            )

    def test_provider_is_explicitly_bound_to_vendored_library(self):
        provider = concurrency_c3_lkmm.load_manifest(ROOT)["provider"]
        self.assertEqual(
            provider["fixed_arguments"],
            ["-set-libdir", "{library_directory}", "-conf", "linux-kernel.cfg"],
        )
        self.assertEqual(provider["library_upstream"]["tag"], "7.58")
        self.assertEqual(provider["library_upstream"]["license"], "CeCILL-B")
        self.assertEqual(
            set(Path(name).name for name in provider["library_identities"]),
            {"LICENSE.txt", "README.md", "stdlib.cat", "cross.cat", "cos-opt.cat"},
        )

    def test_declared_source_and_library_hashes_are_current(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        identities = {
            **manifest["kernel"]["source_identities"],
            **manifest["provider"]["library_identities"],
        }
        for name, expected in identities.items():
            with self.subTest(name=name):
                self.assertEqual(concurrency_c3_lkmm._sha256(ROOT / name), expected)

    def test_parser_accepts_complete_pinned_shape(self):
        case = concurrency_c3_lkmm.load_manifest(ROOT)["cases"][0]
        parsed = concurrency_c3_lkmm.parse_herd_output(rendered_output(case))
        self.assertEqual(parsed["test"], case["expected"]["test"])
        self.assertEqual(parsed["observation"], "Sometimes")
        self.assertEqual(parsed["flags"], [])
        self.assertEqual(len(parsed["state_values"]), parsed["states"])
        self.assertEqual(parsed["seconds"], 0.01)

    def test_parser_retains_a_data_race_flag(self):
        case = deepcopy(concurrency_c3_lkmm.load_manifest(ROOT)["cases"][0])
        case["expected"]["flags"] = ["data-race"]
        parsed = concurrency_c3_lkmm.parse_herd_output(rendered_output(case))
        self.assertEqual(parsed["flags"], ["data-race"])

    def test_parser_distinguishes_execution_witnesses_from_distinct_states(self):
        case = deepcopy(concurrency_c3_lkmm.load_manifest(ROOT)["cases"][0])
        case["expected"].update(states=1, positive=0, negative=2)
        parsed = concurrency_c3_lkmm.parse_herd_output(rendered_output(case))
        self.assertEqual(parsed["states"], 1)
        self.assertEqual(parsed["positive"] + parsed["negative"], 2)

    def test_parser_rejects_truncation_extra_text_and_count_contradictions(self):
        case = concurrency_c3_lkmm.load_manifest(ROOT)["cases"][0]
        valid = rendered_output(case)
        invalid = [
            valid.removesuffix("\n").rsplit("\n", 1)[0] + "\n",
            valid + "unexpected\n",
            valid.replace("States 4", "States 5", 1),
            valid.replace("Observation MP+poonceonces Sometimes 1 3",
                          "Observation MP+poonceonces Sometimes 0 4", 1),
            valid.replace("Time MP+poonceonces", "Time another-test", 1),
        ]
        for value in invalid:
            with self.subTest(value=value[-80:]):
                with self.assertRaises(concurrency_c3_lkmm.ConcurrencyC3LkmmError):
                    concurrency_c3_lkmm.parse_herd_output(value)

    def test_comment_mentions_do_not_satisfy_operation_gate(self):
        source = "/* smp_mb(); */\nWRITE_ONCE(*x, 1);\n// smp_load_acquire(x)\n"
        code = concurrency_c3_lkmm._code_without_comments(source)
        self.assertTrue(concurrency_c3_lkmm._operation_present(code, "WRITE_ONCE"))
        self.assertFalse(concurrency_c3_lkmm._operation_present(code, "smp_mb"))
        self.assertFalse(
            concurrency_c3_lkmm._operation_present(code, "smp_load_acquire")
        )

    def test_weak_control_cannot_be_promoted_to_never(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][0]["expected"].update(
            observation="Never", positive=0, negative=4, marker="No"
        )
        with mock.patch.object(
            concurrency_c3_lkmm, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_lkmm.ConcurrencyC3LkmmError,
                "detecting weak control",
            ):
                concurrency_c3_lkmm.load_manifest(ROOT)

    def test_ordered_calibration_cannot_become_a_permitted_outcome(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][1]["expected"].update(
            observation="Sometimes", positive=1, negative=2, marker="Ok"
        )
        with mock.patch.object(
            concurrency_c3_lkmm, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_lkmm.ConcurrencyC3LkmmError,
                "ordered Never calibration",
            ):
                concurrency_c3_lkmm.load_manifest(ROOT)

    def test_pair_must_remove_the_named_ordering_primitive(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][0]["forbidden_operations"].remove("smp_store_release")
        with mock.patch.object(
            concurrency_c3_lkmm, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_lkmm.ConcurrencyC3LkmmError,
                "weak control does not remove pair primitive",
            ):
                concurrency_c3_lkmm.load_manifest(ROOT)

    def test_model_relative_escape_is_rejected(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["cases"][0]["path"] = "../linux-kernel.cat"
        with mock.patch.object(
            concurrency_c3_lkmm, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_lkmm.ConcurrencyC3LkmmError, "model-relative"
            ):
                concurrency_c3_lkmm.load_manifest(ROOT)

    def test_fake_complete_run_accepts_four_calibrations_and_zero_kernel_claims(self):
        manifest = concurrency_c3_lkmm.load_manifest(ROOT)
        by_path = {case["path"]: case for case in manifest["cases"]}

        def fake_run(argv, cwd, timeout):
            if argv[-1] == "-version":
                stdout = manifest["provider"]["expected_version"] + "\n"
            elif argv[-1] == "-libdir":
                stdout = "/compiled/default/is/not/the/explicit/library\n"
            else:
                stdout = rendered_output(by_path[argv[-1]])
            return {
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
                "timed_out": False,
            }

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            concurrency_c3_lkmm, "_run", side_effect=fake_run
        ):
            output = Path(temporary) / "evidence"
            result = concurrency_c3_lkmm.run_c3_lkmm(ROOT, output)
            self.assertIs(result["accepted"], True)
            self.assertEqual(result["calibration_count"], 4)
            self.assertEqual(result["kernel_verification_count"], 0)
            self.assertIs(result["c3_capability_baseline_complete"], True)
            self.assertIs(result["c3_stage_complete"], False)
            self.assertIs(result["sudo_or_install_used"], False)
            self.assertTrue((output / "pilot-audit.json").is_file())
            self.assertTrue((output / "cases/mp_once_once/stdout.txt").is_file())

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                concurrency_c3_lkmm.ConcurrencyC3LkmmError, "already exists"
            ):
                concurrency_c3_lkmm.run_c3_lkmm(ROOT, Path(temporary))

    def test_boolean_timeout_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with self.assertRaisesRegex(
                concurrency_c3_lkmm.ConcurrencyC3LkmmError,
                "positive integer",
            ):
                concurrency_c3_lkmm.run_c3_lkmm(ROOT, output, True)


if __name__ == "__main__":
    unittest.main()
