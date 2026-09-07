from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from fragma import concurrency_c3_ipc_refcount
from fragma import concurrency_c3_llsc_progress


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyC3LlscProgressTests(unittest.TestCase):
    def test_manifest_has_six_fail_closed_profile_assessments(self):
        manifest = concurrency_c3_llsc_progress.load_manifest(ROOT)
        self.assertEqual(
            [profile["id"] for profile in manifest["profiles"]],
            [
                "arm64-ipc-refcount-c3",
                "riscv64-ipc-refcount-c3",
                "arm32-ipc-refcount-c3",
                "powerpc32-smp-ipc-refcount-c3",
                "sh-smp-ipc-refcount-c3",
                "alpha-smp-ipc-refcount-c3",
            ],
        )
        self.assertTrue(all(
            profile["verification_candidate"] is False
            and profile["decision"] == "not_promoted"
            for profile in manifest["profiles"]
        ))
        self.assertEqual(
            manifest["base"]["progress_implementation_profiles"],
            [
                "x86_64-ipc-refcount-c3",
                "s390x-ipc-refcount-c3",
                "um-x86_64-smp-ipc-refcount-c3",
            ],
        )
        self.assertEqual(manifest["base"]["kernel_verification_count"], 2)
        self.assertEqual(
            manifest["base"]["progress_kernel_verification_count"], 1
        )
        self.assertEqual(
            manifest["base"]["progress_implementation_mapping_count"], 3
        )
        excluded = " ".join(manifest["exclusions"]).lower()
        for boundary in (
            "no ll/sc profile", "hypothetical", "native lse", "zacas",
            "scheduler fairness", "wait-freedom", "rcu progress",
            "whole-kernel",
        ):
            with self.subTest(boundary=boundary):
                self.assertIn(boundary, excluded)

    def test_bounded_diagnostic_is_finite_but_never_verification(self):
        diagnostic = concurrency_c3_llsc_progress.load_manifest(ROOT)[
            "conditional_diagnostic"
        ]
        actual = concurrency_c3_llsc_progress._bounded_diagnostic(diagnostic)
        self.assertEqual(
            {key: actual[key] for key in diagnostic["expected"]},
            diagnostic["expected"],
        )
        self.assertEqual(actual["maximum_witness"]["source_cas_attempts"], 4)
        self.assertEqual(
            actual["maximum_witness"]["failure_schedule"], [2, 2, 2, 2]
        )
        self.assertIs(diagnostic["verification_candidate"], False)

    def test_unbounded_failure_control_detects_retry_cycle(self):
        manifest = concurrency_c3_llsc_progress.load_manifest(ROOT)
        expected = manifest["conditional_diagnostic"][
            "unbounded_failure_control"
        ]["expected"]
        actual = concurrency_c3_llsc_progress._unbounded_failure_cycle()
        self.assertEqual(
            {key: actual[key] for key in expected},
            expected,
        )
        self.assertEqual(
            [step["event"] for step in actual["trace"]],
            [
                "load-linked",
                "store-conditional-failure",
                "retry-same-cas",
            ],
        )

    def test_profile_promotion_is_rejected(self):
        manifest = concurrency_c3_llsc_progress.load_manifest(ROOT)
        changes = []
        promoted = deepcopy(manifest)
        promoted["profiles"][0]["verification_candidate"] = True
        promoted["profiles"][0]["decision"] = "promoted"
        changes.append(promoted)
        wrong_architecture = deepcopy(manifest)
        wrong_architecture["profiles"][0]["architecture"] = "x86_64"
        changes.append(wrong_architecture)
        wrong_kind = deepcopy(manifest)
        wrong_kind["profiles"][0]["implementation_kind"] = (
            "llsc_only_selected_object"
        )
        changes.append(wrong_kind)
        for changed in changes:
            with self.subTest(change=changed["profiles"][0]), mock.patch.object(
                concurrency_c3_llsc_progress, "_strict_json", return_value=changed
            ):
                with self.assertRaisesRegex(
                    concurrency_c3_llsc_progress.ConcurrencyC3LlscProgressError,
                    "cannot be promoted",
                ):
                    concurrency_c3_llsc_progress.load_manifest(ROOT)

    def test_hypothetical_diagnostic_promotion_is_rejected(self):
        manifest = concurrency_c3_llsc_progress.load_manifest(ROOT)
        changed = deepcopy(manifest)
        changed["conditional_diagnostic"]["verification_candidate"] = True
        with mock.patch.object(
            concurrency_c3_llsc_progress, "_strict_json", return_value=changed
        ):
            with self.assertRaisesRegex(
                concurrency_c3_llsc_progress.ConcurrencyC3LlscProgressError,
                "cannot satisfy its evidence role",
            ):
                concurrency_c3_llsc_progress.load_manifest(ROOT)

    def test_declared_documentation_and_source_checks_are_current(self):
        manifest = concurrency_c3_llsc_progress.load_manifest(ROOT)
        documentation = manifest["documentation"]
        self.assertEqual(
            concurrency_c3_ipc_refcount._sha256(ROOT / documentation["path"]),
            documentation["sha256"],
        )
        self.assertTrue(concurrency_c3_ipc_refcount._ordered(
            (ROOT / documentation["path"]).read_text(),
            documentation["required_order"],
        ))
        for profile in manifest["profiles"]:
            for source in profile["source_checks"]:
                with self.subTest(profile=profile["id"], path=source["path"]):
                    path = ROOT / source["path"]
                    self.assertEqual(
                        concurrency_c3_ipc_refcount._sha256(path),
                        source["sha256"],
                    )
                    self.assertTrue(concurrency_c3_ipc_refcount._ordered(
                        path.read_text(), source["ordered_tokens"]
                    ))

    def test_profile_assessment_records_fresh_full_disassembly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.h"
            source.write_text("load-linked compare store-conditional retry")
            object_path = root / "object.o"
            object_path.write_bytes(b"object")
            profile = {
                "id": "test-profile",
                "architecture": "test",
                "implementation_kind": "llsc_only_selected_object",
                "source_checks": [{
                    "path": "source.h",
                    "sha256": concurrency_c3_ipc_refcount._sha256(source),
                    "ordered_tokens": ["load-linked", "store-conditional", "retry"],
                }],
                "disassembly_order": ["<function>", "ll", "sc", "retry"],
                "verification_candidate": False,
                "decision": "not_promoted",
                "blocking_reason": "Without a finite failure bound.",
            }
            base_profile = {
                "objdump": {"binary": "/usr/bin/objdump"},
                "configured_compile": {"object": "object.o"},
            }
            accepted_profile = {
                "configured_object": {
                    "sha256": concurrency_c3_ipc_refcount._sha256(object_path),
                    "size": object_path.stat().st_size,
                },
            }
            process = {
                "returncode": 0,
                "stdout": "<function>\nll\nsc\nretry\n",
                "stderr": "",
                "timed_out": False,
            }
            with mock.patch.object(
                concurrency_c3_llsc_progress.lkmm,
                "_run",
                return_value=process,
            ):
                checks, result = (
                    concurrency_c3_llsc_progress._run_profile_assessment(
                        root, profile, base_profile, accepted_profile,
                        root / "evidence", 5
                    )
                )
            self.assertTrue(all(check["passed"] for check in checks), checks)
            self.assertTrue(result["passed"])
            self.assertTrue((root / "evidence/disassembly/command.json").is_file())
            self.assertTrue((root / "evidence/assessment.json").is_file())
            object_path.write_bytes(b"changed object")
            with mock.patch.object(
                concurrency_c3_llsc_progress.lkmm,
                "_run",
                return_value=process,
            ):
                stale_checks, stale_result = (
                    concurrency_c3_llsc_progress._run_profile_assessment(
                        root, profile, base_profile, accepted_profile,
                        root / "stale-evidence", 5
                    )
                )
            self.assertFalse(stale_result["passed"])
            self.assertIn(
                "test-profile accepted object identity",
                [check["name"] for check in stale_checks if not check["passed"]],
            )

    def test_artifact_escape_and_result_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = root / "result"
            result.mkdir()
            outside = root / "outside.txt"
            outside.write_text("outside")
            with self.assertRaisesRegex(
                concurrency_c3_llsc_progress.ConcurrencyC3LlscProgressError,
                "escapes result",
            ):
                concurrency_c3_llsc_progress._safe_result_file(
                    result, "../outside.txt"
                )
            linked = root / "linked-result"
            linked.symlink_to(result, target_is_directory=True)
            with self.assertRaisesRegex(
                concurrency_c3_llsc_progress.ConcurrencyC3LlscProgressError,
                "must be a directory",
            ):
                concurrency_c3_llsc_progress._verify_base(
                    ROOT,
                    linked,
                    concurrency_c3_llsc_progress.load_manifest(ROOT),
                )

    def test_summary_keeps_zero_promotion_explicit(self):
        result = {
            "accepted": True,
            "checks": [{"passed": True}],
            "llsc_profile_assessment_count": 1,
            "kernel_verification_count": 0,
            "progress_implementation_mapping_count": 0,
            "detecting_control_count": 1,
            "profiles": [{
                "id": "sample",
                "implementation_kind": "llsc_only_selected_object",
                "decision": "not_promoted",
                "passed": True,
            }],
            "conditional_diagnostic": {
                "actual": {
                    "finite_schedules": 120,
                    "max_store_conditional_attempts": 12,
                },
            },
        }
        summary = concurrency_c3_llsc_progress.render_summary(result)
        self.assertIn("New kernel progress properties: **0**", summary)
        self.assertIn("Promoted LL/SC mappings: **0**", summary)
        self.assertIn("permanently ineligible", summary)

    def test_existing_output_and_boolean_timeout_are_rejected(self):
        manifest = concurrency_c3_llsc_progress.load_manifest(ROOT)
        del manifest
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary)
            with self.assertRaisesRegex(
                concurrency_c3_llsc_progress.ConcurrencyC3LlscProgressError,
                "already exists",
            ):
                concurrency_c3_llsc_progress.audit_llsc_progress(
                    ROOT, Path("unused"), existing
                )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with self.assertRaisesRegex(
                concurrency_c3_llsc_progress.ConcurrencyC3LlscProgressError,
                "positive integer",
            ):
                concurrency_c3_llsc_progress.audit_llsc_progress(
                    ROOT, Path("unused"), output, True
                )


if __name__ == "__main__":
    unittest.main()
