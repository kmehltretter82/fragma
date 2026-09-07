"""The common runner requests and checks the actual current guard pipeline."""

import contextlib
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma import analysis_policy, common24_calibration, frontend_policy, profiles, suite
from fragma.sources import sha256


class SuitePolicyTests(unittest.TestCase):
    def test_registered_reviews_bind_explicit_current_model_and_pipeline(self):
        root = Path(__file__).resolve().parents[1]
        _, targets, ledger = suite.load_registry(root)
        configured = profiles.load_profiles(root)
        reviewed = {name: target for name, target in targets.items()
                    if target.get("review_context")}
        first_common = {"common.unaligned24.arm", "common.unaligned24.powerpc32", "common.unaligned24.m68k"}
        next_common = {"common.unaligned24.arm64", "common.unaligned24.riscv64", "common.unaligned24.sh"}
        third_common = {"common.unaligned24.alpha", "common.unaligned24.x86_64", "common.unaligned24.um-x86_64"}
        common = first_common | next_common | third_common
        self.assertEqual(set(reviewed), {"string.verified.strnchr", "string.verified.strlcat",
            "s390.unaligned24", "s390.unaligned48", "s390.tod_to_ns",
            "riscv.base-encoders", "arm64.cpuid"} | common)
        self.assertEqual(len(reviewed), 16)
        for name, target in reviewed.items():
            with self.subTest(target=name):
                context = target["review_context"]
                self.assertEqual(context["analysis"],
                    analysis_policy.model_identity(configured[target["profile"]]["analysis"]))
                self.assertEqual(context["analysis_pipeline"], analysis_policy.pipeline_identity(target))
                review_docs = ["common/REVIEW-WAVE3-20260906.md"] if name in common else ["docs/pointer-policy-review.md"]
                if name in first_common | next_common:
                    review_docs.append("common/REVIEW-WAVE2-20260906.md")
                if name in first_common:
                    review_docs.append("common/REVIEW-20260906.md")
                for filename in ("fragma/analysis_policy.py", *review_docs):
                    self.assertEqual(context["file_hashes"][filename], sha256(root / filename))
                for review_doc in review_docs:
                    self.assertIn(review_doc, context["review_evidence"])
                if name in common:
                    self.assertEqual(context["compiler_calibration"], common24_calibration.review_identity(target))
                    self.assertEqual(context["preprocessing"]["frontend_policy"], frontend_policy.identity(target))
                    self.assertEqual(target["reviewed_smoke"], [])
                    self.assertEqual(len(target["reviewed_warnings"]), 6 if name.endswith("powerpc32") else 5)
                    for filename in common24_calibration.required_files(target):
                        self.assertEqual(context["file_hashes"][filename], sha256(root / filename))
                    for filename in context["review_evidence"]:
                        self.assertEqual(context["file_hashes"][filename], sha256(root / filename))
                    for assumption in target["assumptions"]:
                        self.assertEqual(ledger[assumption]["review_status"], "reviewed-assumption")
                        self.assertIs(ledger[assumption]["implementation_proved"], False)
                        self.assertIn(target["profile"], ledger[assumption]["reviewed_profiles"])
                    if name in third_common:
                        self.assertEqual(target["assumptions"],
                                         ["common24-wave3-types", "common24-wave3-frontend"])
                        for assumption in target["assumptions"]:
                            self.assertEqual(set(ledger[assumption]["reviewed_profiles"]),
                                             {"alpha-gcc", "x86_64-gcc", "um-x86_64-gcc"})
                            self.assertIn("common/REVIEW-WAVE3-20260906.md",
                                          ledger[assumption]["review_evidence"])

    def execute(self, *, analysis="eva", pipeline=None, audit_pointer="true"):
        with tempfile.TemporaryDirectory(prefix="fragma pipeline ") as temporary:
            root = Path(temporary)
            target = {"id": "fixture", "profile": "fixture-gcc", "source": "helper.c",
                      "harness": "helper.c", "functions": ["helper"], "analysis": analysis,
                      "input_mode": "standalone", "role": "proof", "required_properties": [],
                      "claims": [], "assumptions": []}
            if analysis == "eva":
                target.update(entry="entry", role="calibration")
            if pipeline is not None:
                target["analysis_pipeline"] = {"kind": pipeline}
            model = {"status": "passed", "level": "L1", "fingerprint": "model",
                     "analysis": {"machdep": "fixture", "wp_model": "Typed",
                         "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS),
                         "runtime_checks": {"pointer_formation": "object-or-null"}}}
            correctness = {flag.removeprefix("-no"): "false" for flag in analysis_policy.ARITHMETIC_FLAGS}
            correctness.update({"-warn-invalid-pointer": audit_pointer, "-main": "entry",
                                "-eva-builtins-auto": "true", "-eva-builtin": ""})
            audit = {"parameters": {"eva": {"correctness-parameters": correctness}}}
            prepared = {"frama_cpp_command": "gcc -E -C", "frama_input": str(root / "helper.c"),
                        "cwd": str(root), "inputs": []}
            build = {"path": str(root), "files": {}, "receipt_sha256": "a" * 64}
            command = []

            def run(argv, **kwargs):
                command.extend(argv)
                kwargs["log"].write_text("test-only analyzer invocation\n")
                return {"argv": argv, "cwd": str(root), "returncode": 0,
                        "timed_out": False, "seconds": 0.01}

            with contextlib.ExitStack() as stack:
                overrides = {
                    "provenance.check_target": {"passed": True},
                    "assumption_records": [],
                    "inputs.kernel_model_check": {},
                    "inputs.prepare_input": prepared,
                    "integrity.validate_review": None,
                    "integrity.receipt": {},
                    "integrity.metadata_records": [],
                    "integrity.profile_records": [],
                    "integrity.merge_records": [],
                    "integrity.changed_files": [],
                    "inputs.audit_inputs": audit,
                    "report.parse_wp_report": [],
                    "report.parse_properties": [],
                }
                for name, value in overrides.items():
                    stack.enter_context(patch("fragma.suite." + name, return_value=copy.deepcopy(value)))
                stack.enter_context(patch("fragma.suite.inputs.run_recorded", side_effect=run))
                result = suite.execute_target(root, root, "b" * 40, target, model, build,
                    {"tools": {"frama-c": {"path": "frama-c"}}}, {}, root / "result", {},
                    timeout=1, jobs=2, provers="alt-ergo,z3", wall_timeout=30)
            return result, command

    def test_rte_runs_before_eva_and_cannot_reuse_prior_eva_results(self):
        result, command = self.execute(pipeline="rte-eva")
        self.assertEqual(command.count("-warn-invalid-pointer"), 1)
        self.assertEqual(command[command.index("-rte"):command.index("-eva")],
                         ["-rte", "-rte-select", "helper,entry", "-rte-no-use-eva-results", "-then"])
        self.assertLess(command.index("-warn-invalid-pointer"), command.index("-rte"))
        checked = result["validated_analysis_policy"]
        self.assertEqual(checked["status"], "checked")
        self.assertEqual(checked["pipeline"]["kind"], "rte-eva")
        # The mock emits no properties: checking policy is not accepting proof.
        self.assertIs(result["accepted"], False)

    def test_plain_eva_still_uses_the_explicit_pointer_policy(self):
        result, command = self.execute()
        self.assertNotIn("-rte", command)
        self.assertEqual(result["validated_analysis_policy"]["pipeline"]["kind"], "eva")
        self.assertEqual(command.count("-warn-invalid-pointer"), 1)

    def test_wp_uses_pointer_checks_and_the_unchanged_arithmetic_policy(self):
        result, command = self.execute(analysis="wp")
        start = command.index("-no-warn-signed-overflow")
        self.assertEqual(command[start:start + 6],
                         [*analysis_policy.ARITHMETIC_FLAGS, "-warn-invalid-pointer"])
        self.assertIn("-wp-rte", command)
        self.assertEqual(result["validated_analysis_policy"]["pipeline"]["kind"], "wp-rte")

    def test_successful_analyzer_with_disabled_actual_checks_cannot_pass(self):
        result, _ = self.execute(pipeline="rte-eva", audit_pointer="false")
        self.assertIs(result["accepted"], False)
        self.assertEqual(result["status"], "tool-error")
        self.assertIn("actual audited semantic settings differ", result["error"])
        self.assertNotIn("validated_analysis_policy", result)


if __name__ == "__main__":
    unittest.main()
