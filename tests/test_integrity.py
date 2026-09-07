"""Scoped-review identities and final dependency ordering fail closed."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma import analysis_policy, integrity
from fragma.sources import SourceError, sha256
from fragma.suite import finalize_results


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        names = ["harness.c", "specs.h", "source/lib/helper.c", "build/fragma-build.json",
                 "profile.yaml", "notes.md", "receipt.json", "fragma/analysis_policy.py"]
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + "\n")
        self.revision = "a" * 40
        self.model = {"analysis": {"wp_model": "Typed", "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS),
                                  "runtime_checks": {"pointer_formation": "object-or-null"}},
                      "machdep": {"sha256": sha256(self.root / "profile.yaml")}}
        self.build = {"source": str(self.root / "source"), "path": str(self.root / "build")}
        self.tools = {"lock_sha256": "b" * 64}
        self.prepared = {"frama_cpp_command": "gcc -E -C", "annotations": "native ACSL"}
        context = {"kernel_revision": self.revision, "profile": "example-gcc",
                   "analysis": copy.deepcopy(self.model["analysis"]),
                   "analysis_pipeline": {"kind": "wp-rte", "functions": ["helper"]},
                   "toolchain_lock_sha256": self.tools["lock_sha256"],
                   "preprocessing": {"cpp_command": "gcc -E -C", "annotations": "native ACSL",
                                     "input_mode": "kernel-tu", "extra_args": ["-std=gnu11"]},
                   "file_hashes": {name: sha256(self.root / name) for name in [*names[:5], names[-1]]},
                   "review_evidence": ["notes.md", "receipt.json"]}
        self.target = {"id": "helper", "profile": "example-gcc", "analysis": "wp", "input_mode": "kernel-tu",
                       "functions": ["helper"],
                       "source": "lib/helper.c", "harness": "harness.c", "specs": "specs.h",
                       "review_context": context, "reviewed_warnings": [{
                           "message": "Missing RTE guards", "file_hashes": {"harness.c": sha256(self.root / "harness.c")},
                           "review_evidence": ["notes.md"]}], "reviewed_smoke": []}

    def validate(self):
        return integrity.validate_review(self.root, self.target, self.revision, self.model,
                                         self.build, self.tools, self.prepared)

    def test_approval_preserves_exact_context_and_tracks_evidence(self):
        review = self.validate()
        self.assertEqual(review["status"], "passed")
        self.assertEqual(review["review_context"], self.target["review_context"])
        self.assertEqual(len(review["tracked_files"]), 8)
        self.assertEqual(integrity.changed_files(review["tracked_files"]), [])

    def test_changed_specification_rejects_review(self):
        (self.root / "specs.h").write_text("different specification\n")
        with self.assertRaisesRegex(SourceError, "reviewed inputs changed"):
            self.validate()

    def test_changed_analysis_options_reject_review(self):
        self.model["analysis"]["arithmetic_flags"] = []
        with self.assertRaisesRegex(SourceError, "arithmetic/memory"):
            self.validate()

    def test_changed_preprocessing_policy_rejects_review(self):
        self.prepared["frama_cpp_command"] += " -DCHANGED=1"
        with self.assertRaisesRegex(SourceError, "preprocessing policy"):
            self.validate()

    def test_old_review_cannot_inherit_new_pointer_policy(self):
        del self.target["review_context"]["analysis"]["runtime_checks"]
        with self.assertRaisesRegex(SourceError, "runtime model"):
            self.validate()

    def test_missing_or_weakened_policy_never_defaults_to_checked(self):
        for runtime in (None, {}, {"pointer_formation": "disabled"}, {"pointer_formation": True}):
            with self.subTest(runtime=runtime):
                self.model["analysis"]["runtime_checks"] = runtime
                self.target["review_context"]["analysis"]["runtime_checks"] = runtime
                with self.assertRaisesRegex(SourceError, "unsupported .* analysis policy"):
                    self.validate()

    def test_changed_pipeline_or_function_selection_rejects_old_review(self):
        self.target["functions"].append("another_helper")
        with self.assertRaisesRegex(SourceError, "pipeline mismatch"):
            self.validate()

    def test_missing_pipeline_identity_rejects_old_review(self):
        del self.target["review_context"]["analysis_pipeline"]
        with self.assertRaisesRegex(SourceError, "pipeline mismatch"):
            self.validate()

    def test_pipeline_review_preserves_json_types(self):
        self.target.update(analysis="eva", entry="example_entry",
                           analysis_pipeline={"kind": "rte-eva"})
        pipeline = analysis_policy.pipeline_identity(self.target)
        self.target["review_context"]["analysis_pipeline"] = pipeline
        self.assertEqual(self.validate()["status"], "passed")
        for field, wrong_type in (("eva_auto_builtins", 1),
                                  ("rte_use_eva_results", 0),
                                  ("eva_slevel", 100.0)):
            with self.subTest(field=field):
                changed = copy.deepcopy(pipeline)
                changed[field] = wrong_type
                self.target["review_context"]["analysis_pipeline"] = changed
                with self.assertRaisesRegex(SourceError, "pipeline mismatch"):
                    self.validate()

    def test_policy_implementation_is_a_required_review_input(self):
        del self.target["review_context"]["file_hashes"]["fragma/analysis_policy.py"]
        with self.assertRaisesRegex(SourceError, "omits"):
            self.validate()

    def test_changed_policy_implementation_invalidates_review(self):
        (self.root / "fragma/analysis_policy.py").write_text("changed guard policy\n")
        with self.assertRaisesRegex(SourceError, "reviewed inputs changed"):
            self.validate()

    def test_new_machine_description_rejects_old_review(self):
        self.model["machdep"]["sha256"] = "c" * 64
        with self.assertRaisesRegex(SourceError, "fresh machine"):
            self.validate()

    def test_omitted_source_identity_rejects_review(self):
        del self.target["review_context"]["file_hashes"]["source/lib/helper.c"]
        with self.assertRaisesRegex(SourceError, "omits"):
            self.validate()

    def test_missing_review_evidence_rejected(self):
        self.target["review_context"]["review_evidence"] = ["missing.md"]
        with self.assertRaisesRegex(SourceError, "missing or out-of-project"):
            self.validate()

    def test_conflicting_receipts_never_choose_the_latest_hash(self):
        a = integrity.receipt(self.root / "harness.c")
        with self.assertRaisesRegex(SourceError, "conflicting"):
            integrity.merge_records([a], [{**a, "sha256": "d" * 64}])

    def test_absolute_hash_maps_and_support_directories_are_tracked(self):
        expected = sha256(self.root / "specs.h")
        metadata = {"input_hashes": {str(self.root / "harness.c"): "c" * 64},
                    "support_data": {"directory": str(self.root), "files": {"specs.h": expected}},
                    "libraries": {"example": {"resolved_path": str(self.root / "notes.md"), "sha256": "d" * 64}}}
        records = integrity.merge_records(integrity.metadata_records(metadata))
        self.assertEqual(len(records), 3)
        self.assertEqual(len(integrity.changed_files(records)), 2)

    def test_symlink_retargeting_invalidates_invoked_input(self):
        alias = self.root / "tool"
        alias.symlink_to(self.root / "harness.c")
        record = integrity.receipt(alias)
        alias.unlink()
        alias.symlink_to(self.root / "specs.h")
        self.assertEqual(len(integrity.changed_files([record])), 1)

    def test_changed_companion_invalidated_before_parent_finalization(self):
        watched = integrity.receipt(self.root / "harness.c")
        (self.root / "harness.c").write_text("changed driver\n")
        items = [{"target": {"id": "parent"}, "evaluation": {"target_id": "parent", "accepted": False, "status": "needs-companion"}},
                 {"target": {"id": "companion"}, "evaluation": {"target_id": "companion", "accepted": True, "status": "calibration-passed"},
                  "integrity_inputs": [watched]}]

        def finalize(evaluations):
            self.assertFalse(evaluations[1]["accepted"])
            self.assertFalse(evaluations[1]["local_policy_passed"])
            self.assertEqual(evaluations[1]["status"], "input-changed")
            return evaluations

        with patch("fragma.suite.report.finalize_companions", side_effect=finalize):
            finalize_results(items, [])
        self.assertFalse(items[1]["accepted"])


if __name__ == "__main__":
    unittest.main()
