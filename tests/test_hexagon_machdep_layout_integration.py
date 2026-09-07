"""Inert checks for source-derived max_align_t producer orchestration.

The real declaration reader, fixture producer and recorder are used against
temporary synthetic headers. Compiler subprocesses and ELF layout decoding are
mocked. These tests check gates/provenance, never a genuine ABI or L1 model.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma import hexagon_layout as layout
from fragma import hexagon_machdep as adapter


DEFINITION = "struct { long long __ll; long double __ld; }"
OBSERVED = {
    "size": 16, "c_alignment": 8, "gnu_alignment": 8,
    "ll_offset": 0, "ld_offset": 8, "ll_size": 8, "ld_size": 8,
    "array_size": 32, "array_alignment": 8,
    "wrapper_value_offset": 8, "wrapper_tail_offset": 24,
    "wrapper_size": 32, "wrapper_c_alignment": 8, "wrapper_gnu_alignment": 8,
}


class HexagonLayoutProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fragma-hexagon-layout-integration-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sysroot = self.root / "sysroot"
        self.template = self.sysroot / layout.TEMPLATE
        self.header = self.sysroot / layout.HEADER
        self.template.parent.mkdir(parents=True)
        self.header.parent.mkdir(parents=True)
        self.template.write_text("TYPEDEF " + DEFINITION + " max_align_t;\n")
        self.header.write_text("#if defined(__NEED_max_align_t) && !defined(__DEFINED_max_align_t)\n"
                               "typedef " + DEFINITION + " max_align_t;\n"
                               "#define __DEFINED_max_align_t\n#endif\n")
        self.model = {"max_align_t": "long long", "alignof_max_align_t": 8,
                      "gcc_alignof_max_align_t": 8}
        self.output = self.root / "output"
        self.output.mkdir()
        self.environment = {"PATH": "/inert/bin", "LC_ALL": "C", "LANG": "C"}
        self.recorder = adapter.Recorder(self.output, "/inert/clang", list(adapter.ARCH_FLAGS), self.environment)
        self.process = self.start_patch("subprocess.run", side_effect=self.compiler_fixture)
        self.start_patch("subprocess.Popen", side_effect=AssertionError("Inert test attempted Popen"))
        self.start_patch("os.system", side_effect=AssertionError("Inert test attempted shell execution"))
        self.observation = {
            "status": "checked-paired-layout-not-L1", "symbol": layout.SYMBOL,
            "layout": copy.deepcopy(OBSERVED),
            "values": {prefix + "_" + name: value for name, value in OBSERVED.items()
                       for prefix in ("actual", "candidate")},
        }
        self.validate = self.start_patch("fragma.hexagon_layout.validate_object", return_value=self.observation)
        self.changed_control = None
        self.control_result = None
        self.positive_result = None
        self.after_process = None

    def start_patch(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    @staticmethod
    def assertion(name):
        return ("/inert/control.c:4:1: error: static assertion failed: "
                + layout.CONTROL_ASSERTIONS[name] + "\n1 error generated.\n").encode()

    def compiler_fixture(self, command, **kwargs):
        source = Path(command[-1])
        self.assertTrue(source.is_file())
        self.assertIn("-c", command)
        self.assertNotIn("-E", command)
        if source.name == "positive.c":
            outcome = self.positive_result or (0, b"", b"", 1)
        else:
            self.assertIn(source.stem, layout.CONTROL_ASSERTIONS)
            outcome = ((1, b"", self.assertion(source.stem), 0) if self.changed_control != source.stem
                       else self.control_result)
        code, stdout, stderr, objects = outcome
        for index in range(objects):
            (kwargs["cwd"] / ("inert-%d.o" % index)).write_bytes(b"inert object: layout decoding mocked")
        if self.after_process:
            self.after_process(source)
        return subprocess.CompletedProcess(command, code, stdout, stderr)

    def measure(self):
        return adapter.measure_max_align_layout(self.recorder, self.sysroot, self.output, self.model)

    def test_source_derived_declaration_is_returned_with_full_measured_pairs(self):
        before = copy.deepcopy(self.model)
        result = self.measure()
        self.assertEqual(result["definition"], DEFINITION)
        self.assertEqual(result["declaration"], layout.declaration(self.sysroot))
        self.assertEqual(result["previous_alignment_representative"], "long long")
        self.assertEqual(result["compiler_observation"], self.observation)
        self.assertEqual(len(result["compiler_observation"]["values"]), 28)
        self.assertEqual(self.model, before)
        self.assertNotIn("candidate", result)
        self.assertFalse((self.output / "candidate.yaml").exists())
        self.assertEqual(len(result["source_files"]), 4)
        for row in result["source_files"]:
            self.assertEqual(row, adapter.file_record(row["absolute_path"]))
        self.validate.assert_called_once_with(b"inert object: layout decoding mocked")

    def test_positive_and_all_three_negative_controls_are_required_in_order(self):
        result = self.measure()
        self.assertEqual([Path(row["command"][-1]).stem for row in self.recorder.records],
                         ["positive", *layout.CONTROL_ASSERTIONS])
        self.assertEqual([row["returncode"] for row in self.recorder.records], [0, 1, 1, 1])
        self.assertEqual(result["controls"], [
            {"name": name, "assertion": assertion, "command_index": index,
             "status": "expected-rejection"}
            for index, (name, assertion) in enumerate(layout.CONTROL_ASSERTIONS.items(), 2)])
        for call in self.process.call_args_list:
            self.assertEqual(call.kwargs["env"], self.environment)
            self.assertIs(call.kwargs["stdin"], subprocess.DEVNULL)
            self.assertGreater(call.kwargs["timeout"], 0)
            self.assertLessEqual(call.kwargs["timeout"], 10)

    def test_authored_sources_are_exact_producer_outputs(self):
        result = self.measure()
        expected = {"positive": layout.fixture(DEFINITION), **layout.controls(DEFINITION)}
        for name, text in expected.items():
            path = self.output / "max-align-layout" / (name + ".c")
            self.assertEqual(path.read_text(), text)
            self.assertIn(adapter.file_record(path), result["source_files"])

    def test_changed_template_fails_before_external_command(self):
        self.template.write_text("TYPEDEF struct { long long changed; } max_align_t;\n")
        with self.assertRaises(layout.LayoutError):
            self.measure()
        self.process.assert_not_called()
        self.assertFalse((self.output / "max-align-layout").exists())

    def test_installed_declaration_mismatch_fails_before_external_command(self):
        self.header.write_text(self.header.read_text().replace("long double", "double"))
        with self.assertRaises(layout.LayoutError):
            self.measure()
        self.process.assert_not_called()

    def test_missing_previous_scalar_observation_is_not_invented(self):
        del self.model["max_align_t"]
        with self.assertRaisesRegex(adapter.AdapterError, "original max_align_t"):
            self.measure()
        self.process.assert_not_called()

    def test_positive_failure_does_not_run_controls(self):
        self.positive_result = (1, b"", b"inert compilation failed", 0)
        with self.assertRaisesRegex(adapter.AdapterError, "layout compilation failed"):
            self.measure()
        self.assertEqual(self.process.call_count, 1)
        self.validate.assert_not_called()

    def test_positive_warning_is_not_silently_accepted(self):
        self.positive_result = (0, b"", b"inert warning", 1)
        with self.assertRaises(adapter.AdapterError):
            self.measure()
        self.validate.assert_not_called()

    def test_positive_stdout_is_not_silently_accepted(self):
        self.positive_result = (0, b"unexpected output", b"", 1)
        with self.assertRaises(adapter.AdapterError):
            self.measure()
        self.validate.assert_not_called()

    def test_positive_missing_object_is_rejected(self):
        self.positive_result = (0, b"", b"", 0)
        with self.assertRaises(adapter.AdapterError):
            self.measure()
        self.validate.assert_not_called()

    def test_positive_multiple_objects_are_rejected(self):
        self.positive_result = (0, b"", b"", 2)
        with self.assertRaises(adapter.AdapterError):
            self.measure()
        self.validate.assert_not_called()

    def test_independent_object_validation_failure_blocks_controls(self):
        self.validate.side_effect = layout.LayoutError("inert paired layout mismatch")
        with self.assertRaisesRegex(layout.LayoutError, "paired layout mismatch"):
            self.measure()
        self.assertEqual(self.process.call_count, 1)

    def test_alignment_disagreement_with_standard_probe_is_rejected(self):
        self.observation["layout"]["c_alignment"] = 16
        with self.assertRaisesRegex(adapter.AdapterError, "alignment probes disagree"):
            self.measure()
        self.assertEqual(self.process.call_count, 1)

    def test_gnu_alignment_disagreement_with_individual_probe_is_rejected(self):
        self.observation["layout"]["gnu_alignment"] = 16
        with self.assertRaisesRegex(adapter.AdapterError, "GNU alignment probes disagree"):
            self.measure()
        self.assertEqual(self.process.call_count, 1)

    def test_negative_control_success_is_rejected(self):
        self.changed_control = "legacy_scalar"
        self.control_result = (0, b"", b"", 1)
        with self.assertRaisesRegex(adapter.AdapterError, "layout control"):
            self.measure()
        self.assertEqual(self.process.call_count, 2)

    def test_negative_control_with_object_is_rejected(self):
        self.changed_control = "reordered_members"
        self.control_result = (1, b"", self.assertion(self.changed_control), 1)
        with self.assertRaisesRegex(adapter.AdapterError, "layout control"):
            self.measure()
        self.assertEqual(self.process.call_count, 3)

    def test_wrong_control_assertion_cannot_be_borrowed(self):
        self.changed_control = "wrong_member_type"
        self.control_result = (1, b"", self.assertion("legacy_scalar"), 0)
        with self.assertRaisesRegex(adapter.AdapterError, "layout control"):
            self.measure()
        self.assertEqual(self.process.call_count, 4)

    def test_control_warning_or_incidental_error_is_rejected(self):
        self.changed_control = "legacy_scalar"
        self.control_result = (1, b"", self.assertion(self.changed_control)
                               + b"/inert/control.c:5:1: warning: unrelated warning\n", 0)
        with self.assertRaisesRegex(adapter.AdapterError, "warning"):
            self.measure()

    def test_multiple_control_errors_are_rejected(self):
        self.changed_control = "legacy_scalar"
        self.control_result = (1, b"", self.assertion(self.changed_control) * 2, 0)
        with self.assertRaisesRegex(adapter.AdapterError, "layout control"):
            self.measure()

    def test_control_error_source_excerpt_without_assertion_is_rejected(self):
        self.changed_control = "legacy_scalar"
        self.control_result = (1, b"", b'/inert/control.c:4:1: error: unknown type name\n'
                               + b'4 | _Static_assert(0, "fragma_max_align_legacy_scalar_size");\n', 0)
        with self.assertRaisesRegex(adapter.AdapterError, "layout control"):
            self.measure()

    def test_control_output_is_rejected_even_with_named_assertion(self):
        self.changed_control = "legacy_scalar"
        self.control_result = (1, b"unexpected output", self.assertion(self.changed_control), 0)
        with self.assertRaisesRegex(adapter.AdapterError, "layout control"):
            self.measure()

    def test_declaration_identity_change_during_probes_is_rejected(self):
        def changed(source):
            if source.stem == "wrong_member_type":
                self.header.write_text(self.header.read_text() + "/* changed retained bytes */\n")
        self.after_process = changed
        with self.assertRaisesRegex(adapter.AdapterError, "declaration changed"):
            self.measure()

    def test_authored_source_change_during_probes_is_rejected(self):
        def changed(source):
            if source.stem == "wrong_member_type":
                positive = source.parent / "positive.c"
                positive.write_text(positive.read_text() + "/* changed retained bytes */\n")
        self.after_process = changed
        with self.assertRaisesRegex(adapter.AdapterError, "fixture changed"):
            self.measure()

    def test_existing_layout_directory_is_not_overwritten(self):
        directory = self.output / "max-align-layout"
        directory.mkdir()
        marker = directory / "preserve"
        marker.write_bytes(b"earlier evidence")
        with self.assertRaises(FileExistsError):
            self.measure()
        self.assertEqual(marker.read_bytes(), b"earlier evidence")
        self.process.assert_not_called()

    def test_timeout_retains_partial_diagnostics_and_no_representation(self):
        self.process.side_effect = subprocess.TimeoutExpired(["/inert/clang"], 10,
                                                             output=b"partial", stderr=b"diagnostic")
        with self.assertRaisesRegex(adapter.AdapterError, "timeout"):
            self.measure()
        directory = self.output / "command-001"
        self.assertEqual((directory / "stdout").read_bytes(), b"partial")
        self.assertEqual((directory / "stderr").read_bytes(), b"diagnostic")
        self.assertIsNone(json.loads((directory / "result.json").read_text())["returncode"])


if __name__ == "__main__":
    unittest.main()
