"""Inert transport/control-flow checks, not compiler or model acceptance.

Every subprocess is mocked. Minimal probe selections and schema validation are
mocked only in generate-control tests; they cannot establish a complete model.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fragma import hexagon_machdep as adapter

GNU_FIELDS = tuple("gcc_alignof_" + name for name in (
    "short", "int", "long", "longlong", "ptr", "float", "double", "longdouble",
    "void", "fun", "aligned", "max_align_t"))


class InertCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fragma-hexagon-transport-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.process = self.start_patch("subprocess.run", side_effect=AssertionError("Unmocked process"))
        self.start_patch("subprocess.Popen", side_effect=AssertionError("Inert test attempted Popen"))
        self.start_patch("os.system", side_effect=AssertionError("Inert test attempted shell execution"))

    def start_patch(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()


class HexagonRecorderTests(InertCase):
    def setUp(self):
        super().setUp()
        self.env = {"PATH": "/inert/bin", "LC_ALL": "C", "LANG": "C"}
        self.flags = ["--target=hexagon-linux-musl", "-mv68", "-ffreestanding", "-c"]
        self.recorder = adapter.Recorder(self.root, "/inert/clang", self.flags, self.env)

    def complete(self, stdout=b"", stderr=b"", code=0):
        self.process.side_effect = lambda command, **kwargs: subprocess.CompletedProcess(command, code, stdout, stderr)

    def retained(self, index=1):
        directory = self.root / ("command-%03d" % index)
        return directory, json.loads((directory / "result.json").read_text())

    def test_exact_environment_stdin_cwd_umask_and_byte_capture(self):
        self.complete(b"raw output\n", b"raw diagnostic\n", 1)
        with patch.dict(os.environ, {"CPATH": "/untrusted/include", "MAKEFLAGS": "untrusted"}):
            code, stdout, stderr, row = self.recorder.run("inert", Path("/inert/source.c"))
        self.assertEqual((code, stdout, stderr), (1, "raw output\n", "raw diagnostic\n"))
        call = self.process.call_args
        self.assertEqual(call.args[0], ["/inert/clang", "--target=hexagon-linux-musl", "-mv68",
                                       "-ffreestanding", "-c", "/inert/source.c"])
        self.assertEqual(call.kwargs["cwd"], self.root / "command-001")
        self.assertEqual(call.kwargs["env"], self.env)
        self.assertIs(call.kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(call.kwargs["capture_output"], True)
        self.assertNotIn("text", call.kwargs)
        self.assertEqual(call.kwargs["umask"], 0o022)
        self.assertGreater(call.kwargs["timeout"], 0)
        self.assertLessEqual(call.kwargs["timeout"], 10)
        directory, retained = self.retained()
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual((directory / "stdout").read_bytes(), b"raw output\n")
        self.assertEqual((directory / "stderr").read_bytes(), b"raw diagnostic\n")
        self.assertEqual(retained, row)
        self.assertEqual(retained["stdout"], adapter.file_record(directory / "stdout"))
        self.assertEqual(retained["stderr"], adapter.file_record(directory / "stderr"))

    def test_constructor_copies_caller_environment(self):
        self.complete()
        self.env["CPATH"] = "/changed/after/construction"
        self.recorder.run("version", mode="version")
        self.assertNotIn("CPATH", self.process.call_args.kwargs["env"])

    def test_preprocessing_and_macro_queries_drop_compile_flag(self):
        self.complete()
        self.recorder.run("source", Path("/inert/source.c"), mode="preprocess")
        self.recorder.run("macros", mode="macros")
        commands = [call.args[0] for call in self.process.call_args_list]
        self.assertTrue(all("-E" in command and "-c" not in command for command in commands))
        self.assertEqual(commands[1][-5:], ["-dM", "-E", "-x", "c", "-"])
        self.assertEqual([row["cwd"] for row in self.recorder.records],
                         [str(self.root / "command-001"), str(self.root / "command-002")])

    def test_timeout_retains_partial_binary_streams_and_failed_result(self):
        self.process.side_effect = subprocess.TimeoutExpired(["/inert/clang"], 10,
                                                             output=b"partial stdout\xff", stderr=b"partial stderr\n")
        with self.assertRaisesRegex(adapter.AdapterError, "timeout"):
            self.recorder.run("timeout", mode="version")
        directory, row = self.retained()
        self.assertIsNone(row["returncode"])
        self.assertEqual(row["failure"], "Compiler timeout")
        self.assertEqual((directory / "stdout").read_bytes(), b"partial stdout\xff")
        self.assertEqual((directory / "stderr").read_bytes(), b"partial stderr\n")
        self.assertEqual(len(self.recorder.records), 1)

    def test_timeout_without_output_retains_empty_streams(self):
        self.process.side_effect = subprocess.TimeoutExpired(["/inert/clang"], 10)
        with self.assertRaises(adapter.AdapterError):
            self.recorder.run("timeout", mode="version")
        directory, row = self.retained()
        self.assertEqual((directory / "stdout").read_bytes(), b"")
        self.assertEqual((directory / "stderr").read_bytes(), b"")
        self.assertIsNone(row["returncode"])

    def test_oserror_retains_intent_and_failed_result(self):
        self.process.side_effect = OSError("inert executable unavailable")
        with self.assertRaisesRegex(adapter.AdapterError, "OSError"):
            self.recorder.run("missing", mode="version")
        directory, row = self.retained()
        self.assertTrue((directory / "intent.json").is_file())
        self.assertIn("inert executable unavailable", row["failure"])
        self.assertIsNone(row["returncode"])

    def test_interrupt_retains_intent_and_failed_result(self):
        self.process.side_effect = KeyboardInterrupt("inert interruption")
        with self.assertRaisesRegex(adapter.AdapterError, "KeyboardInterrupt"):
            self.recorder.run("interrupted", mode="version")
        directory, row = self.retained()
        self.assertTrue((directory / "intent.json").is_file())
        self.assertIn("KeyboardInterrupt", row["failure"])
        self.assertIsNone(row["returncode"])

    def test_invalid_utf8_is_rejected_after_raw_stream_retention(self):
        self.complete(b"\xff", b"raw error")
        with self.assertRaises(UnicodeDecodeError):
            self.recorder.run("bytes", mode="version")
        directory, row = self.retained()
        self.assertEqual((directory / "stdout").read_bytes(), b"\xff")
        self.assertEqual(row["returncode"], 0)

    def test_shared_budget_caps_individual_timeout(self):
        self.complete()
        self.recorder.deadline = 100.75
        with patch.object(adapter.time, "monotonic", return_value=100.0):
            self.recorder.run("short-budget", mode="version")
        self.assertEqual(self.process.call_args.kwargs["timeout"], 0.75)

    def test_elapsed_shared_budget_fails_before_output_or_process(self):
        self.recorder.deadline = 100
        with patch.object(adapter.time, "monotonic", return_value=100), self.assertRaises(adapter.AdapterError):
            self.recorder.run("expired", mode="version")
        self.process.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_command_budget_fails_before_output_or_process(self):
        self.recorder.records = [{} for _ in range(112)]
        with self.assertRaisesRegex(adapter.AdapterError, "budget"):
            self.recorder.run("exhausted", mode="version")
        self.process.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_old_96_call_boundary_allows_required_gnu_observations(self):
        self.complete()
        self.recorder.records = [{} for _ in range(96)]
        self.recorder.run("additional-gnu-probe", mode="version")
        self.assertEqual(len(self.recorder.records), 97)
        self.assertEqual(self.process.call_args.kwargs["cwd"], self.root / "command-097")

    def test_112th_call_is_last_permitted_command(self):
        self.complete()
        self.recorder.records = [{} for _ in range(111)]
        self.recorder.run("final-budget-slot", mode="version")
        self.assertEqual(len(self.recorder.records), 112)
        with self.assertRaisesRegex(adapter.AdapterError, "budget"):
            self.recorder.run("over-budget", mode="version")
        self.assertEqual(self.process.call_count, 1)
        self.assertFalse((self.root / "command-113").exists())

    def test_existing_command_directory_is_not_overwritten(self):
        directory = self.root / "command-001"
        directory.mkdir()
        marker = directory / "preserve"
        marker.write_bytes(b"original evidence")
        with self.assertRaises(FileExistsError):
            self.recorder.run("reuse", mode="version")
        self.assertEqual(marker.read_bytes(), b"original evidence")
        self.process.assert_not_called()
        self.assertEqual(self.recorder.records, [])

    def test_object_inventory_is_per_call_and_hash_bound(self):
        def run(command, **kwargs):
            (kwargs["cwd"] / "inert.o").write_bytes(b"inert object, never executed")
            return subprocess.CompletedProcess(command, 0, b"", b"")
        self.process.side_effect = run
        self.recorder.run("one", Path("/inert/source.c"))
        self.recorder.run("two", Path("/inert/source.c"))
        for index in (1, 2):
            directory, row = self.retained(index)
            self.assertEqual(row["objects"], [adapter.file_record(directory / "inert.o")])


class HexagonGenerateControlTests(InertCase):
    """Only orchestration is real here; mocked miniature models are not evidence."""

    def setUp(self):
        super().setUp()
        self.helper = self.root / "upstream/helper.py"
        self.schema = self.root / "schema.yaml"
        self.provider = self.root / "profiles/setup_hexagon_musl.py"
        self.sysroot = self.root / "sysroot"
        self.resources = self.root / "resources"
        self.output = self.root / "output"
        for path in (self.helper, self.schema, self.provider):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# inert identity fixture\n")
        for path in (self.sysroot / "include", self.resources / "include"):
            path.mkdir(parents=True)
        self.start_patch("fragma.hexagon_machdep.SETUP_SHA256", new=adapter.digest(self.provider.read_bytes()))
        self.start_patch("fragma.hexagon_machdep.SCHEMA_SHA256", new=adapter.digest(self.schema.read_bytes()))
        self.setup = SimpleNamespace(path_checked=self.checked_path)
        self.start_patch("fragma.hexagon_machdep.importlib.util.spec_from_file_location",
                         return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock())))
        self.start_patch("fragma.hexagon_machdep.importlib.util.module_from_spec", return_value=self.setup)
        self.before = {"files": [adapter.file_record(self.provider)], "fixture": "inert input inventory"}
        self.inventory = self.start_patch("fragma.hexagon_machdep.inputs", side_effect=lambda *args: copy.deepcopy(self.before))
        self.prepare = self.start_patch("fragma.hexagon_machdep.prepare_sources", side_effect=self.prepare_minimal)
        self.validation = self.start_patch("fragma.hexagon_machdep.validate_model")
        self.layout_measurement = {
            "definition": "struct { long long __ll; long double __ld; }",
            "declaration": {"definition": "struct { long long __ll; long double __ld; }", "inputs": []},
            "previous_alignment_representative": "long long",
            "compiler_observation": {"status": "inert mocked layout observation; not model evidence",
                                     "layout": {"c_alignment": 8, "gnu_alignment": 8}},
            "controls": [], "source_files": [],
        }
        self.layout_model_before = None
        self.measure = self.start_patch("fragma.hexagon_machdep.measure_max_align_layout",
                                        side_effect=self.measure_minimal)
        self.observe = self.start_patch("fragma.hexagon_machdep.alignment_observation", return_value={
            "requested_alignment": 16, "observed_alignment": 8, "symbol_offset": 0, "honored": False})
        self.version_output = b"Ubuntu clang version 21.1.8 (inert fixture)\nTarget: inert\n"
        self.gnu_values = {name: 1 << (index % 5) for index, name in enumerate(GNU_FIELDS)}
        self.gnu_values["gcc_alignof_max_align_t"] = 8
        self.process.side_effect = self.compiler_fixture

    @staticmethod
    def checked_path(path, *, directory=False, exists=True):
        path = Path(path).absolute()
        if exists:
            adapter.require(path.is_dir() if directory else path.is_file(), "Missing inert input")
        else:
            adapter.require(not path.exists(), "Output already exists")
        return path

    @staticmethod
    def prepare_minimal(helper, destination):
        destination.mkdir()
        for name in ("sanity_check.c", "alignof_max_align_t.c", "max_align_t.c", "max_extended_alignment.c",
                     *(field + ".c" for field in GNU_FIELDS)):
            (destination / name).write_bytes(b"/* inert source; never compiled */\n")
        return [("sanity_check.c", "none"), ("alignof_max_align_t.c", "number"), ("max_align_t.c", "type"),
                *((field + ".c", "number") for field in GNU_FIELDS)]

    def measure_minimal(self, recorder, sysroot, output, model):
        self.layout_model_before = copy.deepcopy(model)
        return copy.deepcopy(self.layout_measurement)

    def compiler_fixture(self, command, **kwargs):
        if command == [adapter.COMPILER, "--version"]:
            return subprocess.CompletedProcess(command, 0, self.version_output, b"")
        if "-dM" in command:
            return subprocess.CompletedProcess(command, 0, b"#define __inert 1\n", b"")
        name = Path(command[-1]).stem
        if name in self.gnu_values:
            errors = ("/inert/probe.c:1:1: error: static assertion failed: " + name
                      + " is " + str(self.gnu_values[name]) + "\n1 error generated.\n").encode()
            return subprocess.CompletedProcess(command, 1, b"", errors)
        if command[-1].endswith("alignof_max_align_t.c"):
            errors = (b"/inert/probe.c:1:1: error: static assertion failed: alignof_max_align_t is 8\n"
                      b"1 error generated.\n")
            return subprocess.CompletedProcess(command, 1, b"", errors)
        if command[-1].endswith("max_align_t.c"):
            errors = (b"/inert/probe.c:1:1: error: static assertion failed: max_align_t is `long long`\n"
                      b"1 error generated.\n")
            return subprocess.CompletedProcess(command, 1, b"", errors)
        if "-DALIGN_TEST=32" in command:
            errors = b"/inert/probe.c:1:1: error: requested alignment must be 16 bytes or smaller\n1 error generated.\n"
            return subprocess.CompletedProcess(command, 1, b"", errors)
        if command[-1].endswith(("sanity_check.c", "max_extended_alignment.c")):
            (kwargs["cwd"] / "inert.o").write_bytes(b"inert object; ELF observation mocked")
            return subprocess.CompletedProcess(command, 0, b"", b"")
        raise AssertionError("Unexpected inert command: " + repr(command))

    def generate(self):
        return adapter.generate(self.root, helper=self.helper, schema=self.schema,
                                sysroot=self.sysroot, resource_root=self.resources, output=self.output)

    def receipt(self):
        return json.loads((self.output / "receipt.json").read_text())

    def test_alignment_contradiction_retains_candidate_but_never_acceptance(self):
        result = self.generate()
        self.assertEqual(result["status"], "blocked-object-alignment")
        self.assertEqual(result["level"], "unregistered")
        self.assertIs(result["integration_eligible"], False)
        self.assertEqual(result["alignment_contradictions"], result["alignment_observations"])
        self.assertEqual(result["candidate"], adapter.file_record(self.output / "candidate.yaml"))
        self.assertFalse(result["input_drift"])
        self.assertEqual(self.receipt(), result)
        self.assertEqual(self.inventory.call_count, 2)
        self.validation.assert_called_once()

    def test_no_alignment_contradiction_still_does_not_award_l1(self):
        self.observe.return_value = {"requested_alignment": 16, "observed_alignment": 16,
                                     "symbol_offset": 0, "honored": True}
        result = self.generate()
        self.assertEqual(result["status"], "candidate-extracted-not-L1")
        self.assertEqual(result["level"], "unregistered")
        self.assertFalse(result["integration_eligible"])

    def test_source_derived_layout_is_used_before_validation_and_yaml_write(self):
        validation_snapshots = []
        self.validation.side_effect = lambda model, schema: validation_snapshots.append(copy.deepcopy(model))
        with patch.object(adapter, "save", wraps=adapter.save) as writes:
            result = self.generate()
        self.measure.assert_called_once()
        self.assertEqual(self.measure.call_args.args[1:3], (self.sysroot, self.output))
        self.assertEqual(self.layout_model_before["max_align_t"], "long long")
        self.assertEqual(self.layout_model_before["alignof_max_align_t"], 8)
        self.assertEqual(result["max_align_t_representation"], self.layout_measurement)
        self.assertEqual(len(validation_snapshots), 1)
        validated_model = validation_snapshots[0]
        self.assertEqual(validated_model["max_align_t"], self.layout_measurement["definition"])
        self.assertEqual(validated_model["compiler"], "clang")
        self.assertEqual({name: validated_model[name] for name in GNU_FIELDS}, self.gnu_values)
        import yaml
        candidate_writes = [call for call in writes.call_args_list if Path(call.args[0]).name == "candidate.yaml"]
        self.assertEqual(len(candidate_writes), 1)
        self.assertEqual(yaml.safe_load(candidate_writes[0].args[1]), validated_model)
        saved = yaml.safe_load((self.output / "candidate.yaml").read_text())
        self.assertEqual(saved, validated_model)
        self.assertEqual(result["candidate"], adapter.file_record(self.output / "candidate.yaml"))
        self.assertEqual(result["status"], "blocked-object-alignment")

    def test_gnu_fields_are_individually_probed_not_copied_from_c_alignment(self):
        result = self.generate()
        self.assertEqual({name: self.layout_model_before[name] for name in GNU_FIELDS}, self.gnu_values)
        gnu_calls = [call for call in self.process.call_args_list
                     if Path(call.args[0][-1]).stem in GNU_FIELDS]
        self.assertEqual([Path(call.args[0][-1]).stem for call in gnu_calls], list(GNU_FIELDS))
        self.assertTrue(all(call.args[0][0] == adapter.COMPILER and "-c" in call.args[0] for call in gnu_calls))
        self.assertEqual(result["schema_validation"]["measured_gnu_alignment_fields"], 12)

    def test_family_selector_and_exact_compiler_executable_are_separate(self):
        result = self.generate()
        self.assertEqual(result["compiler_semantics"], {
            "family": "clang", "dialect": "gnu11",
            "executable": {"path": adapter.COMPILER, "sha256": adapter.COMPILER_SHA256},
            "machdep_compiler": "clang", "gnu_alignment_fields": list(GNU_FIELDS),
            "scope": "Frama-C compiler is a dialect selector; the executable path is retained separately. GNU alignments are individually probed.",
        })
        self.assertTrue(all(call.args[0][0] == adapter.COMPILER for call in self.process.call_args_list))
        import yaml
        self.assertEqual(yaml.safe_load((self.output / "candidate.yaml").read_text())["compiler"], "clang")

    def test_wrong_named_gnu_observation_blocks_generation(self):
        def run(command, **kwargs):
            if Path(command[-1]).stem == "gcc_alignof_int":
                errors = b"/inert/probe.c:1:1: error: static assertion failed: alignof_int is 4\n1 error generated.\n"
                return subprocess.CompletedProcess(command, 1, b"", errors)
            return self.compiler_fixture(command, **kwargs)
        self.process.side_effect = run
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("candidate", result)
        self.assertIn("unparsed assertion", result["error"])
        self.validation.assert_not_called()

    def test_failed_layout_measurement_prevents_candidate_or_schema_acceptance(self):
        self.measure.side_effect = adapter.AdapterError("inert paired layout mismatch")
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertIn("paired layout mismatch", result["error"])
        self.assertNotIn("candidate", result)
        self.validation.assert_not_called()
        self.assertFalse((self.output / "candidate.yaml").exists())

    def test_layout_source_changed_after_measurement_invalidates_candidate(self):
        path = self.output / "inert-layout.c"
        def measure(recorder, sysroot, output, model):
            path.write_bytes(b"/* initial inert layout source */\n")
            result = self.measure_minimal(recorder, sysroot, output, model)
            result["source_files"] = [adapter.file_record(path)]
            return result
        def run(command, **kwargs):
            result = self.compiler_fixture(command, **kwargs)
            if "-dM" in command:
                path.write_bytes(b"/* changed after layout measurement */\n")
            return result
        self.measure.side_effect = measure
        self.process.side_effect = run
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["input_drift"])
        self.assertIn("layout", result["drift_error"].lower())
        self.assertFalse(result["integration_eligible"])

    def test_clean_environment_and_target_flags_reach_every_nonversion_call(self):
        with patch.dict(os.environ, {"CPATH": "/bad/include", "PYTHONPATH": "/bad/python", "LANG": "bad"}):
            self.generate()
        for call in self.process.call_args_list:
            self.assertEqual(call.kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
            self.assertIs(call.kwargs["stdin"], subprocess.DEVNULL)
            if call.args[0] != [adapter.COMPILER, "--version"]:
                self.assertEqual(call.args[0][1:1 + len(adapter.ARCH_FLAGS)], adapter.ARCH_FLAGS)
                includes = [index for index, arg in enumerate(call.args[0]) if arg == "-isystem"]
                self.assertEqual([call.args[0][index + 1] for index in includes],
                                 [str(self.sysroot / "include"), str(self.resources / "include")])

    def test_changed_provider_identity_fails_before_import_or_output(self):
        self.provider.write_bytes(b"changed provider")
        with self.assertRaisesRegex(adapter.AdapterError, "verifier identity"):
            self.generate()
        self.assertFalse(self.output.exists())
        self.inventory.assert_not_called()
        self.process.assert_not_called()

    def test_changed_schema_identity_fails_before_output_or_process(self):
        self.schema.write_bytes(b"changed schema")
        with self.assertRaisesRegex(adapter.AdapterError, "schema identity"):
            self.generate()
        self.assertFalse(self.output.exists())
        self.inventory.assert_not_called()
        self.process.assert_not_called()

    def test_initial_input_identity_failure_prevents_output_and_process(self):
        self.inventory.side_effect = adapter.AdapterError("inert compiler identity changed")
        with self.assertRaisesRegex(adapter.AdapterError, "compiler identity"):
            self.generate()
        self.assertFalse(self.output.exists())
        self.process.assert_not_called()

    def test_existing_output_is_preserved_before_any_process(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_bytes(b"dated evidence")
        with self.assertRaisesRegex(adapter.AdapterError, "already exists"):
            self.generate()
        self.assertEqual(marker.read_bytes(), b"dated evidence")
        self.process.assert_not_called()

    def test_output_within_input_tree_is_rejected_before_write(self):
        for index, directory in enumerate((self.helper.parent, self.sysroot, self.resources)):
            self.output = directory / ("new-output-%d" % index)
            with self.subTest(directory=directory), self.assertRaisesRegex(adapter.AdapterError, "input tree"):
                self.generate()
            self.assertFalse(self.output.exists())
        self.process.assert_not_called()

    def test_relative_helper_path_cannot_evade_output_overlap_check(self):
        self.output = self.helper.parent / "overlapping-output"
        self.helper = Path(os.path.relpath(self.helper, Path.cwd()))
        with self.assertRaisesRegex(adapter.AdapterError, "input tree"):
            self.generate()
        self.assertFalse(self.output.exists())
        self.process.assert_not_called()

    def test_drift_overrides_candidate_status_and_preserves_both_inventories(self):
        changed = copy.deepcopy(self.before)
        changed["fixture"] = "changed during inert generation"
        self.inventory.side_effect = [copy.deepcopy(self.before), changed]
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["input_drift"])
        self.assertFalse(result["integration_eligible"])
        self.assertIn("changed during execution", result["drift_error"])
        self.assertTrue((self.output / "candidate.yaml").is_file())
        self.assertEqual(json.loads((self.output / "inputs-before.json").read_text()), self.before)
        self.assertEqual(json.loads((self.output / "inputs-after.json").read_text()), changed)

    def test_final_identity_check_failure_overrides_candidate_status(self):
        self.inventory.side_effect = [copy.deepcopy(self.before), adapter.AdapterError("inert resource changed")]
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["input_drift"])
        self.assertIn("inert resource changed", result["drift_error"])
        self.assertFalse(result["integration_eligible"])

    def test_changed_adapted_source_overrides_candidate_status(self):
        def run(command, **kwargs):
            returned = self.compiler_fixture(command, **kwargs)
            if "-dM" in command:
                (self.output / "probes/sanity_check.c").write_bytes(b"/* changed inert probe */\n")
            return returned
        self.process.side_effect = run
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["input_drift"])
        self.assertIn("Adapted probe sources changed", result["drift_error"])
        self.assertNotEqual(result["adapted_sources_before"], result["adapted_sources_after"])
        self.assertFalse(result["integration_eligible"])

    def test_timeout_is_retained_as_failed_generation_not_candidate(self):
        self.process.side_effect = subprocess.TimeoutExpired([adapter.COMPILER], 10,
                                                             output=b"partial\n", stderr=b"interrupted diagnostic\n")
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertIn("timeout", result["error"])
        self.assertNotIn("candidate", result)
        self.assertEqual((self.output / "command-001/stdout").read_bytes(), b"partial\n")
        self.assertEqual((self.output / "command-001/stderr").read_bytes(), b"interrupted diagnostic\n")
        self.assertEqual(self.receipt(), result)

    def test_interrupt_is_retained_as_failed_generation(self):
        self.process.side_effect = KeyboardInterrupt("inert stop")
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertIn("KeyboardInterrupt", result["error"])
        self.assertNotIn("candidate", result)
        self.assertEqual(self.receipt(), result)

    def test_oserror_is_retained_as_failed_generation(self):
        self.process.side_effect = OSError("inert compiler missing")
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertIn("OSError", result["error"])
        self.assertNotIn("candidate", result)
        self.assertEqual(self.receipt(), result)

    def test_schema_failure_never_writes_candidate(self):
        self.validation.side_effect = adapter.AdapterError("inert incomplete model")
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("candidate", result)
        self.assertFalse((self.output / "candidate.yaml").exists())

    def test_empty_successful_version_output_is_retained_failure(self):
        self.version_output = b""
        result = self.generate()
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("candidate", result)
        self.assertIn("version", result["error"].lower())
        self.assertEqual(self.receipt(), result)

    def test_ambiguous_or_unpinned_version_output_is_retained_failure(self):
        outputs = (b"Ubuntu clang version 21.1.7 (fixture)\n",
                   b"Ubuntu clang version 21.1.8git (fixture)\n",
                   b"clang version 21.1.8\nclang version 21.1.8\n",
                   b"gcc version 21.1.8\n")
        for index, output in enumerate(outputs):
            self.version_output = output
            self.output = self.root / ("bad-version-%d" % index)
            with self.subTest(output=output):
                result = self.generate()
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("candidate", result)
                self.assertIn("version", result["error"].lower())

    def test_cli_returns_nonzero_for_blocked_alignment_without_promotion(self):
        with patch.object(adapter, "generate", return_value={"status": "blocked-object-alignment",
                "level": "unregistered", "integration_eligible": False}), contextlib.redirect_stdout(io.StringIO()) as out:
            code = adapter.main(["--sysroot", str(self.sysroot), "--output", str(self.output)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["status"], "blocked-object-alignment")
        self.process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
