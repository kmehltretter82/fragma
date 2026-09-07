"""Independent, inert checks for the reviewed Hexagon generator adapter.

Only the installed upstream probe/schema text is read. Diagnostics and ELF
objects are synthetic; no compiler, analyzer, target code or subprocess runs.
"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from fragma import hexagon_machdep as adapter


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "toolchain/verified-prefix/opam/fragma/lib/frama-c/lib/make_machdep"
SCHEMA = ROOT / "toolchain/verified-prefix/opam/fragma/share/frama-c/share/machdeps/machdep-schema.yaml"
GNU_FIELDS = tuple("gcc_alignof_" + name for name in (
    "short", "int", "long", "longlong", "ptr", "float", "double", "longdouble",
    "void", "fun", "aligned", "max_align_t"))


def diagnostic(name, value, *, kind="number", requirement=True):
    value = "`" + value + "`" if kind == "type" else str(value)
    explanation = " due to requirement 'fixture != expected'" if requirement else ""
    return (f"/fixture/{name}.c:12:16: error: static assertion failed{explanation}: "
            f"{name} is {value}\n"
            "   12 | _Static_assert(fixture, \"inert fixture\");\n"
            "      |                ^~~~~~~\n")


def synthetic_elf(*, alignment=16, symbol_name=b"x", value=0, size=4,
                  symbol_info=0x11, section_flags=3, machine=164, flags=0x68,
                  section_kind=1):
    """Encode a tiny ELF32LE relocatable independently of production readers."""
    names = b"\0.data\0.shstrtab\0.strtab\0.symtab\0"
    strings = b"\0" + symbol_name + b"\0"
    data_offset = ((52 + alignment - 1) // alignment) * alignment
    data = bytearray(data_offset)
    data.extend(struct.pack("<I", 42))
    names_offset = len(data)
    data.extend(names)
    strings_offset = len(data)
    data.extend(strings)
    data.extend(b"\0" * (-len(data) % 4))
    symbols_offset = len(data)
    data.extend(bytes(16))
    data.extend(struct.pack("<IIIBBH", 1, value, size, symbol_info, 0, 1))
    sections_offset = len(data)
    sections = [
        (0,) * 10,
        (names.index(b".data"), section_kind, section_flags, 0, data_offset, 4, 0, 0, alignment, 0),
        (names.index(b".shstrtab"), 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
        (names.index(b".strtab"), 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        (names.index(b".symtab"), 2, 0, 0, symbols_offset, 32, 3, 1, 4, 16),
    ]
    for row in sections:
        data.extend(struct.pack("<IIIIIIIIII", *row))
    ident = bytes([127, 69, 76, 70, 1, 1, 1]) + bytes(9)
    data[:52] = struct.pack("<16sHHIIIIIHHHHHH", ident, 1, machine, 1, 0, 0,
                            sections_offset, flags, 52, 0, 0, 40, 5, 2)
    return bytes(data)


class HexagonMachdepTests(unittest.TestCase):
    def setUp(self):
        for target in ("subprocess.run", "subprocess.Popen", "os.system"):
            blocker = patch(target, side_effect=AssertionError("inert adapter test attempted execution"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def original(self, name):
        return (UPSTREAM / name).read_text()

    def parse(self, name="sizeof_int", value=4, kind="number", **changes):
        arguments = dict(name=name, kind=kind, returncode=1, stdout="",
                         stderr=diagnostic(name, value, kind=kind) + "1 error generated.\n")
        arguments.update(changes)
        return adapter.parse_diagnostic(**arguments)

    def model_and_schema(self):
        schema = yaml.safe_load(SCHEMA.read_text())
        values = {"integer": 4, "boolean": True, "string": "fixture",
                  "array": [], "object": {}}
        model = {name: copy.deepcopy(values[specification["type"]])
                 for name, specification in schema.items() if not specification.get("optional", False)}
        model["wordsize"] = ""
        model["custom_defs"] = {"__hexagon__": "1"}
        model["errno"] = {"edom": "33"}
        model["compiler"] = "clang"
        model.update({name: 4 for name in GNU_FIELDS})
        return model, schema

    def test_sanity_change_preserves_original_except_explicit_return(self):
        source = self.original("sanity_check.c")
        changed = adapter.adapt_probe("sanity_check.c", source)
        self.assertIn("return 0;", changed)
        self.assertEqual(self.original("sanity_check.c"), source)
        self.assertNotEqual(changed, source)

    def test_wordsize_has_explicit_undefined_observation_without_invented_width(self):
        source = self.original("wordsize.c")
        changed = adapter.adapt_probe("wordsize.c", source)
        self.assertIn("const int fragma_wordsize_undefined = 1;", changed)
        self.assertIn("wordsize_is = __WORDSIZE;", changed)
        self.assertNotIn("__WORDSIZE 32", changed)
        self.assertIn("#else", changed)
        self.assertEqual(self.original("wordsize.c"), source)

    def test_max_align_t_fallback_struct_tags_are_distinct(self):
        source = self.original("max_align_t.c")
        changed = adapter.adapt_probe("max_align_t.c", source)
        self.assertEqual(changed.count("struct __machdep_max_align_t {"), 1)
        self.assertEqual(changed.count("struct __machdep_max_align_t_16 {"), 1)
        self.assertEqual(self.original("max_align_t.c"), source)

    def test_unmodified_probe_is_byte_identical(self):
        source = self.original("sizeof_int.c")
        self.assertEqual(adapter.adapt_probe("sizeof_int.c", source), source)

    def test_source_edit_requires_expected_anchor(self):
        for name in ("sanity_check.c", "wordsize.c", "max_align_t.c"):
            with self.subTest(name=name), self.assertRaises(adapter.AdapterError):
                adapter.adapt_probe(name, "/* changed upstream source */\n")

    def test_numeric_assertion_observation(self):
        self.assertEqual(self.parse(), 4)

    def test_type_assertion_observation(self):
        self.assertEqual(self.parse("size_t", "unsigned int", "type"), "unsigned int")

    def test_boolean_assertions_with_and_without_requirement(self):
        self.assertIs(self.parse("char_is_unsigned", "True", "bool"), True)
        output = diagnostic("little_endian", "False", requirement=False) + "1 error generated.\n"
        self.assertIs(self.parse("little_endian", "False", "bool", stderr=output), False)

    def test_primary_diagnostic_value_not_source_excerpt_is_used(self):
        output = diagnostic("sizeof_int", 4).replace(
            '"inert fixture"', '"sizeof_int is 8"') + "1 error generated.\n"
        self.assertEqual(self.parse(stderr=output), 4)

    def test_source_excerpt_without_primary_named_assertion_cannot_supply_value(self):
        output = ("/fixture/sizeof_int.c:12:16: error: unknown type name 'fixture'\n"
                  '12 | _Static_assert(0, "sizeof_int is 4");\n1 error generated.\n')
        with self.assertRaises(adapter.AdapterError):
            self.parse(stderr=output)

    def test_incidental_error_alongside_correct_value_is_rejected(self):
        output = diagnostic("sizeof_int", 4) + (
            "/fixture/sizeof_int.c:13:1: error: unknown type name 'broken'\n2 errors generated.\n")
        with self.assertRaises(adapter.AdapterError):
            self.parse(stderr=output)

    def test_warning_alongside_correct_value_is_rejected(self):
        output = diagnostic("sizeof_int", 4) + (
            "/fixture/sizeof_int.c:13:1: warning: unrelated diagnostic [-Wfixture]\n"
            "1 warning and 1 error generated.\n")
        with self.assertRaises(adapter.AdapterError):
            self.parse(stderr=output)

    def test_unknown_diagnostic_field_is_rejected(self):
        with self.assertRaises(adapter.AdapterError):
            self.parse(stderr=diagnostic("sizeof_long", 4) + "1 error generated.\n")

    def test_missing_assertion_and_success_status_are_rejected(self):
        for changes in ({"stderr": ""}, {"returncode": 0}, {"returncode": -9}, {"stdout": "unexpected output"}):
            with self.subTest(changes=changes), self.assertRaises(adapter.AdapterError):
                self.parse(**changes)

    def test_conflicting_numeric_observations_are_rejected(self):
        output = diagnostic("sizeof_int", 4) + diagnostic("sizeof_int", 8) + "2 errors generated.\n"
        with self.assertRaises(adapter.AdapterError):
            self.parse(stderr=output)

    def test_conflicting_exact_type_observations_are_rejected(self):
        output = diagnostic("size_t", "unsigned int", kind="type")
        output += diagnostic("size_t", "unsigned long", kind="type") + "2 errors generated.\n"
        with self.assertRaises(adapter.AdapterError):
            self.parse("size_t", "unsigned int", "type", stderr=output)

    def test_max_align_t_multiple_alignment_equivalents_preserve_first(self):
        output = "".join(diagnostic("max_align_t", value, kind="type")
                         for value in ("long long", "double", "long double")) + "3 errors generated.\n"
        self.assertEqual(self.parse("max_align_t", "long long", "type", stderr=output), "long long")

    def test_max_align_t_redefinition_is_not_an_expected_assertion(self):
        output = diagnostic("max_align_t", "long long", kind="type")
        output += "/fixture/max_align_t.c:24:28: error: redefinition of '__machdep_max_align_t'\n2 errors generated.\n"
        with self.assertRaises(adapter.AdapterError):
            self.parse("max_align_t", "long long", "type", stderr=output)

    def test_defined_wordsize_is_measured(self):
        fields, undefined = adapter.parse_macros("wordsize", 0, "const int wordsize_is = 32;\n", "")
        self.assertEqual(fields, {"wordsize": "32"})
        self.assertEqual(undefined, [])

    def test_explicit_undefined_wordsize_is_not_a_missing_probe(self):
        fields, undefined = adapter.parse_macros("wordsize", 0, "const int fragma_wordsize_undefined = 1;\n", "")
        self.assertEqual(fields, {"wordsize": ""})
        self.assertEqual(undefined, ["wordsize"])

    def test_wordsize_failure_empty_output_and_contradictory_marker_are_rejected(self):
        for status, output, errors in (
            (1, "const int fragma_wordsize_undefined = 1;\n", "preprocessing failed"),
            (0, "", ""),
            (0, "const int wordsize_is = 32; const int fragma_wordsize_undefined = 1;", ""),
            (0, "const int fragma_wordsize_undefined = 0;", ""),
            (0, "const int wordsize_is = ;", ""),
        ):
            with self.subTest(status=status, output=output), self.assertRaises(adapter.AdapterError):
                adapter.parse_macros("wordsize", status, output, errors)

    def test_defined_but_unexpanded_wordsize_is_rejected(self):
        for value in ("__WORDSIZE", "(__WORDSIZE)"):
            with self.subTest(value=value), self.assertRaises(adapter.AdapterError):
                adapter.parse_macros("wordsize", 0, "const int wordsize_is = " + value + ";\n", "")

    def test_malformed_declaration_cannot_hide_behind_valid_value_or_undefined_marker(self):
        for output in (
            "int wordsize_is = 32; int wordsize_is = ;\n",
            "int wordsize_is = 32; int surprise_is = ;\n",
            "const int fragma_wordsize_undefined = 1;\nint wordsize_is = ;\n",
            "int wordsize_is=32; int wordsize_is=;\n",
            "int wordsize_is=32; int surprise_is=;\n",
            "const int fragma_wordsize_undefined = 1;\nint wordsize_is=;\n",
        ):
            with self.subTest(output=output), self.assertRaises(adapter.AdapterError):
                adapter.parse_macros("wordsize", 0, output, "")

    def test_missing_posix_limit_is_not_treated_like_undefined_wordsize(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.parse_macros("limits_macros", 0, "int path_max_is = 4096;\n", "")

    def test_complete_posix_limits_are_observed(self):
        output = "int path_max_is = 4096; int tty_name_max_is = 32; int host_name_max_is = 255;\n"
        fields, undefined = adapter.parse_macros("limits_macros", 0, output, "")
        self.assertEqual(fields, {"path_max": "4096", "tty_name_max": "32", "host_name_max": "255"})
        self.assertEqual(undefined, [])

    def test_duplicate_macro_field_is_rejected(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.parse_macros("wordsize", 0, "int wordsize_is = 32; int wordsize_is = 64;\n", "")

    def test_duplicate_undefined_marker_is_rejected(self):
        output = "const int fragma_wordsize_undefined = 1;\n" * 2
        with self.assertRaises(adapter.AdapterError):
            adapter.parse_macros("wordsize", 0, output, "")

    def test_macro_warning_and_unknown_field_are_rejected(self):
        for output, errors in (("int wordsize_is = 32;", "clang: warning: ignored flag\n"),
                               ("int wordsize_is = 32; int surprise_is = 1;", "")):
            with self.subTest(output=output, errors=errors), self.assertRaises(adapter.AdapterError):
                adapter.parse_macros("wordsize", 0, output, errors)

    def test_errno_names_retain_upstream_lowercase_spelling(self):
        self.assertIn("int edom_is = EDOM;", self.original("errno.c"))
        fields, undefined = adapter.parse_macros("errno", 0, "int edom_is = 33; int erange_is = 34;\n", "")
        self.assertEqual(fields, {"errno": {"edom": "33", "erange": "34"}})
        self.assertEqual(undefined, [])

    def test_actual_schema_has_66_required_and_12_optional_fields(self):
        model, schema = self.model_and_schema()
        self.assertEqual(len(model), 78)
        self.assertEqual(sum(not specification.get("optional", False) for specification in schema.values()), 66)
        self.assertEqual(sum(specification.get("optional", False) for specification in schema.values()), 12)
        self.assertIsNone(adapter.validate_model(model, schema))

    def test_all_gnu_fields_are_required_by_this_route_despite_optional_schema(self):
        model, schema = self.model_and_schema()
        self.assertEqual(set(GNU_FIELDS), {name for name, specification in schema.items() if specification.get("optional", False)})
        self.assertEqual(adapter.GNU_ALIGNOF_FIELDS, GNU_FIELDS)
        self.assertIsNone(adapter.validate_model(model, schema))
        for field in GNU_FIELDS:
            changed = copy.deepcopy(model)
            del changed[field]
            with self.subTest(field=field), self.assertRaises(adapter.AdapterError):
                adapter.validate_model(changed, schema)

    def test_compiler_field_must_be_clang_selector_not_executable(self):
        model, schema = self.model_and_schema()
        for selector in (adapter.COMPILER, "gcc", "clang-21", "Clang", "", None):
            changed = copy.deepcopy(model)
            changed["compiler"] = selector
            with self.subTest(selector=selector), self.assertRaises(adapter.AdapterError):
                adapter.validate_model(changed, schema)

    def test_gnu_alignments_must_be_positive_power_of_two_integers(self):
        model, schema = self.model_and_schema()
        for field in GNU_FIELDS:
            for value in (0, -1, 3, True, 4.0, "4", None):
                changed = copy.deepcopy(model)
                changed[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(adapter.AdapterError):
                    adapter.validate_model(changed, schema)

    def test_independent_gnu_values_are_not_replaced_by_c_alignments(self):
        model, schema = self.model_and_schema()
        model.update({name: 1 << index for index, name in enumerate(GNU_FIELDS)})
        before = copy.deepcopy(model)
        self.assertIsNone(adapter.validate_model(model, schema))
        self.assertEqual(model, before)

    def test_each_gnu_diagnostic_is_parsed_under_its_own_name(self):
        for index, name in enumerate(GNU_FIELDS):
            value = 1 << index
            with self.subTest(name=name):
                self.assertEqual(self.parse(name, value), value)
                with self.assertRaises(adapter.AdapterError):
                    self.parse(name, value, stderr=diagnostic(name.removeprefix("gcc_"), value))

    def test_missing_required_unknown_and_wrong_type_fields_are_rejected(self):
        original, schema = self.model_and_schema()
        for field, value in (("sizeof_int", True), ("little_endian", 1), ("wordsize", 32),
                             ("cpp_arch_flags", "-mv68"), ("cpp_arch_flags", [4]), ("surprise", "value")):
            model = copy.deepcopy(original)
            model[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(adapter.AdapterError):
                adapter.validate_model(model, schema)
        del original["wordsize"]
        with self.assertRaises(adapter.AdapterError):
            adapter.validate_model(original, schema)

    def test_macro_mapping_values_require_strings_despite_upstream_schema_gap(self):
        for field in ("custom_defs", "errno"):
            model, schema = self.model_and_schema()
            model[field] = {"fixture": 4}
            with self.subTest(field=field), self.assertRaises(adapter.AdapterError):
                adapter.validate_model(model, schema)

    def test_wrong_optional_field_type_is_rejected(self):
        model, schema = self.model_and_schema()
        model["gcc_alignof_int"] = "4"
        with self.assertRaises(adapter.AdapterError):
            adapter.validate_model(model, schema)

    def test_non_mapping_model_is_rejected(self):
        _, schema = self.model_and_schema()
        for model in (None, [], "not a model"):
            with self.subTest(model=model), self.assertRaises(adapter.AdapterError):
                adapter.validate_model(model, schema)

    def test_missing_jsonschema_cannot_report_success(self):
        model, schema = self.model_and_schema()
        original_import = __import__

        def unavailable(name, *args, **kwargs):
            if name == "jsonschema":
                raise ImportError("inert missing validation dependency")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=unavailable), self.assertRaises(ImportError):
            adapter.validate_model(model, schema)

    def test_compile_command_preserves_target_semantics(self):
        flags = ["--target=hexagon-linux-musl", "-mv68", "-ffreestanding", "-fshort-wchar", "-c"]
        original = list(flags)
        command = adapter.command_for("/usr/bin/clang-21", flags, "/fixture/sizeof_int.c")
        self.assertEqual(command, ["/usr/bin/clang-21", *flags, "/fixture/sizeof_int.c"])
        self.assertEqual(flags, original)

    def test_preprocess_command_removes_only_compile_mode(self):
        flags = ["--target=hexagon-linux-musl", "-mv68", "-ffreestanding", "-fshort-wchar", "-c", "-nostdinc"]
        command = adapter.command_for("/usr/bin/clang-21", flags, "/fixture/wordsize.c", mode="preprocess")
        self.assertNotIn("-c", command)
        self.assertIn("-E", command)
        for flag in flags:
            if flag != "-c":
                self.assertIn(flag, command)

    def test_alignment_command_retains_explicit_trial(self):
        command = adapter.command_for("/usr/bin/clang-21", ["--target=hexagon-linux-musl", "-c"],
                                      "/fixture/max_extended_alignment.c", alignment=16)
        self.assertIn("-DALIGN_TEST=16", command)
        self.assertIn("-c", command)

    def test_macro_inventory_command_is_preprocessing_only(self):
        flags = ["--target=hexagon-linux-musl", "-mv68", "-ffreestanding", "-c"]
        command = adapter.command_for("/usr/bin/clang-21", flags, mode="macros")
        self.assertIn("-dM", command)
        self.assertIn("-E", command)
        self.assertNotIn("-c", command)
        self.assertEqual(command[-1], "-")
        self.assertIn("--target=hexagon-linux-musl", command)

    def test_version_command_does_not_compile_any_source(self):
        self.assertEqual(adapter.command_for("/usr/bin/clang-21", [], mode="version"),
                         ["/usr/bin/clang-21", "--version"])

    def test_unknown_command_mode_is_rejected(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.command_for("/usr/bin/clang-21", [], "/fixture/test.c", mode="execute")

    def test_elf_alignment_observes_honored_request(self):
        observation = adapter.alignment_observation(synthetic_elf(alignment=16), 16)
        self.assertEqual(observation["observed_alignment"], 16)
        self.assertIs(observation["honored"], True)

    def test_elf_alignment_does_not_conflate_exit_success_with_alignment(self):
        observation = adapter.alignment_observation(synthetic_elf(alignment=4), 4294967296)
        self.assertEqual(observation["observed_alignment"], 4)
        self.assertIs(observation["honored"], False)

    def test_truncated_or_wrong_abi_elf_is_rejected(self):
        for data in (b"", synthetic_elf()[:51], synthetic_elf(machine=62), synthetic_elf(flags=0)):
            with self.subTest(length=len(data)), self.assertRaises(adapter.AdapterError):
                adapter.alignment_observation(data, 16)

    def test_missing_or_wrong_object_symbol_is_rejected(self):
        for changes in ({"symbol_name": b"different"}, {"size": 8}, {"symbol_info": 0x12}, {"value": 4}):
            with self.subTest(changes=changes), self.assertRaises(adapter.AdapterError):
                adapter.alignment_observation(synthetic_elf(**changes), 16)

    def test_elf_alignment_probe_value_is_checked(self):
        data = bytearray(synthetic_elf(alignment=16))
        struct.pack_into("<I", data, 64, 43)
        with self.assertRaises(adapter.AdapterError):
            adapter.alignment_observation(bytes(data), 16)

    def test_recorder_timeout_retains_partial_streams_and_failed_result(self):
        with tempfile.TemporaryDirectory(prefix="fragma-hexagon-recorder-test-") as directory:
            recorder = adapter.Recorder(directory, "/usr/bin/clang-21", ["--target=hexagon-linux-musl"],
                                        {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            failure = subprocess.TimeoutExpired(["inert"], 10, output=b"partial stdout", stderr=b"partial stderr")
            with patch("subprocess.run", side_effect=failure) as run, self.assertRaises(adapter.AdapterError):
                recorder.run("sizeof_int", "/fixture/sizeof_int.c")
            self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertLessEqual(run.call_args.kwargs["timeout"], 10)
            result = json.loads((Path(directory) / "command-001/result.json").read_text())
            self.assertIsNone(result["returncode"])
            self.assertIn("timeout", result["failure"].lower())
            self.assertEqual((Path(directory) / "command-001/stdout").read_bytes(), b"partial stdout")
            self.assertEqual((Path(directory) / "command-001/stderr").read_bytes(), b"partial stderr")

    def test_recorder_interruption_retains_failed_result(self):
        with tempfile.TemporaryDirectory(prefix="fragma-hexagon-recorder-test-") as directory:
            recorder = adapter.Recorder(directory, "/usr/bin/clang-21", [], {})
            with patch("subprocess.run", side_effect=KeyboardInterrupt), self.assertRaises(adapter.AdapterError):
                recorder.run("sizeof_int", "/fixture/sizeof_int.c")
            result = json.loads((Path(directory) / "command-001/result.json").read_text())
            self.assertEqual(result["failure"], "KeyboardInterrupt: ")
            self.assertIsNone(result["returncode"])

    def test_recorder_can_retain_legitimate_padded_alignment_object(self):
        # The unmodified initialized alignment probe has a real 16 MiB padding
        # boundary below the final 256 MiB object. This is inert data, not code.
        data = synthetic_elf(alignment=1 << 24)
        with tempfile.TemporaryDirectory(prefix="fragma-hexagon-recorder-test-") as directory:
            recorder = adapter.Recorder(directory, "/usr/bin/clang-21", [], {})

            def emit_fixture(command, **kwargs):
                (Path(kwargs["cwd"]) / "max_extended_alignment.o").write_bytes(data)
                return subprocess.CompletedProcess(command, 0, b"", b"")

            with patch("subprocess.run", side_effect=emit_fixture):
                code, stdout, stderr, record = recorder.run("max_extended_alignment", "/fixture/max_extended_alignment.c",
                                                            alignment=1 << 24)
            self.assertEqual((code, stdout, stderr), (0, "", ""))
            self.assertEqual(len(record["objects"]), 1)
            self.assertTrue((Path(directory) / "command-001/result.json").is_file())


class HexagonProbeInventoryTests(unittest.TestCase):
    """Read/copy pinned probe text; malformed helper ASTs are inert test data."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fragma-hexagon-probe-inventory-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "upstream"
        self.source.mkdir()
        self.helper = self.source / "make_machdep.py"
        self.helper.write_bytes((UPSTREAM / "make_machdep.py").read_bytes())
        for path in UPSTREAM.iterdir():
            if path.suffix in (".c", ".h"):
                (self.source / path.name).write_bytes(path.read_bytes())
        self.destination = self.root / "adapted"
        for target in ("subprocess.run", "subprocess.Popen", "os.system"):
            blocker = patch(target, side_effect=AssertionError("Probe inventory must not execute a tool"))
            self.addCleanup(blocker.stop)
            blocked = blocker.start()
            if target == "subprocess.run":
                self.process = blocked

    @staticmethod
    def selected_assignments(tree, name):
        return [node for node in tree.body if isinstance(node, ast.Assign)
                and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == name]

    def replace_inventory(self, name, value):
        tree = ast.parse(self.helper.read_text())
        matches = self.selected_assignments(tree, name)
        self.assertEqual(len(matches), 1)
        matches[0].value = ast.parse(repr(value), mode="eval").body
        self.helper.write_text(ast.unparse(tree) + "\n")

    def malformed_rejected(self):
        # Only this temporary helper's hash pin changes; its Python is parsed,
        # never executed. The complete original 67-source inventory stays pinned.
        with patch.object(adapter, "HELPER_SHA256", adapter.digest(self.helper.read_bytes())):
            with self.assertRaises((adapter.AdapterError, ValueError)):
                adapter.prepare_sources(self.helper, self.destination)
        self.assertFalse(self.destination.exists())
        self.process.assert_not_called()

    def test_all_64_probes_selected_and_all_67_sources_retained(self):
        tree = ast.parse(self.helper.read_text())
        standard = ast.literal_eval(self.selected_assignments(tree, "standard_source_files")[0].value)
        gnu = [(name + ".c", "number") for name in GNU_FIELDS]
        selected = adapter.prepare_sources(self.helper, self.destination)
        self.assertEqual(len(standard), 52)
        self.assertEqual(selected, standard + gnu)
        self.assertEqual(len(selected), 64)
        originals = {path.name: path.read_bytes() for path in self.source.iterdir() if path.suffix in (".c", ".h")}
        self.assertEqual(len(originals), 67)
        self.assertEqual({path.name for path in self.destination.iterdir()}, set(originals))
        changed = []
        for name, data in originals.items():
            copied = (self.destination / name).read_bytes()
            self.assertEqual(copied, adapter.adapt_probe(name, data.decode()).encode())
            if copied != data:
                changed.append(name)
        self.assertEqual(sorted(changed), ["max_align_t.c", "sanity_check.c", "wordsize.c"])
        self.process.assert_not_called()

    def test_all_gnu_sources_are_byte_identical_not_generated_from_c_probes(self):
        adapter.prepare_sources(self.helper, self.destination)
        for field in GNU_FIELDS:
            name = field + ".c"
            with self.subTest(field=field):
                self.assertEqual((self.destination / name).read_bytes(), (UPSTREAM / name).read_bytes())
                self.assertIn(field + " is", (self.destination / name).read_text())

    def test_missing_gnu_inventory_is_rejected_before_output(self):
        tree = ast.parse(self.helper.read_text())
        tree.body.remove(self.selected_assignments(tree, "gcc_alignof_source_files")[0])
        self.helper.write_text(ast.unparse(tree) + "\n")
        self.malformed_rejected()

    def test_duplicate_gnu_assignment_is_rejected_before_output(self):
        self.helper.write_text(self.helper.read_text() + "\ngcc_alignof_source_files = []\n")
        self.malformed_rejected()

    def test_missing_gnu_row_is_rejected_before_output(self):
        self.replace_inventory("gcc_alignof_source_files", [(name + ".c", "number") for name in GNU_FIELDS[:-1]])
        self.malformed_rejected()

    def test_duplicate_gnu_row_is_rejected_before_output(self):
        rows = [(name + ".c", "number") for name in GNU_FIELDS]
        rows[-1] = rows[0]
        self.replace_inventory("gcc_alignof_source_files", rows)
        self.malformed_rejected()

    def test_wrong_gnu_observation_kind_is_rejected_before_output(self):
        rows = [(name + ".c", "number") for name in GNU_FIELDS]
        rows[0] = (rows[0][0], "type")
        self.replace_inventory("gcc_alignof_source_files", rows)
        self.malformed_rejected()

    def test_c_alignment_cannot_replace_gnu_inventory_row(self):
        rows = [(name + ".c", "number") for name in GNU_FIELDS]
        rows[0] = ("alignof_short.c", "number")
        self.replace_inventory("gcc_alignof_source_files", rows)
        self.malformed_rejected()

    def test_malformed_gnu_inventory_container_is_rejected(self):
        self.replace_inventory("gcc_alignof_source_files", {name + ".c": "number" for name in GNU_FIELDS})
        self.malformed_rejected()

    def test_duplicate_standard_assignment_is_rejected(self):
        self.helper.write_text(self.helper.read_text() + "\nstandard_source_files = []\n")
        self.malformed_rejected()

    def test_duplicate_standard_probe_row_is_rejected(self):
        tree = ast.parse(self.helper.read_text())
        rows = ast.literal_eval(self.selected_assignments(tree, "standard_source_files")[0].value)
        rows[-1] = rows[0]
        self.replace_inventory("standard_source_files", rows)
        self.malformed_rejected()

    def test_unavailable_selected_standard_source_is_rejected(self):
        tree = ast.parse(self.helper.read_text())
        rows = ast.literal_eval(self.selected_assignments(tree, "standard_source_files")[0].value)
        rows[1] = ("unavailable.c", "number")
        self.replace_inventory("standard_source_files", rows)
        self.malformed_rejected()

    def test_changed_original_gnu_source_is_rejected_before_output(self):
        (self.source / "gcc_alignof_short.c").write_bytes(b"/* changed inert source */\n")
        with self.assertRaisesRegex(adapter.AdapterError, "inventory/content"):
            adapter.prepare_sources(self.helper, self.destination)
        self.assertFalse(self.destination.exists())
        self.process.assert_not_called()

    def test_missing_original_gnu_source_is_rejected_before_output(self):
        (self.source / "gcc_alignof_short.c").unlink()
        with self.assertRaisesRegex(adapter.AdapterError, "inventory/content"):
            adapter.prepare_sources(self.helper, self.destination)
        self.assertFalse(self.destination.exists())
        self.process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
