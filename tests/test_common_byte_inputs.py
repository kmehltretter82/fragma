"""Mock-only common24 selector integration; no compiler or analyzer executes."""

import copy
import json
from pathlib import Path
import shlex
import struct
import tempfile
import unittest
from unittest.mock import patch

from fragma import frontend_policy as frontend, inputs
from fragma.sources import SourceError, sha256


def fixture_elf(policy, *, bits=32, little_endian=True):
    """Build a data-only synthetic ET_REL with real section/symbol layouts."""
    endian = "<" if little_endian else ">"
    is64 = bits == 64
    inline = ("inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) "
              + frontend.VARIANTS[policy["variant"]][1]).encode() + b"\0"
    names = (b"fragma_common24_effective_inline", b"fragma_common24_expected_inline")
    strings = b"\0" + names[0] + b"\0" + names[1] + b"\0"
    name_offsets = (1, len(names[0]) + 2)
    header_size, section_size, symbol_size = (64, 64, 24) if is64 else (52, 40, 16)
    data = bytearray(header_size)
    rodata_offset = len(data)
    data.extend(inline * 2)
    strings_offset = len(data)
    data.extend(strings)
    data.extend(b"\0" * (-len(data) % (8 if is64 else 4)))
    symbols_offset = len(data)
    symbols = [bytes(symbol_size)]
    for index, name_offset in enumerate(name_offsets):
        values = (name_offset, 0x11, 0, 1, index * len(inline), len(inline)) if is64 else (
            name_offset, index * len(inline), len(inline), 0x11, 0, 1)
        symbols.append(struct.pack(endian + ("IBBHQQ" if is64 else "IIIBBH"), *values))
    data.extend(b"".join(symbols))
    sections_offset = len(data)
    section_format = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    sections = [(0,) * 10,
        (0, 1, 2, 0, rodata_offset, len(inline) * 2, 0, 0, 1, 0),
        (0, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        (0, 2, 0, 0, symbols_offset, symbol_size * 3, 2, 1, 8 if is64 else 4, symbol_size)]
    for section in sections:
        data.extend(struct.pack(section_format, *section))
    ident = b"\x7fELF" + bytes((2 if is64 else 1, 1 if little_endian else 2, 1)) + bytes(9)
    # Machine identity is descriptive fixture data; no ISA/tool execution claim.
    machine = (62 if little_endian else 21) if is64 else (40 if little_endian else 20)
    # Reuse the string table for empty section names (all sh_name values are 0).
    values = (1, machine, 1, 0, 0, sections_offset, 0, header_size, 0, 0, section_size, len(sections), 2)
    header = ident + struct.pack(endian + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"), *values)
    data[:header_size] = header
    return bytes(data)


class CommonByteInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project with spaces"
        self.source = self.root / "kernel source"
        self.build_path = self.root / "build/kernel/mock profile"
        self.build_path.mkdir(parents=True)
        self.compiler = str(self.root / "tools/mock compiler")
        self.write(Path(self.compiler), "mock compiler identity; never executed\n")
        self.write(self.source / "lib/string.c", "int mock_string_translation_unit;\n")
        self.write(self.source / "include/linux/types.h", "typedef unsigned char u8; typedef unsigned int u32;\n")
        self.write(self.source / "include/linux/unaligned.h", "/* valid mock kernel header */\n")
        self.generated = self.build_path / "include/generated/autoconf.h"
        self.write(self.generated, "#define CONFIG_MOCK 1\n")
        self.write(self.root / frontend.HEADER, "/* valid mock inline header */\n")
        self.strategy = "/*@ lemma mock_reflexive: \\forall integer x; x == x; */\n"
        self.write(self.root / frontend.STRATEGY, self.strategy)
        definitions = []
        for name in frontend.FUNCTIONS:
            signature = ("u32 " + name + "(const u8 *p) { return p[0]; }" if name.startswith("__get_")
                         else "void " + name + "(const u32 val, u8 *p) { *p = val; }")
            contract = ("/*@ requires \\valid_read(p); assigns \\nothing; ensures \\result == p[0]; */\n"
                        if name.startswith("__get_") else
                        "/*@ requires \\valid(p); assigns *p; ensures *p == val % 256; */\n")
            definitions.append(contract + "static inline " + signature)
        for order in ("be", "le"):
            definitions.append("/*@ assigns \\nothing; ensures \\result <= 255; */\n"
                "u32 fragma_roundtrip_" + order + "24(u32 val) { u8 bytes[3] = {0, 0, 0}; "
                "__put_unaligned_" + order + "24(val, bytes); return __get_unaligned_" + order + "24(bytes); }")
        self.raw = '#include "inline-policy.h"\n#include "byteproof.h"\n'
        self.raw += "typedef unsigned char u8; typedef unsigned int u32;\n" + "\n".join(definitions) + "\n"
        self.write(self.root / frontend.HARNESS, self.raw)
        fixture = '#include <linux/types.h>\n#include <linux/unaligned.h>\nint mock_fixture;\n'
        self.write(self.root / frontend.FIXTURE, fixture)
        self.write(self.root / "legacy/helper.c", "int legacy_helper(void) { return 1; }\n")
        self.write(self.root / "legacy/fixture.c", fixture)
        self.write(self.root / "annotated/specs.h", "/* valid mock legacy specifications */\n")
        self.write(self.root / "annotated/compat.h", "/* valid mock legacy compatibility */\n")
        (self.root / "annotated/override").mkdir()
        self.entry = {"file": str(self.source / "lib/string.c"), "directory": str(self.build_path),
            "arguments": [self.compiler, "-m32", "-O2", "-std=gnu11", "-D__KERNEL__",
                "-DGENUINE_BUILD=1", "-I", str(self.source / "include"), "-c",
                str(self.source / "lib/string.c"), "-o", "lib/string.o", "-Wp,-MMD,lib/.string.o.d"]}
        self.save_entry()
        self.build = {"path": str(self.build_path), "source": str(self.source)}
        self.profile = {"compiler": {"path": self.compiler},
            "analysis": {"compiler_flags": ["-m32", "-std=gnu11", "-funsigned-char"]},
            "machdep": {"checked_fields": {"sizeof_ptr": 4, "sizeof_int": 4, "little_endian": True}},
            "build": {"source": str(self.source), "matched_commands": [copy.deepcopy(self.entry)]}}
        self.target = {"id": "mock-common24", "profile": "mock-profile", "input_mode": "standalone",
            "source": "include/linux/unaligned.h", "harness": frontend.HARNESS,
            "kernel_model_check": frontend.FIXTURE, "wp_strategy_file": frontend.STRATEGY,
            "frontend_policy": {"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"}}
        self.env = {"PATH": "/mock-only"}
        self.counter = 0
        self.calls = []
        self.object_bytes = lambda: fixture_elf(self.target["frontend_policy"],
            bits=self.profile["machdep"]["checked_fields"]["sizeof_ptr"] * 8,
            little_endian=self.profile["machdep"]["checked_fields"]["little_endian"])
        self.returncode, self.timed_out = 0, False
        self.emit_dependencies = True
        runner = patch.object(inputs, "run_recorded", side_effect=self.run_mock)
        self.runner = runner.start()
        self.addCleanup(runner.stop)
        snapshots = patch.object(inputs, "check_snapshot_files", side_effect=self.mock_snapshot)
        self.snapshot = snapshots.start()
        self.addCleanup(snapshots.stop)
        processes = patch("subprocess.Popen", side_effect=AssertionError("test must not start any process"))
        processes.start()
        self.addCleanup(processes.stop)

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def save_entry(self):
        self.write(self.build_path / "compile_commands.json", json.dumps([self.entry]))

    def output(self):
        self.counter += 1
        path = self.root / ("results/output " + str(self.counter))
        path.mkdir(parents=True)
        return path

    def mock_snapshot(self, kernel, revision, source, paths):
        self.assertEqual(kernel, self.source)
        self.assertEqual(revision, "mock-revision")
        return [{"path": str(path.relative_to(source)), "sha256": sha256(path), "passed": True}
                for path in paths]

    @staticmethod
    def make_escape(path):
        return str(path).replace("\\", "\\\\").replace(" ", "\\ ").replace("#", "\\#").replace("$", "$$")

    def run_mock(self, argv, *, cwd, env, log, timeout, stdout_file=None):
        self.calls.append({"argv": list(argv), "cwd": cwd, "env": copy.deepcopy(env),
                           "log": log, "timeout": timeout, "stdout_file": stdout_file})
        log.write_text("")
        if stdout_file is not None:
            source = Path(argv[-1])
            stdout_file.write_text(source.read_text())
            dependencies = [source, self.root / frontend.HEADER, self.root / frontend.STRATEGY]
        else:
            source = Path(argv[argv.index("-c") + 1])
            dependencies = [source, self.root / frontend.HEADER,
                self.source / "include/linux/types.h", self.source / "include/linux/unaligned.h", self.generated]
            if self.object_bytes is not None:
                content = self.object_bytes() if callable(self.object_bytes) else self.object_bytes
                Path(argv[argv.index("-o") + 1]).write_bytes(content)
        if self.emit_dependencies:
            Path(argv[argv.index("-MF") + 1]).write_text(
                "fragma: " + " ".join(self.make_escape(path) for path in dependencies) + "\n")
        return {"argv": list(argv), "cwd": str(cwd), "returncode": self.returncode,
            "timed_out": self.timed_out, "seconds": 0.0, "log": str(log), "log_sha256": sha256(log)}

    def prepare(self, target=None, output=None):
        return inputs.prepare_input(self.root, target or self.target, self.profile, self.build,
                                    self.source, "mock-revision", output or self.output(), self.env)

    def fixture(self, target=None, output=None):
        return inputs.kernel_model_check(self.root, target or self.target, self.build,
                                         self.source, "mock-revision", output or self.output(), self.env)

    def both(self, target=None):
        output = self.output()
        return output, self.prepare(target, output), self.fixture(target, output)

    def validate_returned_frontend(self, output, prepared, fixture):
        stream = output / "tmp/unaligned24.verified.c123.i456.pp"
        attribute = frontend.VARIANTS[self.target["frontend_policy"]["variant"]][1]
        expanded = self.raw.replace("static inline ",
            "static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) " + attribute + " ")
        expanded = expanded.replace('#include "inline-policy.h"\n', "").replace(
            '#include "byteproof.h"\n', (self.root / frontend.STRATEGY).read_text())
        self.write(stream, expanded)
        retained = {"path": str(stream.relative_to(output)), "absolute_path": str(stream), "sha256": sha256(stream)}
        audit = {"inputs": prepared["inputs"], "retained_preprocessing": [retained],
                 "parsed_streams": [{"source": frontend.HARNESS, **retained}]}
        actual = {"argv": ["/mock/frama-c", "-cpp-command", prepared["frama_cpp_command"],
            "-cpp-extra-args=-std=gnu11", "-cpp-frama-c-compliant", "-pp-annot", "-keep-temp-files",
            prepared["frama_input"], "-wp", "-then", "-report"],
            "cwd": prepared["cwd"], "returncode": 0, "timed_out": False}
        return frontend.validate_actual(self.root, self.target, self.profile, prepared, fixture, actual, audit)

    def test_same_explicit_selector_in_all_three_command_forms_without_mutation(self):
        for variant, (selector, _) in frontend.VARIANTS.items():
            with self.subTest(variant=variant):
                self.target["frontend_policy"]["variant"] = variant
                before = copy.deepcopy((self.profile, self.target, self.build, self.entry, self.env))
                _, prepared, fixture = self.both()
                flag = "-D" + frontend.MACRO + "=" + str(selector)
                for argv in (prepared["preprocess"]["argv"], shlex.split(prepared["frama_cpp_command"]), fixture["argv"]):
                    self.assertEqual([arg for arg in argv if frontend.MACRO in arg], [flag])
                    self.assertEqual(argv[0], self.compiler)
                self.assertEqual((self.profile, self.target, self.build, self.entry, self.env), before)
                self.assertEqual(inputs.compile_entry(self.build, "lib/string.c"), self.entry)
        self.assertEqual(len(self.calls), 4)  # The analyzer CPP is recorded, never executed.

    def test_returned_inputs_and_fixture_pass_full_actual_frontend_gate(self):
        for variant in frontend.VARIANTS:
            with self.subTest(variant=variant):
                self.target["frontend_policy"]["variant"] = variant
                output, prepared, fixture = self.both()
                result = self.validate_returned_frontend(output, prepared, fixture)
                self.assertEqual(result["status"], "checked")
                self.assertEqual(result["policy"], self.target["frontend_policy"])
                self.assertEqual(len(result["functions"]), 4)
                self.assertEqual([row["function"] for row in result["witnesses"]],
                                 ["fragma_roundtrip_be24", "fragma_roundtrip_le24"])
                self.assertTrue(all(row["declaration_prefix"] == ["u32"] for row in result["witnesses"]))
                self.assertEqual(result["annotations"]["block_count"], 7)
                self.assertEqual(len(result["annotations"]["block_token_sha256"]), 7)
                self.assertEqual(result["typedefs"], {"u8": ["unsigned", "char"], "u32": ["unsigned", "int"]})
                self.assertEqual(result["fixture_object"]["class"], 32)
                self.assertEqual(result["fixture_object"]["byte_order"], "little")
                self.assertEqual(set(result["fixture_object"]["inline_metadata"]),
                                 {"fragma_common24_effective_inline", "fragma_common24_expected_inline"})
                self.assertEqual(result["harness_sha256"], sha256(self.root / frontend.HARNESS))
                self.assertEqual(result["strategy_sha256"], sha256(self.root / frontend.STRATEGY))

    def test_genuine_fixture_binds_entry_dependencies_object_and_input_origins(self):
        output, prepared, fixture = self.both()
        flag = frontend.cpp_arguments(self.target)
        expected = [*inputs.command_without_outputs(self.entry), *flag, "-Werror", "-MD", "-MF",
            str(output / "model-headers.d"), "-MT", "fragma", "-c", str(self.root / frontend.FIXTURE),
            "-o", str(output / "kernel-model.o")]
        self.assertEqual(fixture["argv"], expected)
        self.assertEqual(fixture["original_compile_command"], self.entry)
        self.assertEqual(fixture["frontend_policy"], self.target["frontend_policy"])
        self.assertEqual(fixture["fixture_sha256"], sha256(self.root / frontend.FIXTURE))
        for field, filename in (("object", "kernel-model.o"), ("dependencies", "model-headers.d")):
            self.assertEqual(fixture[field], {"absolute_path": str(output / filename), "sha256": sha256(output / filename)})
        self.assertEqual(fixture["diagnostics"], {"absolute_path": fixture["log"], "sha256": fixture["log_sha256"]})
        rows = {row["absolute_path"]: row for row in fixture["inputs"]}
        self.assertEqual(rows[str(self.source / "include/linux/types.h")]["origin"], "kernel")
        self.assertEqual(rows[str(self.generated)]["origin"], "kernel-build")
        self.assertEqual(rows[str(self.root / frontend.HEADER)]["origin"], "project")
        self.assertEqual(set(rows), {str(path) for path in inputs.dependency_paths(output / "model-headers.d", self.build_path)})
        self.assertEqual(prepared["frama_input"], str(self.root / frontend.HARNESS))
        self.assertNotEqual(prepared["frama_input"], prepared["path"])
        self.assertEqual(self.calls[-1]["timeout"], 120)

    def test_missing_policy_rejects_before_either_compiler_invocation(self):
        del self.target["frontend_policy"]
        for action in (self.prepare, self.fixture):
            with self.subTest(action=action.__name__), self.assertRaises(SourceError):
                action()
        self.runner.assert_not_called()

    def test_missing_policy_cannot_use_normalized_or_absolute_common_paths(self):
        for field, controlled in (("harness", frontend.HARNESS), ("kernel_model_check", frontend.FIXTURE)):
            for alias in ("./" + controlled, controlled.replace("common/annotated/", "common/annotated/../annotated/"),
                          str(self.root / controlled)):
                target = {"harness": "legacy/helper.c", "kernel_model_check": "legacy/fixture.c",
                          "input_mode": "standalone", "profile": "legacy", field: alias}
                for action in (self.prepare, self.fixture):
                    with self.subTest(field=field, alias=alias, action=action.__name__), self.assertRaisesRegex(SourceError, "explicit policy"):
                        action(target)
        self.runner.assert_not_called()

    def test_missing_policy_cannot_reach_common_inputs_through_symlinks(self):
        aliases = self.root / "aliases"
        aliases.mkdir()
        (self.root / "linked-common").symlink_to(self.root / "common", target_is_directory=True)
        for field, controlled in (("harness", frontend.HARNESS), ("kernel_model_check", frontend.FIXTURE)):
            link = aliases / Path(controlled).name
            link.symlink_to(self.root / controlled)
            for alias in (str(link.relative_to(self.root)), controlled.replace("common/", "linked-common/", 1)):
                target = {"harness": "legacy/helper.c", "kernel_model_check": "legacy/fixture.c",
                          "input_mode": "standalone", "profile": "legacy", field: alias}
                for action in (self.prepare, self.fixture):
                    with self.subTest(field=field, alias=alias, action=action.__name__), self.assertRaisesRegex(SourceError, "explicit policy"):
                        action(target)
        self.runner.assert_not_called()

    def test_closed_policy_rejects_invalid_schema_before_invocation(self):
        original = copy.deepcopy(self.target["frontend_policy"])
        for policy in (None, {}, True, {**original, "schema_version": True},
                       {**original, "schema_version": 1.0}, {**original, "variant": 1},
                       {**original, "variant": "unknown"}, {**original, "flags": ["-Dinline="]}):
            self.target["frontend_policy"] = policy
            for action in (self.prepare, self.fixture):
                with self.subTest(policy=policy, action=action.__name__), self.assertRaises(SourceError):
                    action()
        self.runner.assert_not_called()

    def test_arbitrary_target_cpp_overrides_reject_before_invocation(self):
        for key, value in (("cpp_definitions", {"inline": ""}), ("cpp_extra_args", []), ("cpp_flags", ["-U__KERNEL__"])):
            target = {**self.target, key: value}
            for action in (self.prepare, self.fixture):
                with self.subTest(key=key, action=action.__name__), self.assertRaises(SourceError):
                    action(target)
        self.runner.assert_not_called()

    def test_profile_cannot_predefine_or_undefine_selector(self):
        original = copy.deepcopy(self.profile)
        for flags in (["-D" + frontend.MACRO + "=1"], ["-D", frontend.MACRO + "=2"],
                      ["-U" + frontend.MACRO], ["-U", frontend.MACRO]):
            self.profile = copy.deepcopy(original)
            self.profile["analysis"]["compiler_flags"] += flags
            before = copy.deepcopy(self.profile)
            with self.subTest(flags=flags), self.assertRaisesRegex(SourceError, "pre-existing"):
                self.prepare()
            self.assertEqual(self.profile, before)
        self.runner.assert_not_called()

    def test_genuine_command_cannot_predefine_or_undefine_selector(self):
        original = copy.deepcopy(self.entry)
        for flags in (["-D" + frontend.MACRO + "=1"], ["-D", frontend.MACRO + "=2"], ["-U", frontend.MACRO]):
            self.entry = copy.deepcopy(original)
            self.entry["arguments"][1:1] = flags
            self.save_entry()
            with self.subTest(flags=flags), self.assertRaisesRegex(SourceError, "pre-existing"):
                self.fixture()
            self.assertEqual(inputs.compile_entry(self.build, "lib/string.c"), self.entry)
        self.runner.assert_not_called()

    def test_new_fixture_requires_nonempty_object_and_no_timeout(self):
        for content, timed_out in ((None, False), (b"", False), (b"\x7fELFmock", True)):
            self.object_bytes, self.timed_out = content, timed_out
            with self.subTest(content=content, timed_out=timed_out), self.assertRaisesRegex(SourceError, "produce an object"):
                self.fixture()

    def test_new_fixture_and_preprocessing_reject_failed_commands(self):
        self.returncode = 1
        for action in (self.prepare, self.fixture):
            with self.subTest(action=action.__name__), self.assertRaises(SourceError):
                action()

    def test_missing_actual_dependency_file_is_not_a_successful_receipt(self):
        self.emit_dependencies = False
        for action in (self.prepare, self.fixture):
            with self.subTest(action=action.__name__), self.assertRaisesRegex(SourceError, "did not emit dependencies"):
                action()

    def test_rehashed_non_elf_fixture_cannot_pass_actual_frontend_gate(self):
        self.object_bytes = b"not an ELF object"
        output, prepared, fixture = self.both()
        with self.assertRaisesRegex(SourceError, "ELF"):
            self.validate_returned_frontend(output, prepared, fixture)

    def test_rehashed_wrong_elf_class_order_and_truncated_header_reject(self):
        policy = self.target["frontend_policy"]
        for data in (fixture_elf(policy, bits=64), fixture_elf(policy, little_endian=False),
                     fixture_elf(policy)[:40]):
            self.object_bytes = data
            output, prepared, fixture = self.both()
            with self.subTest(ident=data[:16]), self.assertRaisesRegex(SourceError, "ELF"):
                self.validate_returned_frontend(output, prepared, fixture)

    def test_rehashed_inline_metadata_cannot_differ_from_selected_policy(self):
        valid = fixture_elf(self.target["frontend_policy"])
        self.object_bytes = valid.replace(b"inline __attribute__", b"Inline __attribute__", 1)
        output, prepared, fixture = self.both()
        with self.assertRaisesRegex(SourceError, "inline metadata"):
            self.validate_returned_frontend(output, prepared, fixture)

    def test_fixture_requires_strict_checked_pointer_width_and_byte_order(self):
        self.object_bytes = fixture_elf(self.target["frontend_policy"])
        for fields in ({}, {"sizeof_ptr": True, "little_endian": True},
                       {"sizeof_ptr": 4, "little_endian": 1}, {"sizeof_ptr": 16, "little_endian": True},
                       {"sizeof_ptr": 4, "little_endian": "true"}):
            self.profile["machdep"]["checked_fields"] = fields
            output, prepared, fixture = self.both()
            with self.subTest(fields=fields), self.assertRaisesRegex(SourceError, "checked pointer width"):
                self.validate_returned_frontend(output, prepared, fixture)

    def test_legacy_standalone_argv_and_receipt_shape_are_unchanged(self):
        target = {"harness": "legacy/helper.c", "input_mode": "standalone", "profile": "legacy"}
        output = self.output()
        prepared = self.prepare(target, output)
        base = [self.compiler, *self.profile["analysis"]["compiler_flags"], "-nostdinc", "-D__KERNEL__"]
        self.assertEqual(shlex.split(prepared["frama_cpp_command"]), [*base, "-E", "-C"])
        self.assertEqual(prepared["preprocess"]["argv"], [*base, "-D__FRAMAC__", "-E", "-C", "-MD", "-MF",
            str(output / "headers.d"), "-MT", "fragma", str(self.root / target["harness"])])
        self.assertEqual(set(prepared), {"path", "sha256", "frama_input", "frama_cpp_command", "cwd",
            "preprocess", "original_compile_command", "inputs", "annotations"})
        self.assertIsNone(prepared["original_compile_command"])
        self.assertFalse(any(frontend.MACRO in arg for arg in prepared["preprocess"]["argv"]))

    def test_legacy_kernel_tu_command_adaptation_remains_unchanged(self):
        target = {"harness": "legacy/helper.c", "input_mode": "kernel-tu", "profile": "x86_64-gcc", "source": "lib/string.c"}
        prepared = self.prepare(target)
        expected = inputs.command_without_outputs(self.entry)
        expected[1:1] = ["-I", str(self.root / "annotated/override")]
        expected += ["-include", str(self.root / "annotated/specs.h"), "-include",
                     str(self.root / "annotated/compat.h"), *inputs.SHIMS, "-E", "-C"]
        self.assertEqual(shlex.split(prepared["frama_cpp_command"]), expected)
        self.assertEqual(prepared["original_compile_command"], self.entry)
        self.assertFalse(any(frontend.MACRO in arg for arg in expected))

    def test_arm32_kernel_tu_uses_real_arch_headers_and_exact_opt_in(self):
        target = {"harness": "legacy/helper.c", "input_mode": "kernel-tu",
                  "profile": "arm-gcc", "source": "lib/string.c",
                  "kernel_tu_policy": copy.deepcopy(inputs.ARM32_KERNEL_TU_POLICY)}
        prepared = self.prepare(target)
        expected = inputs.command_without_outputs(self.entry)
        expected += ["-include", str(self.root / "annotated/specs.h"), "-include",
                     str(self.root / "annotated/compat.h"), *inputs.ARM32_SHIMS, "-E", "-C"]
        self.assertEqual(shlex.split(prepared["frama_cpp_command"]), expected)
        self.assertNotIn(str(self.root / "annotated/override"), expected)
        self.assertFalse(any(str(self.root / directory) in expected
                             for directory in inputs.ARM32_HEADER_MODEL_DIRS.values()))
        self.assertNotIn("-D__SIZEOF_INT128__=16", expected)
        self.assertEqual(prepared["original_compile_command"], self.entry)

    def test_arm32_header_model_is_closed_and_explicit(self):
        base = {"harness": "legacy/helper.c", "input_mode": "kernel-tu",
                "profile": "arm-gcc", "source": "lib/string.c",
                "kernel_tu_policy": copy.deepcopy(inputs.ARM32_KERNEL_TU_POLICY)}
        target = {**base,
                  "arm32_header_models": ["word-at-a-time-mapped-load-v1"]}
        prepared = self.prepare(target)
        argv = shlex.split(prepared["frama_cpp_command"])
        override = str(self.root / inputs.ARM32_HEADER_MODEL_DIRS[
            "word-at-a-time-mapped-load-v1"])
        self.assertEqual(argv[1:3], ["-I", override])
        for models in (True, "word-at-a-time-mapped-load-v1",
                       ["word-at-a-time-mapped-load-v2"],
                       ["word-at-a-time-mapped-load-v1"] * 2):
            with self.subTest(models=models), self.assertRaisesRegex(
                    SourceError, "header-model inventory"):
                self.prepare({**base, "arm32_header_models": models})

    def test_arm32_header_models_preserve_declared_precedence(self):
        base = {"harness": "legacy/helper.c", "input_mode": "kernel-tu",
                "profile": "arm-gcc", "source": "lib/string.c",
                "kernel_tu_policy": copy.deepcopy(inputs.ARM32_KERNEL_TU_POLICY),
                "arm32_header_models": ["recent-pci-frontend-v1",
                                        "word-at-a-time-mapped-load-v1"]}
        argv = shlex.split(self.prepare(base)["frama_cpp_command"])
        self.assertEqual(argv[1:5], [
            "-I", str(self.root / "harness/arm32-recent-override"),
            "-I", str(self.root / "harness/arm32-override")])

    def test_pinned_arm32_translation_unit_is_analyzed_directly(self):
        target = {"input_mode": "kernel-tu", "profile": "arm-gcc",
                  "source": "lib/string.c", "specs": "annotated/specs.h",
                  "kernel_tu_policy": copy.deepcopy(inputs.ARM32_KERNEL_TU_POLICY),
                  "provenance": {"mode": "pinned-translation-unit"}}
        prepared = self.prepare(target)
        source = str((self.source / "lib/string.c").resolve())
        self.assertEqual(prepared["frama_input"], source)
        self.assertEqual(prepared["analysis_source"], source)
        self.assertEqual(Path(prepared["preprocess"]["argv"][-1]), Path(source))
        self.assertNotIn("harness", target)

    def test_pinned_translation_unit_rejects_a_copy_or_standalone_route(self):
        base = {"input_mode": "kernel-tu", "profile": "arm-gcc",
                "source": "lib/string.c", "specs": "annotated/specs.h",
                "kernel_tu_policy": copy.deepcopy(inputs.ARM32_KERNEL_TU_POLICY),
                "provenance": {"mode": "pinned-translation-unit"}}
        for target in ({**base, "harness": "legacy/helper.c"},
                       {**base, "input_mode": "standalone"}):
            with self.subTest(target=target), self.assertRaisesRegex(
                    SourceError, "pinned translation units"):
                self.prepare(target)

    def test_non_x86_kernel_tu_requires_the_exact_supported_policy(self):
        base = {"harness": "legacy/helper.c", "input_mode": "kernel-tu",
                "profile": "arm-gcc", "source": "lib/string.c"}
        for policy in (None, {}, {"schema_version": True, "kind": "configured-arm32-v1"},
                       {"schema_version": 1, "kind": "configured-arm32-v2"},
                       {"schema_version": 1, "kind": "configured-arm32-v1", "extra": True}):
            target = {**base, **({} if policy is None else {"kernel_tu_policy": policy})}
            with self.subTest(policy=policy), self.assertRaisesRegex(
                    SourceError, "whole-TU frontend policy"):
                self.prepare(target)

        changed_profile = {**base, "profile": "powerpc32-gcc",
                           "kernel_tu_policy": copy.deepcopy(inputs.ARM32_KERNEL_TU_POLICY)}
        with self.assertRaisesRegex(SourceError, "whole-TU frontend policy"):
            self.prepare(changed_profile)

    def test_legacy_fixture_keeps_original_argv_and_receipt_shape(self):
        target = {"harness": "legacy/helper.c", "kernel_model_check": "legacy/fixture.c"}
        output = self.output()
        fixture = self.fixture(target, output)
        self.assertEqual(fixture["argv"], [*inputs.command_without_outputs(self.entry), "-Werror", "-MD", "-MF",
            str(output / "model-headers.d"), "-MT", "fragma", "-c", str(self.root / target["kernel_model_check"]),
            "-o", str(output / "kernel-model.o")])
        self.assertEqual(set(fixture), {"argv", "cwd", "returncode", "timed_out", "seconds", "log",
                                      "log_sha256", "inputs", "fixture_sha256"})
        self.assertFalse(any(frontend.MACRO in arg for arg in fixture["argv"]))

    def test_absent_legacy_fixture_remains_none_without_execution(self):
        self.assertIsNone(self.fixture({"harness": "legacy/helper.c"}))
        self.runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
