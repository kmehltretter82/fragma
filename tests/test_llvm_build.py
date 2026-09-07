"""Closed Hexagon LLVM build gates, using inert files and mocked processes only."""

import copy
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma.llvm_build import prepare_llvm, verify_llvm_build
from fragma.sources import SourceError


TOOLS = {
    "CC": "clang", "HOSTCC": "clang", "HOSTCXX": "clang++",
    "LD": "ld.lld", "AR": "llvm-ar", "LLVM_LINK": "llvm-link",
    "NM": "llvm-nm", "OBJCOPY": "llvm-objcopy", "OBJDUMP": "llvm-objdump",
    "READELF": "llvm-readelf", "STRIP": "llvm-strip",
}
REQUIRED_FLAGS = [
    "--target=hexagon-linux-musl", "-mv68", "-fintegrated-as", "-G0",
    "-fno-short-enums", "-mlong-calls", "-ffixed-r19",
    "-DTHREADINFO_REG=r19", "-D__linux__", "-nostdinc",
]


def checksum(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def elf_object(*, bits=32, endian="little", machine=164, elf_type=1):
    """Bounded data-only ELF tables; no instructions or compiler-product claim."""
    encoding = "<" if endian == "little" else ">"
    wide = bits == 64
    header_size, section_size, symbol_size = (64, 64, 24) if wide else (52, 40, 16)
    identification = b"\x7fELF" + bytes([1 if bits == 32 else 2,
                                         1 if endian == "little" else 2, 1, 0, 0]) + bytes(7)
    strings = b"\0.strtab\0.symtab\0"
    data = bytearray(header_size)
    strings_offset = len(data)
    data.extend(strings)
    data.extend(bytes(-len(data) % (8 if wide else 4)))
    symbols_offset = len(data)
    data.extend(bytes(symbol_size))  # The sole, all-zero null symbol.
    section_offset = len(data)
    sections = [(0,) * 10,
                (1, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
                (9, 2, 0, 0, symbols_offset, symbol_size, 1, 1,
                 8 if wide else 4, symbol_size)]
    for section in sections:
        data.extend(struct.pack(encoding + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), *section))
    fields = struct.pack(encoding + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"),
                         elf_type, machine, 1, 0, 0, section_offset, 0, header_size,
                         0, 0, section_size, len(sections), 1)
    data[:header_size] = identification + fields
    return bytes(data)


class LLVMBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fragma-llvm-build-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Several real LLVM aliases share a binary. Preserve that distinction
        # here without creating a script or ever executing these inert bytes.
        aliases = {"clang++": "clang", "ld.lld": "lld",
                   "llvm-readelf": "llvm-readobj", "llvm-strip": "llvm-objcopy"}
        for name in set(TOOLS.values()):
            backing = self.bin / aliases.get(name, name)
            if not backing.exists():
                backing.write_bytes(("inert mock LLVM binary: " + backing.name + "\n").encode())
                backing.chmod(0o755)
            alias = self.bin / name
            if alias != backing:
                alias.symlink_to(backing.name)
        self.compiler = self.bin / "clang"
        self.profile = {
            "id": "hexagon-clang", "architecture": "hexagon",
            "compiler_family": "clang", "compiler": "clang",
            "compiler_version": "21.1.8",
            "compiler_target": "hexagon-unknown-linux-musl",
            "flags": ["-mv68"],
            "kernel": {
                "arch": "hexagon", "subarch": None,
                "required_config": {"CONFIG_HEXAGON_ARCH_VERSION": "68"},
                "llvm": {
                    "schema_version": 1, "target": "hexagon-linux-musl",
                    "observed_target": "hexagon-unknown-linux-musl", "cpu": 68,
                    "tools": {role: {"path": str(self.bin / name),
                                     "sha256": checksum(self.bin / name)}
                              for role, name in TOOLS.items()},
                },
            },
        }
        self.env = {
            "PATH": str(self.bin), "LANG": "C.UTF-8", "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(self.root / "loader"),
        }
        self.output = self.root / "build"
        (self.output / "lib").mkdir(parents=True)
        self.source = self.root / "source" / "lib" / "string.c"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("/* inert command-identity fixture; never compiled */\n")
        self.entry = {
            "directory": str(self.output), "file": str(self.source),
            "arguments": [str(self.compiler), *REQUIRED_FLAGS,
                          "-std=gnu11", "-funsigned-char", "-fshort-wchar",
                          "-fno-strict-overflow", "-fno-strict-aliasing", "-O2",
                          "-Wp,-MMD,lib/.string.o.d", "-c", "-o", "lib/string.o",
                          str(self.source)],
        }
        self.write_build()

    def write_build(self, entries=None):
        (self.output / ".config").write_text(
            "CONFIG_HEXAGON=y\nCONFIG_HEXAGON_ARCH_VERSION=68\n# CONFIG_64BIT is not set\n")
        entries = [self.entry] if entries is None else entries
        (self.output / "compile_commands.json").write_text(json.dumps(entries))
        selected = next((entry for entry in entries if isinstance(entry, dict) and
                         str(entry.get("file", "")).endswith("/lib/string.c")), self.entry)
        args = selected.get("arguments") or shlex.split(selected["command"])
        (self.output / "lib/.string.o.cmd").write_text(
            "savedcmd_lib/string.o := " + shlex.join(args) + "\n")
        (self.output / "lib/string.o").write_bytes(elf_object())

    def fake_process(self, argv, **kwargs):
        self.assertIsInstance(argv, list)
        self.assertTrue(all(isinstance(value, str) for value in argv))
        self.assertFalse(kwargs.get("shell", False))
        self.assertGreater(kwargs["timeout"], 0)
        self.assertTrue(kwargs.get("capture_output"))
        self.assertTrue(kwargs.get("text"))
        self.assertIsInstance(kwargs.get("env"), dict)
        if argv[1:] == ["--version"]:
            name = Path(argv[0]).name
            if name in ("clang", "clang++"):
                value = "Ubuntu clang version 21.1.8 (test fixture)\n"
            elif name == "ld.lld":
                value = "Ubuntu LLD 21.1.8 (test fixture)\n"
            else:
                value = "Debian LLVM version 21.1.8\n  Optimized build.\n"
        else:
            self.assertEqual(argv, [str(self.compiler), "--target=hexagon-linux-musl",
                                    "-mv68", "-dumpmachine"])
            value = "hexagon-unknown-linux-musl\n"
        return subprocess.CompletedProcess(argv, 0, value, "")

    def prepare(self, profile=None, *, env=None, responder=None, compiler=None):
        with patch("fragma.llvm_build.subprocess.run",
                   side_effect=responder or self.fake_process) as run, \
                patch("subprocess.Popen", side_effect=AssertionError("unmocked process launch")):
            value = prepare_llvm(self.profile if profile is None else profile,
                                 str(self.compiler if compiler is None else compiler),
                                 self.env if env is None else env)
        return value, run.call_args_list

    def verify(self, receipt, profile=None):
        with patch("subprocess.run", side_effect=AssertionError("readback must not launch a tool")), \
                patch("subprocess.Popen", side_effect=AssertionError("readback must not launch a tool")):
            return verify_llvm_build(self.profile if profile is None else profile,
                                     self.output, receipt, source=self.source.parent.parent)

    def valid_receipt(self):
        (_, receipt, _), _ = self.prepare()
        # Every negative readback starts from an actually accepted synthetic
        # context; an unrelated earlier rejection must not hide a missing gate.
        self.assertIsInstance(self.verify(receipt), dict)
        return receipt

    def test_prepare_binds_complete_tools_versions_and_target_without_alias_resolution(self):
        before = copy.deepcopy(self.profile)
        (assignments, receipt, clean), calls = self.prepare()
        expected = ["LLVM=1", "LLVM_IAS=1", *[
            role + "=" + settings["path"]
            for role, settings in self.profile["kernel"]["llvm"]["tools"].items()],
            "HOSTAR=" + str(self.bin / "llvm-ar"),
            "HOSTLD=" + str(self.bin / "ld.lld"),
            "KBUILD_HOSTLDFLAGS=--ld-path=" + str(self.bin / "ld.lld")]
        self.assertCountEqual(assignments, expected)
        self.assertEqual(len(assignments), len(set(assignments)))
        self.assertEqual(set(receipt["tools"]), set(TOOLS))
        for role, expected_tool in self.profile["kernel"]["llvm"]["tools"].items():
            observed = receipt["tools"][role]
            self.assertEqual(observed["path"], expected_tool["path"])
            self.assertEqual(observed["resolved_path"], str(Path(expected_tool["path"]).resolve()))
            self.assertEqual(observed["sha256"], expected_tool["sha256"])
            self.assertEqual(observed["version"], "21.1.8")
            self.assertEqual(observed["version_command"], [expected_tool["path"], "--version"])
            self.assertIn("21.1.8", observed["version_output"])
        self.assertEqual(receipt["target"]["requested"], "hexagon-linux-musl")
        self.assertEqual(receipt["target"]["observed"], "hexagon-unknown-linux-musl")
        self.assertEqual(receipt["target"]["command"],
                         [str(self.compiler), "--target=hexagon-linux-musl", "-mv68", "-dumpmachine"])
        self.assertEqual(receipt["cpu"], 68)
        self.assertEqual(self.profile, before)
        commands = [call.args[0] for call in calls]
        for observed in receipt["tools"].values():
            self.assertIn(observed["version_command"], commands)
        self.assertEqual(commands.count(receipt["target"]["command"]), 1)
        self.assertTrue(all(call.kwargs["env"] == clean for call in calls))

    def test_prepare_environment_is_allowlisted_and_does_not_mutate_caller(self):
        injected = {**self.env, **{key: "must-not-survive" for key in (
            "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
            "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEOVERRIDES", "KCFLAGS",
            "KCPPFLAGS", "KAFLAGS", "CROSS_COMPILE", "CC", "HOSTCC", "HOSTCXX",
            "LLVM", "LLVM_IAS", "LD", "AR", "KBUILD_HOSTLDFLAGS", "LIBRARY_PATH",
            "COMPILER_PATH", "GCC_EXEC_PREFIX", "CCC_OVERRIDE_OPTIONS", "UNRELATED_SECRET")}}
        before = copy.deepcopy(injected)
        (_, _, clean), calls = self.prepare(env=injected)
        self.assertEqual(clean, self.env)
        self.assertEqual(injected, before)
        self.assertTrue(all(call.kwargs["env"] == clean for call in calls))

    def test_prepare_requires_explicit_closed_hexagon_v68_route(self):
        mutations = [
            ("compiler_family", "gcc"), ("compiler_family", None),
            ("compiler_version", "21.1.7"),
        ]
        for field, value in mutations:
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(SourceError):
                self.prepare(profile)
        for field, value in (("schema_version", True), ("schema_version", 2),
                             ("target", "hexagon-unknown-linux-musl"),
                             ("observed_target", "x86_64-pc-linux-gnu"),
                             ("cpu", 60), ("cpu", "68"), ("cpu", True)):
            profile = copy.deepcopy(self.profile)
            profile["kernel"]["llvm"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(SourceError):
                self.prepare(profile)
        for field, value in (("arch", "x86"),
                             ("required_config", {"CONFIG_HEXAGON_ARCH_VERSION": "2"})):
            profile = copy.deepcopy(self.profile)
            profile["kernel"][field] = value
            with self.subTest(field=field), self.assertRaises(SourceError):
                self.prepare(profile)

    def test_prepare_rejects_missing_extra_and_malformed_tool_roles(self):
        for role in TOOLS:
            profile = copy.deepcopy(self.profile)
            del profile["kernel"]["llvm"]["tools"][role]
            with self.subTest(missing=role), self.assertRaises(SourceError):
                self.prepare(profile)
        for value in (None, [], {}, {**self.profile["kernel"]["llvm"]["tools"],
                                    "AS": self.profile["kernel"]["llvm"]["tools"]["CC"]}):
            profile = copy.deepcopy(self.profile)
            profile["kernel"]["llvm"]["tools"] = value
            with self.subTest(tools=repr(value)), self.assertRaises(SourceError):
                self.prepare(profile)

    def test_prepare_rejects_bad_tool_paths_and_hashes(self):
        # Give unsafe absolute paths valid bytes and hashes: rejection must be
        # the path policy, not merely a missing-file or hash-mismatch shortcut.
        for name in ("tool with space", "tool;bad", "tool$bad", "tool#bad"):
            (self.bin / name).write_bytes(self.compiler.read_bytes())
        for value in ("clang", str(self.bin / "absent"), str(self.bin),
                      str(self.bin / "tool with space"), str(self.bin / "tool;bad"),
                      str(self.bin / "tool$bad"), str(self.bin / "tool#bad")):
            profile = copy.deepcopy(self.profile)
            profile["kernel"]["llvm"]["tools"]["CC"]["path"] = value
            with self.subTest(path=value), self.assertRaises(SourceError):
                self.prepare(profile, compiler=Path(value))
        for value in (None, "", "f" * 63, "g" * 64, "0" * 64):
            profile = copy.deepcopy(self.profile)
            profile["kernel"]["llvm"]["tools"]["LD"]["sha256"] = value
            with self.subTest(sha=value), self.assertRaises(SourceError):
                self.prepare(profile)

    def test_prepare_does_not_substitute_same_binary_different_compiler_alias(self):
        alias = self.bin / "another-clang"
        alias.symlink_to(self.compiler.name)
        self.assertEqual(checksum(alias), checksum(self.compiler))
        with self.assertRaises(SourceError):
            self.prepare(compiler=alias)

    def test_prepare_rejects_wrong_version_and_wrong_tool_family(self):
        cases = [(role, marker) for role, marker in (
            ("CC", "LLVM version 21.1.8"), ("HOSTCC", "LLD 21.1.8"),
            ("HOSTCXX", "LLVM version 21.1.8"), ("LD", "LLVM version 21.1.8"),
            ("AR", "clang version 21.1.8"), ("NM", "LLD 21.1.8"))]
        cases += [(role, "LLVM version 21.1.7") for role in TOOLS]
        for role, output in cases:
            chosen = self.profile["kernel"]["llvm"]["tools"][role]["path"]

            def responder(argv, **kwargs):
                result = self.fake_process(argv, **kwargs)
                if argv == [chosen, "--version"]:
                    result.stdout = output + "\n"
                return result

            with self.subTest(role=role, output=output), self.assertRaises(SourceError):
                self.prepare(responder=responder)

    def test_prepare_rejects_failed_tool_query_and_host_default_target(self):
        for target, exit_code in (("x86_64-pc-linux-gnu\n", 0),
                                  ("hexagon-linux-musl\n", 0),
                                  ("hexagon-unknown-linux-musl\n", 1)):
            def responder(argv, **kwargs):
                result = self.fake_process(argv, **kwargs)
                if argv[-1] == "-dumpmachine":
                    result.stdout, result.returncode = target, exit_code
                return result
            with self.subTest(target=target, exit_code=exit_code), self.assertRaises(SourceError):
                self.prepare(responder=responder)
        def failed_version(argv, **kwargs):
            result = self.fake_process(argv, **kwargs)
            if argv[1:] == ["--version"]:
                result.returncode = 1
            return result
        with self.assertRaises(SourceError):
            self.prepare(responder=failed_version)

    def test_verify_accepts_exact_retained_command_and_never_runs_tools(self):
        receipt = self.valid_receipt()
        before = copy.deepcopy(receipt)
        result = self.verify(receipt)
        self.assertIsInstance(result, dict)
        self.assertTrue(result)
        self.assertIs(result["target_execution"], False)
        self.assertIs(result["model_support_awarded"], False)
        self.assertEqual(receipt, before)
        entry = copy.deepcopy(self.entry)
        entry["command"] = shlex.join(entry.pop("arguments"))
        self.write_build([entry])
        self.assertIsInstance(self.verify(receipt), dict)

    def test_verify_requires_exact_configured_cpu(self):
        receipt = self.valid_receipt()
        for content in ("", "CONFIG_HEXAGON_ARCH_VERSION=2\n",
                        "CONFIG_HEXAGON_ARCH_VERSION=60\n",
                        "CONFIG_HEXAGON_ARCH_VERSION=\"68\"\n",
                        "CONFIG_HEXAGON_ARCH_VERSION=68\nCONFIG_HEXAGON_ARCH_VERSION=2\n"):
            (self.output / ".config").write_text(content)
            with self.subTest(content=content), self.assertRaises(SourceError):
                self.verify(receipt)

    def test_verify_requires_one_and_only_one_string_translation_unit(self):
        receipt = self.valid_receipt()
        unrelated = copy.deepcopy(self.entry)
        unrelated["file"] = str(self.source.parent / "unrelated.c")
        for entries in ([], [unrelated], [self.entry, self.entry], [self.entry, unrelated, self.entry]):
            self.write_build(entries)
            with self.subTest(entries=len(entries)), self.assertRaises(SourceError):
                self.verify(receipt)
        self.write_build([unrelated, self.entry])
        self.assertIsInstance(self.verify(receipt), dict)

    def test_verify_rejects_missing_required_flags(self):
        receipt = self.valid_receipt()
        for flag in REQUIRED_FLAGS:
            entry = copy.deepcopy(self.entry)
            entry["arguments"].remove(flag)
            self.write_build([entry])
            with self.subTest(flag=flag), self.assertRaises(SourceError):
                self.verify(receipt)

    def test_verify_rejects_duplicate_or_opposing_target_cpu_and_assembler_options(self):
        receipt = self.valid_receipt()
        changes = [
            ["--target=hexagon-linux-musl"], ["--target=x86_64-linux-gnu"],
            ["--target", "hexagon-linux-musl"], ["-target", "x86_64-linux-gnu"],
            ["-mv68"], ["-mv60"], ["-mcpu=hexagonv60"],
            ["-fno-integrated-as"], ["-no-integrated-as"],
            ["@hidden-options"], ["-Xclang", "-triple", "-Xclang", "x86_64-linux-gnu"],
            ["-Wp,-D__linux__=0"], ["-Wp,@hidden-options"],
            ["-fshort-enums"], ["-mno-long-calls"], ["-G8"], ["-G0"], ["-G", "8"],
            ["-DTHREADINFO_REG=r18"], ["-UTHREADINFO_REG"], ["-U__linux__"],
        ]
        for extra in changes:
            entry = copy.deepcopy(self.entry)
            entry["arguments"][1:1] = extra
            self.write_build([entry])
            with self.subTest(extra=extra), self.assertRaises(SourceError):
                self.verify(receipt)

    def test_verify_does_not_accept_another_alias_of_the_same_compiler(self):
        receipt = self.valid_receipt()
        alias = self.bin / "compiler-alias"
        alias.symlink_to(self.compiler.name)
        entry = copy.deepcopy(self.entry)
        entry["arguments"][0] = str(alias)
        self.write_build([entry])
        with self.assertRaises(SourceError):
            self.verify(receipt)

    def test_verify_requires_actual_hexagon_elf32_little_endian_object(self):
        receipt = self.valid_receipt()
        object_path = self.output / "lib/string.o"
        for data in (b"", b"not an ELF object", b"\x7fELF", elf_object()[:20],
                     elf_object()[:52], elf_object()[:-1], elf_object(bits=64),
                     elf_object(endian="big"), elf_object(machine=62), elf_object(elf_type=2)):
            object_path.write_bytes(data)
            with self.subTest(data=data[:20]), self.assertRaises(SourceError):
                self.verify(receipt)
        object_path.unlink()
        with self.assertRaises(SourceError):
            self.verify(receipt)

    def test_verify_rejects_changed_tool_content_and_alias_resolution(self):
        receipt = self.valid_receipt()
        backing = (self.bin / "ld.lld").resolve()
        original = backing.read_bytes()
        backing.write_bytes(original + b"changed")
        with self.assertRaises(SourceError):
            self.verify(receipt)
        backing.write_bytes(original)
        alternate = self.bin / "lld-copy"
        alternate.write_bytes(original)
        alias = self.bin / "ld.lld"
        alias.unlink()
        alias.symlink_to(alternate.name)
        self.assertEqual(checksum(alias), checksum(backing))
        with self.assertRaises(SourceError):
            self.verify(receipt)

    def test_verify_reconstructs_receipt_target_cpu_tool_and_command_identity(self):
        receipt = self.valid_receipt()
        for field, value in (("requested", "x86_64-linux-gnu"),
                             ("observed", "x86_64-pc-linux-gnu"),
                             ("command", [str(self.compiler), "-dumpmachine"])):
            changed = copy.deepcopy(receipt)
            changed["target"][field] = value
            with self.subTest(field=field), self.assertRaises(SourceError):
                self.verify(changed)
        changed = copy.deepcopy(receipt)
        changed["cpu"] = 60
        with self.assertRaises(SourceError):
            self.verify(changed)
        for field, value in (("path", str(self.bin / "lld")),
                             ("sha256", "0" * 64), ("version", "21.1.7"),
                             ("version_output", "LLVM version 21.1.8"),
                             ("version_command", [str(self.bin / "lld"), "--version"])):
            changed = copy.deepcopy(receipt)
            changed["tools"]["LD"][field] = value
            with self.subTest(field=field), self.assertRaises(SourceError):
                self.verify(changed)
        changed = copy.deepcopy(receipt)
        del changed["tools"]["LLVM_LINK"]
        with self.assertRaises(SourceError):
            self.verify(changed)

    def test_verify_binds_source_directory_and_compile_output_operations(self):
        receipt = self.valid_receipt()
        for field, value in (("directory", str(self.root)),
                             ("file", str(self.root / "different-source/lib/string.c"))):
            entry = copy.deepcopy(self.entry)
            entry[field] = value
            self.write_build([entry])
            with self.subTest(field=field), self.assertRaises(SourceError):
                self.verify(receipt)
        for extra in (["-c"], ["-o", "lib/string.o"], [str(self.source)]):
            entry = copy.deepcopy(self.entry)
            entry["arguments"][1:1] = extra
            self.write_build([entry])
            with self.subTest(extra=extra), self.assertRaises(SourceError):
                self.verify(receipt)
        for flag in ("-c", "-o", str(self.source)):
            entry = copy.deepcopy(self.entry)
            entry["arguments"].remove(flag)
            self.write_build([entry])
            with self.subTest(missing=flag), self.assertRaises(SourceError):
                self.verify(receipt)
        entry = copy.deepcopy(self.entry)
        entry["arguments"][entry["arguments"].index("lib/string.o")] = "lib/other.o"
        self.write_build([entry])
        with self.assertRaises(SourceError):
            self.verify(receipt)
        entry = copy.deepcopy(self.entry)
        entry["arguments"][-1] = str(self.root / "other.c")
        self.write_build([entry])
        with self.assertRaises(SourceError):
            self.verify(receipt)

    def test_verify_requires_token_equal_kbuild_saved_command(self):
        receipt = self.valid_receipt()
        cmd = self.output / "lib/.string.o.cmd"
        original = cmd.read_text()
        for value in ("", original.replace("savedcmd_lib/string.o", "savedcmd_lib/other.o"),
                      original.replace("-mv68", "-mv60"), original + original):
            cmd.write_text(value)
            with self.subTest(value=value[:80]), self.assertRaises(SourceError):
                self.verify(receipt)
        cmd.unlink()
        with self.assertRaises(SourceError):
            self.verify(receipt)

    def test_verify_rejects_symlinked_retained_artifacts_even_when_bytes_match(self):
        receipt = self.valid_receipt()
        for relative in (".config", "compile_commands.json", "lib/.string.o.cmd", "lib/string.o"):
            path = self.output / relative
            original = path.read_bytes()
            alternate = self.root / (path.name + ".alternate")
            alternate.write_bytes(original)
            path.unlink()
            path.symlink_to(alternate)
            with self.subTest(path=relative), self.assertRaises(SourceError):
                self.verify(receipt)
            path.unlink()
            path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
