"""Closed MT7621 MIPS32el LLVM build gates with inert, data-only fixtures."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma.llvm_build import prepare_llvm, verify_llvm_build
from fragma.profiles import load_profiles
from fragma.sources import SourceError, sha256
from tests.test_llvm_build import TOOLS, elf_object


ROOT = Path(__file__).resolve().parents[1]


class MIPSLLVMBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fragma-mips-llvm-build-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
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
        self.profile = copy.deepcopy(load_profiles(ROOT)["mips32el-clang"])
        self.profile["compiler"] = "clang"
        self.profile["kernel"]["llvm"]["tools"] = {
            role: {"path": str(self.bin / name), "sha256": sha256(self.bin / name)}
            for role, name in TOOLS.items()
        }
        self.env = {"PATH": str(self.bin), "LANG": "C.UTF-8", "LC_ALL": "C"}
        self.output = self.root / "build"
        (self.output / "lib").mkdir(parents=True)
        self.source_root = self.root / "source"
        self.source = self.source_root / "lib/string.c"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("/* inert command identity; never compiled */\n")
        platform = self.source_root / "arch/mips/include/asm"
        self.args = [
            str(self.compiler), "-Wp,-MMD,lib/.string.o.d", "-nostdinc",
            "--target=mipsel-linux-gnu", "-fintegrated-as", "-fshort-wchar",
            "-funsigned-char", "-fno-PIE", "-fno-strict-aliasing", "-std=gnu11", "-mabi=32",
            "-G", "0", "-mno-abicalls", "-fno-pic", "-msoft-float",
            "-Wa,-msoft-float", "-ffreestanding", "-EL", "-march=mips32r2",
            "-I" + str(platform / "mach-ralink"),
            "-I" + str(platform / "mach-ralink/mt7621"),
            "-I" + str(platform / "mach-generic"), "-Wa,--trap",
            "-c", "-o", "lib/string.o", str(self.source),
        ]
        self.write_build()

    def fake_process(self, argv, **kwargs):
        self.assertTrue(kwargs.get("capture_output"))
        self.assertTrue(kwargs.get("text"))
        if argv[1:] == ["--version"]:
            if Path(argv[0]).name in {"clang", "clang++"}:
                output = "Ubuntu clang version 21.1.8 (inert mock)\n"
            elif Path(argv[0]).name == "ld.lld":
                output = "Ubuntu LLD 21.1.8 (inert mock)\n"
            else:
                output = "Debian LLVM version 21.1.8\n"
        else:
            self.assertEqual(argv, [str(self.compiler),
                "--target=mipsel-linux-gnu", "-mabi=32", "-EL",
                "-march=mips32r2", "-msoft-float", "-dumpmachine"])
            output = "mipsel-unknown-linux-gnu\n"
        return subprocess.CompletedProcess(argv, 0, output, "")

    def write_build(self, args=None, *, flags=0x70001001, machine=8):
        lines = []
        for key, value in self.profile["kernel"]["required_config"].items():
            lines.append("# " + key + " is not set" if value == "n" else key + "=" + value)
        (self.output / ".config").write_text("\n".join(lines) + "\n")
        args = list(self.args if args is None else args)
        entry = {"directory": str(self.output), "file": str(self.source), "arguments": args}
        (self.output / "compile_commands.json").write_text(json.dumps([entry]))
        (self.output / "lib/.string.o.cmd").write_text(
            "savedcmd_lib/string.o := " + shlex.join(args) + "\n")
        data = bytearray(elf_object(machine=machine))
        struct.pack_into("<I", data, 36, flags)
        (self.output / "lib/string.o").write_bytes(data)

    def receipt(self):
        with patch("fragma.llvm_build.subprocess.run", side_effect=self.fake_process):
            _, receipt, _ = prepare_llvm(self.profile, str(self.compiler), self.env)
        return receipt

    def verify(self, receipt):
        with patch("subprocess.run", side_effect=AssertionError("readback launched a tool")):
            return verify_llvm_build(self.profile, self.output, receipt, source=self.source_root)

    def test_accepts_exact_mt7621_command_and_mips_elf(self):
        receipt = self.receipt()
        result = self.verify(receipt)
        self.assertEqual(receipt["architecture"], "mips")
        self.assertEqual(receipt["cpu"], "mips32r2")
        self.assertEqual(result["architecture"], "mips")
        self.assertEqual(result["object"]["machine"], 8)
        self.assertEqual(result["object"]["e_flags_observed"], 0x70001001)

    def test_rejects_wrong_abi_endian_cpu_platform_flags_and_elf(self):
        receipt = self.receipt()
        for old, new in (("-mabi=32", "-mabi=64"), ("-EL", "-EB"),
                         ("-march=mips32r2", "-march=mips32r6"),
                         ("-msoft-float", "-mhard-float"),
                         ("-Wa,--trap", "-Wa,-mips32r6")):
            args = [new if arg == old else arg for arg in self.args]
            self.write_build(args)
            with self.subTest(change=(old, new)), self.assertRaises(SourceError):
                self.verify(receipt)
        self.write_build(flags=0)
        with self.assertRaisesRegex(SourceError, "ELF flags"):
            self.verify(receipt)
        self.write_build(machine=164)
        with self.assertRaisesRegex(SourceError, "not MIPS32el"):
            self.verify(receipt)

    def test_rejects_overrides_duplicates_and_platform_aliases(self):
        receipt = self.receipt()
        compile_index = self.args.index("-c")
        for extra in ("-fPIE", "-fno-short-wchar", "-fsigned-char",
                      "-fstrict-aliasing", "-fhosted", "-std=gnu17", "-G0"):
            self.write_build([*self.args[:compile_index], extra,
                              *self.args[compile_index:]])
            with self.subTest(extra=extra), self.assertRaises(SourceError):
                self.verify(receipt)
        self.write_build([*self.args[:compile_index], "-nostdinc",
                          *self.args[compile_index:]])
        with self.assertRaisesRegex(SourceError, "duplicate"):
            self.verify(receipt)
        args = list(self.args)
        first, second = args.index(next(arg for arg in args if arg.endswith("mach-ralink"))), args.index(
            next(arg for arg in args if arg.endswith("mach-ralink/mt7621")))
        args[first], args[second] = args[second], args[first]
        self.write_build(args)
        with self.assertRaisesRegex(SourceError, "platform include"):
            self.verify(receipt)

    def test_rejects_profile_or_receipt_relabeling_before_readback(self):
        receipt = self.receipt()
        changed = copy.deepcopy(receipt)
        changed["architecture"] = "hexagon"
        with self.assertRaises(SourceError):
            self.verify(changed)
        changed = copy.deepcopy(self.profile)
        changed["kernel"]["required_config"]["CONFIG_SOC_MT7621"] = "n"
        with self.assertRaises(SourceError):
            verify_llvm_build(changed, self.output, receipt, source=self.source_root)


if __name__ == "__main__":
    unittest.main()
