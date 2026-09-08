"""Checks for the module sh_info multi-architecture A/B harness."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MUTATOR = ROOT / "harness/module-sh-info-multiarch/mutate_sh_info.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf64_le_fixture() -> bytes:
    """Build a minimal ELF64 object with one executable target section."""
    section_offset = 64
    section_count = 4
    names_offset = 384
    relocation_offset = 448
    names = b"\0.rela.fragma_probe.text\0.shstrtab\0.fragma_probe.text\0"
    data = bytearray(relocation_offset + 24)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<HHIQQQIHHHHHH", data, 16,
        1, 62, 1, 0, 0, section_offset, 0,
        64, 0, 0, 64, section_count, 2,
    )

    def section(index: int, values: tuple[int, ...]) -> None:
        struct.pack_into("<IIQQQQIIQQ", data, section_offset + index * 64,
                         *values)

    section(0, (0,) * 10)
    section(1, (1, 4, 0, 0, relocation_offset, 24, 0, 3, 8, 24))
    section(2, (25, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0))
    section(3, (35, 1, 6, 0, 0, 0, 0, 0, 16, 0))
    data[names_offset:names_offset + len(names)] = names
    return bytes(data)


class ModuleShInfoMultiarchTests(unittest.TestCase):
    def test_mutator_rewrites_only_elf64_little_endian_sh_info(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control.ko"
            evil = root / "evil.ko"
            control.write_bytes(elf64_le_fixture())
            process = subprocess.run(
                [sys.executable, str(MUTATOR), str(control), str(evil)],
                check=True, text=True, capture_output=True,
            )
            receipt = json.loads(process.stdout)
            before = control.read_bytes()
            after = evil.read_bytes()
            self.assertEqual(receipt["section"], ".rela.fragma_probe.text")
            self.assertEqual(receipt["target_section"],
                             ".fragma_probe.text")
            self.assertEqual(receipt["elf_bits"], 64)
            self.assertEqual(receipt["byte_order"], "little")
            self.assertEqual(receipt["old_sh_info"], 3)
            self.assertEqual(receipt["new_sh_info"], 0x10000000)
            self.assertEqual(receipt["sh_info_file_offset"], 172)
            self.assertEqual(before[172:176], bytes.fromhex("03000000"))
            self.assertEqual(after[172:176], bytes.fromhex("00000010"))
            self.assertEqual(
                [index for index, values in enumerate(zip(before, after))
                 if values[0] != values[1]],
                [172, 175],
            )

    def test_retained_qemu_evidence_matches_records_when_available(self):
        evidence = ROOT / "build/module-sh-info-qemu-multiarch"
        if not evidence.is_dir():
            self.skipTest("retained multi-architecture evidence unavailable")

        expected = {
            "arm64": {
                "offset": "+0x110/0x414",
                "control": "f66c4ab91a151d3c614d48b2441da9d220f419cd8905dab08d9ccbda6f8a289e",
                "evil": "94a6ea2ea7f6c190c9d5b095398fe46883ad60bcc3133d79edcfa5bb862da6aa",
            },
            "riscv64": {
                "offset": "+0xe4/0x37e",
                "control": "6bf5c5f1e436b150090cec7c8a4b90d31367a023b5f6fe31acb25e5579c8337a",
                "evil": "e2050e7abf63514e42b1aa91dbba157c3918445ea89944b3ba7038eaaed49deb",
            },
            "loongarch64": {
                "offset": "+0x1b8/0x420",
                "control": "268bdd58655890f1aeb9481a663098e5a519251893306e737bb400d8877ad519",
                "evil": "b39b4eb5f893aa7bdf831a4112cb364f1c0c26d154bade5190056a3558e2bb26",
            },
        }
        for architecture, values in expected.items():
            with self.subTest(architecture=architecture):
                root = evidence / architecture
                receipt = json.loads(
                    (root / "artifacts/mutation.json").read_text()
                )
                self.assertEqual(receipt["new_sh_info"], 0x10000000)
                self.assertEqual(
                    sha256(root / "initramfs/control.ko"),
                    values["control"],
                )
                self.assertEqual(
                    sha256(root / "initramfs/evil.ko"), values["evil"]
                )
                original = (
                    root / "logs/qemu-original-final.log"
                ).read_text(errors="replace")
                fixed = (
                    root / "logs/qemu-fixed-final.log"
                ).read_text(errors="replace")
                self.assertIn("module_frob_arch_sections" + values["offset"],
                              original)
                self.assertIn("Kernel panic - not syncing", original)
                self.assertIn(
                    "Invalid ELF relocation section target index 268435456",
                    fixed,
                )
                self.assertIn("FRAGMA_EVIL_LOAD ret=-1 errno=8", fixed)

        x86 = evidence / "x86_64"
        original = (x86 / "logs/qemu-original-final.log").read_text(
            errors="replace"
        )
        fixed = (x86 / "logs/qemu-fixed-final.log").read_text(
            errors="replace"
        )
        self.assertIn("FRAGMA_EVIL_LOAD ret=0 errno=0", original)
        self.assertIn("FRAGMA_EVIL_UNLOAD ret=0 errno=0", original)
        self.assertNotIn("module_frob_arch_sections+", original)
        self.assertIn("FRAGMA_EVIL_LOAD ret=-1 errno=8", fixed)
        self.assertIn("FRAGMA_AB_COMPLETE arch=x86_64", fixed)


if __name__ == "__main__":
    unittest.main()
