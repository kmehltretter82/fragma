"""Checks for the PA-RISC module sh_info same-input A/B harness."""

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
MUTATOR = ROOT / "harness/parisc-module-sh-info/mutate_sh_info.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf32_hppa_fixture(relocation_type: int = 12) -> bytes:
    """Build a minimal big-endian ELF32 object with one SHT_RELA section."""
    section_offset = 64
    section_count = 4
    names_offset = 256
    relocation_offset = 320
    names = b"\0.rela.text\0.shstrtab\0.text\0"
    data = bytearray(relocation_offset + 12)
    data[:16] = b"\x7fELF\x01\x02\x01" + bytes(9)
    struct.pack_into(
        ">HHIIIIIHHHHHH", data, 16,
        1, 15, 1, 0, 0, section_offset, 0,
        52, 0, 0, 40, section_count, 2,
    )

    def section(index: int, values: tuple[int, ...]) -> None:
        struct.pack_into(">IIIIIIIIII", data, section_offset + index * 40,
                         *values)

    section(0, (0,) * 10)
    section(1, (1, 4, 0, 0, relocation_offset, 12, 0, 3, 4, 12))
    section(2, (12, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0))
    section(3, (22, 1, 0, 0, 0, 0, 0, 0, 4, 0))
    data[names_offset:names_offset + len(names)] = names
    struct.pack_into(">III", data, relocation_offset, 0,
                     (1 << 8) | relocation_type, 0)
    return bytes(data)


class PariscModuleShInfoTests(unittest.TestCase):
    def test_mutator_rewrites_only_the_selected_big_endian_field(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control.ko"
            evil = root / "evil.ko"
            control.write_bytes(elf32_hppa_fixture())
            process = subprocess.run(
                [sys.executable, str(MUTATOR), str(control), str(evil)],
                check=True, text=True, capture_output=True,
            )
            receipt = json.loads(process.stdout)
            before = control.read_bytes()
            after = evil.read_bytes()
            self.assertEqual(receipt["section"], ".rela.text")
            self.assertEqual(receipt["section_index"], 1)
            self.assertEqual(receipt["section_count"], 4)
            self.assertEqual(receipt["old_sh_info"], 3)
            self.assertEqual(receipt["new_sh_info"], 0x10000000)
            self.assertEqual(receipt["counted_relocations"], [12])
            self.assertEqual(receipt["sh_info_file_offset"], 132)
            self.assertEqual(before[132:136], bytes.fromhex("00000003"))
            self.assertEqual(after[132:136], bytes.fromhex("10000000"))
            self.assertEqual(
                [index for index, values in enumerate(zip(before, after))
                 if values[0] != values[1]],
                [132, 135],
            )

    def test_mutator_rejects_a_relocation_not_counted_by_the_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control.ko"
            evil = root / "evil.ko"
            control.write_bytes(elf32_hppa_fixture(relocation_type=1))
            process = subprocess.run(
                [sys.executable, str(MUTATOR), str(control), str(evil)],
                text=True, capture_output=True,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("no SHT_RELA section contains a relocation counted",
                          process.stderr)
            self.assertFalse(evil.exists())

    def test_retained_runtime_inputs_match_the_record_when_available(self):
        evidence = ROOT / "build/parisc-module-sh-info-qemu"
        if not evidence.is_dir():
            self.skipTest("retained PA-RISC A/B evidence unavailable")
        receipt = json.loads((evidence / "mutation.json").read_text())
        self.assertEqual(receipt["section_count"], 28)
        self.assertEqual(receipt["sh_info_file_offset"], 0xae4)
        self.assertEqual(receipt["old_sh_info"], 3)
        self.assertEqual(receipt["new_sh_info"], 0x10000000)
        self.assertEqual(receipt["counted_relocations"], [12])
        self.assertEqual(
            sha256(evidence / "control.ko"),
            "0e58fa885361336346ac6d04c84d8b82ce53de9a1b11e15b50e8af34377ebed1",
        )
        self.assertEqual(
            sha256(evidence / "evil.ko"),
            "9396cb24ae8a2689ab00e2c4ff5d76b429e230765652a7ac2e0ec3040d80ce14",
        )
        before = (evidence / "qemu-before.log").read_text(errors="replace")
        after = (evidence / "qemu-after.log").read_text(errors="replace")
        self.assertIn("module_frob_arch_sections+0x11c/0x1ac", before)
        self.assertIn("Kernel panic - not syncing", before)
        self.assertIn("FRAGMA_EVIL_LOAD ret=-1 errno=8", after)
        self.assertIn("FRAGMA_PARISC_AB_COMPLETE", after)
        self.assertIn("Invalid ELF relocation section target index 268435456",
                      after)


if __name__ == "__main__":
    unittest.main()
