"""Inert checks for the unregistered MIPS32el machdep adapter."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from fragma import mips_machdep


class MipsMachdepTests(unittest.TestCase):
    def test_profile_binds_o32_little_endian_kernel_types(self):
        profile = mips_machdep.candidate_profile()
        self.assertEqual(profile["architecture"], "mips")
        self.assertEqual(profile["header_type"], "asm/posix_types.h")
        self.assertEqual(profile["extra_uapi_headers"], ["sgidefs.h"])
        self.assertEqual(profile["abi"], {
            "bits": 32, "byte_order": "little", "char_unsigned": True,
            "wchar_bytes": 2, "short_bytes": 2, "int_bytes": 4,
            "long_bytes": 4, "long_long_bytes": 8, "pointer_bytes": 4,
            "long_alignment": 4, "pointer_alignment": 4,
            "long_long_alignment": 8,
        })

    def test_target_flags_bind_triple_abi_isa_endian_and_kernel_semantics(self):
        self.assertEqual(mips_machdep.ARCH_FLAGS[:5], [
            "--target=mipsel-linux-gnu", "-mabi=32", "-EL",
            "-march=mips32r2", "-msoft-float",
        ])
        for flag in ("-funsigned-char", "-fshort-wchar", "-ffreestanding",
                     "-fno-strict-overflow", "-fno-strict-aliasing", "-std=gnu11"):
            self.assertIn(flag, mips_machdep.ARCH_FLAGS)
        self.assertEqual(mips_machdep.OBJECT_FLAGS,
                         ["-mno-abicalls", "-fno-pic", "-G0"])

    def test_model_check_accepts_only_expected_scalars(self):
        values = {
            "sizeof_short": 2, "sizeof_int": 4, "sizeof_long": 4,
            "sizeof_longlong": 8, "sizeof_ptr": 4,
            "alignof_long": 4, "alignof_ptr": 4, "alignof_longlong": 8,
            "little_endian": True, "char_is_unsigned": True,
            "wchar_t": "unsigned short", "size_t": "unsigned int",
            "alignof_max_align_t": 8, "alignof_aligned": 16,
            "path_max": "4096", "tty_name_max": "32",
            "host_name_max": "255", "wordsize": "32",
            "wint_t": "unsigned int", "intptr_t": "int",
            "uintptr_t": "unsigned int", "compiler": str(mips_machdep.COMPILER),
            "machdep_name": "test",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate.yaml"
            path.write_text(yaml.safe_dump(values, sort_keys=True))
            checked = mips_machdep._check_model(
                mips_machdep.candidate_profile(), path
            )
            self.assertEqual(checked["abi_fields"]["sizeof_ptr"], 4)
            values["little_endian"] = False
            path.write_text(yaml.safe_dump(values, sort_keys=True))
            with self.assertRaisesRegex(ValueError, "little_endian"):
                mips_machdep._check_model(mips_machdep.candidate_profile(), path)

    def test_elf_gate_requires_mips_o32_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "calibration.o"
            data = bytearray(64)
            data[36:40] = (0x70001001).to_bytes(4, "little")
            path.write_bytes(data)
            parsed = mock.Mock(bits=32, little=True, machine=8)
            with mock.patch.object(mips_machdep.elf, "parse_relocatable",
                                   return_value=parsed):
                result = mips_machdep._elf_observation(path, {"sizeof_ptr": 4})
            self.assertEqual(result["flags"], "0x70001001")
            data[36:40] = (0).to_bytes(4, "little")
            path.write_bytes(data)
            with mock.patch.object(mips_machdep.elf, "parse_relocatable",
                                   return_value=parsed):
                with self.assertRaisesRegex(mips_machdep.AdapterError,
                                            "ELF flags"):
                    mips_machdep._elf_observation(path, {"sizeof_ptr": 4})

    def test_generation_never_overwrites_an_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "existing"
            output.mkdir()
            marker = output / "marker"
            marker.write_text("keep")
            with self.assertRaisesRegex(mips_machdep.AdapterError,
                                        "output already exists"):
                mips_machdep.generate(
                    Path(temporary), sysroot=Path(temporary),
                    kernel=Path(temporary), output=output,
                )
            self.assertEqual(marker.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
