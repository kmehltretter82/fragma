"""Fail-closed MIPS calibration metadata checks using inert object bytes."""
import struct
import unittest

from fragma import elf
from tests.test_elf import calibration_elf, fixture, header_change, model, section_change


def mips_object():
    return calibration_elf(machine=8, mips_metadata=True)


def observe(data):
    return elf.calibration_object(data, model(), fixture(machine=8))


def change_section_bytes(data, index, offset, value):
    result = bytearray(data)
    obj = elf.parse_relocatable(data, model())
    result[obj.sections[index].offset + offset] = value
    return bytes(result)


class MIPSELFTests(unittest.TestCase):
    def test_exact_metadata_is_observed_without_an_isa_claim(self):
        result = observe(mips_object())
        self.assertEqual(result["machine_observed"], 8)
        self.assertEqual(result["mips_abi_metadata"], {
            "header_flags": "0x70001001",
            "sections": [".reginfo", ".MIPS.abiflags", ".llvm_addrsig"],
            "reginfo": {"gpr_mask": "0x80000001", "cpr_masks": [0, 0, 0, 0],
                        "gp_value": "0x00000000"},
            "abi_flags": {"version": 0, "isa_level": 32, "isa_revision": 2,
                          "gpr_size_encoding": 1, "cpr1_size_encoding": 0,
                          "cpr2_size_encoding": 0, "fp_abi_encoding": 3,
                          "isa_extension": 0, "ases": 0, "flags1": 1, "flags2": 0},
            "scope": "Exact MIPS32el/O32 container metadata only; no instruction, linker or runtime proof",
        })
        self.assertEqual(result["definition"]["name"],
                         "fragma_common24_compiler_calibration")

    def test_mips_metadata_requires_exact_machine_and_header_flags(self):
        valid = mips_object()
        for changed in (header_change(valid, 1, 40), header_change(valid, 6, 0),
                        header_change(valid, 6, 0x70001000),
                        header_change(valid, 6, 0x70001003)):
            with self.subTest(changed=changed[16:40]), self.assertRaises(elf.ELFError):
                observe(changed)

    def test_every_special_section_requires_exact_name_kind_and_shape(self):
        valid = mips_object()
        # Indices 4, 5 and 6 are .reginfo, .MIPS.abiflags and .llvm_addrsig.
        mutations = (
            (4, 0, 0), (4, 1, 1), (4, 2, 0), (4, 5, 20), (4, 8, 8), (4, 9, 0),
            (5, 0, 0), (5, 1, 1), (5, 2, 0), (5, 5, 20), (5, 8, 4), (5, 9, 0),
            (6, 0, 0), (6, 1, 1), (6, 2, 0), (6, 5, 1), (6, 6, 0), (6, 8, 2),
        )
        for index, field, value in mutations:
            with self.subTest(index=index, field=field, value=value), self.assertRaises(elf.ELFError):
                observe(section_change(valid, index, field, value))

    def test_reginfo_and_abi_contents_are_exact(self):
        valid = mips_object()
        for index, offset in ((4, 0), (4, 23), (5, 0), (5, 2), (5, 7),
                              (5, 16), (5, 23)):
            with self.subTest(index=index, offset=offset), self.assertRaises(elf.ELFError):
                observe(change_section_bytes(valid, index, offset, 0xff))

    def test_processor_metadata_does_not_leak_to_generic_objects(self):
        generic = calibration_elf(machine=8)
        result = elf.calibration_object(generic, model(), fixture(machine=8))
        self.assertNotIn("mips_abi_metadata", result)
        for index, kind in ((1, 0x70000006), (1, 0x7000002a),
                            (1, 0x6fff4c03)):
            with self.subTest(kind=kind), self.assertRaises(elf.ELFError):
                elf.calibration_object(section_change(generic, index, 1, kind),
                                       model(), fixture(machine=8))

    def test_retained_clang_object_matches_exact_metadata_gate(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        path = root / ("build/common24-mips-l2-initial-20260907/run-4/"
                       "common.unaligned24.mips32el/compiler-calibration/positive.o")
        if not path.is_file():
            self.skipTest("retained MIPS L2 run-4 object is unavailable")
        # The real fixture binding is tested by the end-to-end pilot.  This
        # read-only check isolates the newly admitted complete-table shape.
        obj = elf.parse_relocatable(path.read_bytes(), model())
        self.assertEqual((obj.bits, obj.little, obj.machine), (32, True, 8))
        self.assertEqual(struct.unpack_from("<I", obj.data, 36)[0], 0x70001001)
        metadata = elf._mips_calibration_metadata(obj)
        self.assertEqual(metadata["abi_flags"]["fp_abi_encoding"], 3)


if __name__ == "__main__":
    unittest.main()
