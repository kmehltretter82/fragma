"""Pure ELF-container corruptions; no synthetic or retained code is executed."""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest

from fragma import elf, frontend_policy


CALIBRATION_NAME = b"fragma_common24_compiler_calibration"


def calibration_elf(*, bits=32, little_endian=True, machine=40, arm_unwind=False,
                    relocation_addend=False, mips_metadata=False):
    """Data-only ET_REL for orchestration tests; the bytes are not ISA claims."""
    if mips_metadata and (bits != 32 or not little_endian or machine != 8 or arm_unwind):
        raise ValueError("synthetic MIPS metadata requires its exact ELF32 little-endian route")
    endian, wide = ("<" if little_endian else ">"), bits == 64
    header_size, section_size, symbol_size = (64, 64, 24) if wide else (52, 40, 16)
    strings = bytearray(b"\0")

    def name(value):
        offset = len(strings)
        strings.extend(value + b"\0")
        return offset

    section_names = [0, name(b".text"), name(b".strtab"), name(b".symtab")]
    function_name = name(CALIBRATION_NAME)
    if arm_unwind:
        section_names += [name(b".ARM.exidx"), name(b".rel.ARM.exidx")]
        unwind_name = name(b"__aeabi_unwind_cpp_pr0")
    if mips_metadata:
        section_names += [name(b".reginfo"), name(b".MIPS.abiflags"),
                          name(b".llvm_addrsig")]
    data = bytearray(header_size)
    sections = [(0,) * 10]

    def append(content, alignment):
        data.extend(bytes(-len(data) % alignment))
        offset = len(data)
        data.extend(content)
        return offset

    text_offset = append(bytes(4), 4)
    sections.append((section_names[1], 1, 6, 0, text_offset, 4, 0, 0, 4, 0))
    strings_offset = append(strings, 1)
    sections.append((section_names[2], 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0))
    symbol_rows = [(0, 0, 0, 0, 0, 0), (function_name, 0, 4, 0x12, 0, 1)]
    if arm_unwind:
        symbol_rows.append((unwind_name, 0, 0, 0x10, 0, 0))
    symbols = bytearray()
    for n, v, size, info, other, section in symbol_rows:
        symbols.extend(struct.pack(endian + ("IBBHQQ" if wide else "IIIBBH"),
            *((n, info, other, section, v, size) if wide else (n, v, size, info, other, section))))
    symbols_offset = append(symbols, 8 if wide else 4)
    sections.append((section_names[3], 2, 0, 0, symbols_offset, len(symbols), 2, 1,
                     8 if wide else 4, symbol_size))
    if arm_unwind:
        exidx_offset = append(bytes(8), 4)
        sections.append((section_names[4], 0x70000001, 0x82, 0, exidx_offset, 8, 1, 0, 4, 0))
        reloc = struct.pack(endian + ("QQ" if wide else "II"), 0, 2 << (32 if wide else 8))
        if relocation_addend:
            reloc += struct.pack(endian + ("q" if wide else "i"), 0)
        reloc_offset = append(reloc, 8 if wide else 4)
        sections.append((section_names[5], 4 if relocation_addend else 9, 0x40, 0, reloc_offset, len(reloc), 3, 4,
                         8 if wide else 4, len(reloc)))
    if mips_metadata:
        reginfo = struct.pack("<6I", 0x80000001, 0, 0, 0, 0, 0)
        reginfo_offset = append(reginfo, 4)
        sections.append((section_names[4], 0x70000006, 2, 0, reginfo_offset,
                         len(reginfo), 0, 0, 4, 24))
        abi = struct.pack("<HBBBBBBIIII", 0, 32, 2, 1, 0, 0, 3, 0, 0, 1, 0)
        abi_offset = append(abi, 8)
        sections.append((section_names[5], 0x7000002a, 2, 0, abi_offset,
                         len(abi), 0, 0, 8, 24))
        sections.append((section_names[6], 0x6fff4c03, 0x80000000, 0,
                         len(data), 0, 3, 0, 1, 0))
    data.extend(bytes(-len(data) % (8 if wide else 4)))
    section_offset = len(data)
    for section in sections:
        data.extend(struct.pack(endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), *section))
    ident = b"\x7fELF" + bytes((2 if wide else 1, 1 if little_endian else 2, 1)) + bytes(9)
    flags = 0x70001001 if mips_metadata else 0
    header = (1, machine, 1, 0, 0, section_offset, flags, header_size, 0, 0,
              section_size, len(sections), 2)
    data[:header_size] = ident + struct.pack(endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), *header)
    return bytes(data)


def model(*, bits=32, little=True):
    return {"machdep": {"checked_fields": {"sizeof_ptr": bits // 8, "little_endian": little}}}


def fixture(*, bits=32, little=True, machine=40):
    return {"class": bits, "byte_order": "little" if little else "big",
            "machine_observed": machine, "type": "relocatable"}


def layout(data):
    wide, endian = data[4] == 2, "<" if data[5] == 1 else ">"
    fmt = endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH")
    return wide, endian, fmt, list(struct.unpack_from(fmt, data, 16))


def header_change(data, index, value):
    result = bytearray(data)
    _, _, fmt, header = layout(data)
    header[index] = value
    struct.pack_into(fmt, result, 16, *header)
    return bytes(result)


def section_change(data, index, field, value):
    result = bytearray(data)
    wide, endian, _, header = layout(data)
    fmt = endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    offset = header[5] + index * header[10]
    section = list(struct.unpack_from(fmt, data, offset))
    section[field] = value
    struct.pack_into(fmt, result, offset, *section)
    return bytes(result)


def symbol_change(data, index, field, value):
    """Field uses Symbol order: name, value, size, info, other, section."""
    result = bytearray(data)
    wide, endian, _, header = layout(data)
    section_fmt = endian + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    table = struct.unpack_from(section_fmt, data, header[5] + 3 * header[10])
    fmt = endian + ("IBBHQQ" if wide else "IIIBBH")
    offset = table[4] + index * table[9]
    symbol = list(struct.unpack_from(fmt, data, offset))
    symbol[(0, 4, 5, 1, 2, 3)[field] if wide else field] = value
    struct.pack_into(fmt, result, offset, *symbol)
    return bytes(result)


class ELFTests(unittest.TestCase):
    def check(self, data, *, bits=32, little=True, machine=40):
        return elf.calibration_object(data, model(bits=bits, little=little),
                                      fixture(bits=bits, little=little, machine=machine))

    def rejects(self, data):
        with self.assertRaises(elf.ELFError):
            self.check(data)

    def test_all_class_endian_combinations(self):
        for bits in (32, 64):
            for little in (False, True):
                machine = (40 if little else 20) if bits == 32 else (62 if little else 21)
                with self.subTest(bits=bits, little=little):
                    result = self.check(calibration_elf(bits=bits, little_endian=little, machine=machine),
                                        bits=bits, little=little, machine=machine)
                    self.assertEqual(result["definition"]["name"], CALIBRATION_NAME.decode())
                    self.assertEqual(result["definition"]["size"], 4)
                    self.assertEqual(result["definition"]["section"], ".text")
                    self.assertEqual(result["undefined_metadata"], [])

    def test_partial_or_wrong_headers(self):
        valid = calibration_elf()
        for bad in (None, bytearray(valid), b"", valid[:7], valid[:51], valid[:-1],
                    b"!" + valid[1:], header_change(valid, 0, 2), header_change(valid, 2, 0),
                    header_change(valid, 3, 1), header_change(valid, 4, 52),
                    header_change(valid, 5, len(valid)), header_change(valid, 7, 0),
                    header_change(valid, 9, 1), header_change(valid, 10, 0),
                    header_change(valid, 11, 0), header_change(valid, 12, 0)):
            with self.subTest(bad=repr(bad)[:60]):
                self.rejects(bad)

    def test_wrong_model_and_genuine_machine_binding(self):
        for bad in (calibration_elf(bits=64), calibration_elf(little_endian=False), calibration_elf(machine=20)):
            self.rejects(bad)
        for key, value in (("class", True), ("class", 32.0), ("machine_observed", True),
                           ("machine_observed", 40.0), ("machine_observed", 0),
                           ("byte_order", "big"), ("type", "executable")):
            with self.subTest(key=key, value=value), self.assertRaises(elf.ELFError):
                elf.calibration_object(calibration_elf(), model(), {**fixture(), key: value})
        for fields in ({"sizeof_ptr": True, "little_endian": True},
                       {"sizeof_ptr": 4, "little_endian": 1}, {}):
            with self.assertRaises(elf.ELFError):
                elf.calibration_object(calibration_elf(), {"machdep": {"checked_fields": fields}}, fixture())

    def test_section_table_bounds_names_links_alignment_and_overlap(self):
        valid = calibration_elf()
        changes = ((0, 1, 1), (1, 0, 0xffffff), (1, 4, len(valid)), (1, 5, len(valid)),
                   (1, 4, 0), (1, 8, 3), (1, 3, 1), (1, 6, 99),
                   (1, 2, 0x806), (2, 1, 1), (3, 1, 1), (3, 6, 1),
                   (3, 9, 0), (3, 5, 17), (3, 7, 3), (3, 7, 0), (1, 1, 2))
        for index, field, value in changes:
            with self.subTest(index=index, field=field, value=value):
                self.rejects(section_change(valid, index, field, value))

    def test_missing_wrong_or_duplicate_function_symbol(self):
        valid = calibration_elf()
        for field, value in ((0, 0), (1, 4), (2, 0), (2, 5), (3, 0x11), (3, 0x22),
                             (4, 2), (5, 0), (5, 99), (5, 0xfff1), (5, 0xfff2), (5, 0xffff)):
            with self.subTest(field=field, value=value):
                self.rejects(symbol_change(valid, 1, field, value))
        with_unwind = calibration_elf(arm_unwind=True)
        obj = elf.parse_relocatable(with_unwind, model())
        name_offset = obj.section_bytes(2).index(CALIBRATION_NAME)
        self.rejects(symbol_change(with_unwind, 2, 0, name_offset))

    def test_function_needs_allocated_executable_file_backing(self):
        for kind, flags in ((8, 6), (1, 2), (1, 4), (1, 7), (1, 0)):
            data = section_change(calibration_elf(), 1, 1, kind)
            self.rejects(section_change(data, 1, 2, flags))

    def test_complete_unrelated_symbol_inventory(self):
        valid = calibration_elf(arm_unwind=True)
        for index, field, value in ((0, 1, 1), (2, 0, 0xffffff), (2, 1, 1),
                                    (2, 3, 0x30), (2, 3, 0x13), (2, 5, 99)):
            with self.subTest(index=index, field=field, value=value):
                self.rejects(symbol_change(valid, index, field, value))

    def test_arm_unwind_is_metadata_only_not_an_unchecked_external(self):
        data = calibration_elf(arm_unwind=True)
        observed = self.check(data)
        self.assertEqual(observed["undefined_metadata"], [{"name": "__aeabi_unwind_cpp_pr0",
            "kind": "ARM exception-index metadata", "relocation_type": "R_ARM_NONE", "references": 1}])
        for modified in (data.replace(b"__aeabi_unwind_cpp_pr0", b"unexpected_dependency"),
                         section_change(data, 4, 6, 2), section_change(data, 5, 7, 1),
                         section_change(data, 5, 5, 0), section_change(data, 5, 9, 0),
                         section_change(data, 5, 6, 2),
                         calibration_elf(arm_unwind=True, relocation_addend=True)):
            self.rejects(modified)
        obj = elf.parse_relocatable(data, model())
        for offset, info in ((0, (2 << 8) | 1), (1, 2 << 8), (8, 2 << 8), (0, 99 << 8)):
            bad = bytearray(data)
            struct.pack_into("<II", bad, obj.sections[5].offset, offset, info)
            self.rejects(bytes(bad))

    def test_complete_relocation_tables_64_bit_both_byte_orders(self):
        for little in (True, False):
            for addend in (True, False):
                machine = 62 if little else 21
                data = calibration_elf(bits=64, little_endian=little, machine=machine,
                                       arm_unwind=True, relocation_addend=addend)
                # Convert the test metadata section to ordinary nonallocated
                # data and define its auxiliary symbol. This is structural
                # REL/RELA test data, not ARM semantics on another architecture.
                for field, value in ((1, 1), (2, 0), (6, 0)):
                    data = section_change(data, 4, field, value)
                data = symbol_change(data, 2, 5, 4)
                result = self.check(data, bits=64, little=little, machine=machine)
                self.assertEqual(result["relocation_count"], 1)
                obj = elf.parse_relocatable(data, model(bits=64, little=little))
                for address, info in ((8, 2 << 32), (0, 99 << 32)):
                    bad = bytearray(data)
                    struct.pack_into(("<" if little else ">") + "QQ", bad, obj.sections[5].offset,
                                     address, info)
                    with self.subTest(little=little, addend=addend), self.assertRaises(elf.ELFError):
                        self.check(bytes(bad), bits=64, little=little, machine=machine)

    def test_unterminated_symbol_and_section_strings_fail(self):
        valid = calibration_elf()
        obj = elf.parse_relocatable(valid, model())
        bad = bytearray(valid)
        strings = obj.sections[2]
        bad[strings.offset + strings.size - 1] = 65
        self.rejects(bytes(bad))

    def test_fixture_metadata_alone_is_not_a_calibration_definition(self):
        from tests.test_frontend_policy import fixture_elf
        self.rejects(fixture_elf({"variant": "no-instrument"}))

    def test_retained_real_objects_read_only(self):
        root = Path(__file__).resolve().parents[1]
        directory = Path(os.environ.get("FRAGMA_COMMON24_ELF_EVIDENCE",
            root / "build/common-byte-calibration-work/run-2"))
        if not directory.is_dir():
            self.skipTest("set FRAGMA_COMMON24_ELF_EVIDENCE to retained compiler-only run-2 evidence")
        for profile, machine, size in (("arm-gcc", 40, 4), ("powerpc32-gcc", 20, 12), ("m68k-gcc", 4, 2)):
            with self.subTest(profile=profile):
                receipt = json.loads((directory / profile / "receipt.json").read_text())

                def read(record):
                    data = Path(record["path"]).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
                    return data

                genuine = json.loads(read(receipt["fixture"]))
                actual_model = json.loads(read(receipt["profile"]))
                policy = {"schema_version": 1, "kind": "common24-inline",
                          "variant": "no-instrument" if genuine["inline_policy"] == 1 else "patchable-entry-0"}
                target = {"frontend_policy": policy, "input_mode": "standalone",
                          "source": "include/linux/unaligned.h", "harness": frontend_policy.HARNESS,
                          "kernel_model_check": frontend_policy.FIXTURE}
                fixture_record = next(row for row in genuine["artifacts"] if Path(row["path"]).name == "fixture.o")
                bound_fixture = frontend_policy.fixture_object(read(fixture_record), target, actual_model)
                positive = next(row for row in receipt["artifacts"] if Path(row["path"]).name == "positive.o")
                observed = elf.calibration_object(read(positive), actual_model, bound_fixture)
                self.assertEqual(observed["machine_observed"], machine)
                self.assertEqual(observed["definition"]["size"], size)
                self.assertEqual(len(observed["undefined_metadata"]), int(profile == "arm-gcc"))


if __name__ == "__main__":
    unittest.main()
