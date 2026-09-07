"""Inert source and independently constructed ELF checks; no tool executes."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from fragma import hexagon_layout as layout


DEFINITION = "struct { long long __ll; long double __ld; }"
TEMPLATE = "#define _Addr int\nTYPEDEF " + DEFINITION + " max_align_t;\n"
HEADER = ("#if defined(__NEED_max_align_t) && !defined(__DEFINED_max_align_t)\n"
          "typedef " + DEFINITION + " max_align_t;\n#define __DEFINED_max_align_t\n#endif\n")
FIELD_NAMES = (
    "size", "c_alignment", "gnu_alignment", "ll_offset", "ld_offset", "ll_size", "ld_size",
    "array_size", "array_alignment", "wrapper_value_offset", "wrapper_tail_offset", "wrapper_size",
    "wrapper_c_alignment", "wrapper_gnu_alignment",
)
BASE_VALUES = (16, 8, 8, 0, 8, 8, 8, 32, 8, 8, 24, 32, 8, 8)


def synthetic_elf(*, values=None, symbol_name=b"fragma_max_align_layout", symbol_info=0x11,
                  symbol_other=0, symbol_value=0, symbol_size=112, machine=164,
                  flags=0x68, section_flags=2, section_kind=1, duplicate=False,
                  additional_symbol=False, extra_alloc=False):
    """Independent minimal ELF32LE encoding, not a production-reader fixture."""
    values = [value for value in BASE_VALUES for _ in range(2)] if values is None else values
    names = b"\0.rodata\0.shstrtab\0.strtab\0.symtab\0.extra\0"
    strings = b"\0" + symbol_name + b"\0extra\0"
    data = bytearray(56)
    data_offset = len(data)
    data.extend(struct.pack("<" + "I" * len(values), *values))
    names_offset = len(data)
    data.extend(names)
    strings_offset = len(data)
    data.extend(strings)
    data.extend(bytes(-len(data) % 4))
    symbols_offset = len(data)
    symbols = [bytes(16), struct.pack("<IIIBBH", 1, symbol_value, symbol_size, symbol_info, symbol_other, 1)]
    if duplicate:
        symbols.append(symbols[1])
    if additional_symbol:
        symbols.append(struct.pack("<IIIBBH", strings.index(b"extra"), 0, 0, 0x10, 0, 0))
    data.extend(b"".join(symbols))
    extra_offset = len(data)
    if extra_alloc:
        data.extend(b"ABCD")
    section_offset = len(data)
    sections = [(0,) * 10,
        (names.index(b".rodata"), section_kind, section_flags, 0, data_offset, 4 * len(values), 0, 0, 8, 0),
        (names.index(b".shstrtab"), 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
        (names.index(b".strtab"), 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        (names.index(b".symtab"), 2, 0, 0, symbols_offset, 16 * len(symbols), 3, 1, 4, 16)]
    if extra_alloc:
        sections.append((names.index(b".extra"), 1, 6, 0, extra_offset, 4, 0, 0, 4, 0))
    for section in sections:
        data.extend(struct.pack("<10I", *section))
    ident = bytes([127, 69, 76, 70, 1, 1, 1]) + bytes(9)
    data[:52] = struct.pack("<16sHHIIIIIHHHHHH", ident, 1, machine, 1, 0, 0, section_offset,
                            flags, 52, 0, 0, 40, len(sections), 2)
    return bytes(data)


class HexagonLayoutTests(unittest.TestCase):
    def setUp(self):
        for target in ("subprocess.run", "subprocess.Popen", "os.system"):
            blocker = patch(target, side_effect=AssertionError("layout tests must remain inert"))
            blocker.start()
            self.addCleanup(blocker.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def sysroot(self, template=TEMPLATE, header=HEADER):
        for relative, text in ((layout.TEMPLATE, template), (layout.HEADER, header)):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return self.root

    def changed_values(self, name, value, *, both=True):
        values = [item for item in BASE_VALUES for _ in range(2)]
        index = 2 * FIELD_NAMES.index(name)
        values[index] = value
        if both:
            values[index + 1] = value
        return values

    def test_source_and_installed_definition_tie(self):
        result = layout.declaration(self.sysroot())
        self.assertEqual(result["definition"], DEFINITION)
        self.assertEqual(result["inputs"], [result["template"], result["header"]])
        for key, relative, source in (("template", layout.TEMPLATE, TEMPLATE), ("header", layout.HEADER, HEADER)):
            self.assertEqual(result[key], {"absolute_path": str(self.root / relative),
                                           "sha256": hashlib.sha256(source.encode()).hexdigest()})
        self.assertIn("authentication", result["scope"])

    def test_missing_sysroot_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.root / "absent")

    def test_missing_header_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.root)

    def test_duplicate_template_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(template=TEMPLATE + TEMPLATE))

    def test_changed_template_syntax_rejected(self):
        for old, new in (("long double", "double"), ("__ll", "__other"), ("struct {", "struct tagged {"),
                         ("TYPEDEF", "typedef"), ("; }", "; } __attribute__((aligned(8)))")):
            with self.subTest(change=new), self.assertRaises(layout.LayoutError):
                layout.declaration(self.sysroot(template=TEMPLATE.replace(old, new)))

    def test_duplicate_installed_header_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(header=HEADER + HEADER))

    def test_installed_source_disagreement_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(header=HEADER.replace("long double", "double")))

    def test_changed_installed_guard_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(header=HEADER.replace("__NEED_max_align_t", "__NEED_other")))

    def test_extra_guard_use_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(header=HEADER + "#undef __DEFINED_max_align_t\n"))

    def test_non_ascii_header_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(header=HEADER + "/* é */\n"))

    def test_oversized_header_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.sysroot(header=HEADER + " " * layout.MAX_INPUT_BYTES))

    def test_nonregular_header_rejected(self):
        self.sysroot()
        path = self.root / layout.HEADER
        path.unlink()
        path.mkdir()
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.root)

    def test_symlinked_header_rejected(self):
        self.sysroot()
        path = self.root / layout.HEADER
        original = self.root / "retained-header"
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaises(layout.LayoutError):
            layout.declaration(self.root)

    def test_symlinked_parent_rejected(self):
        self.sysroot()
        link = self.root / "aliased"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(layout.LayoutError):
            layout.declaration(link)

    def test_parent_path_alias_rejected(self):
        self.sysroot()
        with self.assertRaises(layout.LayoutError):
            layout.declaration(str(self.root) + "/unused/..")

    def test_read_drift_rejected(self):
        self.sysroot()
        original = layout.os.fstat
        calls = 0
        def changed(descriptor):
            nonlocal calls
            calls += 1
            row = original(descriptor)
            if calls == 2:
                (self.root / layout.TEMPLATE).write_text(TEMPLATE + "\n")
            return row
        with patch.object(layout.os, "fstat", side_effect=changed), self.assertRaises(layout.LayoutError):
            layout.declaration(self.root)

    def test_fixture_has_source_definition_and_all_pairs(self):
        source = layout.fixture(DEFINITION)
        self.assertIn("typedef " + DEFINITION + " fragma_candidate_max_align_t;", source)
        self.assertEqual(layout.LAYOUT_FIELDS, FIELD_NAMES)
        self.assertEqual(len(layout.LAYOUT_NAMES), 28)
        self.assertIn("const unsigned int fragma_max_align_layout[]", source)
        for field in FIELD_NAMES:
            self.assertIn('"fragma_max_align_' + field + '"', source)
            self.assertIn("/* " + field + " */", source)
        self.assertEqual(source.count("__builtin_types_compatible_p"), 4)
        self.assertNotIn("main(", source)
        self.assertNotIn("sizeof(max_align_t) == 16", source)
        self.assertNotIn("_Alignof(max_align_t) == 8", source)

    def test_fixture_type_checks_are_members_not_struct_identity(self):
        source = layout.fixture(DEFINITION)
        self.assertIn("__typeof__(((max_align_t *)0)->__ll), long long", source)
        self.assertIn("__typeof__(((fragma_candidate_max_align_t *)0)->__ld), long double", source)
        self.assertNotIn("__builtin_types_compatible_p(max_align_t", source)

    def test_fixture_definition_is_closed(self):
        for bad in ("long long", DEFINITION + "; int injected;", DEFINITION.replace("__ld", "other"), None):
            with self.subTest(bad=bad), self.assertRaises(layout.LayoutError):
                layout.fixture(bad)

    def test_controls_are_distinct_single_assertions(self):
        controls = layout.controls(DEFINITION)
        self.assertEqual(set(controls), {"legacy_scalar", "reordered_members", "wrong_member_type"})
        for name, source in controls.items():
            self.assertEqual(source.count("_Static_assert("), 1)
            self.assertIn('"' + layout.CONTROL_ASSERTIONS[name] + '"', source)
            self.assertIn("typedef " + DEFINITION + " fragma_candidate_max_align_t;", source)
            self.assertNotIn("const unsigned int", source)
        self.assertIn("typedef long long fragma_bad_max_align_t;", controls["legacy_scalar"])
        self.assertIn("struct { long double __ld; long long __ll; }", controls["reordered_members"])
        self.assertIn("struct { long long __ll; double __ld; }", controls["wrong_member_type"])

    def test_controls_require_exact_candidate(self):
        with self.assertRaises(layout.LayoutError):
            layout.controls("struct { double __ld; }")

    def test_positive_object_observations_are_named_and_paired(self):
        data = synthetic_elf()
        result = layout.validate_object(data)
        self.assertEqual(result["layout"], dict(zip(FIELD_NAMES, BASE_VALUES)))
        self.assertEqual(result["symbol_size"], 112)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertIn("not-L1", result["status"])
        self.assertEqual(list(result["values"]), list(layout.LAYOUT_NAMES))

    def test_alternative_consistent_measured_values_not_hardcoded(self):
        values = (32, 16, 16, 0, 16, 8, 16, 64, 16, 16, 48, 64, 16, 16)
        result = layout.validate_object(synthetic_elf(values=[value for value in values for _ in range(2)]))
        self.assertEqual(result["layout"]["size"], 32)

    def test_mismatched_paired_measurements_rejected(self):
        for name in FIELD_NAMES:
            values = self.changed_values(name, BASE_VALUES[FIELD_NAMES.index(name)] + 1, both=False)
            with self.subTest(name=name), self.assertRaisesRegex(layout.LayoutError, "mismatch"):
                layout.validate_object(synthetic_elf(values=values))

    def test_invalid_equal_member_measurements_rejected(self):
        for name, value in (("size", 0), ("ll_offset", 1), ("ll_size", 0), ("ld_size", 0),
                            ("ld_offset", 4), ("ld_size", 20)):
            with self.subTest(name=name, value=value), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(values=self.changed_values(name, value)))

    def test_invalid_equal_array_measurements_rejected(self):
        for name, value in (("array_size", 16), ("array_alignment", 4)):
            with self.subTest(name=name), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(values=self.changed_values(name, value)))

    def test_invalid_equal_wrapper_measurements_rejected(self):
        for name, value in (("wrapper_value_offset", 0), ("wrapper_value_offset", 4),
                            ("wrapper_tail_offset", 25), ("wrapper_size", 24),
                            ("wrapper_c_alignment", 4), ("wrapper_gnu_alignment", 4)):
            with self.subTest(name=name, value=value), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(values=self.changed_values(name, value)))

    def test_non_power_of_two_measured_alignment_rejected(self):
        for value in (0, 3):
            with self.subTest(value=value), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(values=self.changed_values("c_alignment", value)))

    def test_wrong_object_identity_rejected(self):
        for changes in ({"machine": 62}, {"flags": 0x67}):
            with self.subTest(changes=changes), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(**changes))
        for offset, value in ((4, 2), (5, 2), (16, 2)):
            changed = bytearray(synthetic_elf())
            changed[offset] = value
            with self.subTest(offset=offset), self.assertRaises(layout.LayoutError):
                layout.validate_object(bytes(changed))

    def test_missing_and_duplicate_symbols_rejected(self):
        for changes in ({"symbol_name": b"wrong"}, {"duplicate": True}):
            with self.subTest(changes=changes), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(**changes))

    def test_invalid_symbol_type_binding_visibility_extent_rejected(self):
        for changes in ({"symbol_info": 1}, {"symbol_info": 0x12}, {"symbol_info": 0x21},
                        {"symbol_other": 2}, {"symbol_value": 4}, {"symbol_size": 108}):
            with self.subTest(changes=changes), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(**changes))

    def test_writable_executable_unallocated_and_nobits_rejected(self):
        for changes in ({"section_flags": 3}, {"section_flags": 6}, {"section_flags": 0}, {"section_kind": 8}):
            with self.subTest(changes=changes), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(**changes))

    def test_relocation_sections_rejected(self):
        for kind in (4, 9):
            with self.subTest(kind=kind), self.assertRaises(layout.LayoutError):
                layout.validate_object(synthetic_elf(section_kind=kind))

    def test_additional_external_dependency_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.validate_object(synthetic_elf(additional_symbol=True))

    def test_additional_allocated_instructions_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.validate_object(synthetic_elf(extra_alloc=True))

    def test_overlapping_section_rejected(self):
        data = bytearray(synthetic_elf())
        offset = struct.unpack_from("<I", data, 32)[0]
        struct.pack_into("<I", data, offset + 40 + 16, 0)
        with self.assertRaisesRegex(layout.LayoutError, "Overlapping"):
            layout.validate_object(bytes(data))

    def test_truncated_and_oversized_object_rejected(self):
        for data in (b"", synthetic_elf()[:-1], bytes(layout.MAX_OBJECT_BYTES + 1), bytearray(synthetic_elf())):
            with self.subTest(size=len(data)), self.assertRaises(layout.LayoutError):
                layout.validate_object(data)

    def test_payload_extent_mismatch_rejected(self):
        with self.assertRaises(layout.LayoutError):
            layout.validate_object(synthetic_elf(values=[value for value in BASE_VALUES for _ in range(2)] + [0]))


if __name__ == "__main__":
    unittest.main()
