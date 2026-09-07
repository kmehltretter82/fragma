"""Source-derived, compile-only Hexagon musl ``max_align_t`` representation.

The caller must authenticate the complete sysroot and compiler invocation. This
module additionally ties the reviewed source template to the installed typedef,
generates comparison fixtures, and reads their bounded relocatable data. It does
not provision headers, execute a tool, award L1, or resolve extended alignment.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import struct

from . import elf


TEMPLATE = "source/arch/hexagon/bits/alltypes.h.in"
HEADER = "include/bits/alltypes.h"
MAX_INPUT_BYTES = 65536
MAX_OBJECT_BYTES = 1024 * 1024
SYMBOL = "fragma_max_align_layout"
LAYOUT_FIELDS = (
    "size", "c_alignment", "gnu_alignment", "ll_offset", "ld_offset",
    "ll_size", "ld_size", "array_size", "array_alignment",
    "wrapper_value_offset", "wrapper_tail_offset", "wrapper_size",
    "wrapper_c_alignment", "wrapper_gnu_alignment",
)
LAYOUT_NAMES = tuple(prefix + "_" + field for field in LAYOUT_FIELDS
                     for prefix in ("actual", "candidate"))
CONTROL_ASSERTIONS = {
    "legacy_scalar": "fragma_max_align_legacy_scalar_size",
    "reordered_members": "fragma_max_align_reordered_member_offset",
    "wrong_member_type": "fragma_max_align_wrong_member_type",
}
_DEFINITION = r"struct \{ long long __ll; long double __ld; \}"


class LayoutError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LayoutError(message)


def _path(path):
    raw = os.fspath(path)
    require(isinstance(raw, str) and raw and "\x00" not in raw
            and "//" not in raw and not any(part in (".", "..") for part in raw.split("/")),
            "Noncanonical layout input path")
    path = Path(os.path.abspath(raw))
    require(all(not item.is_symlink() for item in (path, *path.parents)),
            "Symlinked layout input path")
    return path


def _read(path):
    try:
        path = _path(path)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_INPUT_BYTES,
                    "Layout input is not a bounded regular file")
            data = stream.read(MAX_INPUT_BYTES + 1)
            after = os.fstat(stream.fileno())
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        require(len(data) <= MAX_INPUT_BYTES and identity(before) == identity(after)
                == identity(_path(path).lstat()), "Layout input changed while reading")
        return data.decode("ascii"), {"absolute_path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
    except (OSError, UnicodeError) as exc:
        raise LayoutError("Cannot read ASCII layout input: " + str(path)) from exc


def _definition(value):
    require(isinstance(value, str) and re.fullmatch(_DEFINITION, value) is not None,
            "Unreviewed Hexagon max_align_t declaration")
    return value


def declaration(sysroot):
    """Read the exact reviewed declaration; authentication is a caller gate.

No declaration is guessed from a scalar's alignment. A changed source syntax,
duplicate typedef, or disagreement with the installed guarded definition fails.
"""
    sysroot = _path(sysroot)
    require(sysroot.is_dir(), "Missing layout sysroot")
    template, template_record = _read(sysroot / TEMPLATE)
    header, header_record = _read(sysroot / HEADER)
    matches = re.findall(r"(?m)^TYPEDEF (" + _DEFINITION + r") max_align_t;$", template)
    require(len(matches) == 1 and len(re.findall(r"\bmax_align_t\b", template)) == 1,
            "Missing, duplicate, or changed max_align_t template declaration")
    definition = _definition(matches[0])
    block = ("#if defined(__NEED_max_align_t) && !defined(__DEFINED_max_align_t)\n"
             "typedef " + definition + " max_align_t;\n"
             "#define __DEFINED_max_align_t\n#endif")
    require(header.count(block) == 1 and len(re.findall(r"\bmax_align_t\b", header)) == 1
            and header.count("__NEED_max_align_t") == 1 and header.count("__DEFINED_max_align_t") == 2,
            "Installed max_align_t definition does not match the source template")
    return {"definition": definition, "template": template_record, "header": header_record,
            "inputs": [template_record, header_record],
            "scope": "Source/installed-declaration tie; complete sysroot authentication is required separately"}


def _expressions(type_name, wrapper):
    return (
        "sizeof(" + type_name + ")", "_Alignof(" + type_name + ")",
        "__alignof__(" + type_name + ")", "offsetof(" + type_name + ", __ll)",
        "offsetof(" + type_name + ", __ld)", "sizeof(( (" + type_name + " *)0)->__ll)",
        "sizeof(( (" + type_name + " *)0)->__ld)", "sizeof(" + type_name + "[2])",
        "_Alignof(" + type_name + "[2])", "offsetof(struct " + wrapper + ", value)",
        "offsetof(struct " + wrapper + ", tail)", "sizeof(struct " + wrapper + ")",
        "_Alignof(struct " + wrapper + ")", "__alignof__(struct " + wrapper + ")",
    )


def fixture(definition):
    """Positive comparison fixture with 28 paired, compiler-measured constants.

Pointer expressions appear only in unevaluated sizeof/typeof operands. There
are no functions, loads through pointers, runtime checks, or target execution.
Distinct anonymous aggregate types are compared by members/layout, not by an
incorrect assertion that separately declared structs have C type identity.
"""
    definition = _definition(definition)
    actual = _expressions("max_align_t", "fragma_actual_wrapper")
    candidate = _expressions("fragma_candidate_max_align_t", "fragma_candidate_wrapper")
    lines = ["/* SPDX-License-Identifier: MIT; compile-only source-derived layout comparison. */",
             "#include <stddef.h>", "typedef " + definition + " fragma_candidate_max_align_t;",
             "struct fragma_actual_wrapper { char lead; max_align_t value; char tail; };",
             "struct fragma_candidate_wrapper { char lead; fragma_candidate_max_align_t value; char tail; };",
             '_Static_assert(__CHAR_BIT__ == 8 && sizeof(unsigned int) == 4, "fragma_layout_u32_transport");']
    for type_name in ("max_align_t", "fragma_candidate_max_align_t"):
        for member, member_type in (("__ll", "long long"), ("__ld", "long double")):
            lines.append("_Static_assert(__builtin_types_compatible_p(__typeof__(((" + type_name
                         + " *)0)->" + member + "), " + member_type + "), \"fragma_max_align_"
                         + type_name + member + '_type\");')
    for name, observed, represented in zip(LAYOUT_FIELDS, actual, candidate):
        lines.append("_Static_assert(" + observed + " == " + represented
                     + ', "fragma_max_align_' + name + '");')
    lines.append("const unsigned int " + SYMBOL + "[] = {")
    for name, observed, represented in zip(LAYOUT_FIELDS, actual, candidate):
        lines.append("    " + observed + ", " + represented + ", /* " + name + " */")
    lines.extend(["};", ""])
    return "\n".join(lines)


def controls(definition):
    """Three intentional compile-time rejection controls; each has one assert."""
    definition = _definition(definition)
    alternatives = {
        "legacy_scalar": ("long long", "sizeof(max_align_t) == sizeof(fragma_bad_max_align_t)"),
        "reordered_members": (
            definition.replace("long long __ll; long double __ld;", "long double __ld; long long __ll;"),
            "offsetof(max_align_t, __ll) == offsetof(fragma_bad_max_align_t, __ll)"),
        "wrong_member_type": (definition.replace("long double __ld;", "double __ld;"),
            "__builtin_types_compatible_p(__typeof__(((max_align_t *)0)->__ld), "
            "__typeof__(((fragma_bad_max_align_t *)0)->__ld))"),
    }
    return {name: ("/* SPDX-License-Identifier: MIT; expected compile-time rejection. */\n"
                   "#include <stddef.h>\ntypedef " + definition + " fragma_candidate_max_align_t;\n"
                   "typedef " + bad + " fragma_bad_max_align_t;\n_Static_assert(" + condition
                   + ', "' + CONTROL_ASSERTIONS[name] + '");\n')
            for name, (bad, condition) in alternatives.items()}


def validate_object(data):
    """Validate a unique, relocation-free read-only paired layout array.

The observations come from object bytes, not expected ABI constants. This
checks internal consistency and actual/candidate agreement; authentic compiler
success, source assertions and before/after provenance remain caller gates.
"""
    require(isinstance(data, bytes) and len(data) <= MAX_OBJECT_BYTES, "Unbounded layout object")
    try:
        obj = elf.parse_relocatable(data, {"machdep": {"checked_fields": {
            "sizeof_ptr": 4, "little_endian": True}}})
    except (ValueError, struct.error) as exc:
        raise LayoutError("Invalid layout ELF: " + str(exc)) from exc
    require(obj.machine == 164 and struct.unpack_from("<I", data, 36)[0] == 0x68,
            "Layout object is not Hexagon v68")
    require(len(obj.sections) <= 64 and len(obj.symbols) <= 64, "Unbounded layout metadata")
    ranges = [(0, obj.header_size), (obj.section_offset, obj.section_offset + len(obj.sections) * obj.section_size)]
    for section in obj.sections[1:]:
        require(section.kind in (1, 2, 3, 0x70000003, 0x6FFF4C03)
                and section.address == 0 and not section.flags & (0x200 | 0x400 | 0x800),
                "Unsupported layout section or relocation")
        require(not section.alignment or section.offset % section.alignment == 0,
                "Misaligned layout section")
        if section.size:
            ranges.append((section.offset, section.offset + section.size))
    ranges.sort()
    require(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])),
            "Overlapping layout ELF sections")
    require(obj.symbols[0] == elf.Symbol(b"", 0, 0, 0, 0, 0), "Invalid layout null symbol")
    first_global = obj.sections[obj.symbol_table].info
    require(0 < first_global < len(obj.symbols), "Invalid layout symbol boundary")
    matches = [symbol for symbol in obj.symbols if symbol.name == SYMBOL.encode()]
    require(len(matches) == 1, "Missing or duplicate layout array")
    symbol = matches[0]
    expected_size = 4 * len(LAYOUT_NAMES)
    require(symbol.info == 0x11 and symbol.other == 0 and symbol.value == 0
            and symbol.size == expected_size and 0 < symbol.section < len(obj.sections),
            "Layout array must be a unique global default-visible data definition")
    section = obj.sections[symbol.section]
    require(section.kind == 1 and section.flags == 2 and section.size == expected_size
            and section.alignment >= 4 and section.offset % 4 == 0,
            "Layout array lacks bounded allocated read-only storage")
    for index, item in enumerate(obj.symbols[1:], 1):
        require((item.info >> 4 == 0) == (index < first_global), "Invalid layout local/global ordering")
        if item == symbol:
            continue
        require(item.other == 0 and item.value == item.size == 0
                and ((item.info == 4 and item.section == 0xFFF1)
                     or (item.info == 3 and 0 < item.section < len(obj.sections))),
                "Unexpected layout symbol or external dependency")
    require(all(not row.flags & 2 or not row.size or index == symbol.section
                for index, row in enumerate(obj.sections)), "Unexpected allocated layout data or instructions")
    values = struct.unpack("<" + "I" * len(LAYOUT_NAMES), obj.section_bytes(symbol.section))
    observations = dict(zip(LAYOUT_NAMES, values))
    for name in LAYOUT_FIELDS:
        require(observations["actual_" + name] == observations["candidate_" + name],
                "Actual/candidate layout mismatch: " + name)
    layout = {name: observations["actual_" + name] for name in LAYOUT_FIELDS}
    for name in ("c_alignment", "gnu_alignment", "array_alignment", "wrapper_c_alignment", "wrapper_gnu_alignment"):
        value = layout[name]
        require(value > 0 and value & (value - 1) == 0, "Invalid measured alignment: " + name)
    require(layout["size"] > 0 and layout["size"] % layout["c_alignment"] == 0
            and layout["ll_offset"] == 0 and layout["ll_size"] > 0 and layout["ld_size"] > 0
            and layout["ld_offset"] >= layout["ll_size"]
            and layout["ld_offset"] + layout["ld_size"] <= layout["size"], "Invalid measured member layout")
    require(layout["array_size"] == 2 * layout["size"]
            and layout["array_alignment"] == layout["c_alignment"], "Invalid measured array layout")
    require(layout["wrapper_value_offset"] >= 1
            and layout["wrapper_value_offset"] % layout["c_alignment"] == 0
            and layout["wrapper_tail_offset"] == layout["wrapper_value_offset"] + layout["size"]
            and layout["wrapper_size"] >= layout["wrapper_tail_offset"] + 1
            and layout["wrapper_size"] % layout["wrapper_c_alignment"] == 0
            and layout["wrapper_c_alignment"] == layout["c_alignment"]
            and layout["wrapper_gnu_alignment"] == layout["gnu_alignment"], "Invalid measured wrapper layout")
    return {"status": "checked-paired-layout-not-L1", "symbol": SYMBOL, "class": 32,
            "byte_order": "little", "machine": obj.machine, "flags": 0x68,
            "symbol_size": expected_size, "values": observations, "layout": layout,
            "sha256": hashlib.sha256(data).hexdigest()}
