"""Small, pure readers for the project's retained relocatable ELF objects.

No files are opened here. Callers authenticate regular-file bytes, commands,
compiler/header/model identities and drift. Container/symbol observations never
verify instructions, instrumentation, execution, linker behavior or an ISA.
Extended numbering, compressed sections and dynamic objects are not supported.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct


class ELFError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ELFError(message)


@dataclass(frozen=True)
class Section:
    name: bytes
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class Symbol:
    name: bytes
    value: int
    size: int
    info: int
    other: int
    section: int


@dataclass(frozen=True)
class Relocatable:
    data: bytes
    bits: int
    little: bool
    machine: int
    header_size: int
    section_offset: int
    section_size: int
    sections: tuple[Section, ...]
    symbols: tuple[Symbol, ...]
    symbol_table: int

    def section_bytes(self, index):
        row = self.sections[index]
        require(row.kind != 8, "metadata points into a non-file-backed section")
        return self.data[row.offset:row.offset + row.size]


def parse_relocatable(data: bytes, model: dict) -> Relocatable:
    """Preserve the frontend fixture's bounded header/table reading behavior.

All section/name and symbol/name tables are read, but this compatibility reader
does not validate unrelated symbol definitions or relocation semantics. The
calibration-specific complete-table gate below performs those additional checks.
"""
    machdep = model.get("machdep") if isinstance(model, dict) else None
    fields = machdep.get("checked_fields") if isinstance(machdep, dict) else None
    require(isinstance(fields, dict), "fixture object requires checked machine fields")
    width, little = fields.get("sizeof_ptr"), fields.get("little_endian")
    require(type(width) is int and width in (4, 8) and type(little) is bool,
            "fixture object requires checked pointer width and byte order")
    bits, endian = width * 8, "<" if little else ">"
    size, section_size, symbol_size = (52, 40, 16) if bits == 32 else (64, 64, 24)
    require(isinstance(data, bytes) and len(data) >= size
            and data[:7] == bytes([127, 69, 76, 70, 1 if bits == 32 else 2, 1 if little else 2, 1]),
            "truncated or wrong-class/byte-order ELF fixture")
    header_format = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstr = struct.unpack_from(endian + header_format, data, 16)
    require(kind == 1 and version == 1 and entry == 0 and ehsize == size
            and phoff == phentsize == phnum == 0 and shentsize == section_size
            and 2 <= shnum < 0xff00 and 0 < shstr < shnum and shoff >= size
            and shoff + shnum * section_size <= len(data), "invalid relocatable ELF header/section bounds")
    section_format = "IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"
    rows = [struct.unpack_from(endian + section_format, data, shoff + i * section_size)
            for i in range(shnum)]
    require(rows[0] == (0,) * 10, "unexpected ELF null section/extended numbering")
    for row in rows[1:]:
        _, section_type, _, _, offset, length, link, _, alignment, _ = row
        require(offset <= len(data) and (section_type == 8 or offset + length <= len(data))
                and link < shnum and (alignment == 0 or alignment & (alignment - 1) == 0),
                "ELF section lies outside its bounded container")

    def section_bytes(index):
        row = rows[index]
        require(row[1] != 8, "metadata points into a non-file-backed section")
        return data[row[4]:row[4] + row[5]]

    def string(table, offset):
        require(offset < len(table), "ELF string offset is out of bounds")
        end = table.find(b"\0", offset)
        require(end >= 0, "unterminated ELF string")
        return table[offset:end]

    require(rows[shstr][1] == 3, "missing ELF section-name string table")
    names = section_bytes(shstr)
    require(names.startswith(b"\0"), "invalid ELF section-name table")
    sections = tuple(Section(string(names, row[0]), *row[1:]) for row in rows)
    tables = [index for index, row in enumerate(rows) if row[1] == 2]
    require(len(tables) == 1, "missing or ambiguous ELF symbol table")
    table = rows[tables[0]]
    require(table[9] == symbol_size and table[5] >= symbol_size and table[5] % symbol_size == 0
            and 0 < table[6] < shnum and rows[table[6]][1] == 3,
            "invalid ELF symbol table/link/bounds")
    strings = section_bytes(table[6])
    require(strings.startswith(b"\0"), "invalid ELF symbol-name table")
    symbols = []
    for offset in range(table[4], table[4] + table[5], symbol_size):
        if bits == 32:
            name, value, length, info, other, section = struct.unpack_from(endian + "IIIBBH", data, offset)
        else:
            name, info, other, section, value, length = struct.unpack_from(endian + "IBBHQQ", data, offset)
        symbols.append(Symbol(string(strings, name), value, length, info, other, section))
    return Relocatable(data, bits, little, machine, size, shoff, section_size,
                       sections, tuple(symbols), tables[0])


def _alpha_function_metadata(obj, symbol):
    """Recognize only documented Alpha function metadata, without masking it.

    The configured positive object uses ELF64 little-endian EM_ALPHA, flags 0,
    and STO_ALPHA_NOPV. STO_ALPHA_STD_GPLOAD is the other documented encoding.
    This observes ABI metadata only, not procedure-value or linker behavior.
    """
    if not (obj.bits == 64 and obj.little and obj.machine == 0x9026
            and struct.unpack_from("<I", obj.data, 48)[0] == 0
            and symbol.other in (0x80, 0x88) and symbol.info in (0x02, 0x12)
            and symbol.name and symbol.size > 0 and 0 < symbol.section < len(obj.sections)):
        return False
    section = obj.sections[symbol.section]
    return (section.kind == 1 and section.flags & 6 == 6 and not section.flags & 1
            and symbol.value + symbol.size <= section.size)


def _header_flags(obj):
    endian = "<" if obj.little else ">"
    return struct.unpack_from(endian + "I", obj.data, 36 if obj.bits == 32 else 48)[0]


def _mips_calibration_metadata(obj):
    """Admit only the exact fixed-input Clang MIPS32el/O32 metadata family.

    These sections do not establish instruction semantics.  They merely keep
    the complete-table calibration gate closed around the metadata emitted by
    the locked compiler for this one profile and command.
    """
    kinds = {b".reginfo": 0x70000006, b".MIPS.abiflags": 0x7000002a,
             b".llvm_addrsig": 0x6fff4c03}
    marked = [section for section in obj.sections
              if section.name in kinds or section.kind in kinds.values()]
    exact_route = (obj.bits == 32 and obj.little and obj.machine == 8
                   and _header_flags(obj) == 0x70001001)
    if not exact_route:
        require(not marked, "MIPS calibration metadata outside exact MIPS32el/O32 route")
        return None

    selected = {}
    for name, kind in kinds.items():
        matches = [section for section in obj.sections
                   if section.name == name or section.kind == kind]
        require(len(matches) == 1 and matches[0].name == name and matches[0].kind == kind,
                "missing, duplicate or mismatched MIPS calibration metadata")
        selected[name] = matches[0]
    require(len(marked) == len(kinds), "unexpected extra MIPS calibration metadata")

    reginfo = selected[b".reginfo"]
    require((reginfo.flags, reginfo.address, reginfo.size, reginfo.link, reginfo.info,
             reginfo.alignment, reginfo.entry_size) == (2, 0, 24, 0, 0, 4, 24),
            "unexpected MIPS reginfo section shape")
    registers = struct.unpack("<6I", obj.section_bytes(obj.sections.index(reginfo)))
    require(registers == (0x80000001, 0, 0, 0, 0, 0),
            "unexpected MIPS reginfo contents")

    abi = selected[b".MIPS.abiflags"]
    require((abi.flags, abi.address, abi.size, abi.link, abi.info,
             abi.alignment, abi.entry_size) == (2, 0, 24, 0, 0, 8, 24),
            "unexpected MIPS ABI-flags section shape")
    abi_fields = struct.unpack("<HBBBBBBIIII", obj.section_bytes(obj.sections.index(abi)))
    require(abi_fields == (0, 32, 2, 1, 0, 0, 3, 0, 0, 1, 0),
            "unexpected MIPS ABI-flags contents")

    addrsig = selected[b".llvm_addrsig"]
    require((addrsig.flags, addrsig.address, addrsig.size, addrsig.link, addrsig.info,
             addrsig.alignment, addrsig.entry_size) ==
            (0x80000000, 0, 0, obj.symbol_table, 0, 1, 0),
            "unexpected LLVM address-significance section shape")
    return {
        "header_flags": "0x70001001",
        "sections": [".reginfo", ".MIPS.abiflags", ".llvm_addrsig"],
        "reginfo": {"gpr_mask": "0x80000001", "cpr_masks": [0, 0, 0, 0],
                    "gp_value": "0x00000000"},
        "abi_flags": {"version": 0, "isa_level": 32, "isa_revision": 2,
                      "gpr_size_encoding": 1, "cpr1_size_encoding": 0,
                      "cpr2_size_encoding": 0, "fp_abi_encoding": 3,
                      "isa_extension": 0, "ases": 0, "flags1": 1, "flags2": 0},
        "scope": "Exact MIPS32el/O32 container metadata only; no instruction, linker or runtime proof",
    }


def _complete_tables(obj):
    """Bound every section/symbol/REL[A] entry used by this small object family."""
    sections, symbols = obj.sections, obj.symbols
    mips_metadata = _mips_calibration_metadata(obj)
    ranges = [(0, obj.header_size),
              (obj.section_offset, obj.section_offset + len(sections) * obj.section_size)]
    for index, section in enumerate(sections[1:], 1):
        generic = section.kind in (1, 2, 3, 4, 7, 8, 9)
        arm_metadata = obj.machine == 40 and section.kind in (0x70000001, 0x70000003)
        mips_kind = mips_metadata is not None and section.kind in (
            0x6fff4c03, 0x70000006, 0x7000002a)
        require(generic or arm_metadata or mips_kind,
                "unsupported calibration ELF section kind")
        require(section.address == 0 and not section.flags & (0x200 | 0x400 | 0x800),
                "unsupported calibration ELF section address/group/TLS/compression")
        require(not section.alignment or section.offset % section.alignment == 0,
                "misaligned calibration ELF section")
        if section.kind != 8 and section.size:
            ranges.append((section.offset, section.offset + section.size))
        if section.kind == 3:
            content = obj.section_bytes(index)
            require(content.startswith(b"\0") and content.endswith(b"\0"), "invalid complete ELF string table")
        if section.kind in (1, 3, 7, 8, 0x70000003):
            require(section.link == section.info == 0, "unexpected calibration ELF section link/info")
        if section.kind == 0x70000001:
            require(section.name == b".ARM.exidx" and section.flags == 0x82
                    and section.info == 0 and 0 < section.link < len(sections)
                    and sections[section.link].kind == 1 and sections[section.link].flags & 6 == 6,
                    "unexpected ARM exception-index metadata")
    ranges.sort()
    require(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])),
            "overlapping ELF headers/sections")
    require(symbols[0] == Symbol(b"", 0, 0, 0, 0, 0), "invalid ELF null symbol")
    first_global = sections[obj.symbol_table].info
    require(0 < first_global <= len(symbols), "invalid ELF local/global symbol boundary")
    for index, symbol in enumerate(symbols):
        binding, kind = symbol.info >> 4, symbol.info & 15
        require(binding in (0, 1, 2) and kind in range(7)
                and (symbol.other in range(4) or _alpha_function_metadata(obj, symbol))
                and (binding == 0) is (index < first_global), "invalid ELF symbol type/binding/order")
        if symbol.section == 0:
            require(symbol.value == symbol.size == 0, "undefined ELF symbol has a value/extent")
        elif symbol.section == 0xfff1:
            require(kind == 4 and binding == 0 and symbol.value == symbol.size == 0,
                    "unsupported absolute ELF symbol")
        else:
            require(0 < symbol.section < len(sections), "unsupported/out-of-range ELF symbol section")
            require(symbol.value + symbol.size <= sections[symbol.section].size,
                    "ELF symbol extent exceeds its section")
        if kind == 3:
            require(binding == 0 and 0 < symbol.section < len(sections)
                    and symbol.value == symbol.size == 0, "invalid ELF section symbol")
        if kind == 4:
            require(symbol.section == 0xfff1, "invalid ELF file symbol")
    relocations = []
    endian = "<" if obj.little else ">"
    for index, section in enumerate(sections):
        if section.kind not in (4, 9):
            continue
        is_rela = section.kind == 4
        expected_size = (12 if is_rela else 8) if obj.bits == 32 else (24 if is_rela else 16)
        require(section.link == obj.symbol_table and 0 < section.info < len(sections)
                and section.entry_size == expected_size and section.size % expected_size == 0,
                "invalid ELF relocation table/link/entry bounds")
        target = sections[section.info]
        require(not target.flags & 4, "calibration executable section has relocations")
        for offset in range(section.offset, section.offset + section.size, expected_size):
            address, info = struct.unpack_from(endian + ("II" if obj.bits == 32 else "QQ"), obj.data, offset)
            symbol = info >> (8 if obj.bits == 32 else 32)
            kind = info & (0xff if obj.bits == 32 else 0xffffffff)
            require(symbol < len(symbols) and address < target.size,
                    "ELF relocation symbol/offset is out of bounds")
            relocations.append((index, section.info, address, symbol, kind))
    return relocations, mips_metadata


def calibration_object(data: bytes, model: dict, fixture_observation: dict) -> dict:
    """Observe the one external nonempty calibration definition in positive.o.

The fixture envelope must already have been rederived from authenticated genuine
fixture bytes by frontend_policy.fixture_object; an arbitrary passed JSON object
does not authenticate a compiler/model. Full fixed-input sensitivity additionally
requires the source/command and all 22 compiler-negative controls at the caller.
"""
    obj = parse_relocatable(data, model)
    require(isinstance(fixture_observation, dict)
            and type(fixture_observation.get("class")) is int
            and type(fixture_observation.get("machine_observed")) is int
            and 0 < fixture_observation["machine_observed"] <= 0xffff
            and fixture_observation.get("type") == "relocatable"
            and fixture_observation["class"] == obj.bits
            and fixture_observation.get("byte_order") == ("little" if obj.little else "big")
            and fixture_observation["machine_observed"] == obj.machine,
            "positive object differs from genuine fixture class/byte-order/machine")
    relocations, mips_metadata = _complete_tables(obj)
    name = b"fragma_common24_compiler_calibration"
    matches = [symbol for symbol in obj.symbols if symbol.name == name]
    require(len(matches) == 1, "missing or duplicate calibration definition")
    symbol = matches[0]
    require(symbol.info == 0x12 and (symbol.other == 0 or _alpha_function_metadata(obj, symbol))
            and symbol.size > 0
            and 0 < symbol.section < len(obj.sections),
            "calibration must be a global defined nonempty STT_FUNC")
    section = obj.sections[symbol.section]
    require(section.kind == 1 and section.flags & 6 == 6 and not section.flags & 1,
            "calibration definition lacks allocated executable file-backed storage")
    undefined = []
    for index, item in enumerate(obj.symbols[1:], 1):
        if item.section != 0:
            continue
        references = [row for row in relocations if row[3] == index]
        require(obj.bits == 32 and obj.machine == 40 and item.name == b"__aeabi_unwind_cpp_pr0"
                and item.info == 0x10 and item.other == 0 and len(references) == 1
                and all(obj.sections[row[0]].kind == 9 and obj.sections[row[1]].kind == 0x70000001
                        and obj.sections[row[1]].link == symbol.section and obj.sections[row[1]].size == 8
                        and row[2] == row[4] == 0 for row in references),
                "unexpected undefined calibration symbol or non-metadata use")
        require(not undefined, "duplicate ARM unwind metadata symbol")
        undefined.append({"name": item.name.decode(), "kind": "ARM exception-index metadata",
                          "relocation_type": "R_ARM_NONE", "references": len(references)})
    content = obj.section_bytes(symbol.section)[symbol.value:symbol.value + symbol.size]
    observed = {"schema_version": 1, "status": "checked", "class": obj.bits,
            "byte_order": "little" if obj.little else "big", "type": "relocatable",
            "machine_observed": obj.machine, "section_count": len(obj.sections),
            "symbol_count": len(obj.symbols), "relocation_count": len(relocations),
            "definition": {"name": name.decode(), "section": section.name.decode("latin1"),
                           "section_index": symbol.section, "section_flags": section.flags,
                           "offset": symbol.value, "size": symbol.size,
                           "bytes_sha256": hashlib.sha256(content).hexdigest()},
            "undefined_metadata": undefined,
            "scope": "Bounded ELF tables and external definition only; no ISA, code-generation or runtime proof"}
    metadata = [{"name": item.name.decode("latin1"), "other": item.other,
                 "meaning": "STO_ALPHA_NOPV" if item.other == 0x80 else "STO_ALPHA_STD_GPLOAD",
                 "binding": "local" if item.info >> 4 == 0 else "global",
                 "section_index": item.section, "header_flags": 0}
                for item in obj.symbols if _alpha_function_metadata(obj, item)]
    if metadata:
        observed["alpha_symbol_metadata"] = metadata
    if mips_metadata is not None:
        observed["mips_abi_metadata"] = mips_metadata
    return observed
