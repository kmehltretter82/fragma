#!/usr/bin/env python3
"""Change only one big-endian ELF32 SHT_RELA sh_info field."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


SHT_RELA = 4
R_PARISC_PCREL17F = 12
R_PARISC_PCREL22F = 74
COUNTED_RELOCS = {R_PARISC_PCREL17F, R_PARISC_PCREL22F}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated section name")
    return data[offset:end].decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--section",
                        help="SHT_RELA section to mutate; default: first "
                             "section with a counted PA-RISC relocation")
    parser.add_argument("--value", type=lambda value: int(value, 0),
                        default=0x10000000)
    args = parser.parse_args()

    original = args.input.read_bytes()
    if original[:6] != b"\x7fELF\x01\x02":
        raise ValueError("input is not a big-endian ELF32 object")

    e_shoff = struct.unpack_from(">I", original, 32)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(">HHH", original,
                                                               46)
    if e_shentsize != 40:
        raise ValueError(f"unexpected section-header size {e_shentsize}")
    if not 0 < e_shstrndx < e_shnum:
        raise ValueError("invalid section-name string table index")

    def section(index: int) -> tuple[int, ...]:
        offset = e_shoff + index * e_shentsize
        return struct.unpack_from(">IIIIIIIIII", original, offset)

    shstr = section(e_shstrndx)
    names = original[shstr[4]:shstr[4] + shstr[5]]
    target_index = -1
    target_name = ""
    target = ()
    relocation_types = []
    for index in range(1, e_shnum):
        current = section(index)
        name = c_string(names, current[0])
        if args.section is not None and name != args.section:
            continue
        if current[1] != SHT_RELA:
            continue
        if current[9] != 12 or current[5] % current[9]:
            raise ValueError(f"unexpected Elf32_Rela layout in {name!r}")

        current_types = []
        for offset in range(current[4], current[4] + current[5], current[9]):
            r_info = struct.unpack_from(">I", original, offset + 4)[0]
            current_types.append(r_info & 0xff)
        if not any(value in COUNTED_RELOCS for value in current_types):
            if args.section is not None:
                raise ValueError("selected section has no relocation counted "
                                 "by module_frob_arch_sections()")
            continue

        target_index = index
        target_name = name
        target = current
        relocation_types = current_types
        break

    if target_index < 0:
        if args.section is not None:
            raise ValueError(f"counted SHT_RELA section {args.section!r} "
                             "not found")
        raise ValueError("no SHT_RELA section contains a relocation counted "
                         "by module_frob_arch_sections()")

    counted = [value for value in relocation_types if value in COUNTED_RELOCS]
    if not 0 <= args.value <= 0xffffffff:
        raise ValueError("sh_info value is outside Elf32_Word")
    if args.value < e_shnum:
        raise ValueError("new sh_info is not out of range")

    info_offset = e_shoff + target_index * e_shentsize + 28
    old_value = struct.unpack_from(">I", original, info_offset)[0]
    mutated = bytearray(original)
    struct.pack_into(">I", mutated, info_offset, args.value)
    changed = [index for index, pair in enumerate(zip(original, mutated))
               if pair[0] != pair[1]]
    if (not changed or
            any(index < info_offset or index >= info_offset + 4
                for index in changed)):
        raise AssertionError("mutation changed bytes outside sh_info")

    args.output.write_bytes(mutated)
    print(json.dumps({
        "schema_version": 1,
        "input": str(args.input),
        "output": str(args.output),
        "input_sha256": sha256(original),
        "output_sha256": sha256(mutated),
        "section": target_name,
        "section_index": target_index,
        "section_count": e_shnum,
        "sh_info_file_offset": info_offset,
        "old_sh_info": old_value,
        "new_sh_info": args.value,
        "changed_byte_offsets": changed,
        "relocation_types": relocation_types,
        "counted_relocations": counted,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
