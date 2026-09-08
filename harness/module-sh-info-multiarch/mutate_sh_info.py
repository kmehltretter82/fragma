#!/usr/bin/env python3
"""Change only the sh_info field of one ELF relocation section."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


SHT_RELA = 4
SHT_REL = 9
SHF_EXECINSTR = 0x4


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
    parser.add_argument(
        "--section",
        help="relocation section to mutate; default: first section whose "
             "target is executable",
    )
    parser.add_argument(
        "--value", type=lambda value: int(value, 0), default=0x10000000
    )
    args = parser.parse_args()

    original = args.input.read_bytes()
    if original[:4] != b"\x7fELF":
        raise ValueError("input is not an ELF object")

    elf_class = original[4]
    elf_data = original[5]
    if elf_class not in (1, 2):
        raise ValueError(f"unsupported ELF class {elf_class}")
    if elf_data not in (1, 2):
        raise ValueError(f"unsupported ELF data encoding {elf_data}")

    endian = "<" if elf_data == 1 else ">"
    byte_order = "little" if elf_data == 1 else "big"
    if elf_class == 1:
        elf_bits = 32
        e_shoff = struct.unpack_from(endian + "I", original, 32)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            endian + "HHH", original, 46
        )
        shdr_format = endian + "IIIIIIIIII"
        expected_shentsize = 40
        sh_info_offset = 28
    else:
        elf_bits = 64
        e_shoff = struct.unpack_from(endian + "Q", original, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            endian + "HHH", original, 58
        )
        shdr_format = endian + "IIQQQQIIQQ"
        expected_shentsize = 64
        sh_info_offset = 44

    if e_shentsize != expected_shentsize:
        raise ValueError(f"unexpected section-header size {e_shentsize}")
    if not 0 < e_shstrndx < e_shnum:
        raise ValueError("invalid section-name string table index")

    def section(index: int) -> tuple[int, ...]:
        offset = e_shoff + index * e_shentsize
        return struct.unpack_from(shdr_format, original, offset)

    shstr = section(e_shstrndx)
    names = original[shstr[4]:shstr[4] + shstr[5]]
    candidates = []
    for index in range(1, e_shnum):
        current = section(index)
        name = c_string(names, current[0])
        if args.section is not None and name != args.section:
            continue
        if current[1] not in (SHT_REL, SHT_RELA):
            continue
        target_index = current[7]
        if not 0 < target_index < e_shnum:
            continue
        target = section(target_index)
        if not target[2] & SHF_EXECINSTR:
            continue
        candidates.append((index, name, current, target_index, target))

    if not candidates:
        detail = f" named {args.section!r}" if args.section else ""
        raise ValueError(
            f"no relocation section{detail} targets an executable section"
        )

    preferred_names = (
        ".rela.fragma_probe.text",
        ".rel.fragma_probe.text",
        ".rela.text",
        ".rel.text",
    )
    preferred = sorted(
        (entry for entry in candidates if entry[1] in preferred_names),
        key=lambda entry: preferred_names.index(entry[1]),
    )
    index, name, current, target_index, target = (
        preferred[0] if preferred else candidates[0]
    )
    target_name = c_string(names, target[0])

    if not 0 <= args.value <= 0xffffffff:
        raise ValueError("sh_info value is outside Elf32_Word")
    if args.value < e_shnum:
        raise ValueError("new sh_info is not out of range")

    info_offset = e_shoff + index * e_shentsize + sh_info_offset
    old_value = struct.unpack_from(endian + "I", original, info_offset)[0]
    mutated = bytearray(original)
    struct.pack_into(endian + "I", mutated, info_offset, args.value)
    changed = [position for position, pair in enumerate(zip(original, mutated))
               if pair[0] != pair[1]]
    if (not changed or
            any(position < info_offset or position >= info_offset + 4
                for position in changed)):
        raise AssertionError("mutation changed bytes outside sh_info")

    args.output.write_bytes(mutated)
    print(json.dumps({
        "schema_version": 1,
        "input": str(args.input),
        "output": str(args.output),
        "input_sha256": sha256(original),
        "output_sha256": sha256(mutated),
        "elf_bits": elf_bits,
        "byte_order": byte_order,
        "section": name,
        "section_index": index,
        "section_count": e_shnum,
        "section_type": current[1],
        "target_section": target_name,
        "target_section_index": target_index,
        "target_section_flags": target[2],
        "sh_info_file_offset": info_offset,
        "old_sh_info": old_value,
        "new_sh_info": args.value,
        "changed_byte_offsets": changed,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
