"""One benign s390 specification witness, with independent emulated execution.

This is not a kernel runner, an ACSL compiler, or a signed attestation service.
Only the frozen valid three-byte example is translated. Raw EVA outcomes remain
unchanged; the caller separately authenticates its current proof/model inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys

from . import analysis_policy, inputs, native_sensitivity as native, provenance, sources
from .sources import sha256


class S390Error(ValueError):
    """Missing, contradictory, or out-of-scope s390 runtime evidence."""


TARGET = "calibration.s390.byte-order.eva"
PROFILE = "s390x-gcc"
ENTRY = "fragma_byte_order_calibration"
HELPER = "__get_unaligned_be24"
THUNK = "__s390_indirect_jump_r14"
BACKEND = "arch/s390/lib/expoline.S"
LAYOUT = "fragma_s390_native_layout"
HARNESS = "s390/annotated/unaligned.acsl.c"
MAPPING = "config/s390-native-observations.json"
SUPPORT = "harness/s390_native_support.h"
OBSERVER = "harness/s390_native_observer.c"
KIND = "fragma-s390-spec-sensitivity"
REQUESTED_CPU = "z13"
CPU = "max"
QEMU_SHA256 = "45c6c089cb17ee97da7aca36a24abeecc3528cb036bee64f6c49fb2baa11ac44"
ARCHIVE_SHA256 = "f0585a9676a039f46607f185b3657c1e78c1ba4187595724cc567fcc1ae0d1b9"
ISOLATION = ["-ffunction-sections", "-fdata-sections", "-fno-inline", "-fno-ipa-cp", "-fno-ipa-sra"]
INSERTION = re.compile(r"/\* FRAGMA_S390_BEGIN_(\d+) \*/.*?/\* FRAGMA_S390_END_\1 \*/", re.S)
ENTRY_SOURCE = """void fragma_byte_order_calibration(void)
{
    u8 bytes[3] = {0x12, 0x34, 0x56};
    u32 value = __get_unaligned_be24(bytes);
}
"""
STATE = {"kind": "state", "value": 1193046, "bytes": [18, 52, 86]}
LAYOUT_STATE = {"kind": "native-layout", "bits": 64, "byte_order": "big",
                "word": 16909060, "bytes": [1, 2, 3, 4]}
PREDICATES = [{"name": "decoded_be24", "acsl": "value == 0x123456", "expected": True},
              {"name": "byte_order_REFUTED", "acsl": "value == 0x563412", "expected": False}]


def same(left, right):
    """Canonical JSON equality rejects bool/int/float confusion."""
    return native.digest(left) == native.digest(right)


def file_record(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": sha256(path)}


def inventory(paths):
    return [file_record(path) for path in sorted({Path(path).resolve() for path in paths})]


def artifacts(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path != directory / "receipt.json":
            if not path.resolve().is_relative_to(directory):
                raise S390Error("artifact escapes its isolated output directory")
            result[path.relative_to(directory).as_posix()] = sha256(path)
    return result


def read_json(path):
    result = native.strict_json(Path(path).read_text())
    if not isinstance(result, dict):
        raise S390Error("expected a JSON object: " + str(path))
    return result


def write_receipt(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def scope(root, target=None):
    manifest = read_json(root / "config/s390-targets.json")
    matches = [row for row in manifest["targets"] if row["id"] == TARGET]
    if len(matches) != 1 or (target is not None and not same(matches[0], target)):
        raise S390Error("target is not the current uniquely registered s390 calibration")
    target = matches[0]
    expected = {"id": TARGET, "profile": PROFILE, "source": "include/linux/unaligned.h",
                "harness": HARNESS, "entry": ENTRY, "functions": [HELPER], "analysis": "eva",
                "role": "calibration", "input_mode": "standalone",
                "analysis_pipeline": {"kind": "rte-eva"},
                "kernel_model_check": "s390/annotated/kernel-model-check.c",
                "required_properties": [row["name"] for row in PREDICATES],
                "expected_invalid": [PREDICATES[-1]["name"]]}
    if any(not same(target.get(key), value) for key, value in expected.items()) or target.get("driver"):
        raise S390Error("target exceeds the reviewed s390 harness/property scope")
    return manifest["kernel_revision"], target


def render_adapter(source, target, mapping):
    if (type(mapping.get("schema_version")) is not int or mapping["schema_version"] != 1 or
            mapping.get("target_id") != TARGET or mapping.get("profile") != PROFILE or
            mapping.get("harness") != HARNESS or mapping.get("entry") != ENTRY or
            mapping.get("harness_sha256") != hashlib.sha256(source.encode()).hexdigest() or
            not same(mapping.get("properties"), PREDICATES) or
            not same(mapping.get("state"), STATE) or not same(mapping.get("native_layout"), LAYOUT_STATE) or
            not isinstance(mapping.get("review"), str) or not mapping["review"].strip()):
        raise S390Error("source or reviewed observation mapping changed")
    if "FRAGMA_S390_" in source:
        raise S390Error("reserved instrumentation marker in original harness")
    if provenance.extract_function(source, ENTRY).tokens != provenance.extract_function(ENTRY_SOURCE, ENTRY).tokens:
        raise S390Error("entry is no longer the bounded valid three-byte example")
    assertions = list(native.ASSERTION.finditer(source))
    # Other helpers carry requires/ensures, but only this entry has assertions.
    if [match[1] for match in assertions] != [row["name"] for row in PREDICATES]:
        raise S390Error("harness assertion inventory differs")
    rows, insertions = [], []
    for index, (match, expected) in enumerate(zip(assertions, PREDICATES)):
        expression = native.normalized(match[2])
        if expression != expected["acsl"]:
            raise S390Error("named predicate changed")
        row = {**expected, "file": HARNESS, "line": source.count("\n", 0, match.start()) + 1,
               "function": ENTRY, "native_expression": expression,
               "translation": "same-side-effect-free-scalar-expression",
               "justification": "Exact scalar C predicate at the frozen valid-input ACSL assertion."}
        rows.append(row)
        call = f'fragma_s390_expect("{row["name"]}", !!({expression}), {int(row["expected"])});'
        if index == 1:
            call += "\n\tfragma_s390_state(bytes, value);"
        snippet = f"/* FRAGMA_S390_BEGIN_{index} */\n\t{call}\n\t/* FRAGMA_S390_END_{index} */"
        insertions.append((match.end(), snippet))
    generated = source
    for position, snippet in reversed(insertions):
        generated = generated[:position] + snippet + generated[position:]
    erased = INSERTION.sub("", generated)
    if erased != source or provenance.tokenize(erased) != provenance.tokenize(source):
        raise S390Error("instrumentation changed original harness tokens")
    return generated, rows


def validate_events(stdout, rows, returncode, stderr):
    if type(returncode) is not int or returncode != 0 or stderr:
        raise S390Error("witness lacks clean normal process completion")
    events = [native.strict_json(line) for line in stdout.splitlines()]
    expected = [{"kind": "begin", "entry": ENTRY}, LAYOUT_STATE]
    expected += [{"kind": "property", "name": row["name"],
                  "observed": row["expected"], "expected": row["expected"]} for row in rows]
    expected += [STATE, {"kind": "normal-return", "entry": ENTRY}]
    if not same(events, expected):
        raise S390Error("observed layout/state/properties/order/normal return differ")
    return [{**row, "observed": event["observed"], "reached": True}
            for row, event in zip(rows, events[2:4])]


def elf_identity(path, *, machine, byte_order, executable=True):
    """Inspect actual ELF64 headers; reject dynamic interpreters and truncation."""
    data = Path(path).read_bytes()
    encoding = 2 if byte_order == "big" else 1
    if len(data) < 64 or data[:7] != bytes([127, 69, 76, 70, 2, encoding, 1]):
        raise S390Error("wrong or malformed ELF64 byte order: " + str(path))
    fmt = ">" if encoding == 2 else "<"
    fields = struct.unpack_from(fmt + "HHIQQQIHHHHHH", data, 16)
    kind, actual_machine, version, entry, offset, shoff, flags, size, entsize, count, shsize, shcount, shstr = fields
    if (actual_machine != machine or kind not in ((2,) if executable else (2, 3)) or
            version != 1 or entry == 0 or size != 64 or entsize != 56 or count < 1 or
            offset < size or offset + count * entsize > len(data)):
        raise S390Error("ELF machine/type/program-header identity mismatch")
    names = ("type", "flags", "offset", "virtual", "physical", "filesz", "memsz", "align")
    segments = [dict(zip(names, struct.unpack_from(fmt + "IIQQQQQQ", data, offset + i * entsize)))
                for i in range(count)]
    if any(row["type"] == 3 for row in segments):
        raise S390Error("runtime must be statically linked, without PT_INTERP")
    if any(row["offset"] + row["filesz"] > len(data) or row["memsz"] < row["filesz"] for row in segments):
        raise S390Error("truncated or contradictory ELF segment")
    if sum(row["type"] == 1 and bool(row["flags"] & 1) and
           row["virtual"] <= entry < row["virtual"] + row["filesz"] for row in segments) != 1:
        raise S390Error("ELF entry is not uniquely mapped in executable file bytes")
    return {"class": 64, "byte_order": byte_order, "machine": machine,
            "type": kind, "entry": entry, "flags": flags, "interpreter": None,
            "version": version, "ident": data[:16].hex(), "phoff": offset,
            "ehsize": size, "phentsize": entsize, "phnum": count,
            "shoff": shoff, "shentsize": shsize, "shnum": shcount, "shstrndx": shstr,
            "segments": segments}


def check_readelf(text, identity):
    """Bind retained target readelf header/segment fields to actual ELF bytes."""
    ident = bytes.fromhex(identity["ident"])
    if identity["machine"] != 22 or ident[7:9] != bytes(2):
        raise S390Error("target readelf scope requires the current System-V s390 ABI")
    expected = [
        ("Magic", " ".join(f"{value:02x}" for value in ident)),
        ("Class", "ELF64"), ("Data", "2's complement, big endian"),
        ("Version", "1 (current)"), ("OS/ABI", "UNIX - System V"),
        ("ABI Version", "0"), ("Type", "EXEC (Executable file)"),
        ("Machine", "IBM S/390"), ("Version", hex(identity["version"])),
        ("Entry point address", hex(identity["entry"])),
        ("Start of program headers", str(identity["phoff"]) + " (bytes into file)"),
        ("Start of section headers", str(identity["shoff"]) + " (bytes into file)"),
        ("Flags", hex(identity["flags"])),
        ("Size of this header", str(identity["ehsize"]) + " (bytes)"),
        ("Size of program headers", str(identity["phentsize"]) + " (bytes)"),
        ("Number of program headers", str(identity["phnum"])),
        ("Size of section headers", str(identity["shentsize"]) + " (bytes)"),
        ("Number of section headers", str(identity["shnum"])),
        ("Section header string table index", str(identity["shstrndx"]))]
    pieces = text.split("\nProgram Headers:\n")
    if len(pieces) != 2 or not pieces[0].startswith("ELF Header:\n"):
        raise S390Error("missing or ambiguous readelf header")
    observed = []
    for line in pieces[0].splitlines()[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise S390Error("malformed readelf header field")
        key, value = line.strip().split(":", 1)
        observed.append((key, " ".join(value.split())))
    if observed != expected:
        raise S390Error("retained readelf header contradicts actual ELF bytes")
    segment_text = pieces[1].split("\n Section to Segment mapping:\n")
    if len(segment_text) != 2:
        raise S390Error("missing or ambiguous readelf segment list")
    lines = [line.strip() for line in segment_text[0].splitlines() if line.strip()]
    if not lines or lines.pop(0).split() != ["Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flg", "Align"]:
        raise S390Error("readelf segment columns differ")
    types = {"LOAD": 1, "NOTE": 4, "TLS": 7, "GNU_STACK": 0x6474e551, "GNU_RELRO": 0x6474e552}
    segments = []
    for line in lines:
        columns = line.split()
        if len(columns) < 7 or columns[0] not in types:
            raise S390Error("unsupported or malformed readelf segment")
        flag_text = "".join(columns[6:-1])
        if any(flag not in "RWE" for flag in flag_text) or len(set(flag_text)) != len(flag_text):
            raise S390Error("malformed readelf segment flags")
        segments.append({"type": types[columns[0]],
            **dict(zip(("offset", "virtual", "physical", "filesz", "memsz"),
                       [int(value, 16) for value in columns[1:6]])),
            "flags": sum({"R": 4, "W": 2, "E": 1}[flag] for flag in flag_text),
            "align": int(columns[-1], 16)})
    if not same(segments, identity["segments"]):
        raise S390Error("retained readelf segments contradict actual ELF bytes")


def elf_code(path, address, size):
    """Read a uniquely mapped byte range from an already checked s390 ELF."""
    data = Path(path).read_bytes()
    phoff = struct.unpack_from(">Q", data, 32)[0]
    entsize, count = struct.unpack_from(">HH", data, 54)
    found = []
    for index in range(count):
        kind, flags, offset, virtual, _, filesz, _, _ = struct.unpack_from(">IIQQQQQQ", data, phoff + index * entsize)
        if kind == 1 and flags & 1 and virtual <= address and address + size <= virtual + filesz:
            start = offset + address - virtual
            if start + size > len(data):
                raise S390Error("truncated executable code mapping")
            found.append(data[start:start + size])
    if len(found) != 1:
        raise S390Error("helper is not uniquely mapped in executable ELF bytes")
    return found[0]


def runtime_identity(root):
    prefix = root / "toolchain/runtime-prefix"
    lock_path, setup_path = root / "toolchain/runtime-lock.json", root / "toolchain/setup_runtime.py"
    receipt_path = prefix / "fragma-runtime.json"
    binary = prefix / "usr/bin/qemu-s390x"
    lock, receipt = read_json(lock_path), read_json(receipt_path)
    host = {"machine": platform.machine(), "system": platform.system()}
    if (host != {"machine": "x86_64", "system": "Linux"} or not same(lock.get("host"), host) or
            type(lock.get("schema_version")) is not int or lock["schema_version"] != 1 or
            lock.get("artifact", {}).get("sha256") != ARCHIVE_SHA256 or
            not same(lock.get("probe"), {"binary": "usr/bin/qemu-s390x", "version_prefix": "qemu-s390x version 10.2.1"}) or
            type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1 or
            (receipt.get("mode"), receipt.get("status"), receipt.get("prefix")) != ("apply", "installed", str(prefix)) or
            receipt.get("lock_sha256") != sha256(lock_path) or not same(receipt.get("lock"), lock) or
            receipt.get("setup_sha256") != sha256(setup_path) or
            receipt.get("files", {}).get("usr/bin/qemu-s390x", {}).get("sha256") != QEMU_SHA256 or
            sha256(binary) != QEMU_SHA256):
        raise S390Error("optional emulator installation differs from reviewed pinned runtime")
    return {"method": "qemu-user", "cpu": CPU, "requested_cpu": REQUESTED_CPU,
            "compiler_cpu": "z13", "binary": file_record(binary),
            "install_receipt": file_record(receipt_path), "lock": file_record(lock_path),
            "setup": file_record(setup_path), "archive_sha256": ARCHIVE_SHA256,
            "host": {**host, "release": platform.release(), "byte_order": sys.byteorder},
            "elf": elf_identity(binary, machine=62, byte_order="little", executable=False),
            "scope": "One static integer-only s390 witness compiled for z13, executed using QEMU max because its exact z13 model is unavailable. Emulator/host/target libc trusted; no full z13 or complete kernel execution claim."}


def observer_flags(model):
    flags = [flag for flag in model["compiler"]["flags"]
             if flag not in ("-ffreestanding", "-mpacked-stack", "-mbackchain")]
    return [*flags, "-mno-packed-stack", "-mno-backchain", "-O0", "-fno-builtin",
            "-fno-pie", "-fno-PIE", "-fno-stack-protector"]


def deviations(model):
    return {"kernel_added_flags": ISOLATION, "observer_flags": observer_flags(model),
            "optimization": "Original optimization/ABI/arithmetic flags retained; explicit isolation disables inlining/IPA constant propagation and section collection drops unrelated functions.",
            "observer_abi": "Hosted observer uses ordinary unpacked/no-backchain s390 stack frames; only integer/pointer arguments cross to the kernel-flag object. No floating-point ABI operation is exercised.",
            "link": "Static target CRT/libc from the installed cross toolchain; complete archive hashes and link map retained.",
            "return_backend": "Pinned unmodified arch/s390/lib/expoline.S is separately trusted native compiler/backend support. Mitigation flags stay enabled; no assembly theorem is claimed. It uses the real kernel include/config/flag context plus __ASSEMBLY__.",
            "claims": "Two reached predicates on one valid input and a separate volatile big-endian layout check; no universal theorem or kernel-defect claim."}


def command_plan(root, build, model, directory, runtime):
    compiler = build["compiler"]
    kernel_flags = inputs.command_without_outputs(inputs.compile_entry(build, "lib/string.c"))
    tools = {}
    for name in ("nm", "readelf", "objdump"):
        tools[name] = shutil.which("s390x-linux-gnu-" + name, path=os.defpath)
        if not tools[name]:
            raise S390Error("missing target inspection tool: " + name)
    plan = {"locate-" + name: ([compiler, "-print-prog-name=" + name], directory)
            for name in ("cc1", "collect2", "as", "ld")}
    qemu = runtime["binary"]["path"]
    plan.update({"emulator-version": ([qemu, "--version"], directory),
                 "emulator-cpus": ([qemu, "-cpu", "help"], directory)})
    plan["compile-model"] = ([*kernel_flags, "-Werror", "-MD", "-MF", str(directory / "model-headers.d"),
        "-MT", "fragma", "-c", str(root / "s390/annotated/kernel-model-check.c"),
        "-o", str(directory / "kernel-model.o")], Path(build["path"]))
    plan["compile-backend"] = ([*kernel_flags, "-D__ASSEMBLY__", "-MD", "-MF", str(directory / "backend-headers.d"),
        "-MT", "fragma", "-c", str(Path(build["source"]) / BACKEND),
        "-o", str(directory / "kernel-expoline.o")], Path(build["path"]))
    plan["compile-kernel"] = ([*kernel_flags, *ISOLATION, "-I", str(root / "s390/annotated"),
        "-include", str(root / SUPPORT), "-MD", "-MF", str(directory / "kernel-headers.d"),
        "-MT", "fragma", "-c", str(directory / "calibration.native.c"),
        "-o", str(directory / "kernel-calibration.o")], Path(build["path"]))
    plan["compile-observer"] = ([compiler, *observer_flags(model), "-MD", "-MF", str(directory / "observer-headers.d"),
        "-MT", "fragma", "-c", str(root / OBSERVER), "-o", str(directory / "observer.o")], directory)
    binary = directory / "s390-witness"
    plan["link"] = ([compiler, "-m64", "-march=z13", "-static", "-no-pie", "-Wl,--gc-sections",
        "-Wl,-Map=" + str(directory / "link.map"), "-Wl,--trace-symbol=" + ENTRY, "-Wl,--trace-symbol=" + THUNK,
        str(directory / "observer.o"), str(directory / "kernel-calibration.o"),
        str(directory / "kernel-expoline.o"), "-o", str(binary)], directory)
    plan["defined-symbols"] = ([tools["nm"], "--defined-only", "--print-size", "--format=posix", str(binary)], directory)
    plan["elf-header"] = ([tools["readelf"], "--file-header", "--program-headers", "--wide", str(binary)], directory)
    plan["disassemble-entry"] = ([tools["objdump"], "-d", "--disassemble=" + ENTRY, str(binary)], directory)
    plan["disassemble-helper"] = ([tools["objdump"], "-d", "--disassemble=" + HELPER, str(binary)], directory)
    plan["requested-cpu-check"] = ([qemu, "-cpu", REQUESTED_CPU, str(binary)], directory)
    plan["case-0"] = ([qemu, "-cpu", CPU, "-d", "in_asm,exec,nochain", "-D", str(directory / "qemu.trace"), str(binary)], directory)
    return plan


def expected_returncode(name):
    # Pinned QEMU 10.2.1 prints the CPU list and exits 1 with empty stderr.
    # This is an informational probe, never the witness execution outcome.
    return 1 if name in ("emulator-cpus", "requested-cpu-check") else 0


def check_model(model, build, revision):
    analysis_policy.model_identity(model["analysis"])
    if ((model.get("profile_id"), model.get("status"), model.get("level"), model.get("kernel_revision")) !=
            (PROFILE, "passed", "L1", revision) or
            model["compiler"]["target"] != "s390x-linux-gnu" or
            model["compiler"]["sha256"] != sha256(Path(build["compiler"])) or
            model["build"]["build_receipt_sha256"] != build["receipt_sha256"] or
            sha256(Path(model["machdep"]["path"])) != model["machdep"]["sha256"] or
            model["machdep"]["checked_fields"].get("little_endian") is not False):
        raise S390Error("a matching configured s390 big-endian L1 model is required")


def trace_evidence(directory):
    text = (directory / "defined-symbols.stdout").read_text()
    symbols = {}
    for name, kind in ((HELPER, "t"), (ENTRY, "T"), (LAYOUT, "T"), (THUNK, "T")):
        matches = re.findall(r"^" + re.escape(name) + r" " + kind + r" ([0-9a-fA-F]+) ([0-9a-fA-F]+)$", text, re.M)
        if len(matches) != 1 or int(matches[0][1], 16) < 1:
            raise S390Error("missing or ambiguous retained runtime symbol: " + name)
        symbols[name] = {"address": int(matches[0][0], 16), "size": int(matches[0][1], 16), "type": kind}
    trace = (directory / "qemu.trace").read_text()
    # QEMU's exec log identifies guest TB addresses as the second slash field.
    executed = {int(value, 16) for value in re.findall(r"(?m)^Trace \d+: [^\n]*\[[0-9a-fA-F]+/([0-9a-fA-F]+)/", trace)}
    if not executed or any(row["address"] not in executed for row in symbols.values()):
        raise S390Error("execution trace does not reach entry/helper/native-layout symbols")
    disassembly = (directory / "disassemble-entry.stdout").read_text()
    calls = re.findall(r"\bbrasl\s+%r14,([0-9a-fA-F]+)\s+<" + re.escape(HELPER) + r">", disassembly)
    if len(calls) != 1 or int(calls[0], 16) != symbols[HELPER]["address"]:
        raise S390Error("entry disassembly lacks the direct retained helper call")
    if str(directory / "kernel-calibration.o") + ": definition of " + ENTRY not in (directory / "link.stderr").read_text():
        raise S390Error("entry did not resolve from the kernel-flag object")
    if str(directory / "kernel-expoline.o") + ": definition of " + THUNK not in (directory / "link.stderr").read_text():
        raise S390Error("return thunk did not resolve from the original pinned backend object")
    helper_disassembly = (directory / "disassemble-helper.stdout").read_text()
    instructions = []
    for address, raw, mnemonic, operands in re.findall(
            r"(?m)^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)([a-z][a-z0-9]*)[ \t]+(.*)$", helper_disassembly):
        instructions.append({"address": int(address, 16), "bytes": "".join(raw.split()),
                             "mnemonic": mnemonic, "operands": operands.strip()})
    next_address = symbols[HELPER]["address"]
    for instruction in instructions:
        if instruction["address"] != next_address:
            raise S390Error("helper disassembly is not contiguous")
        next_address += len(bytes.fromhex(instruction["bytes"]))
    if not instructions or next_address != symbols[HELPER]["address"] + symbols[HELPER]["size"]:
        raise S390Error("helper disassembly does not cover its exact symbol extent")
    code = b"".join(bytes.fromhex(row["bytes"]) for row in instructions)
    if code != elf_code(directory / "s390-witness", symbols[HELPER]["address"], symbols[HELPER]["size"]):
        raise S390Error("helper disassembly differs from executable bytes")
    blocks = re.findall(r"(?ms)^IN: " + re.escape(HELPER) +
                        r"\n(.*?)^Trace \d+: [^\n]*\[[0-9a-fA-F]+/([0-9a-fA-F]+)/", trace)
    if len(blocks) != 1 or int(blocks[0][1], 16) != symbols[HELPER]["address"]:
        raise S390Error("helper execution block is missing or ambiguous")
    block_bytes = "".join(re.findall(r"(?m)^OBJD-T: ([0-9a-fA-F]+)$", blocks[0][0]))
    if bytes.fromhex(block_bytes) != code:
        raise S390Error("executed helper block bytes differ from the retained ELF/disassembly")
    return {"symbols": symbols, "helper_call_confirmed": True, "executed_symbol_entries": list(symbols),
            "trace_sha256": sha256(directory / "qemu.trace"), "disassembly_sha256": sha256(directory / "disassemble-entry.stdout"),
            "helper_disassembly_sha256": sha256(directory / "disassemble-helper.stdout"),
            "executed_helper_bytes_sha256": hashlib.sha256(code).hexdigest(),
            "helper_instructions": instructions}


def facts(root, kernel, directory, target, revision, model, build, profile_path, commands):
    """Reconstruct identities from current inputs and retained raw artifacts."""
    mapping = read_json(root / MAPPING)
    if mapping.get("kernel_revision") != revision:
        raise S390Error("mapping revision differs")
    generated, rows = render_adapter((root / HARNESS).read_text(), target, mapping)
    if (directory / "calibration.native.c").read_text() != generated:
        raise S390Error("adapter no longer regenerates from the original harness")
    check_model(model, build, revision)
    runtime = runtime_identity(root)
    plan = command_plan(root, build, model, directory, runtime)
    if (not isinstance(commands, list) or not all(isinstance(row, dict) for row in commands) or
            [row.get("name") for row in commands] != list(plan)):
        raise S390Error("command inventory is missing, duplicated, or reordered")
    for record, (name, (argv, cwd)) in zip(commands, plan.items()):
        if (not same(record.get("argv"), argv) or record.get("cwd") != str(cwd) or
                type(record.get("returncode")) is not int or record["returncode"] != expected_returncode(name) or
                record.get("timed_out") is not False or type(record.get("seconds")) not in (int, float) or
                record["seconds"] < 0):
            raise S390Error("command contradicts its reconstructed plan: " + name)
        for field in ("stdout", "stderr"):
            if not same(record.get(field), file_record(directory / (name + "." + field))):
                raise S390Error("command output identity differs: " + name)
        if (record.get("log") != str(directory / (name + ".stderr")) or
                record.get("log_sha256") != sha256(directory / (name + ".stderr"))):
            raise S390Error("command stderr metadata differs: " + name)
    if not (directory / "emulator-version.stdout").read_text().startswith("qemu-s390x version 10.2.1"):
        raise S390Error("emulator version probe differs")
    if not re.search(r"(?m)^\s+z13\s+IBM z13 GA1", (directory / "emulator-cpus.stdout").read_text()):
        raise S390Error("emulator did not advertise the selected z13 CPU")
    if not re.search(r"(?m)^\s+max\s+Enables all features supported", (directory / "emulator-cpus.stdout").read_text()):
        raise S390Error("emulator did not advertise the executed max CPU model")
    if any((directory / (name + ".stderr")).read_text() for name in ("emulator-version", "emulator-cpus")):
        raise S390Error("emulator identification probe emitted unexpected errors")
    unavailable = (directory / "requested-cpu-check.stderr").read_text()
    prefix = "qemu-s390x: Some features requested in the CPU model are not available in the current configuration: "
    lines = unavailable.splitlines()
    if ((directory / "requested-cpu-check.stdout").read_text() or len(lines) != 2 or
            not lines[0].startswith(prefix) or not lines[0][len(prefix):].strip() or
            lines[1] != "Consider a different accelerator, QEMU, or kernel version"):
        raise S390Error("requested-z13 availability evidence differs; review CPU selection")
    cpu_gap = {"requested": REQUESTED_CPU, "executed": CPU,
               "requested_model_started_guest": False, "missing_features": lines[0][len(prefix):].split(),
               "stderr": file_record(directory / "requested-cpu-check.stderr"),
               "scope": "The exact z13 model was not emulated; only this observed integer-only run uses max."}
    gate = provenance.check_target(target, kernel, revision, root)
    if gate.get("passed") is not True:
        raise S390Error("current original kernel-body source gate failed")
    kernel_inputs = inputs.input_receipts(root, kernel, revision, build,
        inputs.dependency_paths(directory / "kernel-headers.d", Path(build["path"])))
    model_inputs = inputs.input_receipts(root, kernel, revision, build,
        inputs.dependency_paths(directory / "model-headers.d", Path(build["path"])))
    backend_inputs = inputs.input_receipts(root, kernel, revision, build,
        inputs.dependency_paths(directory / "backend-headers.d", Path(build["path"])))
    if not any(row.get("origin") == "kernel" and row.get("path") == BACKEND for row in backend_inputs):
        raise S390Error("native backend source is absent from pinned kernel dependencies")
    hosted_inputs = inventory(inputs.dependency_paths(directory / "observer-headers.d", directory))
    link_paths = re.findall(r"(?m)^LOAD (/[^\n]+)$", (directory / "link.map").read_text())
    if not link_paths or not any(path.endswith("/libc.a") for path in link_paths):
        raise S390Error("static target CRT/libc link dependency inventory is empty")
    tool_paths = [Path(sys.executable)]
    for name in ("cc1", "collect2", "as", "ld"):
        value = (directory / ("locate-" + name + ".stdout")).read_text().strip()
        filename = Path(value)
        if not filename.is_absolute():
            resolved = shutil.which(value, path=os.defpath)
            if not resolved:
                raise S390Error("compiler component no longer resolves: " + name)
            filename = Path(resolved)
        tool_paths.append(filename)
    tool_paths += [Path(plan[name][0][0]) for name in ("defined-symbols", "elf-header", "disassemble-entry")]
    bindings = inventory([root / "config/s390-targets.json", root / MAPPING, root / HARNESS,
        root / SUPPORT, root / OBSERVER, root / target["kernel_model_check"], Path(__file__),
        Path(analysis_policy.__file__), Path(inputs.__file__), Path(provenance.__file__),
        Path(sources.__file__), Path(native.__file__),
        Path(build["compiler"]), Path(build["path"]) / "fragma-build.json", profile_path,
        Path(model["machdep"]["path"]), *[Path(runtime[key]["path"]) for key in ("binary", "install_receipt", "lock", "setup")]])
    observations = validate_events((directory / "case-0.stdout").read_text(), rows,
                                  commands[-1]["returncode"], (directory / "case-0.stderr").read_text())
    elf = elf_identity(directory / "s390-witness", machine=22, byte_order="big")
    check_readelf((directory / "elf-header.stdout").read_text(), elf)
    return {"bindings": bindings, "analysis_policy": native.analysis_binding(model, [target]),
            "kernel_inputs": kernel_inputs, "model_inputs": model_inputs,
            "backend_inputs": backend_inputs,
            "hosted_inputs": hosted_inputs, "link_inputs": inventory(link_paths), "tool_inputs": inventory(tool_paths),
            "runtime": runtime, "cpu_gap": cpu_gap,
            "elf": elf,
            "source_gate": gate, "properties": observations, "state": STATE, "native_layout": LAYOUT_STATE,
            "trace_evidence": trace_evidence(directory), "native_deviations": deviations(model),
            "adapter": file_record(directory / "calibration.native.c"), "binary": file_record(directory / "s390-witness"),
            "profile_receipt": file_record(profile_path), "original_compile_command": inputs.compile_entry(build, "lib/string.c"),
            "harness_tokens_preserved": True, "normal_return": True, "python_version": sys.version}


def tracked_facts(observed):
    paths = [row for name in ("bindings", "hosted_inputs", "link_inputs", "tool_inputs") for row in observed[name]]
    paths += [{"path": row["absolute_path"], "sha256": row["sha256"]}
              for name in ("kernel_inputs", "model_inputs", "backend_inputs") for row in observed[name]]
    result = {}
    for row in paths:
        if row["path"] in result and result[row["path"]] != row["sha256"]:
            raise S390Error("conflicting input hash observations")
        result[row["path"]] = row["sha256"]
    return result


def immutable_gate(gate):
    """Ignore only explicitly non-authoritative, mutable checkout observations."""
    if not isinstance(gate, dict) or not isinstance(gate.get("source"), dict):
        raise S390Error("missing source gate identity")
    return {**gate, "source": {key: value for key, value in gate["source"].items()
                              if key not in ("checkout_head", "checkout_status", "checkout_sha256",
                                             "checkout_matches_source")}}


def run_native(root, kernel, output, profile_path=None):
    root, kernel, output = Path(root).resolve(), Path(kernel).resolve(), Path(output).resolve()
    parent = root / "build/s390-sensitivity"
    if not output.is_relative_to(parent) or output == parent or output.exists():
        raise S390Error("output must be a new child of build/s390-sensitivity; no overwrites")
    output.mkdir(parents=True)
    evidence = {"schema_version": 1, "kind": KIND, "status": "running", "corroborated": False,
                "verified_kernel_functions": [], "commands": [], "issues": []}
    write_receipt(output / "receipt.json", evidence)
    try:
        revision, target = scope(root)
        profile_path = Path(profile_path or root / "build/profile-checks/s390x-gcc-configured/profile.json").resolve()
        model = read_json(profile_path)
        build = inputs.load_build(root, PROFILE, revision)
        check_model(model, build, revision)
        runtime = runtime_identity(root)
        mapping = read_json(root / MAPPING)
        if mapping.get("kernel_revision") != revision:
            raise S390Error("mapping source revision differs")
        generated, _ = render_adapter((root / HARNESS).read_text(), target, mapping)
        source_gate = provenance.check_target(target, kernel, revision, root)
        if source_gate.get("passed") is not True:
            raise S390Error("source gate failed before compilation")
        (output / "calibration.native.c").write_text(generated)
        evidence.update(kernel_revision=revision, profile_id=PROFILE, target_id=TARGET,
                        target_sha256=native.digest(target), entry=ENTRY, model=model, build=build,
                        analysis_policy=native.analysis_binding(model, [target]),
                        source_gate_before_compile=source_gate)
        initial_paths = [root / "config/s390-targets.json", root / MAPPING, root / HARNESS,
                         root / SUPPORT, root / OBSERVER, root / target["kernel_model_check"],
                         Path(__file__), Path(analysis_policy.__file__), Path(inputs.__file__),
                         Path(provenance.__file__), Path(sources.__file__),
                         Path(native.__file__), profile_path, Path(model["machdep"]["path"]),
                         Path(build["compiler"]), Path(build["source"]) / BACKEND,
                         *[Path(build["path"]) / name for name in build["files"]],
                         *[Path(runtime[key]["path"]) for key in ("binary", "install_receipt", "lock", "setup")]]
        initial = inventory(initial_paths)
        env = {"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(output)}
        for name, (argv, cwd) in command_plan(root, build, model, output, runtime).items():
            stdout, stderr = output / (name + ".stdout"), output / (name + ".stderr")
            record = inputs.run_recorded(argv, cwd=cwd, env=env, log=stderr,
                                        stdout_file=stdout, timeout=30 if name == "case-0" else 120)
            record.update(name=name, stdout=file_record(stdout), stderr=file_record(stderr))
            evidence["commands"].append(record)
            if record["returncode"] != expected_returncode(name):
                raise S390Error(name + " failed: " + str(stderr))
        observed = facts(root, kernel, output, target, revision, model, build, profile_path, evidence["commands"])
        evidence.update(observed)
        tracked = {**tracked_facts(observed), **{row["path"]: row["sha256"] for row in initial}}
        changed = [name for name, checksum in tracked.items() if not Path(name).is_file() or sha256(Path(name)) != checksum]
        if changed:
            evidence["changed_inputs"] = changed
            raise S390Error("an input changed during native corroboration")
        evidence.update(status="native-corroborated", corroborated=True, changed_inputs=[])
    except (OSError, KeyError, TypeError, ValueError, struct.error) as exc:
        evidence.update(status="incomplete", corroborated=False)
        evidence["issues"].append(str(exc))
    evidence["artifact_hashes"] = artifacts(output)
    write_receipt(output / "receipt.json", evidence)
    return evidence


def validate_native_receipt(root, kernel, target, revision, freshmodel, build, receipt_path):
    """Read-only validation; returns only this exact calibration's envelope.

    No process is executed. Source-gate git reads and current dependency/hash
    checks are permitted. This validates local records, not a signed attestation.
    The caller must recheck returned tracked_files before final acceptance.
    """
    root, kernel, path = Path(root).resolve(), Path(kernel).resolve(), Path(receipt_path).resolve()
    if not path.is_relative_to(root / "build/s390-sensitivity") or path.name != "receipt.json":
        raise S390Error("receipt must be an explicit local s390 calibration receipt")
    directory = path.parent
    try:
        current_revision, _ = scope(root, target)
        evidence = read_json(path)
        expected = {"schema_version": 1, "kind": KIND, "status": "native-corroborated", "corroborated": True,
                    "kernel_revision": revision, "profile_id": PROFILE, "target_id": TARGET,
                    "target_sha256": native.digest(target), "entry": ENTRY, "issues": [],
                    "changed_inputs": [], "verified_kernel_functions": []}
        if current_revision != revision or any(not same(evidence.get(key), value) for key, value in expected.items()):
            raise S390Error("receipt status/target/source identity is incomplete or contradictory")
        current_build = inputs.load_build(root, PROFILE, revision)
        if not same(current_build, build) or not same(evidence["build"], build):
            raise S390Error("build receipt changed or differs from the current caller build")
        if not same(native.model_identity(evidence["model"]), native.model_identity(freshmodel)):
            raise S390Error("fresh configured model differs from the native model")
        if not same(evidence.get("analysis_policy"), native.analysis_binding(freshmodel, [target])):
            raise S390Error("native receipt has missing or changed semantic/pipeline binding")
        check_model(freshmodel, build, revision)
        artifact_hashes = artifacts(directory)
        if not artifact_hashes or not same(evidence.get("artifact_hashes"), artifact_hashes):
            raise S390Error("artifact inventory changed or omitted files")
        profile_path = Path(evidence["profile_receipt"]["path"])
        if not profile_path.is_absolute() or not same(read_json(profile_path), evidence["model"]):
            raise S390Error("bound model receipt metadata differs")
        observed = facts(root, kernel, directory, target, revision, evidence["model"], build,
                         profile_path, evidence["commands"])
        for name, value in observed.items():
            if name == "source_gate":
                if not same(immutable_gate(evidence.get(name)), immutable_gate(value)):
                    raise S390Error("source gate metadata differs")
            elif not same(evidence.get(name), value):
                raise S390Error("current reconstructed evidence differs: " + name)
        before, now = evidence.get("source_gate_before_compile", {}), observed["source_gate"]
        if before.get("passed") is not True or not same(immutable_gate(before), immutable_gate(now)):
            raise S390Error("precompile source gate is missing or stale")
        tracked = tracked_facts(observed)
        tracked.update({str((directory / filename).resolve()): checksum for filename, checksum in artifact_hashes.items()})
        tracked[str(path)] = sha256(path)
        return {"status": "passed", "kind": "native-specification-calibration", "target_id": TARGET,
                "profile": PROFILE, "source": target["source"], "entry": ENTRY, "kernel_revision": revision,
                "source_root": str(root), "target_sha256": native.digest(target), "receipt": file_record(path),
                "properties": observed["properties"], "analysis_policy": observed["analysis_policy"],
                "runtime": {**observed["runtime"], "cpu_gap": observed["cpu_gap"],
                            "trace_evidence": observed["trace_evidence"], "native_layout": observed["native_layout"]},
                "tracked_files": [{"absolute_path": name, "sha256": checksum} for name, checksum in sorted(tracked.items())]}
    except (OSError, KeyError, TypeError, ValueError, struct.error) as exc:
        if isinstance(exc, S390Error):
            raise
        raise S390Error("cannot validate s390 witness: " + str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--kernel-tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile-receipt", type=Path)
    args = parser.parse_args(argv)
    result = run_native(args.root, args.kernel_tree, args.output, args.profile_receipt)
    print(json.dumps({key: result[key] for key in ("status", "corroborated", "issues")}, indent=2))
    return 0 if result["corroborated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
