"""Strict, unregistered Hexagon machine-generator adapter.

Uses the hash-pinned Frama-C 33 probes, with three retained source changes.
Probe selection and diagnostic extraction derive from CEA's LGPL-2.1
make_machdep.py. Original installed sources and earlier evidence are untouched.
This produces observations and a candidate, never L1/profile acceptance. In
particular, compile exit status is not evidence that object alignment is honored.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time

from . import elf, hexagon_layout, toolchain

HELPER_SHA256 = "889d3ca26ea964aebcc2e9a1c2fe5ccab3f064b29fd8c69f7c90678d7b2dd6bf"
SCHEMA_SHA256 = "ce8de93d93cc3bfbd8ad843bd6b44dd3f89ac5bd981f48b93433006b1fa34400"
PROBES_SHA256 = "05a00f449556eea8d8865ee2c550b13eb6c5628410b6c3e037ddb2f211e3e1f3"
SETUP_SHA256 = "d534dc306e1ab1edc611c9890b1f6eb68ffe32205b2e90d187b5ae145c41eb50"
COMPILER = "/usr/bin/clang-21"
COMPILER_SHA256 = "412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932"
RESOURCE_SHA256 = "deb75785057f7fa7d497414c903e9c03a6d7005c84999204b21be6001e66b24c"
ARCH_FLAGS = ["--target=hexagon-linux-musl", "-mv68", "-G0", "-fno-short-enums",
              "-mlong-calls", "-ffixed-r19", "-DTHREADINFO_REG=r19", "-D__linux__",
              "-std=gnu11", "-funsigned-char", "-fshort-wchar",
              "-fno-strict-overflow", "-fno-strict-aliasing", "-ffreestanding"]
GNU_ALIGNOF_FIELDS = tuple("gcc_alignof_" + name for name in (
    "short", "int", "long", "longlong", "ptr", "float", "double", "longdouble",
    "void", "fun", "aligned", "max_align_t"))
MACRO_FIELDS = {
    "weof": {"weof"}, "wordsize": {"wordsize"}, "posix_c_source": {"posix_c_source"},
    "limits_macros": {"path_max", "tty_name_max", "host_name_max"},
    "stdio_macros": {"bufsiz", "eof", "fopen_max", "filename_max", "l_ctermid", "l_tmpnam", "tmp_max"},
    "stdlib_macros": {"rand_max", "mb_cur_max"}, "nsig": {"nsig"},
}


class AdapterError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AdapterError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, *, limit=16 * 1024 * 1024):
    path = Path(path)
    require(not path.is_symlink(), "Symlinked input: " + str(path))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                "Input is not a bounded regular file: " + str(path))
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(len(data) <= limit and identity(before) == identity(after) == identity(path.lstat()),
            "Input changed while reading: " + str(path))
    return data


def save(path, data):
    with Path(path).open("xb") as stream:
        stream.write(data)


def save_json(path, value):
    save(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def file_record(path):
    path = Path(path)
    # Initialized alignment probes have real padding up to 256 MiB. Hash them
    # incrementally; do not truncate objects or relax the ordinary source cap.
    if path.suffix != ".o":
        return {"absolute_path": str(path), "sha256": digest(read(path))}
    require(not path.is_symlink(), "Symlinked object")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 512 * 1024 * 1024, "Unbounded object")
        hasher, total = hashlib.sha256(), 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            require(total <= 512 * 1024 * 1024, "Object grew beyond bound")
            hasher.update(block)
        after = os.fstat(stream.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(before) == identity(after) == identity(path.lstat()), "Object changed while hashing")
    return {"absolute_path": str(path), "sha256": hasher.hexdigest()}


def adapt_probe(name, source):
    """Exact reviewed deltas; no replacement types, macros, or measured values."""
    replacements = {
        "sanity_check.c": ("int main () { }", "int main(void) { return 0; }"),
        "wordsize.c": ("const int wordsize_is = __WORDSIZE;\n#endif",
                       "const int wordsize_is = __WORDSIZE;\n#else\nconst int fragma_wordsize_undefined = 1;\n#endif"),
        "max_align_t.c": ("struct __machdep_max_align_t {int __max_align; } __attribute__ ((aligned (16)))",
                          "struct __machdep_max_align_t_16 {int __max_align; } __attribute__ ((aligned (16)))"),
    }
    if name not in replacements:
        return source
    original, replacement = replacements[name]
    require(source.count(original) == 1, "Reviewed probe anchor changed: " + name)
    return source.replace(original, replacement)


def primary_errors(stderr):
    require(not re.search(r"\b(?:warning|fatal error):", stderr), "Unexpected compiler warning/fatal diagnostic")
    errors = re.findall(r"(?m)^.+:\d+:\d+: error: (.+)$", stderr)
    require(len(errors) == len(re.findall(r"\berror:", stderr)), "Unclassified compiler error")
    return errors


def parse_diagnostic(name, kind, returncode, stdout, stderr):
    """Read only primary assertion errors, never echoed source or note lines."""
    require(type(returncode) is int and returncode == 1 and not stdout.strip(),
            "Expected an intentional compile-time assertion failure: " + name)
    errors = primary_errors(stderr)
    require(errors, "Missing assertion observation: " + name)
    patterns = {"number": r"([0-9]+)", "bool": r"(True|False)", "type": r"`([^`]+)`"}
    require(kind in patterns, "Unknown diagnostic probe kind")
    values = []
    for error in errors:
        require(error.startswith("static assertion failed"), "Unrelated compiler error: " + error)
        match = re.search(r"(?:^|: )" + re.escape(name) + " is " + patterns[kind] + r"$", error)
        require(match is not None, "Wrong or unparsed assertion observation: " + error)
        value = match.group(1)
        values.append(int(value) if kind == "number" else value == "True" if kind == "bool" else value)
    # Upstream max_align_t asks for alignment equivalence, not type/size
    # equivalence. Several candidates may match; retain its first-match policy.
    require((name == "max_align_t" and kind == "type" and len(set(values)) == len(values))
            or len(values) == 1, "Ambiguous diagnostic observations: " + name)
    return values[0]


def parse_macros(name, returncode, stdout, stderr):
    require(type(returncode) is int and returncode == 0 and not stderr.strip(),
            "Preprocessing failed or emitted diagnostics: " + name)
    text = "\n".join(line.strip() for line in stdout.splitlines() if not line.lstrip().startswith("#"))
    undefined = re.findall(r"(?m)^const int fragma_wordsize_undefined = 1;$", text)
    marker_count = text.count("fragma_wordsize_undefined")
    require(marker_count == len(undefined) and len(undefined) <= 1, "Malformed/duplicate undefined marker")
    values = {}
    assignments = list(re.finditer(r"\b(\w+)_is\s*=\s*([^;]+);", text))
    require(len(assignments) == len(re.findall(r"\b\w+_is\s*=", text)), "Malformed macro assignment")
    for match in assignments:
        field, value = match.group(1), match.group(2).strip()
        require(field not in values and value, "Duplicate/empty macro observation: " + field)
        values[field] = value
    if undefined:
        require(name == "wordsize" and not values, "Contradictory or misplaced undefined marker")
        return {"wordsize": ""}, ["wordsize"]
    if name == "errno":
        require(values and all(re.fullmatch(r"e[a-z0-9_]+", key) for key in values), "Incomplete errno observations")
        return {"errno": values}, []
    require(name in MACRO_FIELDS and set(values) == MACRO_FIELDS[name], "Missing/unexpected macro fields: " + name)
    require(name != "wordsize" or not re.search(r"\b__WORDSIZE\b", values["wordsize"]),
            "Defined wordsize macro did not expand")
    return values, []


def validate_model(model, schema):
    # ImportError is deliberately fatal. The installed schema misuses `items`
    # for custom_defs objects, so validate their values explicitly as well.
    import jsonschema
    require(isinstance(schema, dict), "Malformed machine schema")
    required = [key for key, spec in schema.items() if not spec.get("optional", False)]
    require(len(required) == 66 and len(schema) == 78, "Unexpected schema field inventory")
    try:
        jsonschema.validate(model, {"type": "object", "required": required,
                                    "properties": schema, "additionalProperties": False})
    except jsonschema.ValidationError as exc:
        raise AdapterError("Machine schema validation failed: " + exc.message) from exc
    for name in ("custom_defs", "errno"):
        require(isinstance(model.get(name), dict) and model[name]
                and all(isinstance(key, str) and key and isinstance(value, str)
                        for key, value in model[name].items()), "Invalid macro mapping: " + name)
    for name in required:
        require(model[name] != "" or name == "wordsize", "Unobserved empty field: " + name)
    # Frama-C's compiler field selects language extensions, not a process path.
    # Its GNU alignments default to -1 if absent; never copy C alignments here.
    require(model.get("compiler") == "clang", "Hexagon model requires the literal clang compiler dialect")
    for name in GNU_ALIGNOF_FIELDS:
        value = model.get(name)
        require(type(value) is int and value > 0 and value & (value - 1) == 0,
                "Missing or invalid measured GNU alignment field: " + name)


def command_for(compiler, flags, source=None, *, mode="compile", alignment=None):
    require(mode in ("compile", "preprocess", "macros", "version"), "Unknown compiler mode")
    require(isinstance(flags, (list, tuple)) and all(isinstance(flag, str) and flag for flag in flags),
            "Invalid compiler flags")
    require(flags.count("-c") <= 1 and not any(flag in ("-E", "-S", "-o", "-fsyntax-only") for flag in flags),
            "Conflicting compiler mode flags")
    if mode == "version":
        require(source is None and alignment is None, "Version query cannot take a source")
        return [str(compiler), "--version"]
    base = [str(compiler), *(flag for flag in flags if flag != "-c")]
    if mode == "macros":
        require(source is None and alignment is None, "Macro query cannot take a source")
        return base + ["-dM", "-E", "-x", "c", "-"]
    require(source is not None, "A source is required")
    if alignment is not None:
        require(mode == "compile" and type(alignment) is int and 0 < alignment <= 2 ** 40
                and alignment & (alignment - 1) == 0, "Invalid alignment trial")
        base += ["-DALIGN_TEST=" + str(alignment)]
    return base + ["-c" if mode == "compile" else "-E", str(source)]


def alignment_observation(data, requested):
    require(type(requested) is int and requested > 0 and requested & (requested - 1) == 0,
            "Invalid requested alignment")
    try:
        obj = elf.parse_relocatable(data, {"machdep": {"checked_fields": {"sizeof_ptr": 4, "little_endian": True}}})
        require(obj.machine == 164 and struct.unpack_from("<I", data, 36)[0] == 0x68,
                "Wrong Hexagon object identity")
        symbols = [symbol for symbol in obj.symbols if symbol.name == b"x"]
        require(len(symbols) == 1, "Missing/ambiguous alignment symbol")
        symbol = symbols[0]
        require(symbol.info == 0x11 and symbol.other == 0 and symbol.size == 4
                and 0 < symbol.section < len(obj.sections), "Unexpected alignment symbol")
        section = obj.sections[symbol.section]
        require(section.kind == 1 and section.flags == 3 and section.address == 0
                and symbol.value + 4 <= section.size, "Unexpected alignment data section")
        require(obj.section_bytes(symbol.section)[symbol.value:symbol.value + 4] == struct.pack("<I", 42),
                "Alignment fixture initializer changed")
        require(not any(row.kind in (4, 9) and row.info == symbol.section for row in obj.sections),
                "Alignment fixture has data relocations")
    except (elf.ELFError, struct.error) as exc:
        raise AdapterError("Invalid alignment object: " + str(exc)) from exc
    return {"requested_alignment": requested, "observed_alignment": section.alignment,
            "symbol_offset": symbol.value,
            "honored": section.alignment >= requested and symbol.value % requested == 0}


class Recorder:
    """Fixed argv, one retained directory per call, finite shared/individual budgets."""
    def __init__(self, output, compiler, flags, env):
        self.output, self.compiler, self.flags, self.env = Path(output), compiler, flags, dict(env)
        self.records = []
        self.deadline = time.monotonic() + 180

    def run(self, name, source=None, *, mode="compile", alignment=None):
        remaining = self.deadline - time.monotonic()
        require(len(self.records) < 112 and remaining > 0, "Generator command/time budget exhausted")
        command = command_for(self.compiler, self.flags, source, mode=mode, alignment=alignment)
        directory = self.output / ("command-%03d" % (len(self.records) + 1))
        directory.mkdir(mode=0o700)
        record = {"name": name, "command": command, "cwd": str(directory), "mode": mode,
                  "environment": self.env, "stdin": "DEVNULL", "timeout_seconds": min(10, remaining)}
        save_json(directory / "intent.json", record)
        self.records.append(record)
        failure = None
        try:
            proc = subprocess.run(command, cwd=directory, env=self.env, stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=record["timeout_seconds"], umask=0o022)
            code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = None, exc.stdout or b"", exc.stderr or b""
            failure = "Compiler timeout"
        except (OSError, KeyboardInterrupt) as exc:
            code, stdout, stderr = None, b"", b""
            failure = type(exc).__name__ + ": " + str(exc)
        save(directory / "stdout", stdout)
        save(directory / "stderr", stderr)
        record.update(returncode=code, stdout=file_record(directory / "stdout"), stderr=file_record(directory / "stderr"),
                      objects=[file_record(path) for path in sorted(directory.glob("*.o"))])
        if failure:
            record["failure"] = failure
        save_json(directory / "result.json", record)
        require(failure is None, failure)
        return code, stdout.decode("utf-8", errors="strict"), stderr.decode("utf-8", errors="strict"), record


def prepare_sources(helper, destination):
    raw = read(helper)
    require(digest(raw) == HELPER_SHA256, "Upstream helper identity changed")
    paths = sorted(path for path in helper.parent.iterdir() if path.suffix in (".c", ".h"))
    original = {path.name: read(path) for path in paths}
    hashes = {name: digest(data) for name, data in original.items()}
    require(len(hashes) == 67 and digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()) == PROBES_SHA256,
            "Upstream probe inventory/content changed")
    inventories = {}
    for node in ast.parse(raw).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in ("standard_source_files", "gcc_alignof_source_files")):
            name = node.targets[0].id
            require(name not in inventories, "Repeated upstream probe inventory: " + name)
            inventories[name] = ast.literal_eval(node.value)
    standard = inventories.get("standard_source_files")
    gnu = inventories.get("gcc_alignof_source_files")
    require(isinstance(standard, list) and len(standard) == 52
            and gnu == [(name + ".c", "number") for name in GNU_ALIGNOF_FIELDS],
            "Unknown upstream standard/GNU probe selection")
    probes = standard + gnu
    require(all(isinstance(row, tuple) and len(row) == 2 and isinstance(row[0], str)
                and row[0] in original and row[0].endswith(".c")
                and row[1] in ("none", "number", "type", "bool", "macro", "macrolist", "has__builtin_va_list")
                for row in probes)
            and len({row[0] for row in probes}) == 64, "Invalid or repeated upstream probe entry")
    destination.mkdir(mode=0o700)
    changes = []
    for name, data in original.items():
        text = data.decode()
        adapted = adapt_probe(name, text)
        save(destination / name, adapted.encode())
        if adapted != text:
            changes.extend(difflib.unified_diff(text.splitlines(True), adapted.splitlines(True),
                                               fromfile="upstream/" + name, tofile="adapted/" + name))
    save(destination.parent / "probe-changes.patch", "".join(changes).encode())
    return probes


def measure_max_align_layout(recorder, sysroot, output, model):
    """Derive the genuine declaration and require independent layout agreement.

The old probe remains an explicitly recorded alignment-equivalent observation.
The actual machine field comes from authenticated source, never from a scalar
chosen only by alignment. This is a producer stage, not a later YAML rewrite.
"""
    declaration = hexagon_layout.declaration(sysroot)
    directory = Path(output) / "max-align-layout"
    directory.mkdir(mode=0o700)
    sources = {"positive": hexagon_layout.fixture(declaration["definition"]),
               **hexagon_layout.controls(declaration["definition"])}
    source_records = []
    for name, source in sources.items():
        path = directory / (name + ".c")
        save(path, source.encode())
        source_records.append(file_record(path))
    previous = model.get("max_align_t")
    require(isinstance(previous, str) and previous, "Missing original max_align_t observation")
    code, stdout, stderr, record = recorder.run("max-align-layout-positive", directory / "positive.c")
    require(code == 0 and not stdout.strip() and not stderr.strip() and len(record["objects"]) == 1,
            "Source-derived max_align_t layout compilation failed")
    observation = hexagon_layout.validate_object(read(record["objects"][0]["absolute_path"]))
    require(observation["layout"]["c_alignment"] == model["alignof_max_align_t"],
            "Independent max_align_t alignment probes disagree")
    require(observation["layout"]["gnu_alignment"] == model.get("gcc_alignof_max_align_t"),
            "Independent max_align_t GNU alignment probes disagree")
    controls = []
    for name, assertion in hexagon_layout.CONTROL_ASSERTIONS.items():
        code, stdout, stderr, record = recorder.run("max-align-layout-" + name, directory / (name + ".c"))
        errors = primary_errors(stderr)
        require(code == 1 and not stdout.strip() and not record["objects"] and len(errors) == 1
                and errors[0].startswith("static assertion failed") and errors[0].endswith(": " + assertion),
                "Unclassified max_align_t layout control: " + name)
        controls.append({"name": name, "assertion": assertion, "command_index": len(recorder.records),
                         "status": "expected-rejection"})
    require(declaration == hexagon_layout.declaration(sysroot), "max_align_t declaration changed during probes")
    require(source_records == [file_record(directory / (name + ".c")) for name in sources],
            "max_align_t layout fixture changed during probes")
    return {"definition": declaration["definition"], "declaration": declaration,
            "previous_alignment_representative": previous, "compiler_observation": observation,
            "controls": controls, "source_files": source_records}


def inputs(root, helper, schema, sysroot, resource_root, setup):
    import yaml
    import jsonschema
    setup.verify_sysroot(sysroot)  # Pure readback, never provisions/fetches.
    compiler = toolchain._clang_binary_identity(Path(COMPILER))
    require(compiler["sha256"] == COMPILER_SHA256, "Compiler identity changed")
    resource = toolchain.clang_resource_tree(resource_root)
    require(resource["include_tree_sha256"] == RESOURCE_SHA256, "Compiler resources changed")
    fixed = [Path(__file__).resolve(), Path(elf.__file__).resolve(), Path(toolchain.__file__).resolve(),
             Path(hexagon_layout.__file__).resolve(),
             root / "profiles/setup_hexagon_musl.py", helper, schema, Path(sys.executable).resolve()]
    paths = set(fixed)
    for directory in (helper.parent, sysroot, Path(yaml.__file__).resolve().parent,
                      Path(jsonschema.__file__).resolve().parent):
        for path in directory.rglob("*"):
            if "__pycache__" in path.parts:
                continue
            require(len(paths) < 10000 and not path.is_symlink(), "Unbounded/symlinked input tree")
            if path.is_file():
                paths.add(path)
            else:
                require(path.is_dir(), "Special input tree entry")
    return {"files": [file_record(path) for path in sorted(paths)], "compiler": compiler,
            "resources": resource, "python_version": sys.version,
            "scope": "Hash-bound sources, headers, tools, PyYAML/jsonschema sources; not a hermetic dynamic-library/Python closure"}


def generate(root, *, helper, schema, sysroot, resource_root, output):
    """Produce a strict candidate and retained evidence, leaving integration gated."""
    import yaml
    root, helper, schema, resource_root = [Path(os.path.abspath(path)) for path in (root, helper, schema, resource_root)]
    provider = root / "profiles/setup_hexagon_musl.py"
    require(digest(read(provider)) == SETUP_SHA256, "Sysroot verifier identity changed")
    specification = importlib.util.spec_from_file_location("fragma_hexagon_setup", provider)
    setup = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(setup)
    helper = setup.path_checked(helper)
    schema = setup.path_checked(schema)
    resource_root = setup.path_checked(resource_root, directory=True)
    sysroot = setup.path_checked(sysroot, directory=True)
    output = setup.path_checked(output, exists=False)
    require(not output.exists(), "Output already exists; choose a fresh directory")
    require(not any(output.is_relative_to(path) for path in (helper.parent, sysroot, resource_root)),
            "Output must not modify an input tree")
    require(digest(read(schema)) == SCHEMA_SHA256, "Machine schema identity changed")
    schema_value = yaml.safe_load(read(schema))
    before = inputs(root, helper, schema, sysroot, resource_root, setup)
    output.mkdir(parents=True, mode=0o700)
    save_json(output / "inputs-before.json", before)
    flags = [*ARCH_FLAGS, "-nostdinc", "-isystem", str(sysroot / "include"),
             "-isystem", str(resource_root / "include"), "-D_POSIX_C_SOURCE=200809L"]
    recorder = Recorder(output, COMPILER, flags, {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
    result = {"schema_version": 1, "status": "failed", "level": "unregistered",
              "started_at": datetime.now(timezone.utc).isoformat(), "commands": recorder.records,
              "undefined_macros": [], "alignment_observations": [], "integration_eligible": False,
              "scope": "Candidate extraction only; no Frama-C, L1, proof, target runtime or libc compatibility claim"}
    try:
        probes = prepare_sources(helper, output / "probes")
        result["adapted_sources_before"] = [file_record(path) for path in sorted((output / "probes").iterdir())]
        model = {}
        for filename, kind in probes:
            name = Path(filename).stem
            mode = "preprocess" if kind in ("macro", "macrolist") else "compile"
            code, stdout, stderr, record = recorder.run(name, output / "probes" / filename, mode=mode)
            if kind in ("none", "has__builtin_va_list"):
                require(code == 0 and not stdout.strip() and not stderr.strip() and len(record["objects"]) == 1,
                        "Required positive compiler probe failed: " + name)
                if kind == "has__builtin_va_list":
                    model[name] = True
            elif kind in ("macro", "macrolist"):
                fields, undefined = parse_macros(name, code, stdout, stderr)
                require(not set(model).intersection(fields), "Repeated model fields")
                model.update(fields)
                result["undefined_macros"].extend(undefined)
            else:
                require(not record["objects"], "Assertion probe unexpectedly emitted an object")
                model[name] = parse_diagnostic(name, kind, code, stdout, stderr)
        representation = measure_max_align_layout(recorder, sysroot, output, model)
        result["max_align_t_representation"] = representation
        model["max_align_t"] = representation["definition"]
        code, stdout, stderr, _ = recorder.run("compiler-version", mode="version")
        versions = re.findall(r"clang version\s+(\d+\.\d+\.\d+)(?![\w.+-])", stdout)
        require(code == 0 and not stderr.strip() and stdout.splitlines() and versions == ["21.1.8"]
                and "clang version 21.1.8 " in stdout.splitlines()[0],
                "Compiler version probe failed")
        # The exact executable/alias/hash remains in every command and inputs.
        # Literal clang enables Frama-C's own GNU-compatible parser branches.
        model.update(compiler="clang", version=stdout.splitlines()[0], cpp_arch_flags=list(ARCH_FLAGS),
                     machdep_name="hexagon-v68-candidate")
        result["compiler_semantics"] = {
            "family": "clang", "dialect": "gnu11",
            "executable": {"path": COMPILER, "sha256": COMPILER_SHA256},
            "machdep_compiler": "clang", "gnu_alignment_fields": list(GNU_ALIGNOF_FIELDS),
            "scope": "Frama-C compiler is a dialect selector; the executable path is retained separately. "
                     "GNU alignments are individually probed.",
        }
        alignment = 2 * model["alignof_max_align_t"]
        maximum = -1
        while True:
            code, stdout, stderr, record = recorder.run("max_extended_alignment", output / "probes/max_extended_alignment.c",
                                                       alignment=alignment)
            if code != 0:
                errors = primary_errors(stderr)
                require(code == 1 and not stdout.strip() and not record["objects"] and len(errors) == 1
                        and re.fullmatch(r"requested alignment must be [0-9]+ bytes or smaller", errors[0]),
                        "Unclassified alignment rejection")
                break
            require(not stdout.strip() and not stderr.strip() and len(record["objects"]) == 1,
                    "Alignment compile emitted diagnostics or no unique object")
            observation = alignment_observation(read(record["objects"][0]["absolute_path"], limit=512 * 1024 * 1024), alignment)
            observation["command_index"] = len(recorder.records)
            result["alignment_observations"].append(observation)
            maximum, alignment = alignment, alignment * 2
        # Preserve the upstream exit-status definition. Do not silently replace
        # it with the lower observed object limit. Any contradiction blocks use.
        model["max_extended_alignment"] = maximum
        code, stdout, stderr, _ = recorder.run("custom_defs", mode="macros")
        require(code == 0 and not stderr.strip(), "Predefined-macro query failed")
        custom = {}
        for line in stdout.splitlines():
            match = re.fullmatch(r"#define ([^ ]+)(?: (.*))?", line)
            require(match is not None, "Unparsed predefined macro")
            name, value = match.group(1), match.group(2) or ""
            if name.startswith("__STDC"):
                continue
            require(name not in custom, "Duplicate predefined macro")
            custom[name] = value
        model["custom_defs"] = custom
        validate_model(model, schema_value)
        save(output / "candidate.yaml", yaml.safe_dump(model, sort_keys=True).encode())
        result["candidate"] = file_record(output / "candidate.yaml")
        result["schema_validation"] = {"required_fields": 66, "optional_fields": 12,
                                       "measured_gnu_alignment_fields": 12, "status": "passed"}
        result["alignment_contradictions"] = [row for row in result["alignment_observations"] if not row["honored"]]
        result["status"] = "blocked-object-alignment" if result["alignment_contradictions"] else "candidate-extracted-not-L1"
        result["limitations"] = ["Source-derived max_align_t passes compiler layout checks; Frama-C/profile calibration remains separate",
                                 "Target libc WCHAR_MAX is incompatible with kernel short-wchar",
                                 "No genuine-kernel L1 or production profile integration has been performed"]
    except (AdapterError, OSError, ImportError, ValueError, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        try:
            if "adapted_sources_before" in result:
                result["adapted_sources_after"] = [file_record(path) for path in sorted((output / "probes").iterdir())]
                require(result["adapted_sources_before"] == result["adapted_sources_after"], "Adapted probe sources changed during execution")
            if "max_align_t_representation" in result:
                sources = result["max_align_t_representation"]["source_files"]
                require(sources == [file_record(row["absolute_path"]) for row in sources],
                        "max_align_t layout sources changed after calibration")
            after = inputs(root, helper, schema, sysroot, resource_root, setup)
            save_json(output / "inputs-after.json", after)
            result["input_drift"] = before != after
            require(before == after, "Generator inputs changed during execution")
        except (OSError, ValueError) as exc:
            result.update(status="failed", input_drift=True, drift_error=str(exc))
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        result["artifacts"] = [file_record(path) for path in sorted(output.rglob("*")) if path.is_file()]
        save_json(output / "receipt.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sysroot", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    prefix = root / "toolchain/verified-prefix/opam/fragma"
    try:
        result = generate(root, helper=prefix / "lib/frama-c/lib/make_machdep/make_machdep.py",
                          schema=prefix / "share/frama-c/share/machdeps/machdep-schema.yaml",
                          sysroot=args.sysroot, resource_root=Path("/usr/lib/llvm-21/lib/clang/21"), output=args.output)
        print(json.dumps({key: result.get(key) for key in ("status", "error", "input_drift", "candidate", "alignment_contradictions")}))
        return 0 if result["status"] == "candidate-extracted-not-L1" else 1
    except (OSError, ValueError, ImportError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
