"""Closed LLVM kernel-build routes for reviewed architecture profiles.

Keep invocation aliases: resolving ld.lld to the multicall lld binary changes
argv[0] semantics. Each route binds a target, CPU/ABI, configuration, complete
tool suite, genuine translation-unit command and ELF container. There is no
implicit LLVM fallback for registered GCC profiles or unreviewed targets.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import struct
import subprocess

from .sources import SourceError, sha256
from .elf import ELFError, parse_relocatable

TOOL_KEYS = frozenset(("CC", "HOSTCC", "HOSTCXX", "LD", "AR", "LLVM_LINK",
                       "NM", "OBJCOPY", "OBJDUMP", "READELF", "STRIP"))
HEXAGON_REQUIRED_FLAGS = ("-nostdinc", "-fintegrated-as", "-G0", "-fno-short-enums",
                          "-mlong-calls", "-ffixed-r19", "-DTHREADINFO_REG=r19",
                          "-D__linux__")
# Kept as the public compatibility name used by the original Hexagon tests.
REQUIRED_FLAGS = HEXAGON_REQUIRED_FLAGS
MIPS_TARGET_ARGS = ("--target=mipsel-linux-gnu", "-mabi=32", "-EL",
                    "-march=mips32r2", "-msoft-float")
MIPS_REQUIRED_FLAGS = ("-nostdinc", "-fintegrated-as", "-fshort-wchar",
                       "-funsigned-char", "-fno-PIE", "-fno-strict-aliasing", "-std=gnu11",
                       "-mabi=32", "-mno-abicalls", "-fno-pic", "-msoft-float",
                       "-ffreestanding", "-EL", "-march=mips32r2")


def _require(condition, message):
    if not condition:
        raise SourceError("LLVM build: " + message)


def _spec(profile):
    kernel = profile.get("kernel", {})
    spec = kernel.get("llvm", {})
    architecture = profile.get("architecture")
    _require(profile.get("compiler_family") == "clang" and
             kernel.get("arch") == architecture and architecture in {"hexagon", "mips"},
             "only explicit reviewed Clang architecture routes are supported")
    _require(isinstance(spec, dict) and set(spec) == {
        "schema_version", "target", "observed_target", "cpu", "tools"}, "invalid LLVM specification")
    _require(type(spec["schema_version"]) is int and spec["schema_version"] == 1,
             "unsupported specification schema")
    if architecture == "hexagon":
        _require(spec["target"] == "hexagon-linux-musl" and
                 spec["observed_target"] == "hexagon-unknown-linux-musl", "unexpected target route")
        _require(type(spec["cpu"]) is int and spec["cpu"] == 68,
                 "only explicit Hexagon CPU v68 is supported")
        _require(kernel.get("required_config", {}).get("CONFIG_HEXAGON_ARCH_VERSION") == "68",
                 "configuration must explicitly require Hexagon CPU v68")
    else:
        required = {"CONFIG_MIPS": "y", "CONFIG_32BIT": "y", "CONFIG_RALINK": "y",
                    "CONFIG_SOC_MT7621": "y",
                    "CONFIG_CPU_LITTLE_ENDIAN": "y", "CONFIG_CPU_MIPS32_R2": "y",
                    "CONFIG_SMP": "y", "CONFIG_MIPS_MT_SMP": "y",
                    "CONFIG_MIPS_CPS": "y", "CONFIG_NR_CPUS": "4"}
        _require(spec["target"] == "mipsel-linux-gnu" and
                 spec["observed_target"] == "mipsel-unknown-linux-gnu" and
                 spec["cpu"] == "mips32r2", "unexpected MIPS target/CPU route")
        _require(profile.get("compiler_target_args") == list(MIPS_TARGET_ARGS),
                 "MIPS compiler target/ABI arguments differ")
        _require(all(kernel.get("required_config", {}).get(key) == value
                     for key, value in required.items()),
                 "configuration must explicitly require SMP MT7621 MIPS32el")
    _require(profile.get("compiler_version") == "21.1.8", "unreviewed compiler version")
    _require(isinstance(spec["tools"], dict) and set(spec["tools"]) == TOOL_KEYS,
             "incomplete or unknown LLVM tool set")
    return spec


def _target_query(profile, compiler_path, spec):
    if profile["architecture"] == "hexagon":
        args = ["--target=" + spec["target"], "-mv68"]
    else:
        args = list(MIPS_TARGET_ARGS)
    return [compiler_path, *args, "-dumpmachine"]


def _tool_identity(row):
    _require(isinstance(row, dict), "invalid tool record")
    path = row.get("path")
    _require(isinstance(path, str) and path.startswith("/") and
             re.fullmatch(r"/[A-Za-z0-9_./+-]+", path) is not None,
             "tool paths must be absolute and safe for Kbuild shell/make expansion")
    _require(isinstance(row.get("sha256"), str) and
             re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None, "missing exact tool hash")
    p = Path(path)
    _require(p.is_file() and sha256(p) == row["sha256"], "tool missing or changed: " + path)
    return {"path": path, "resolved_path": str(p.resolve()), "sha256": row["sha256"]}


def _query(argv, env):
    try:
        run = subprocess.run(argv, env=env, capture_output=True, text=True,
                             timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SourceError("LLVM build: metadata query failed: " + str(exc)) from exc
    _require(run.returncode == 0, "metadata query failed: " + repr(argv))
    return run


def _version(key, output):
    marker = "clang version" if key in {"CC", "HOSTCC", "HOSTCXX"} else "LLD" if key == "LD" else "LLVM version"
    return re.findall(re.escape(marker) + r"\s+(\d+\.\d+\.\d+)(?![\w.+-])", output)


def prepare_llvm(profile, compiler_path, env):
    """Validate the pinned suite before creating a build output directory."""
    spec = _spec(profile)
    clean = {key: env[key] for key in ("PATH", "LANG", "LD_LIBRARY_PATH") if key in env}
    clean["LC_ALL"] = "C"
    _require(bool(clean.get("PATH")), "an explicit tool search PATH is required")
    _require(spec["tools"]["CC"].get("path") == compiler_path,
             "compiler invocation alias differs from the pinned CC")
    # Validate every file before invoking any member of the suite.
    records = {key: _tool_identity(row) for key, row in sorted(spec["tools"].items())}
    for key, row in records.items():
        argv = [row["path"], "--version"]
        run = _query(argv, clean)
        output = (run.stdout + run.stderr).strip()
        versions = _version(key, output)
        _require(versions == [profile["compiler_version"]], "tool version mismatch: " + key)
        row.update(version=versions[0], version_command=argv, version_output=output)
    argv = _target_query(profile, compiler_path, spec)
    run = _query(argv, clean)
    observed = run.stdout.strip()
    _require(not run.stderr.strip() and observed == spec["observed_target"],
             "target-aware compiler triple mismatch")
    scope = ("Hexagon v68 prepare and lib/string.o only; no L1, full kernel or runtime claim"
             if profile["architecture"] == "hexagon" else
             "MT7621 MIPS32el prepare and lib/string.o only; model/L1 require the separate profile calibration gate")
    receipt = {"schema_version": 1, "family": "clang", "cpu": spec["cpu"],
               "architecture": profile["architecture"],
               "tools": records, "environment": clean,
               "target": {"requested": spec["target"], "observed": observed, "command": argv},
               "scope": scope}
    assignments = ["LLVM=1", "LLVM_IAS=1"] + [key + "=" + row["path"] for key, row in records.items()]
    assignments += ["HOSTAR=" + records["AR"]["path"], "HOSTLD=" + records["LD"]["path"],
                    "KBUILD_HOSTLDFLAGS=--ld-path=" + records["LD"]["path"]]
    return assignments, receipt, clean


def _verify_hexagon_args(args):
    _require([arg for arg in args if arg.startswith(("--target", "-target"))]
             == ["--target=hexagon-linux-musl"],
             "missing, duplicate or conflicting TU target")
    _require([arg for arg in args if arg.startswith(("-mv", "-mcpu", "-march"))]
             == ["-mv68"], "missing, duplicate or conflicting TU CPU")
    _require(all(flag in args for flag in HEXAGON_REQUIRED_FLAGS),
             "missing required kernel flags")
    _require([arg for arg in args if arg.startswith("-Wp,")]
             == ["-Wp,-MMD,lib/.string.o.d"], "unreviewed preprocessor forwarding")
    _require([arg for arg in args if arg.startswith("-G")] == ["-G0"],
             "small-data threshold differs")
    _require(all(args.count(flag) == 1 for flag in HEXAGON_REQUIRED_FLAGS),
             "duplicate required kernel flags")
    _require(not {"-fno-integrated-as", "-no-integrated-as", "-fshort-enums",
                  "-mno-long-calls", "-fno-fixed-r19"}.intersection(args),
             "opposing kernel flags")
    selectors = [arg for arg in args if arg.startswith((
        "-DTHREADINFO_REG", "-UTHREADINFO_REG", "-D__linux__", "-U__linux__"))]
    _require(selectors == ["-DTHREADINFO_REG=r19", "-D__linux__"],
             "kernel macro selector differs")


def _verify_mips_args(args, source):
    _require([arg for arg in args if arg.startswith(("--target", "-target"))]
             == [MIPS_TARGET_ARGS[0]], "missing, duplicate or conflicting MIPS TU target")
    _require([arg for arg in args if arg.startswith(("-march", "-mcpu", "-mips"))]
             == ["-march=mips32r2"], "missing, duplicate or conflicting MIPS ISA")
    _require([arg for arg in args if arg.startswith("-mabi")]
             == ["-mabi=32"], "missing, duplicate or conflicting MIPS ABI")
    _require([arg for arg in args if arg in {"-EL", "-EB"}] == ["-EL"],
             "missing, duplicate or conflicting MIPS byte order")
    _require([arg for arg in args if arg in {"-msoft-float", "-mhard-float"}]
             == ["-msoft-float"], "missing, duplicate or conflicting MIPS float ABI")
    _require(all(flag in args for flag in MIPS_REQUIRED_FLAGS),
             "missing required MIPS kernel flags")
    # Kbuild emits -ffreestanding twice for this translation unit. Repetition is
    # semantically idempotent; every other required selector must be unique.
    _require(all(args.count(flag) == 1 for flag in MIPS_REQUIRED_FLAGS
                 if flag != "-ffreestanding"),
             "duplicate required MIPS kernel flags")
    _require([arg for arg in args if arg.startswith("-std=")] == ["-std=gnu11"],
             "missing, duplicate or conflicting MIPS C dialect")
    _require([arg for arg in args if arg.startswith("-Wp,")]
             == ["-Wp,-MMD,lib/.string.o.d"], "unreviewed preprocessor forwarding")
    _require([arg for arg in args if arg.startswith("-Wa,")]
             == ["-Wa,-msoft-float", "-Wa,--trap"],
             "unreviewed MIPS assembler forwarding")
    small_data = []
    for index, arg in enumerate(args):
        if arg == "-G":
            small_data.append((arg, args[index + 1] if index + 1 < len(args) else None))
        elif arg.startswith("-G"):
            small_data.append((arg, None))
    _require(small_data == [("-G", "0")], "MIPS small-data threshold differs")
    _require(not {"-fno-integrated-as", "-no-integrated-as", "-mabicalls", "-fPIC",
                  "-fpic", "-fPIE", "-fpie", "-EB", "-mhard-float",
                  "-fno-short-wchar", "-fsigned-char", "-fstrict-aliasing",
                  "-fhosted"}.intersection(args),
             "opposing MIPS kernel flags")
    _require("-I" not in args, "split MIPS platform include requires review")
    platform_includes = [arg for arg in args if arg.startswith("-I") and
                         "/arch/mips/include/asm/mach-" in arg]
    expected = ["-I" + str(source / "arch/mips/include/asm/mach-ralink"),
                "-I" + str(source / "arch/mips/include/asm/mach-ralink/mt7621"),
                "-I" + str(source / "arch/mips/include/asm/mach-generic")]
    _require(platform_includes == expected, "MIPS platform include selection differs")


def verify_llvm_build(profile, output: Path, receipt, *, source: Path):
    """Read-only validation of the genuine configuration, TU command and ELF."""
    spec = _spec(profile)
    _require(receipt.get("cpu") == spec["cpu"] and
             receipt.get("architecture") == profile["architecture"] and
             receipt.get("target", {}).get("requested") == spec["target"] and
             receipt.get("target", {}).get("observed") == spec["observed_target"],
             "target receipt mismatch")
    _require(set(receipt.get("tools", {})) == TOOL_KEYS, "tool receipt is incomplete")
    _require(receipt.get("family") == "clang" and receipt.get("schema_version") == 1,
             "compiler family or receipt schema differs")
    _require(receipt["target"].get("command") ==
             _target_query(profile, spec["tools"]["CC"]["path"], spec),
             "target query command differs")
    for key, row in spec["tools"].items():
        actual = _tool_identity(row)
        _require(all(receipt["tools"][key].get(k) == v for k, v in actual.items()),
                 "tool invocation or resolved identity changed: " + key)
        retained = receipt["tools"][key]
        _require(retained.get("version") == profile["compiler_version"] and
                 retained.get("version_command") == [actual["path"], "--version"] and
                 isinstance(retained.get("version_output"), str) and
                 _version(key, retained["version_output"]) == [profile["compiler_version"]],
                 "tool version receipt differs: " + key)
    output, source = Path(output).resolve(), Path(source).resolve()
    config_path, db_path = output / ".config", output / "compile_commands.json"
    cmd_path, obj = output / "lib/.string.o.cmd", output / "lib/string.o"
    _require(all(p.is_file() and not p.is_symlink()
                 for p in (config_path, db_path, cmd_path, obj)),
             "missing or symlinked configuration, command, database or object")
    config = config_path.read_text().splitlines()
    for key, value in profile["kernel"]["required_config"].items():
        lines = [line for line in config
                 if line.startswith(key + "=") or line == "# " + key + " is not set"]
        expected = "# " + key + " is not set" if value == "n" else key + "=" + value
        _require(lines == [expected], "configuration mismatch: " + key)
    entries = json.loads(db_path.read_text())
    _require(isinstance(entries, list), "invalid compilation database")
    matches = [entry for entry in entries if isinstance(entry, dict) and
               str(entry.get("file", "")).endswith("/lib/string.c")]
    _require(len(matches) == 1, "expected exactly one genuine lib/string.c command")
    entry = matches[0]
    _require(entry.get("directory") == str(output) and
             entry.get("file") == str(source / "lib/string.c"),
             "TU source or working directory differs")
    _require(isinstance(entry.get("arguments"), list) or
             isinstance(entry.get("command"), str), "missing compiler arguments")
    args = entry.get("arguments") if "arguments" in entry else shlex.split(entry["command"])
    _require(isinstance(args, list) and args and all(isinstance(arg, str) for arg in args),
             "invalid compiler argv")
    _require(args.count("-c") == 1 and args.count("-o") == 1 and
             args.index("-o") + 1 < len(args) and
             args[args.index("-o") + 1] == "lib/string.o" and
             args[-1] == str(source / "lib/string.c") and args.count(args[-1]) == 1,
             "TU source, compile mode or output arguments differ")
    saved = []
    for line in cmd_path.read_text().splitlines():
        match = re.match(r"^(?:saved)?cmd_lib/string\.o := (.*?)(?:;|$)", line)
        if match:
            saved.append(shlex.split(match.group(1).replace("$(pound)", "#")))
    _require(saved == [args], "compilation database differs from retained Kbuild command")
    _require(args[0] == spec["tools"]["CC"]["path"],
             "TU compiler invocation alias differs")
    _require(not any(arg.startswith(("@", "-Xclang", "-Xpreprocessor")) for arg in args),
             "unreviewed forwarded or response-file flags")
    _require(not {"-D", "-U"}.intersection(args),
             "split macro selectors require separate review")
    if profile["architecture"] == "hexagon":
        _verify_hexagon_args(args)
        machine, name, expected_flags = 164, "Hexagon", None
    else:
        _verify_mips_args(args, source)
        machine, name, expected_flags = 8, "MIPS32el O32/MIPS32r2", 0x70001001
    # The parser's legacy parameter shape names these checked_fields. Here they
    # specify ONLY the required ELF container format, never a calibrated model.
    try:
        container = parse_relocatable(obj.read_bytes(), {
            "machdep": {"checked_fields": {"sizeof_ptr": 4, "little_endian": True}}})
    except ELFError as exc:
        raise SourceError("LLVM build: invalid ELF container: " + str(exc)) from exc
    _require(container.machine == machine, "object is not " + name + " ET_REL")
    flags = struct.unpack_from("<I", container.data, 36)[0]
    if expected_flags is not None:
        _require(flags == expected_flags, "MIPS ELF flags differ from O32/MIPS32r2")
    return {"architecture": profile["architecture"], "matched_command": entry,
            "config_sha256": sha256(config_path),
            "compilation_database_sha256": sha256(db_path),
            "kbuild_command_sha256": sha256(cmd_path),
            "source": {"path": str(source / "lib/string.c"),
                       "sha256": sha256(source / "lib/string.c")},
            "object": {"path": str(obj.resolve()), "sha256": sha256(obj),
                       "class": 32, "byte_order": "little", "machine": machine,
                       "e_flags_observed": flags},
            "target_execution": False, "model_support_awarded": False}
