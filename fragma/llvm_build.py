"""Opt-in, compiler-only Hexagon v68 build bring-up; not an L1 model.

Keep invocation aliases: resolving ld.lld to the multicall lld binary changes
argv[0] semantics. This deliberately supports one reviewed candidate, not an
implicit LLVM fallback for all registered GCC profiles.
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
REQUIRED_FLAGS = ("-nostdinc", "-fintegrated-as", "-G0", "-fno-short-enums",
                  "-mlong-calls", "-ffixed-r19", "-DTHREADINFO_REG=r19", "-D__linux__")


def _require(condition, message):
    if not condition:
        raise SourceError("LLVM build: " + message)


def _spec(profile):
    kernel = profile.get("kernel", {})
    spec = kernel.get("llvm", {})
    _require(profile.get("compiler_family") == "clang" and kernel.get("arch") == "hexagon",
             "only explicit Hexagon Clang bring-up is supported")
    _require(isinstance(spec, dict) and set(spec) == {
        "schema_version", "target", "observed_target", "cpu", "tools"}, "invalid LLVM specification")
    _require(type(spec["schema_version"]) is int and spec["schema_version"] == 1,
             "unsupported specification schema")
    _require(spec["target"] == "hexagon-linux-musl" and
             spec["observed_target"] == "hexagon-unknown-linux-musl", "unexpected target route")
    _require(type(spec["cpu"]) is int and spec["cpu"] == 68, "only explicit CPU v68 is supported")
    _require(kernel.get("required_config", {}).get("CONFIG_HEXAGON_ARCH_VERSION") == "68",
             "configuration must explicitly require CPU v68")
    _require(profile.get("compiler_version") == "21.1.8", "unreviewed compiler version")
    _require(isinstance(spec["tools"], dict) and set(spec["tools"]) == TOOL_KEYS,
             "incomplete or unknown LLVM tool set")
    return spec


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
    argv = [compiler_path, "--target=" + spec["target"], "-mv68", "-dumpmachine"]
    run = _query(argv, clean)
    observed = run.stdout.strip()
    _require(not run.stderr.strip() and observed == spec["observed_target"],
             "target-aware compiler triple mismatch")
    receipt = {"schema_version": 1, "family": "clang", "cpu": 68,
               "tools": records, "environment": clean,
               "target": {"requested": spec["target"], "observed": observed, "command": argv},
               "scope": "Hexagon v68 prepare and lib/string.o only; no L1, full kernel or runtime claim"}
    assignments = ["LLVM=1", "LLVM_IAS=1"] + [key + "=" + row["path"] for key, row in records.items()]
    assignments += ["HOSTAR=" + records["AR"]["path"], "HOSTLD=" + records["LD"]["path"],
                    "KBUILD_HOSTLDFLAGS=--ld-path=" + records["LD"]["path"]]
    return assignments, receipt, clean


def verify_llvm_build(profile, output: Path, receipt, *, source: Path):
    """Read-only validation of the genuine configuration, TU command and ELF."""
    spec = _spec(profile)
    _require(receipt.get("cpu") == 68 and receipt.get("target", {}).get("requested") == spec["target"] and
             receipt.get("target", {}).get("observed") == spec["observed_target"], "target receipt mismatch")
    _require(set(receipt.get("tools", {})) == TOOL_KEYS, "tool receipt is incomplete")
    _require(receipt.get("family") == "clang" and receipt.get("schema_version") == 1,
             "compiler family or receipt schema differs")
    _require(receipt["target"].get("command") == [spec["tools"]["CC"]["path"],
             "--target=" + spec["target"], "-mv68", "-dumpmachine"], "target query command differs")
    for key, row in spec["tools"].items():
        actual = _tool_identity(row)
        _require(all(receipt["tools"][key].get(k) == v for k, v in actual.items()),
                 "tool invocation or resolved identity changed: " + key)
        row = receipt["tools"][key]
        _require(row.get("version") == profile["compiler_version"] and
                 row.get("version_command") == [actual["path"], "--version"] and
                 isinstance(row.get("version_output"), str) and
                 _version(key, row["version_output"]) == [profile["compiler_version"]],
                 "tool version receipt differs: " + key)
    output, source = Path(output).resolve(), Path(source).resolve()
    config_path, db_path = output / ".config", output / "compile_commands.json"
    cmd_path, obj = output / "lib/.string.o.cmd", output / "lib/string.o"
    _require(all(p.is_file() and not p.is_symlink() for p in (config_path, db_path, cmd_path, obj)),
             "missing or symlinked configuration, command, database or object")
    config = config_path.read_text().splitlines()
    for key, value in profile["kernel"]["required_config"].items():
        lines = [line for line in config if line.startswith(key + "=") or line == "# " + key + " is not set"]
        expected = "# " + key + " is not set" if value == "n" else key + "=" + value
        _require(lines == [expected], "configuration mismatch: " + key)
    entries = json.loads(db_path.read_text())
    _require(isinstance(entries, list), "invalid compilation database")
    matches = [entry for entry in entries if isinstance(entry, dict) and
               str(entry.get("file", "")).endswith("/lib/string.c")]
    _require(len(matches) == 1, "expected exactly one genuine lib/string.c command")
    entry = matches[0]
    _require(entry.get("directory") == str(output) and entry.get("file") == str(source / "lib/string.c"),
             "TU source or working directory differs")
    _require(isinstance(entry.get("arguments"), list) or isinstance(entry.get("command"), str),
             "missing compiler arguments")
    args = entry.get("arguments") if "arguments" in entry else shlex.split(entry["command"])
    _require(isinstance(args, list) and args and all(isinstance(arg, str) for arg in args), "invalid compiler argv")
    _require(args.count("-c") == 1 and args.count("-o") == 1 and
             args.index("-o") + 1 < len(args) and args[args.index("-o") + 1] == "lib/string.o" and
             args[-1] == str(source / "lib/string.c") and args.count(args[-1]) == 1,
             "TU source, compile mode or output arguments differ")
    saved = []
    for line in cmd_path.read_text().splitlines():
        match = re.match(r"^(?:saved)?cmd_lib/string\.o := (.*?)(?:;|$)", line)
        if match:
            saved.append(shlex.split(match.group(1).replace("$(pound)", "#")))
    _require(saved == [args], "compilation database differs from retained Kbuild command")
    _require(args[0] == spec["tools"]["CC"]["path"], "TU compiler invocation alias differs")
    _require([arg for arg in args if arg.startswith(("--target", "-target"))] == ["--target=" + spec["target"]],
             "missing, duplicate or conflicting TU target")
    _require([arg for arg in args if arg.startswith(("-mv", "-mcpu", "-march"))] == ["-mv68"],
             "missing, duplicate or conflicting TU CPU")
    _require(all(flag in args for flag in REQUIRED_FLAGS), "missing required kernel flags")
    _require(not any(arg.startswith(("@", "-Xclang", "-Xpreprocessor")) for arg in args),
             "unreviewed forwarded or response-file flags")
    _require([arg for arg in args if arg.startswith("-Wp,")] == ["-Wp,-MMD,lib/.string.o.d"],
             "unreviewed preprocessor forwarding")
    _require([arg for arg in args if arg.startswith("-G")] == ["-G0"], "small-data threshold differs")
    _require(all(args.count(flag) == 1 for flag in REQUIRED_FLAGS), "duplicate required kernel flags")
    _require(not {"-fno-integrated-as", "-no-integrated-as", "-fshort-enums", "-mno-long-calls", "-fno-fixed-r19"}.intersection(args),
             "opposing kernel flags")
    selectors = [arg for arg in args if arg.startswith(("-DTHREADINFO_REG", "-UTHREADINFO_REG", "-D__linux__", "-U__linux__"))]
    _require(selectors == ["-DTHREADINFO_REG=r19", "-D__linux__"], "kernel macro selector differs")
    _require(not {"-D", "-U"}.intersection(args), "split macro selectors require separate review")
    # The parser's legacy parameter shape names these checked_fields. Here they
    # specify ONLY the required ELF container format, never a calibrated model.
    try:
        container = parse_relocatable(obj.read_bytes(), {
            "machdep": {"checked_fields": {"sizeof_ptr": 4, "little_endian": True}}})
    except ELFError as exc:
        raise SourceError("LLVM build: invalid ELF container: " + str(exc)) from exc
    _require(container.machine == 164, "object is not Hexagon ET_REL")
    return {"matched_command": entry, "config_sha256": sha256(config_path),
            "compilation_database_sha256": sha256(db_path),
            "kbuild_command_sha256": sha256(cmd_path),
            "source": {"path": str(source / "lib/string.c"), "sha256": sha256(source / "lib/string.c")},
            "object": {"path": str(obj.resolve()), "sha256": sha256(obj),
                       "class": 32, "byte_order": "little", "machine": 164,
                       "e_flags_observed": struct.unpack_from("<I", container.data, 36)[0]},
            "target_execution": False, "model_support_awarded": False}
