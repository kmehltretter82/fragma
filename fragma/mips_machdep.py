"""Strict, unregistered MIPS32r2 little-endian machdep calibration.

The adapter uses the unchanged Frama-C 33 generator, authenticated Clang
builtin headers, and the separately provisioned musl sysroot.  Passing this
adapter is candidate/L0 evidence only: it does not register a profile, renew
the central toolchain lock, or claim kernel L1/L2 support.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
from typing import Any

from . import analysis_policy, elf, profiles, toolchain


class AdapterError(ValueError):
    """A required input, observation, or negative control did not match."""


COMPILER = Path("/usr/bin/clang-21")
COMPILER_SHA256 = "412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932"
COMPILER_VERSION = "21.1.8"
COMPILER_TARGET = "mipsel-unknown-linux-gnu"
RESOURCE_ROOT = Path("/usr/lib/llvm-21/lib/clang/21")
RESOURCE_SHA256 = "deb75785057f7fa7d497414c903e9c03a6d7005c84999204b21be6001e66b24c"
GENERATOR_SHA256 = "889d3ca26ea964aebcc2e9a1c2fe5ccab3f064b29fd8c69f7c90678d7b2dd6bf"
SCHEMA_SHA256 = "ce8de93d93cc3bfbd8ad843bd6b44dd3f89ac5bd981f48b93433006b1fa34400"
PROBES_SHA256 = "05a00f449556eea8d8865ee2c550b13eb6c5628410b6c3e037ddb2f211e3e1f3"
FRAMA_C_SHA256 = "815c916df2361e7af5a18125c97b37665e4eed91e76daa185d571706563e7ef2"
KERNEL_REVISION = "b9b3e33b70b71e516930117e21de3ad2a7723747"
KERNEL_TREE = "054b6818c409ab20ae89b1031a1a7c358f673d87"
ARCH_FLAGS = [
    "--target=mipsel-linux-gnu", "-mabi=32", "-EL", "-march=mips32r2",
    "-msoft-float", "-funsigned-char", "-fshort-wchar",
    "-fno-strict-overflow", "-fno-strict-aliasing", "-ffreestanding",
    "-std=gnu11",
]
OBJECT_FLAGS = ["-mno-abicalls", "-fno-pic", "-G0"]
ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "LANG": "C",
    "TZ": "UTC",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _record_file(path: Path) -> dict[str, Any]:
    path = Path(path).resolve()
    return {"absolute_path": str(path), "sha256": digest(path), "size": path.stat().st_size}


def _probe_inventory(helper: Path) -> dict[str, Any]:
    hashes = {
        path.name: digest(path)
        for path in sorted(helper.parent.iterdir())
        if path.suffix in (".c", ".h")
    }
    aggregate = hashlib.sha256(json.dumps(
        hashes, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    require(len(hashes) == 67 and aggregate == PROBES_SHA256,
            "upstream generator probe inventory/content changed")
    return {"count": len(hashes), "sha256": aggregate, "files": hashes}


class Recorder:
    """Run fixed argv calls and retain their exact stdout/stderr without overwrite."""

    def __init__(self, output: Path):
        self.output = output
        self.records: list[dict[str, Any]] = []
        self.logs = output / "commands"
        self.logs.mkdir(mode=0o700)

    def run(self, name: str, argv: list[object], *, timeout: int = 180,
            stdin: str | None = None) -> dict[str, Any]:
        require(re.fullmatch(r"[a-z0-9-]+", name) is not None, "invalid command name")
        require(not any(row["name"] == name for row in self.records), "duplicate command name")
        command = [str(value) for value in argv]
        process = subprocess.run(command, cwd=self.output, env=ENVIRONMENT,
                                 stdin=subprocess.DEVNULL if stdin is None else None,
                                 input=stdin, text=True, capture_output=True,
                                 timeout=timeout, check=False)
        stdout = self.logs / f"{name}.stdout"
        stderr = self.logs / f"{name}.stderr"
        stdout.write_text(process.stdout)
        stderr.write_text(process.stderr)
        row = {
            "name": name,
            "argv": command,
            "returncode": process.returncode,
            "stdout": _record_file(stdout),
            "stderr": _record_file(stderr),
        }
        self.records.append(row)
        return {**row, "stdout_text": process.stdout, "stderr_text": process.stderr}


def candidate_profile() -> dict[str, Any]:
    return {
        "id": "mips32el-clang-candidate",
        "architecture": "mips",
        "header_type": "asm/posix_types.h",
        "extra_uapi_headers": ["sgidefs.h"],
        "kernel_revision": KERNEL_REVISION,
        "abi": {
            "bits": 32,
            "byte_order": "little",
            "char_unsigned": True,
            "wchar_bytes": 2,
            "short_bytes": 2,
            "int_bytes": 4,
            "long_bytes": 4,
            "long_long_bytes": 8,
            "pointer_bytes": 4,
            "long_alignment": 4,
            "pointer_alignment": 4,
            "long_long_alignment": 8,
        },
    }


def _load_setup(root: Path):
    path = root / "profiles/setup_mips_musl.py"
    specification = importlib.util.spec_from_file_location("fragma_mips_setup", path)
    require(specification is not None and specification.loader is not None,
            "cannot load MIPS sysroot verifier")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _git(recorder: Recorder, name: str, kernel: Path, args: list[str]) -> str:
    result = recorder.run(name, ["git", "-C", kernel, *args], timeout=30)
    require(result["returncode"] == 0 and not result["stderr_text"],
            f"kernel Git query failed: {name}")
    return result["stdout_text"].strip()


def _check_model(profile: dict[str, Any], candidate: Path) -> dict[str, Any]:
    checked = profiles.check_machine_description(profile, candidate)
    import yaml
    value = yaml.safe_load(candidate.read_text())
    expected = {
        "alignof_max_align_t": 8,
        "alignof_aligned": 16,
        "path_max": "4096",
        "tty_name_max": "32",
        "host_name_max": "255",
        "wordsize": "32",
        "wint_t": "unsigned int",
        "intptr_t": "int",
        "uintptr_t": "unsigned int",
    }
    require(isinstance(value, dict), "generator output is not a YAML mapping")
    for name, wanted in expected.items():
        require(value.get(name) == wanted,
                f"candidate field {name}: expected {wanted!r}, observed {value.get(name)!r}")
    require(value.get("compiler") == str(COMPILER), "candidate compiler identity changed")
    return {"abi_fields": checked, "additional_fields": expected,
            "machdep_name": value.get("machdep_name")}


def _elf_observation(path: Path, checked: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    try:
        parsed = elf.parse_relocatable(data, {"machdep": {"checked_fields": checked}})
    except elf.ELFError as exc:
        raise AdapterError(f"invalid compiler calibration object: {exc}") from exc
    require(parsed.bits == 32 and parsed.little and parsed.machine == 8,
            "calibration object is not ELF32 little-endian MIPS")
    flags = struct.unpack_from("<I", data, 36)[0]
    require(flags == 0x70001001, f"unexpected MIPS ELF flags: 0x{flags:x}")
    return {"class_bits": parsed.bits, "little_endian": parsed.little,
            "machine": parsed.machine, "flags": f"0x{flags:08x}",
            "sha256": digest(path)}


def generate(root: Path, *, sysroot: Path, kernel: Path, output: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    sysroot = Path(sysroot).resolve()
    kernel = Path(kernel).resolve()
    output = Path(output).absolute()
    require(not os.path.lexists(output), "output already exists; choose a fresh directory")
    require(kernel.is_dir() and not kernel.is_symlink(), "kernel Git tree is missing")
    output.mkdir(parents=True, mode=0o700)
    recorder = Recorder(output)
    result: dict[str, Any] = {
        "schema_version": 1,
        "kind": "mips32el-clang-machdep-candidate",
        "status": "failed",
        "level": "unregistered",
        "integration_eligible": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "commands": recorder.records,
        "network": False,
        "sudo": False,
        "scope": "Generator, compiler layout and Frama-C calibration only; no configured kernel build, L1, L2, runtime, concurrency, big-endian or 64-bit MIPS claim.",
    }
    try:
        provider_sha256 = digest(Path(__file__))
        setup = _load_setup(root)
        sysroot_receipt = setup.verify(sysroot)
        prefix = root / "toolchain/verified-prefix/opam/fragma"
        helper = prefix / "lib/frama-c/lib/make_machdep/make_machdep.py"
        schema = prefix / "share/frama-c/share/machdeps/machdep-schema.yaml"
        frama_c = prefix / "bin/frama-c"
        for path, wanted, role in (
            (COMPILER.resolve(), COMPILER_SHA256, "compiler"),
            (helper, GENERATOR_SHA256, "generator"),
            (schema, SCHEMA_SHA256, "schema"),
            (frama_c, FRAMA_C_SHA256, "Frama-C"),
        ):
            require(path.is_file() and digest(path) == wanted, f"{role} identity changed")
        resources = toolchain.clang_resource_tree(RESOURCE_ROOT)
        require(resources["include_tree_sha256"] == RESOURCE_SHA256,
                "Clang builtin header tree changed")
        probes = _probe_inventory(helper)

        version = recorder.run("compiler-version", [COMPILER, "--version"], timeout=30)
        versions = re.findall(r"clang version\s+(\d+\.\d+\.\d+)(?![\w.+-])",
                              version["stdout_text"])
        require(version["returncode"] == 0 and versions == [COMPILER_VERSION],
                "compiler version changed")
        target = recorder.run("compiler-target", [COMPILER, *ARCH_FLAGS[:5], "-dumpmachine"], timeout=30)
        require(target["returncode"] == 0 and not target["stderr_text"].strip()
                and target["stdout_text"].strip() == COMPILER_TARGET,
                "compiler target changed")
        revision = _git(recorder, "kernel-revision", kernel,
                        ["rev-parse", f"{KERNEL_REVISION}^{{commit}}"])
        tree = _git(recorder, "kernel-tree", kernel,
                    ["rev-parse", f"{KERNEL_REVISION}^{{tree}}"])
        require(revision == KERNEL_REVISION and tree == KERNEL_TREE,
                "pinned kernel revision/tree changed")

        generator_flags = [
            "-c", "-nostdinc",
            "-isystem", str(sysroot / "generator-overlay"),
            "-isystem", str(RESOURCE_ROOT / "include"),
            "-isystem", str(sysroot / "include"),
            "-D_POSIX_C_SOURCE=200809L",
        ]
        candidate = output / "mips32el-clang-candidate.yaml"
        generation = recorder.run("generate-machdep", [
            "/usr/bin/python3", helper,
            "--compiler", COMPILER,
            "--machdep-schema", schema,
            "--cpp-arch-flags=" + " ".join(ARCH_FLAGS),
            "--compiler-flags=" + " ".join(generator_flags),
            "--check", "-o", candidate,
        ])
        require(generation["returncode"] == 0 and not generation["stdout_text"].strip()
                and not generation["stderr_text"].strip() and candidate.is_file(),
                "upstream machine generator failed or emitted diagnostics")
        profile = candidate_profile()
        model = _check_model(profile, candidate)
        checked = model["abi_fields"]

        headers, header_hashes = profiles._export_headers(
            profile, kernel, output, env=ENVIRONMENT
        )
        source = root / "profiles/calibration.c"
        fixture_sha256 = digest(source)
        definitions = profiles._defines(profile)
        compile_flags = [*ARCH_FLAGS, *OBJECT_FLAGS, "-nostdinc", "-I", str(headers),
                         *definitions]
        calibration = output / "calibration.o"
        positive = recorder.run("compiler-calibration", [
            COMPILER, *compile_flags, "-Werror", "-c", source, "-o", calibration,
        ])
        require(positive["returncode"] == 0 and not positive["stdout_text"].strip()
                and not positive["stderr_text"].strip() and calibration.is_file(),
                "compiler/kernel-header calibration failed")
        object_observation = _elf_observation(calibration, checked)

        controls = []
        for name, flag, assertion in (
            ("wrong-width", "-DFRAGMA_POINTER_BYTES=8", "pointer width"),
            ("wrong-endian", "-DFRAGMA_BYTE_ORDER=4321", "compiler byte order"),
        ):
            target_object = output / f"{name}.o"
            run = recorder.run(name, [
                COMPILER, *compile_flags, flag, "-c", source, "-o", target_object,
            ])
            require(run["returncode"] != 0 and not target_object.exists()
                    and "static assertion failed" in run["stderr_text"]
                    and assertion in run["stderr_text"],
                    f"negative compiler control did not reject {name}")
            controls.append({"name": name, "status": "expected-rejection",
                             "assertion": assertion})

        cpp = shlex.join([str(COMPILER), "-E", "-C", *ARCH_FLAGS])
        cpp_extra = ["-nostdinc", "-I", str(headers), *definitions]
        semantic = {
            "wp_model": "Typed",
            "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS),
            "runtime_checks": dict(analysis_policy.RUNTIME_CHECKS),
        }
        base_frama = [
            frama_c, "-machdep", candidate,
            "-cpp-command", cpp, "-cpp-frama-c-compliant",
            "-cpp-extra-args=" + shlex.join(cpp_extra),
            *analysis_policy.analyzer_flags(semantic), source,
        ]
        parsing = recorder.run("frama-c-parse", base_frama)
        require(parsing["returncode"] == 0, "Frama-C representative parse failed")
        eva = recorder.run("frama-c-eva", [*base_frama, "-eva", "-eva-slevel", "10"])
        eva_text = eva["stdout_text"] + eva["stderr_text"]
        assertions = re.search(r"Assertions\s+(\d+) valid\s+(\d+) unknown\s+(\d+) invalid",
                               eva_text)
        require(eva["returncode"] == 0 and "0 alarms generated" in eva_text
                and assertions is not None and assertions.groups() == ("7", "0", "0"),
                "Frama-C Eva calibration did not prove the seven assertions")

        # Read every mutable input class again before issuing a passing receipt.
        require(setup.verify(sysroot) == sysroot_receipt,
                "MIPS sysroot input changed during calibration")
        require(toolchain.clang_resource_tree(RESOURCE_ROOT)["include_tree_sha256"]
                == RESOURCE_SHA256, "Clang resources changed during calibration")
        require(_probe_inventory(helper) == probes,
                "generator probes changed during calibration")
        for path, wanted in (
            (COMPILER.resolve(), COMPILER_SHA256), (helper, GENERATOR_SHA256),
            (schema, SCHEMA_SHA256), (frama_c, FRAMA_C_SHA256),
            (root / "profiles/calibration.c", fixture_sha256),
            (Path(__file__), provider_sha256),
        ):
            require(digest(path) == wanted, f"input changed during calibration: {path}")
        require(_git(recorder, "kernel-revision-after", kernel,
                     ["rev-parse", f"{KERNEL_REVISION}^{{commit}}"])
                == revision, "kernel revision changed during calibration")
        require(_git(recorder, "kernel-tree-after", kernel,
                     ["rev-parse", f"{KERNEL_REVISION}^{{tree}}"])
                == tree, "kernel tree changed during calibration")

        result.update({
            "status": "candidate-calibrated-not-L1",
            "inputs": {
                "provider": _record_file(Path(__file__)),
                "sysroot_receipt": _record_file(sysroot / "fragma-mips-sysroot.json"),
                "sysroot_archive_sha256": sysroot_receipt["archive_sha256"],
                "compiler": {"path": str(COMPILER), "resolved": str(COMPILER.resolve()),
                             "sha256": COMPILER_SHA256, "version": COMPILER_VERSION,
                             "target": COMPILER_TARGET},
                "resource_include_tree_sha256": RESOURCE_SHA256,
                "generator": _record_file(helper),
                "generator_probes": probes,
                "schema": _record_file(schema),
                "frama_c": _record_file(frama_c),
                "kernel_revision": revision,
                "kernel_tree": tree,
                "calibration_fixture": _record_file(source),
            },
            "candidate": {**_record_file(candidate), "checked": model},
            "exported_kernel_header_hashes": header_hashes,
            "compiler_calibration": object_observation,
            "negative_controls": controls,
            "input_drift": False,
            "frama_c": {
                "version": "33.0 (Arsenic)",
                "parse": "passed",
                "eva": {"alarms": 0, "assertions": {"valid": 7, "unknown": 0,
                                                       "invalid": 0}},
            },
            "limitations": [
                "The candidate is deliberately absent from config/profiles.json and toolchain/lock.json.",
                "No configured MIPS kernel translation unit or L1 build receipt was validated.",
                "No MIPS L2 proof target, target runtime, concurrency model, big-endian or 64-bit variant was validated.",
            ],
        })
    finally:
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        result["commands"] = recorder.records
        (output / "receipt.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sysroot", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    try:
        result = generate(root, sysroot=args.sysroot, kernel=args.kernel, output=args.output)
        print(json.dumps({"status": result["status"], "level": result["level"],
                          "integration_eligible": result["integration_eligible"]}))
        return 0 if result["status"] == "candidate-calibrated-not-L1" else 1
    except (AdapterError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
