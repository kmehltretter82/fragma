"""Source-linked C3 LKMM pilot for the System V IPC refcount lifetime gate."""

from __future__ import annotations

from datetime import datetime, timezone
from itertools import product
from pathlib import Path, PurePosixPath
import re
from typing import Any

from . import concurrency_c2, concurrency_c2_irq, concurrency_c3_lkmm
from . import concurrency_c3_module_stats, concurrency_c3_trace


class ConcurrencyC3IpcRefcountError(ValueError):
    """The IPC refcount declaration, source, build, or evidence is invalid."""


_CASE_IDS = {
    "refcount_put_get_positive",
    "unconditional_resurrection_negative",
}


_PROGRESS_CASE_SPECS = {
    "bounded_quiescent_strong_cas": {
        "role": "verification_candidate",
        "variant": "update_expected_on_mismatch",
        "verification_candidate": True,
        "control_for": None,
        "expected": {
            "total_schedules": 340,
            "successful": 150,
            "zero_exit": 190,
            "nonterminating": 0,
            "max_cas_attempts": 4,
            "max_failures": 3,
        },
    },
    "stale_expected_negative": {
        "role": "required_stale_expected_control",
        "variant": "retain_stale_expected_on_mismatch",
        "verification_candidate": False,
        "control_for": "bounded_quiescent_strong_cas",
        "expected": {
            "total_schedules": 340,
            "successful": 138,
            "zero_exit": 85,
            "nonterminating": 117,
            "max_cas_attempts": 4,
            "max_failures": 4,
        },
    },
    "spurious_failure_negative": {
        "role": "required_spurious_failure_control",
        "variant": "permit_spurious_failure_after_quiescence",
        "verification_candidate": False,
        "control_for": "bounded_quiescent_strong_cas",
        "expected": {
            "cycle_found": True,
            "cycle_length": 1,
            "state": {"refs": 1, "expected": 1},
        },
    },
    "unbounded_interference_negative": {
        "role": "required_unbounded_interference_control",
        "variant": "alternate_counter_forever",
        "verification_candidate": False,
        "control_for": "bounded_quiescent_strong_cas",
        "expected": {
            "cycle_found": True,
            "cycle_length": 2,
            "states": [
                {"refs": 1, "expected": 1},
                {"refs": 2, "expected": 2},
                {"refs": 1, "expected": 1},
            ],
            "interference": [2, 1],
        },
    },
}


_PROFILE_SPECS = {
    "x86_64-ipc-refcount-c3": {
        "arch": "x86_64",
        "subarch": None,
        "cross_compile": None,
        "base_recipe": "x86_64_defconfig",
        "compiler": "/usr/bin/gcc",
        "compiler_target": "x86_64-linux-gnu",
        "objdump": "/usr/bin/objdump",
        "elf": [2, 1, 62],
        "required_config": {
            "CONFIG_64BIT": "y",
            "CONFIG_X86_64": "y",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "y",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "n",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "arm64-ipc-refcount-c3": {
        "arch": "arm64",
        "subarch": None,
        "cross_compile": "/usr/bin/aarch64-linux-gnu-",
        "base_recipe": "defconfig",
        "compiler": "/usr/bin/aarch64-linux-gnu-gcc",
        "compiler_target": "aarch64-linux-gnu",
        "objdump": "/usr/bin/aarch64-linux-gnu-objdump",
        "elf": [2, 1, 183],
        "required_config": {
            "CONFIG_64BIT": "y",
            "CONFIG_ARM64": "y",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "y",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "absent",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "riscv64-ipc-refcount-c3": {
        "arch": "riscv",
        "subarch": None,
        "cross_compile": "/usr/bin/riscv64-linux-gnu-",
        "base_recipe": "defconfig",
        "compiler": "/usr/bin/riscv64-linux-gnu-gcc",
        "compiler_target": "riscv64-linux-gnu",
        "objdump": "/usr/bin/riscv64-linux-gnu-objdump",
        "elf": [2, 1, 243],
        "required_config": {
            "CONFIG_64BIT": "y",
            "CONFIG_RISCV": "y",
            "CONFIG_ARCH_RV64I": "y",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "absent",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "absent",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "s390x-ipc-refcount-c3": {
        "arch": "s390",
        "subarch": None,
        "cross_compile": "/usr/bin/s390x-linux-gnu-",
        "base_recipe": "defconfig",
        "compiler": "/usr/bin/s390x-linux-gnu-gcc",
        "compiler_target": "s390x-linux-gnu",
        "objdump": "/usr/bin/s390x-linux-gnu-objdump",
        "elf": [2, 2, 22],
        "required_config": {
            "CONFIG_64BIT": "y",
            "CONFIG_S390": "y",
            "CONFIG_CPU_BIG_ENDIAN": "y",
            "CONFIG_MARCH_Z13": "y",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "absent",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "n",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "arm32-ipc-refcount-c3": {
        "arch": "arm",
        "subarch": None,
        "cross_compile": "/usr/bin/arm-linux-gnueabi-",
        "base_recipe": "multi_v7_defconfig",
        "compiler": "/usr/bin/arm-linux-gnueabi-gcc",
        "compiler_target": "arm-linux-gnueabi",
        "objdump": "/usr/bin/arm-linux-gnueabi-objdump",
        "elf": [1, 1, 40],
        "required_config": {
            "CONFIG_ARM": "y",
            "CONFIG_CPU_V7": "y",
            "CONFIG_AEABI": "y",
            "CONFIG_CPU_LITTLE_ENDIAN": "y",
            "CONFIG_CPU_BIG_ENDIAN": "n",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "absent",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "absent",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "powerpc32-smp-ipc-refcount-c3": {
        "arch": "powerpc",
        "subarch": None,
        "cross_compile": "/usr/bin/powerpc-linux-gnu-",
        "base_recipe": "chrp32_defconfig",
        "compiler": "/usr/bin/powerpc-linux-gnu-gcc",
        "compiler_target": "powerpc-linux-gnu",
        "objdump": "/usr/bin/powerpc-linux-gnu-objdump",
        "elf": [1, 2, 20],
        "required_config": {
            "CONFIG_PPC": "y",
            "CONFIG_PPC32": "y",
            "CONFIG_PPC64": "n",
            "CONFIG_CPU_BIG_ENDIAN": "y",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "absent",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "n",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "sh-smp-ipc-refcount-c3": {
        "arch": "sh",
        "subarch": None,
        "cross_compile": "/usr/bin/sh4-linux-gnu-",
        "base_recipe": "shx3_defconfig",
        "compiler": "/usr/bin/sh4-linux-gnu-gcc",
        "compiler_target": "sh4-linux-gnu",
        "objdump": "/usr/bin/sh4-linux-gnu-objdump",
        "elf": [1, 1, 42],
        "required_config": {
            "CONFIG_SUPERH": "y",
            "CONFIG_CPU_SH4": "y",
            "CONFIG_CPU_SH4A": "y",
            "CONFIG_CPU_SUBTYPE_SHX3": "y",
            "CONFIG_CPU_LITTLE_ENDIAN": "y",
            "CONFIG_CPU_BIG_ENDIAN": "n",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "y",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "absent",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "alpha-smp-ipc-refcount-c3": {
        "arch": "alpha",
        "subarch": None,
        "cross_compile": "/usr/bin/alpha-linux-gnu-",
        "base_recipe": "defconfig",
        "mutations": [{"symbol": "SMP", "operation": "enable"}],
        "compiler": "/usr/bin/alpha-linux-gnu-gcc",
        "compiler_target": "alpha-linux-gnu",
        "objdump": "/usr/bin/alpha-linux-gnu-objdump",
        "elf": [2, 1, 36902],
        "required_config": {
            "CONFIG_ALPHA": "y",
            "CONFIG_ALPHA_GENERIC": "y",
            "CONFIG_64BIT": "y",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "absent",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "absent",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
    "um-x86_64-smp-ipc-refcount-c3": {
        "arch": "um",
        "subarch": "x86_64",
        "cross_compile": None,
        "base_recipe": "x86_64_defconfig",
        "mutations": [{"symbol": "SMP", "operation": "enable"}],
        "compiler": "/usr/bin/gcc",
        "compiler_target": "x86_64-linux-gnu",
        "objdump": "/usr/bin/objdump",
        "elf": [2, 1, 62],
        "required_config": {
            "CONFIG_UML": "y",
            "CONFIG_UML_X86": "y",
            "CONFIG_64BIT": "y",
            "CONFIG_X86_64": "y",
            "CONFIG_X86_32": "absent",
            "CONFIG_SMP": "y",
            "CONFIG_SYSVIPC": "y",
            "CONFIG_TREE_RCU": "y",
            "CONFIG_PREEMPT_RCU": "absent",
            "CONFIG_RCU_EXPERT": "n",
            "CONFIG_KCSAN": "absent",
            "CONFIG_CC_IS_GCC": "y",
        },
    },
}


_EMPTY_BUILD_DIAGNOSTICS = {
    "base-config": [],
    "config-mutation": [],
    "finalize-config": [],
    "object": [],
}


_PROFILE_DIAGNOSTICS = {
    profile_id: {
        **_EMPTY_BUILD_DIAGNOSTICS,
        **({
            "object": [
                "<stdin>:1519:2: warning: #warning syscall clone3 not implemented [-Wcpp]"
            ],
        } if profile_id == "sh-smp-ipc-refcount-c3" else {}),
    }
    for profile_id in _PROFILE_SPECS
}


_ARCHITECTURE_EXCLUSION = (
    "No architecture implementation other than the nine configured SMP "
    "x86-64, arm64, riscv64, s390x, ARM32, PowerPC32, SuperH, Alpha and "
    "UML x86-64 "
    "profiles is accepted by this source-linked pilot; every other "
    "architecture remains outside the claim."
)


def _strict_json(path: Path) -> Any:
    try:
        return concurrency_c3_lkmm._strict_json(path)
    except concurrency_c3_lkmm.ConcurrencyC3LkmmError as exc:
        raise ConcurrencyC3IpcRefcountError(str(exc)) from exc


def _json(path: Path, value: Any) -> None:
    concurrency_c3_lkmm._json(path, value)


def _sha256(path: Path) -> str:
    return concurrency_c3_lkmm._sha256(path)


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyC3IpcRefcountError(f"{role} must be a nonempty string")
    return value


def _digest(value: Any, role: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        rf"[0-9a-f]{{{length}}}", value
    ):
        raise ConcurrencyC3IpcRefcountError(
            f"{role} is not a {length}-digit hex digest"
        )
    return value


def _strings(value: Any, role: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ConcurrencyC3IpcRefcountError(
            f"{role} must be a nonempty unique string list"
        )
    return value


def _relative(
    root: Path, value: Any, role: str, *, directory: bool = False
) -> Path:
    try:
        return concurrency_c3_lkmm._relative(
            root, value, role, directory=directory
        )
    except concurrency_c3_lkmm.ConcurrencyC3LkmmError as exc:
        raise ConcurrencyC3IpcRefcountError(str(exc)) from exc


def _declared_path(root: Path, value: Any, role: str) -> Path:
    if not isinstance(value, str):
        raise ConcurrencyC3IpcRefcountError(f"{role} must be project-relative")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC3IpcRefcountError(
            f"{role} must be project-relative: {value!r}"
        )
    path = root.joinpath(*pure.parts)
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ConcurrencyC3IpcRefcountError(f"{role} escapes project root") from exc
    return path


def _validate_tool(record: Any, name: str, *, target: bool = False) -> None:
    keys = {"binary", "realpath", "sha256", "version_line"}
    if target:
        keys.add("target")
    if not isinstance(record, dict) or set(record) != keys:
        raise ConcurrencyC3IpcRefcountError(f"{name} tool record is not exact")
    for key in ("binary", "realpath"):
        path = Path(_nonempty(record[key], f"{name} {key}"))
        if not path.is_absolute() or (key == "binary" and not path.is_file()):
            raise ConcurrencyC3IpcRefcountError(f"{name} {key} must be absolute")
    _digest(record["sha256"], f"{name} identity")
    _nonempty(record["version_line"], f"{name} version")
    if target:
        _nonempty(record["target"], f"{name} target")


def _validate_expected(expected: Any, case_id: str) -> None:
    if not isinstance(expected, dict) or set(expected) != {
        "test", "disposition", "states", "marker", "positive", "negative",
        "flags", "condition", "observation", "hash",
    }:
        raise ConcurrencyC3IpcRefcountError(
            f"expected output for {case_id} is not exact"
        )
    for key in ("test", "disposition", "marker", "condition", "observation"):
        _nonempty(expected[key], f"{case_id} expected {key}")
    for key in ("states", "positive", "negative"):
        if type(expected[key]) is not int or expected[key] < 0:
            raise ConcurrencyC3IpcRefcountError(
                f"{case_id} expected {key} is invalid"
            )
    if expected["flags"] != []:
        raise ConcurrencyC3IpcRefcountError(f"{case_id} flags must be empty")
    _digest(expected["hash"], f"{case_id} herd hash", 32)


def _validate_progress(progress: Any) -> None:
    if not isinstance(progress, dict) or set(progress) != {
        "kind", "claim", "backend", "source_function", "selected_caller",
        "implementation_profiles", "domain", "semantics", "assumptions",
        "exclusions", "cases",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC progress record is not exact")
    if (
        progress["kind"] != "bounded_quiescent_retry_progress"
        or progress["backend"] != "project-owned-exhaustive-finite-state-enumerator"
        or progress["source_function"] != "__refcount_add_not_zero"
        or progress["selected_caller"] != "ipc_rcu_getref"
        or progress["implementation_profiles"] != [
            "x86_64-ipc-refcount-c3",
            "um-x86_64-smp-ipc-refcount-c3",
        ]
    ):
        raise ConcurrencyC3IpcRefcountError("unexpected IPC progress scope")
    _nonempty(progress["claim"], "IPC progress claim")
    if progress["domain"] != {
        "initial_values": [0, 1, 2, 3],
        "interference_values": [0, 1, 2, 3],
        "max_interference_observations": 3,
        "increment": 1,
        "max_cas_attempts": 4,
    }:
        raise ConcurrencyC3IpcRefcountError("IPC progress domain is not exact")
    semantics = progress["semantics"]
    if not isinstance(semantics, dict) or set(semantics) != {
        "loop_head_zero", "strong_cas_match", "strong_cas_mismatch",
        "quiescence",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC progress semantics are not exact")
    for key, value in semantics.items():
        _nonempty(value, f"IPC progress semantics {key}")
    assumptions = " ".join(
        _strings(progress["assumptions"], "IPC progress assumptions")
    ).lower()
    for required in (
        "caller-locking", "storage valid", "scheduled", "strong",
        "non-spurious", "updates old", "three", "saturation",
        "x86 cmpxchg", "hardware failure",
    ):
        if required not in assumptions:
            raise ConcurrencyC3IpcRefcountError(
                f"IPC progress assumptions omit {required}"
            )
    exclusions = " ".join(
        _strings(progress["exclusions"], "IPC progress exclusions")
    ).lower()
    for required in (
        "unbounded interference", "wait-free", "spurious", "ll/sc",
        "saturation", "scheduler fairness", "whole-kernel",
    ):
        if required not in exclusions:
            raise ConcurrencyC3IpcRefcountError(
                f"IPC progress exclusions omit {required}"
            )
    cases = progress["cases"]
    expected_ids = list(_PROGRESS_CASE_SPECS)
    if (
        not isinstance(cases, list)
        or [case.get("id") if isinstance(case, dict) else None for case in cases]
        != expected_ids
    ):
        raise ConcurrencyC3IpcRefcountError("IPC progress case inventory is not exact")
    for case in cases:
        if set(case) != {
            "id", "role", "variant", "verification_candidate", "control_for",
            "expected",
        }:
            raise ConcurrencyC3IpcRefcountError("IPC progress case is not exact")
        expected = _PROGRESS_CASE_SPECS[case["id"]]
        if {key: case[key] for key in expected} != expected:
            raise ConcurrencyC3IpcRefcountError(
                f"IPC progress case {case['id']} cannot satisfy its evidence role"
            )


def _validate_profile(root: Path, profile: Any, expected_id: str) -> None:
    if not isinstance(profile, dict) or set(profile) != {
        "id", "arch", "subarch", "cross_compile", "jobs", "build_directory",
        "config", "config_sha256", "execution_scope", "configuration",
        "required_config", "allowed_diagnostics", "make", "compiler",
        "objdump", "configured_compile",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC build profile is not exact")
    spec = _PROFILE_SPECS[expected_id]
    if (
        profile["id"] != expected_id
        or profile["arch"] != spec["arch"]
        or profile["subarch"] != spec["subarch"]
        or profile["cross_compile"] != spec["cross_compile"]
        or type(profile["jobs"]) is not int
        or not 1 <= profile["jobs"] <= 256
    ):
        raise ConcurrencyC3IpcRefcountError(
            f"unexpected IPC build profile {expected_id}"
        )
    if profile["execution_scope"] != "smp-multicpu":
        raise ConcurrencyC3IpcRefcountError(
            f"unexpected execution scope for {expected_id}"
        )
    expected_build = f"build/kernel/{expected_id}"
    build_directory = _declared_path(
        root, profile["build_directory"], f"{expected_id} build directory"
    )
    if profile["build_directory"] != expected_build:
        raise ConcurrencyC3IpcRefcountError(
            f"unexpected build directory for {expected_id}"
        )
    config_path = _declared_path(root, profile["config"], f"{expected_id} config")
    if profile["config"] != f"{expected_build}/.config":
        raise ConcurrencyC3IpcRefcountError(
            f"unexpected config path for {expected_id}"
        )
    try:
        config_path.resolve().relative_to(build_directory.resolve())
    except ValueError as exc:
        raise ConcurrencyC3IpcRefcountError(
            f"kernel config is outside {expected_id} build directory"
        ) from exc
    _digest(profile["config_sha256"], f"{expected_id} config identity")
    if profile["configuration"] != {
        "base_recipe": spec["base_recipe"],
        "mutations": spec.get("mutations", []),
        "finalize_recipe": "olddefconfig",
    }:
        raise ConcurrencyC3IpcRefcountError(
            f"unexpected IPC config recipe for {expected_id}"
        )
    if profile["required_config"] != spec["required_config"]:
        raise ConcurrencyC3IpcRefcountError(
            f"IPC config requirements are not exact for {expected_id}"
        )
    if profile["allowed_diagnostics"] != _PROFILE_DIAGNOSTICS[expected_id]:
        raise ConcurrencyC3IpcRefcountError(
            f"IPC diagnostic allowlist is not exact for {expected_id}"
        )
    for tool_name in ("make", "compiler", "objdump"):
        _validate_tool(profile[tool_name], f"{expected_id} {tool_name}",
                       target=tool_name == "compiler")
    if (
        profile["make"]["binary"] != "/usr/bin/make"
        or profile["compiler"]["binary"] != spec["compiler"]
        or profile["compiler"]["target"] != spec["compiler_target"]
        or profile["objdump"]["binary"] != spec["objdump"]
    ):
        raise ConcurrencyC3IpcRefcountError(
            f"unexpected tool mapping for {expected_id}"
        )

    compile_record = profile["configured_compile"]
    if not isinstance(compile_record, dict) or set(compile_record) != {
        "target", "object", "command_file", "object_sha256", "command_sha256",
        "elf_class", "elf_data", "elf_machine", "required_command_tokens",
        "functions",
    }:
        raise ConcurrencyC3IpcRefcountError(
            f"configured IPC compile is not exact for {expected_id}"
        )
    if compile_record["target"] != "ipc/util.o":
        raise ConcurrencyC3IpcRefcountError("unexpected IPC object target")
    expected_paths = {
        "object": f"{expected_build}/ipc/util.o",
        "command_file": f"{expected_build}/ipc/.util.o.cmd",
    }
    for key, expected_path in expected_paths.items():
        if compile_record[key] != expected_path:
            raise ConcurrencyC3IpcRefcountError(
                f"unexpected configured {key} for {expected_id}"
            )
        path = _declared_path(root, compile_record[key], f"configured {key}")
        try:
            path.resolve().relative_to(build_directory.resolve())
        except ValueError as exc:
            raise ConcurrencyC3IpcRefcountError(
                f"configured {key} is outside {expected_id} build"
            ) from exc
    _digest(compile_record["object_sha256"], f"{expected_id} object identity")
    _digest(compile_record["command_sha256"], f"{expected_id} command identity")
    actual_elf = [
        compile_record[key] for key in ("elf_class", "elf_data", "elf_machine")
    ]
    if actual_elf != spec["elf"]:
        raise ConcurrencyC3IpcRefcountError(
            f"configured object has the wrong ELF identity for {expected_id}"
        )
    tokens = _strings(
        compile_record["required_command_tokens"],
        f"{expected_id} compile command tokens",
    )
    for required in (spec["compiler"], "-D__KERNEL__", "ipc/util.o", "ipc/util.c"):
        if required not in tokens:
            raise ConcurrencyC3IpcRefcountError(
                f"{expected_id} compile command omits {required}"
            )
    functions = compile_record["functions"]
    if not isinstance(functions, dict) or set(functions) != {
        "ipc_rcu_getref", "ipc_rcu_putref",
    }:
        raise ConcurrencyC3IpcRefcountError(
            f"configured function inventory is not exact for {expected_id}"
        )
    address_digits = 8 if compile_record["elf_class"] == 1 else 16
    for name, function in functions.items():
        if (
            not isinstance(function, dict)
            or set(function) != {"section", "value", "size", "disassembly_order"}
            or function["section"] != ".text"
            or not re.fullmatch(
                rf"[0-9a-f]{{{address_digits}}}", function["value"]
            )
            or type(function["size"]) is not int
            or function["size"] < 1
        ):
            raise ConcurrencyC3IpcRefcountError(
                f"invalid configured function {name} for {expected_id}"
            )
        order = _strings(
            function["disassembly_order"],
            f"{expected_id} {name} disassembly order",
        )
        if order[0] != f"<{name}>:":
            raise ConcurrencyC3IpcRefcountError(
                f"{expected_id} {name} disassembly does not start at the function"
            )


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and aggressively validate the sole IPC lifetime pilot."""
    root = root.resolve()
    manifest = _strict_json(root / "config/concurrency-c3-ipc-refcount.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema_version", "id", "kernel", "baseline", "profiles",
            "property", "progress", "model",
        }
        or manifest["schema_version"] != 5
        or manifest["id"] != "linux-ipc-refcount-lifetime-multiarch-c3"
    ):
        raise ConcurrencyC3IpcRefcountError("unsupported IPC refcount C3 schema")

    kernel = manifest["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
        "revision", "git_tree", "source_root", "source_receipt",
        "source_identities",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC refcount kernel record is not exact")
    _digest(kernel["revision"], "kernel revision", 40)
    _digest(kernel["git_tree"], "kernel tree", 40)
    source_root = _relative(root, kernel["source_root"], "kernel source", directory=True)
    receipt = _relative(root, kernel["source_receipt"], "source receipt")
    try:
        receipt.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ConcurrencyC3IpcRefcountError(
            "source receipt is outside kernel source"
        ) from exc
    identities = kernel["source_identities"]
    if not isinstance(identities, dict) or len(identities) != 47:
        raise ConcurrencyC3IpcRefcountError(
            "IPC refcount source identity set is not exact"
        )
    for name, digest in identities.items():
        _relative(root, name, "IPC refcount source identity")
        _digest(digest, f"source identity for {name}")

    baseline = manifest["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != {
        "manifest", "id", "required_capability",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC baseline link is not exact")
    _relative(root, baseline["manifest"], "C3 baseline manifest")
    if (
        baseline["id"] != "linux-lkmm-herd7-c3-calibration"
        or baseline["required_capability"] != "c3_capability_baseline_complete"
    ):
        raise ConcurrencyC3IpcRefcountError("IPC pilot names the wrong baseline")

    profiles = manifest["profiles"]
    expected_ids = list(_PROFILE_SPECS)
    if (
        not isinstance(profiles, list)
        or len(profiles) != len(expected_ids)
        or [profile.get("id") if isinstance(profile, dict) else None
            for profile in profiles] != expected_ids
    ):
        raise ConcurrencyC3IpcRefcountError(
            "IPC architecture profile inventory is not exact"
        )
    for profile, expected_id in zip(profiles, expected_ids, strict=True):
        _validate_profile(root, profile, expected_id)

    prop = manifest["property"]
    if not isinstance(prop, dict) or set(prop) != {
        "kind", "claim", "source_file", "contract_file", "refcount_file",
        "get_function", "put_function", "get_source", "put_test_source",
        "put_destroy_source", "initial_refcount", "stability_argument",
        "lifetime_argument", "model_argument", "implementation_argument",
        "exclusions",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC refcount property record is not exact")
    if (
        prop["kind"] != "kernel_refcount_final_put_vs_get_unless_zero"
        or prop["get_function"] != "ipc_rcu_getref"
        or prop["put_function"] != "ipc_rcu_putref"
        or prop["get_source"] != "return refcount_inc_not_zero(&ptr->refcount);"
        or prop["put_test_source"] != "if (!refcount_dec_and_test(&ptr->refcount))"
        or prop["put_destroy_source"] != "call_rcu(&ptr->rcu, func);"
        or prop["initial_refcount"] != 1
    ):
        raise ConcurrencyC3IpcRefcountError("unexpected IPC refcount property")
    for key in ("source_file", "contract_file", "refcount_file"):
        _relative(root, prop[key], f"property {key}")
    for key in (
        "claim", "stability_argument", "lifetime_argument", "model_argument",
        "implementation_argument",
    ):
        _nonempty(prop[key], f"property {key}")
    exclusion_items = _strings(prop["exclusions"], "property exclusions")
    if _ARCHITECTURE_EXCLUSION not in exclusion_items:
        raise ConcurrencyC3IpcRefcountError(
            "IPC property architecture exclusion does not match its profiles"
        )
    exclusions = " ".join(exclusion_items).lower()
    for boundary in (
        "caller-locking", "third refcount update", "rcu grace", "saturation",
        "control-dependency", "detecting control", "architecture", "progress",
        "whole-kernel",
    ):
        if boundary not in exclusions:
            raise ConcurrencyC3IpcRefcountError(
                f"IPC property omits {boundary} exclusion"
            )

    _validate_progress(manifest["progress"])

    model = manifest["model"]
    if not isinstance(model, dict) or set(model) != {
        "condition", "abstraction", "pair", "cases",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC model record is not exact")
    if model["condition"] != "exists (0:released=1 /\\ 1:acquired=1)":
        raise ConcurrencyC3IpcRefcountError("unexpected IPC model condition")
    abstraction = model["abstraction"]
    if not isinstance(abstraction, dict) or set(abstraction) != {
        "refcount", "put", "get", "control", "omitted",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC abstraction is not exact")
    for key, value in abstraction.items():
        _nonempty(value, f"IPC abstraction {key}")
    pair = model["pair"]
    if pair != {
        "id": "ipc_refcount_no_final_put_get_overlap",
        "positive": "refcount_put_get_positive",
        "negative": "unconditional_resurrection_negative",
        "expected_transition": "Sometimes->Never",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC A/B pair is not exact")
    cases = model["cases"]
    if not isinstance(cases, list) or len(cases) != 2:
        raise ConcurrencyC3IpcRefcountError("IPC pilot requires two cases")
    by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id", "path", "sha256", "role", "verification_candidate",
            "control_for", "required_operations", "forbidden_operations",
            "expected",
        }:
            raise ConcurrencyC3IpcRefcountError("IPC case record is not exact")
        case_id = case["id"]
        if case_id not in _CASE_IDS or case_id in by_id:
            raise ConcurrencyC3IpcRefcountError(
                f"invalid or duplicate IPC case {case_id!r}"
            )
        by_id[case_id] = case
        _relative(root, case["path"], f"model for {case_id}")
        _digest(case["sha256"], f"model identity for {case_id}")
        required = _strings(case["required_operations"], f"{case_id} required operations")
        forbidden = _strings(case["forbidden_operations"], f"{case_id} forbidden operations")
        if set(required) & set(forbidden):
            raise ConcurrencyC3IpcRefcountError(
                f"contradictory operations for {case_id}"
            )
        _validate_expected(case["expected"], case_id)
        if (
            case["expected"]["disposition"] != "Allowed"
            or case["expected"]["condition"] != model["condition"]
        ):
            raise ConcurrencyC3IpcRefcountError(
                f"{case_id} query or condition drift"
            )
    if set(by_id) != _CASE_IDS:
        raise ConcurrencyC3IpcRefcountError("IPC case inventory is incomplete")
    positive = by_id["refcount_put_get_positive"]
    negative = by_id["unconditional_resurrection_negative"]
    if (
        positive["role"] != "verification_candidate"
        or positive["verification_candidate"] is not True
        or positive["control_for"] is not None
        or positive["expected"]["observation"] != "Never"
        or positive["expected"]["positive"] != 0
        or positive["expected"]["marker"] != "No"
    ):
        raise ConcurrencyC3IpcRefcountError(
            "positive IPC case cannot satisfy its evidence role"
        )
    if (
        negative["role"] != "required_unsafe_control"
        or negative["verification_candidate"] is not False
        or negative["control_for"] != positive["id"]
        or negative["expected"]["observation"] != "Sometimes"
        or negative["expected"]["positive"] < 1
        or negative["expected"]["marker"] != "Ok"
    ):
        raise ConcurrencyC3IpcRefcountError(
            "unsafe IPC control cannot satisfy its evidence role"
        )
    return manifest


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {"name": name, "expected": expected, "actual": actual,
            "passed": expected == actual}


def _ordered(text: str, snippets: list[str]) -> bool:
    return concurrency_c3_trace._ordered(text, snippets)


def _function_source(path: Path, function: str) -> str:
    try:
        return concurrency_c2_irq.extract_function(path.read_text(), function)
    except concurrency_c2_irq.ConcurrencyC2IrqError as exc:
        raise ConcurrencyC3IpcRefcountError(str(exc)) from exc


def _function_symbols(
    value: str, names: set[str], address_digits: int = 16
) -> dict[str, dict[str, Any]]:
    if address_digits not in (8, 16):
        raise ConcurrencyC3IpcRefcountError(
            "function symbol address width must be 8 or 16"
        )
    found: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        rf"^(?P<value>[0-9a-f]{{{address_digits}}})\s+g\s+F\s+"
        r"(?P<section>\.[A-Za-z0-9_.]+)\s+"
        rf"(?P<size>[0-9a-f]{{{address_digits}}})"
        r"(?:\s+0x[0-9a-f]+)?\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(value):
        name = match.group("name")
        if name in names:
            if name in found:
                raise ConcurrencyC3IpcRefcountError(
                    f"duplicate configured function {name}"
                )
            found[name] = {
                "section": match.group("section"),
                "value": match.group("value"),
                "size": int(match.group("size"), 16),
            }
    return found


def _simulate_bounded_schedule(
    initial: int,
    schedule: tuple[int, ...],
    *,
    increment: int,
    update_expected: bool,
) -> dict[str, Any]:
    """Execute one finite interference prefix followed by quiescence."""
    refs = initial
    expected = initial
    attempts = 0
    failures = 0
    trace: list[dict[str, Any]] = [
        {"event": "initial-read", "refs": refs, "expected": expected}
    ]

    def terminal(outcome: str) -> dict[str, Any]:
        return {
            "outcome": outcome,
            "initial": initial,
            "schedule": list(schedule),
            "cas_attempts": attempts,
            "cas_failures": failures,
            "final_state": {"refs": refs, "expected": expected},
            "trace": trace,
        }

    for observed in schedule:
        if expected == 0:
            trace.append({
                "event": "zero-exit", "refs": refs, "expected": expected,
            })
            return terminal("zero_exit")
        refs = observed
        trace.append({
            "event": "interference-observation",
            "refs": refs,
            "expected": expected,
        })
        attempts += 1
        if refs == expected:
            refs = expected + increment
            trace.append({
                "event": "cas-success", "refs": refs, "expected": expected,
            })
            return terminal("successful")
        failures += 1
        previous = expected
        if update_expected:
            expected = refs
        trace.append({
            "event": "cas-mismatch",
            "refs": refs,
            "expected_before": previous,
            "expected_after": expected,
        })

    if expected == 0:
        trace.append({
            "event": "zero-exit-after-quiescence",
            "refs": refs,
            "expected": expected,
        })
        return terminal("zero_exit")
    attempts += 1
    if refs == expected:
        refs = expected + increment
        trace.append({
            "event": "quiescent-cas-success",
            "refs": refs,
            "expected": expected,
        })
        return terminal("successful")
    if update_expected:
        raise ConcurrencyC3IpcRefcountError(
            "updated expected value disagrees with quiescent counter"
        )
    failures += 1
    trace.append({
        "event": "quiescent-stale-expected-cycle",
        "refs": refs,
        "expected": expected,
    })
    return terminal("nonterminating")


def _bounded_progress_aggregate(
    domain: dict[str, Any], *, update_expected: bool
) -> dict[str, Any]:
    schedules = [
        schedule
        for length in range(domain["max_interference_observations"] + 1)
        for schedule in product(domain["interference_values"], repeat=length)
    ]
    rows = [
        _simulate_bounded_schedule(
            initial,
            schedule,
            increment=domain["increment"],
            update_expected=update_expected,
        )
        for initial in domain["initial_values"]
        for schedule in schedules
    ]
    max_attempts = max(row["cas_attempts"] for row in rows)
    max_failures = max(row["cas_failures"] for row in rows)
    nonterminating = [row for row in rows if row["outcome"] == "nonterminating"]
    return {
        "total_schedules": len(rows),
        "successful": sum(row["outcome"] == "successful" for row in rows),
        "zero_exit": sum(row["outcome"] == "zero_exit" for row in rows),
        "nonterminating": len(nonterminating),
        "max_cas_attempts": max_attempts,
        "max_failures": max_failures,
        "max_attempt_witness": next(
            row for row in rows if row["cas_attempts"] == max_attempts
        ),
        "nonterminating_witness": nonterminating[0] if nonterminating else None,
    }


def _progress_core(actual: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    return {key: actual.get(key) for key in expected}


def _spurious_failure_cycle() -> dict[str, Any]:
    before = {"refs": 1, "expected": 1}
    # A spurious failure changes neither operand, so it returns to the same
    # nonterminal loop head even after the environment has quiesced.
    after = dict(before)
    return {
        "cycle_found": before == after,
        "cycle_length": 1,
        "state": after,
        "trace": [
            {"event": "loop-head", **before},
            {"event": "spurious-cas-failure", **after},
            {"event": "same-loop-head", **after},
        ],
    }


def _unbounded_interference_cycle() -> dict[str, Any]:
    refs = 1
    expected = 1
    states = [{"refs": refs, "expected": expected}]
    interference = [2, 1]
    trace: list[str] = []
    for observed in interference:
        refs = observed
        if refs == expected:
            raise ConcurrencyC3IpcRefcountError(
                "unbounded-interference control unexpectedly permits CAS success"
            )
        previous = expected
        expected = refs
        states.append({"refs": refs, "expected": expected})
        trace.append(
            f"observe {refs}, fail expected {previous}, update expected to {expected}"
        )
    return {
        "cycle_found": states[-1] == states[0],
        "cycle_length": len(interference),
        "states": states,
        "interference": interference,
        "trace": trace,
    }


def _run_progress_model(
    root: Path,
    manifest: dict[str, Any],
    profile_results: list[dict[str, Any]],
    output: Path,
) -> dict[str, Any]:
    progress = manifest["progress"]
    domain = progress["domain"]
    output.mkdir()
    actual_by_id = {
        "bounded_quiescent_strong_cas": _bounded_progress_aggregate(
            domain, update_expected=True
        ),
        "stale_expected_negative": _bounded_progress_aggregate(
            domain, update_expected=False
        ),
        "spurious_failure_negative": _spurious_failure_cycle(),
        "unbounded_interference_negative": _unbounded_interference_cycle(),
    }
    checks: list[dict[str, Any]] = []
    case_results: list[dict[str, Any]] = []
    for case in progress["cases"]:
        actual = actual_by_id[case["id"]]
        case_checks = [
            _check(
                f"progress {case['id']}: expected result",
                case["expected"],
                _progress_core(actual, case["expected"]),
            ),
            _check(
                f"progress {case['id']}: verification eligibility",
                case["id"] == "bounded_quiescent_strong_cas",
                case["verification_candidate"],
            ),
        ]
        checks.extend(case_checks)
        case_results.append({
            "id": case["id"],
            "role": case["role"],
            "variant": case["variant"],
            "verification_candidate": case["verification_candidate"],
            "control_for": case["control_for"],
            "actual": actual,
            "checks": case_checks,
            "passed": all(item["passed"] for item in case_checks),
        })

    source_root = root / manifest["kernel"]["source_root"]
    refcount_path = _relative(
        root, manifest["property"]["refcount_file"], "progress refcount source"
    )
    add_not_zero = _function_source(refcount_path, progress["source_function"])
    fallback = (
        source_root / "include/linux/atomic/atomic-arch-fallback.h"
    ).read_text()
    x86_cmpxchg = (source_root / "arch/x86/include/asm/cmpxchg.h").read_text()
    checks.extend([
        _check("progress loop starts from one atomic read", 1,
               add_not_zero.count("int old = refcount_read(r);")),
        _check("progress loop exits on observed zero before CAS", True,
               _ordered(add_not_zero, ["if (!old)", "break;",
                                       "atomic_try_cmpxchg_relaxed"])),
        _check("progress loop passes expected by address", 1,
               add_not_zero.count(
                   "atomic_try_cmpxchg_relaxed(&r->refs, &old, old + i)"
               )),
        _check("strong CAS contract updates expected on mismatch", True,
               _ordered(fallback, [
                   "If (@v == @old), atomically updates @v to @new",
                   "Otherwise, @v is not modified, @old is updated to the current value",
                   "Return: @true if the exchange occurred, @false otherwise.",
               ])),
        _check("generic strong CAS fallback writes current expected", True,
               _ordered(fallback, [
                   "r = raw_atomic_cmpxchg_relaxed(v, o, new);",
                   "if (unlikely(r != o))",
                   "*old = r;",
                   "return likely(r == o);",
               ])),
        _check("x86 strong CAS writes instruction result on failure", True,
               _ordered(x86_cmpxchg, [
                   "#define __raw_try_cmpxchg",
                   'asm_inline volatile(lock "cmpxchgl %[new], %[ptr]"',
                   "if (unlikely(!success))",
                   "*_old = __old;",
                   "likely(success);",
               ])),
    ])

    result_profiles = {profile["id"]: profile for profile in profile_results}
    manifest_profiles = {
        profile["id"]: profile for profile in manifest["profiles"]
    }
    retry_tokens = {
        "x86_64-ipc-refcount-c3": [
            "lock cmpxchg", "mov    %eax,%edx",
            "jmp    bfe <ipc_rcu_getref+0xe>",
        ],
        "um-x86_64-smp-ipc-refcount-c3": [
            "lock cmpxchg", "mov    %eax,%ebx",
            "jmp    9c9 <ipc_rcu_getref+0x14>",
        ],
    }
    for profile_id in progress["implementation_profiles"]:
        profile = result_profiles[profile_id]
        declared = manifest_profiles[profile_id]["configured_compile"]["functions"]
        order = declared["ipc_rcu_getref"]["disassembly_order"]
        checks.extend([
            _check(f"progress mapping {profile_id}: build gate", True,
                   profile["accepted"]),
            _check(f"progress mapping {profile_id}: strong CAS retry lowering",
                   True, all(token in order for token in retry_tokens[profile_id])),
        ])

    positive = actual_by_id["bounded_quiescent_strong_cas"]
    stale = actual_by_id["stale_expected_negative"]
    spurious = actual_by_id["spurious_failure_negative"]
    unbounded = actual_by_id["unbounded_interference_negative"]
    checks.extend([
        _check("bounded source model always terminates", 0,
               positive["nonterminating"]),
        _check("bounded source model obeys declared CAS bound",
               domain["max_cas_attempts"], positive["max_cas_attempts"]),
        _check("stale-expected control exposes quiescent cycles", True,
               stale["nonterminating"] > 0),
        _check("spurious-failure control exposes a self-cycle", True,
               spurious["cycle_found"] and spurious["cycle_length"] == 1),
        _check("unbounded-interference control exposes starvation cycle", True,
               unbounded["cycle_found"] and unbounded["cycle_length"] == 2),
    ])
    accepted = all(item["passed"] for item in checks)
    result = {
        "kind": progress["kind"],
        "backend": progress["backend"],
        "claim": progress["claim"],
        "implementation_profiles": progress["implementation_profiles"],
        "domain": domain,
        "assumptions": progress["assumptions"],
        "exclusions": progress["exclusions"],
        "cases": case_results,
        "checks": checks,
        "accepted": accepted,
        "kernel_verification_count": 1 if accepted else 0,
        "detecting_control_count": 3 if accepted else 0,
    }
    _json(output / "result.json", result)
    return result


def _diagnostic_lines(process: dict[str, Any]) -> list[str]:
    """Return stable compiler/make diagnostics without treating chatter as one."""
    selected: list[str] = []
    for stream in (process["stdout"], process["stderr"]):
        for line in stream.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if (
                re.search(r"(?:^|:\s)(?:warning|error):", lowered)
                or "jobserver" in lowered
                or "file exists" in lowered
            ):
                selected.append(stripped)
    return selected


def _semantic_checks(
    root: Path, manifest: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kernel = manifest["kernel"]
    prop = manifest["property"]
    model = manifest["model"]
    source_root = root / kernel["source_root"]
    source_path = _relative(root, prop["source_file"], "IPC source")
    contract_path = _relative(root, prop["contract_file"], "IPC contract")
    refcount_path = _relative(root, prop["refcount_file"], "refcount source")
    source = source_path.read_text()
    contract = contract_path.read_text()
    refcount = refcount_path.read_text()
    get_body = _function_source(source_path, prop["get_function"])
    put_body = _function_source(source_path, prop["put_function"])
    add_nz = _function_source(refcount_path, "__refcount_add_not_zero")
    inc_nz_inner = _function_source(refcount_path, "__refcount_inc_not_zero")
    inc_nz = _function_source(refcount_path, "refcount_inc_not_zero")
    sub_test = _function_source(refcount_path, "__refcount_sub_and_test")
    dec_test = _function_source(refcount_path, "refcount_dec_and_test")
    by_id = {case["id"]: case for case in model["cases"]}
    positive_path = _relative(
        root, by_id["refcount_put_get_positive"]["path"], "positive IPC model"
    )
    negative_path = _relative(
        root, by_id["unconditional_resurrection_negative"]["path"],
        "negative IPC model",
    )
    positive = concurrency_c3_lkmm._code_without_comments(positive_path.read_text())
    negative = concurrency_c3_lkmm._code_without_comments(negative_path.read_text())
    checks: list[dict[str, Any]] = []

    checks.extend([
        _check("unique IPC get operation", 1, get_body.count(prop["get_source"])),
        _check("unique IPC put test", 1, put_body.count(prop["put_test_source"])),
        _check("unique IPC destroy scheduling", 1,
               put_body.count(prop["put_destroy_source"])),
        _check("put test precedes RCU destruction decision", True,
               _ordered(put_body, [prop["put_test_source"], "return;",
                                   prop["put_destroy_source"]])),
        _check("IPC contract starts objects at one", True,
               "Objects are reference counted, they start with reference count 1."
               in contract),
        _check("IPC contract binds zero to RCU destruction", True,
               "putref call that reduces the recount\n * to 0 schedules the rcu destruction"
               in contract),
        _check("IPC contract requires caller locking", True,
               "Caller must guarantee locking." in contract),
        _check("IPC source initializes refcount to one", True,
               "refcount_set(&new->refcount, 1);" in source),
        _check("architecture exclusion binds all selected SMP profiles",
               _ARCHITECTURE_EXCLUSION,
               next((item for item in prop["exclusions"]
                     if "architecture implementation" in item.lower()), None)),
    ])

    checks.extend([
        _check("inc-not-zero reads current count", 1,
               add_nz.count("int old = refcount_read(r);")),
        _check("inc-not-zero rejects zero before CAS", True,
               _ordered(add_nz, ["if (!old)", "break;",
                                 "atomic_try_cmpxchg_relaxed(&r->refs, &old, old + i)"])),
        _check("inc-not-zero retries relaxed CAS", 1,
               add_nz.count("while (!atomic_try_cmpxchg_relaxed")),
        _check("inc-not-zero reports original nonzero value", 1,
               add_nz.count("return old;")),
        _check("one-reference helper adds one", 1,
               inc_nz_inner.count("return __refcount_add_not_zero(1, r, oldp);")),
        _check("public get wrapper selects helper", 1,
               inc_nz.count("return __refcount_inc_not_zero(r, NULL);")),
        _check("final put uses release fetch-sub", 1,
               sub_test.count("atomic_fetch_sub_release(i, &r->refs)")),
        _check("final put tests exact transition", True,
               "if (old > 0 && old == i)" in sub_test),
        _check("successful final put has acquire-after-control", 1,
               sub_test.count("smp_acquire__after_ctrl_dep();")),
        _check("public put wrapper subtracts one", 1,
               dec_test.count("return __refcount_dec_and_test(r, NULL);")),
        _check("refcount header states get stability prerequisite", True,
               "it is assumed the caller has guaranteed the\n * object memory to be stable (RCU, etc.)"
               in refcount),
        _check("refcount header states decrement ordering", True,
               "The decrements will provide release order" in refcount and
               "also provide acquire\n * ordering on success" in refcount),
    ])

    documentation = (
        source_root / "Documentation/core-api/refcount-vs-atomic.rst"
    ).read_text()
    makefile = (source_root / "ipc/Makefile").read_text()
    kconfig = (source_root / "init/Kconfig").read_text()
    instrumented = (
        source_root / "include/linux/atomic/atomic-instrumented.h"
    ).read_text()
    fallback = (
        source_root / "include/linux/atomic/atomic-arch-fallback.h"
    ).read_text()
    x86_atomic = (source_root / "arch/x86/include/asm/atomic.h").read_text()
    x86_cmpxchg = (source_root / "arch/x86/include/asm/cmpxchg.h").read_text()
    arm_atomic = (source_root / "arch/arm/include/asm/atomic.h").read_text()
    arm_cmpxchg = (source_root / "arch/arm/include/asm/cmpxchg.h").read_text()
    arm_barrier = (source_root / "arch/arm/include/asm/barrier.h").read_text()
    arm64_atomic = (source_root / "arch/arm64/include/asm/atomic.h").read_text()
    arm64_ll_sc = (
        source_root / "arch/arm64/include/asm/atomic_ll_sc.h"
    ).read_text()
    arm64_lse_atomic = (
        source_root / "arch/arm64/include/asm/atomic_lse.h"
    ).read_text()
    arm64_cmpxchg = (
        source_root / "arch/arm64/include/asm/cmpxchg.h"
    ).read_text()
    arm64_lse = (source_root / "arch/arm64/include/asm/lse.h").read_text()
    riscv_atomic = (source_root / "arch/riscv/include/asm/atomic.h").read_text()
    riscv_cmpxchg = (
        source_root / "arch/riscv/include/asm/cmpxchg.h"
    ).read_text()
    riscv_barrier = (
        source_root / "arch/riscv/include/asm/barrier.h"
    ).read_text()
    s390_atomic = (source_root / "arch/s390/include/asm/atomic.h").read_text()
    s390_atomic_ops = (
        source_root / "arch/s390/include/asm/atomic_ops.h"
    ).read_text()
    s390_cmpxchg = (
        source_root / "arch/s390/include/asm/cmpxchg.h"
    ).read_text()
    s390_barrier = (
        source_root / "arch/s390/include/asm/barrier.h"
    ).read_text()
    powerpc_atomic = (
        source_root / "arch/powerpc/include/asm/atomic.h"
    ).read_text()
    powerpc_cmpxchg = (
        source_root / "arch/powerpc/include/asm/cmpxchg.h"
    ).read_text()
    powerpc_barrier = (
        source_root / "arch/powerpc/include/asm/barrier.h"
    ).read_text()
    sh_atomic = (source_root / "arch/sh/include/asm/atomic.h").read_text()
    sh_atomic_llsc = (
        source_root / "arch/sh/include/asm/atomic-llsc.h"
    ).read_text()
    sh_cmpxchg = (source_root / "arch/sh/include/asm/cmpxchg.h").read_text()
    sh_cmpxchg_llsc = (
        source_root / "arch/sh/include/asm/cmpxchg-llsc.h"
    ).read_text()
    sh_barrier = (source_root / "arch/sh/include/asm/barrier.h").read_text()
    alpha_atomic = (
        source_root / "arch/alpha/include/asm/atomic.h"
    ).read_text()
    alpha_cmpxchg = (
        source_root / "arch/alpha/include/asm/cmpxchg.h"
    ).read_text()
    alpha_barrier = (
        source_root / "arch/alpha/include/asm/barrier.h"
    ).read_text()
    alpha_kconfig = (source_root / "arch/alpha/Kconfig").read_text()
    um_kconfig = (source_root / "arch/um/Kconfig").read_text()
    um_makefile = (source_root / "arch/um/Makefile").read_text()
    um_x86_kconfig = (source_root / "arch/x86/um/Kconfig").read_text()
    um_x86_barrier = (
        source_root / "arch/x86/um/asm/barrier.h"
    ).read_text()
    config_script = (source_root / "scripts/config").read_text()
    barrier = (source_root / "include/asm-generic/barrier.h").read_text()
    model_def = (source_root / "tools/memory-model/linux-kernel.def").read_text()
    model_cat = (source_root / "tools/memory-model/linux-kernel.cat").read_text()
    checks.extend([
        _check("IPC Makefile selects util for SYSVIPC", True,
               "obj-$(CONFIG_SYSVIPC) += util.o" in makefile),
        _check("SYSVIPC has a boolean Kconfig entry", True,
               "config SYSVIPC\n\tbool \"System V IPC\"" in kconfig),
        _check("refcount documentation preserves atomicity when relaxed", True,
               "atomics & refcounters only provide atomicity and\nprogram order"
               in documentation),
        _check("documentation names inc-not-zero mapping", True,
               "atomic_inc_not_zero() --> refcount_inc_not_zero()" in documentation),
        _check("documentation names final-decrement mapping", True,
               "atomic_dec_and_test() --> refcount_dec_and_test()" in documentation),
        _check("documentation records pointer-ordering prerequisite", True,
               "necessary ordering is provided as a\n   result of obtaining pointer"
               in documentation),
        _check("instrumented fetch-sub routes to raw operation", True,
               _ordered(instrumented, ["atomic_fetch_sub_release(int i, atomic_t *v)",
                                       "kcsan_release();",
                                       "return raw_atomic_fetch_sub_release(i, v);"])),
        _check("instrumented try-CAS routes to raw operation", True,
               _ordered(instrumented, ["atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)",
                                       "instrument_atomic_read_write",
                                       "return raw_atomic_try_cmpxchg_relaxed(v, old, new);"])),
        _check("fallback fetch-sub reaches architecture atomic", True,
               _ordered(fallback, ["raw_atomic_fetch_sub_release(int i, atomic_t *v)",
                                   "#if defined(arch_atomic_fetch_sub_release)",
                                   "arch_atomic_fetch_sub_relaxed",
                                   "return arch_atomic_fetch_sub(i, v);"])),
        _check("fallback relaxed try-CAS reaches architecture atomic", True,
               _ordered(fallback, ["raw_atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)",
                                   "#if defined(arch_atomic_try_cmpxchg_relaxed)",
                                   "return arch_atomic_try_cmpxchg(v, old, new);"])),
        _check("x86 decrement routes through locked xadd", True,
               _ordered(x86_atomic, ["arch_atomic_fetch_add(int i, atomic_t *v)",
                                    "return xadd(&v->counter, i);",
                                    "#define arch_atomic_fetch_sub(i, v) arch_atomic_fetch_add(-(i), v)"])),
        _check("x86 try-CAS routes to architecture cmpxchg", True,
               _ordered(x86_atomic, ["arch_atomic_try_cmpxchg(atomic_t *v, int *old, int new)",
                                    "return arch_try_cmpxchg(&v->counter, old, new);"])),
        _check("x86 try-CAS uses LOCK_PREFIX", True,
               "__raw_try_cmpxchg((ptr), (pold), (new), (size), LOCK_PREFIX)"
               in x86_cmpxchg),
        _check("x86 xadd uses LOCK_PREFIX", True,
               "#define xadd(ptr, inc)\t\t__xadd((ptr), (inc), LOCK_PREFIX)"
               in x86_cmpxchg),
        _check("ARM32 fetch-sub uses load/store exclusives", True,
               _ordered(arm_atomic, [
                   "#define ATOMIC_FETCH_OP(op, c_op, asm_op)",
                   '"1:\tldrex\t%0, [%4]\\n"',
                   '"\tstrex\t%2, %1, [%4]\\n"',
                   "#define arch_atomic_fetch_sub_relaxed",
                   "ATOMIC_OPS(sub, -=, sub)",
               ])),
        _check("ARM32 relaxed compare/exchange uses exclusives", True,
               _ordered(arm_atomic, [
                   "static inline int arch_atomic_cmpxchg_relaxed",
                   '"ldrex\t%1, [%3]\\n"',
                   '"strexeq %0, %5, [%3]\\n"',
                   "#define arch_atomic_cmpxchg_relaxed",
               ])),
        _check("ARM32 generic cmpxchg offers exclusive word path", True,
               _ordered(arm_cmpxchg, [
                   "case 4:",
                   '"\tldrex\t%1, [%2]\\n"',
                   '"\tstrexeq %0, %4, [%2]\\n"',
               ])),
        _check("ARM32 acquire-after-control maps to DMB", True,
               "#define __smp_rmb()\t__smp_mb()" in arm_barrier and
               "#define __smp_mb()\tdmb(ish)" in arm_barrier),
        _check("arm64 atomic wrapper selects LSE or LL/SC", True,
               _ordered(arm64_lse, [
                   "#define __lse_ll_sc_body(op, ...)",
                   "alternative_has_cap_likely(ARM64_HAS_LSE_ATOMICS)",
                   "__lse_##op(__VA_ARGS__)",
                   "__ll_sc_##op(__VA_ARGS__)",
               ])),
        _check("arm64 fetch-sub routes through alternative body", True,
               _ordered(arm64_atomic, [
                   "#define ATOMIC_FETCH_OP(name, op)",
                   "return __lse_ll_sc_body(op##name, i, v);",
                   "ATOMIC_FETCH_OPS(atomic_fetch_sub)",
                   "#define arch_atomic_fetch_sub_release",
               ])),
        _check("arm64 LL/SC release fetch uses exclusive RMW", True,
               _ordered(arm64_ll_sc, [
                   "#define ATOMIC_FETCH_OP(name, mb, acq, rel, cl, op, asm_op, constraint)",
                   '"1:\tld" #acq "xr',
                   '"\tst" #rel "xr',
                   "ATOMIC_FETCH_OP (_release",
               ])),
        _check("arm64 LSE release fetch-sub uses LDADD path", True,
               _ordered(arm64_lse_atomic, [
                   "ATOMIC_FETCH_OPS(add, ldadd)",
                   "__lse_atomic_fetch_sub##name",
                   "return __lse_atomic_fetch_add##name(-i, v);",
                   "ATOMIC_FETCH_OP_SUB(_release)",
               ])),
        _check("arm64 compare/exchange wrapper selects alternatives", True,
               "return __lse_ll_sc_body(_cmpxchg_case_##name##sz"
               in arm64_cmpxchg),
        _check("arm64 LL/SC compare/exchange is exclusive", True,
               _ordered(arm64_ll_sc, [
                   "__ll_sc__cmpxchg_case_##name##sz",
                   '"1:\tld" #acq "xr" #sfx',
                   '"\tst" #rel "xr" #sfx',
               ])),
        _check("arm64 LSE compare/exchange uses CAS", True,
               _ordered(arm64_lse_atomic, [
                   "__lse__cmpxchg_case_##name##sz",
                   '"\tcas" #mb #sfx',
               ])),
        _check("RISC-V fetch-sub maps to AMO add of negative operand", True,
               _ordered(riscv_atomic, [
                   "#define ATOMIC_FETCH_OP(op, asm_op, I, asm_type, c_type, prefix)",
                   '"\tamo" #asm_op "." #asm_type',
                   "ATOMIC_OPS(sub, add, +, -i)",
                   "#define arch_atomic_fetch_sub",
               ])),
        _check("RISC-V compare/exchange has Zacas and LR/SC alternatives", True,
               _ordered(riscv_cmpxchg, [
                   "#define __arch_cmpxchg(lr_sfx, sc_sfx, cas_sfx",
                   "IS_ENABLED(CONFIG_RISCV_ISA_ZACAS)",
                   '"\tamocas" cas_sfx',
                   '"0:\tlr" lr_sfx',
                   '"\tsc" sc_sfx',
               ])),
        _check("RISC-V relaxed compare/exchange adds no ordering suffix", True,
               _ordered(riscv_cmpxchg, [
                   "#define arch_cmpxchg_relaxed(ptr, o, n)",
                   'SC_SFX(""), CAS_SFX("")',
               ])),
        _check("RISC-V acquire-after-control maps to read fence", True,
               "#define __smp_rmb()\tRISCV_FENCE(r, r)" in riscv_barrier),
        _check("s390 fetch-sub maps to barrier fetch-add", True,
               _ordered(s390_atomic, [
                   "static __always_inline int arch_atomic_fetch_add",
                   "return __atomic_add_barrier(i, &v->counter);",
                   "#define arch_atomic_fetch_sub(_i, _v)",
               ])),
        _check("s390 atomic add primitive uses LAA", True,
               '__ATOMIC_OPS(__atomic_add, int, "laa")' in s390_atomic_ops),
        _check("s390 try-CAS maps to CS primitive", True,
               _ordered(s390_atomic, [
                   "static __always_inline bool arch_atomic_try_cmpxchg",
                   "return arch_try_cmpxchg(&v->counter, old, new);",
               ]) and _ordered(s390_cmpxchg, [
                   "#define arch_try_cmpxchg(ptr, oldp, new)",
                   '"\tcs\t%[__old],%[__new],%[__ptr]"',
               ])),
        _check("s390 acquire-after-control is a compiler barrier", True,
               "#define __smp_rmb()\t__rmb()" in s390_barrier and
               "#define __rmb()\t\tbarrier()" in s390_barrier),
        _check("PowerPC32 fetch-sub uses reservation RMW", True,
               _ordered(powerpc_atomic, [
                   "#define ATOMIC_FETCH_OP_RELAXED(op, asm_op, suffix, sign",
                   '"1:\tlwarx\t%0,0,%4',
                   '"\tstwcx.\t%1,0,%4\\n"',
                   "ATOMIC_OPS(sub, sub, \"c\", I, \"xer\")",
                   "#define arch_atomic_fetch_sub_relaxed",
               ])),
        _check("PowerPC32 relaxed cmpxchg uses reservation RMW", True,
               _ordered(powerpc_cmpxchg, [
                   "__cmpxchg_u32_relaxed(u32 *p",
                   '"1:\tlwarx\t%0,0,%2',
                   '"\tstwcx.\t%4,0,%2\\n"',
               ])),
        _check("PowerPC32 acquire-after-control maps to LWSYNC", True,
               "#define __smp_rmb()\t__lwsync()" in powerpc_barrier),
        _check("SuperH profile selects SH4A LL/SC atomics", True,
               _ordered(sh_atomic, [
                   "#elif defined(CONFIG_CPU_SH4A)",
                   "#include <asm/atomic-llsc.h>",
               ])),
        _check("SuperH fetch-sub uses MOVLI/MOVCO", True,
               _ordered(sh_atomic_llsc, [
                   "#define ATOMIC_FETCH_OP(op)",
                   '"1:\tmovli.l @%3, %0',
                   '"\tmovco.l\t%0, @%3',
                   '"\tsynco',
                   "ATOMIC_OPS(sub)",
                   "#define arch_atomic_fetch_sub",
               ])),
        _check("SuperH profile selects LL/SC cmpxchg", True,
               _ordered(sh_cmpxchg, [
                   "#elif defined(CONFIG_CPU_SH4A)",
                   "#include <asm/cmpxchg-llsc.h>",
               ]) and _ordered(sh_cmpxchg_llsc, [
                   "__cmpxchg_u32(volatile u32 *m",
                   '"movli.l\t@%2, %0',
                   '"movco.l\t%0, @%2',
                   '"synco',
               ])),
        _check("SuperH acquire-after-control maps to SYNCO", True,
               '#define mb()\t\t__asm__ __volatile__ ("synco"' in sh_barrier and
               "#define rmb()\t\tmb()" in sh_barrier),
        _check("Alpha fetch-sub uses locked load/store", True,
               _ordered(alpha_atomic, [
                   "#define ATOMIC_FETCH_OP(op, asm_op)",
                   '"1:\tldl_l %2,%1\\n"',
                   '"\tstl_c %0,%1\\n"',
                   "smp_mb();",
                   "ATOMIC_OPS(sub)",
                   "#define arch_atomic_fetch_sub_relaxed",
               ])),
        _check("Alpha cmpxchg is fully ordered locked load/store", True,
               _ordered(alpha_cmpxchg, [
                   "____cmpxchg_u32(volatile int *m",
                   '"1:\tldl_l %0,%5\\n"',
                   '"\tstl_c %1,%2\\n"',
                   "#define arch_cmpxchg(ptr, o, n)",
                   "smp_mb();",
                   "____cmpxchg((ptr)",
                   "smp_mb();",
               ])),
        _check("Alpha SMP barriers emit MB", True,
               _ordered(alpha_barrier, [
                   "#ifdef CONFIG_SMP",
                   '#define __ASM_SMP_MB\t"\\tmb\\n"',
               ])),
        _check("Alpha generic platform permits SMP mutation", True,
               _ordered(alpha_kconfig, [
                   "config SMP",
                   "depends on ALPHA_SABLE || ALPHA_RAWHIDE || ALPHA_DP264",
                   "ALPHA_GENERIC",
               ])),
        _check("UML x86-64 explicitly supports SMP", True,
               _ordered(um_kconfig, [
                   "config UML_SUBARCH_SUPPORTS_SMP",
                   "config SMP",
                   "depends on UML_SUBARCH_SUPPORTS_SMP",
               ]) and _ordered(um_x86_kconfig, [
                   "config UML_X86",
                   "select UML_SUBARCH_SUPPORTS_SMP if X86_CX8",
               ])),
        _check("UML x86-64 selects x86 kernel headers", True,
               _ordered(um_makefile, [
                   "ifneq ($(filter $(SUBARCH),x86 x86_64 i386),)",
                   "HEADER_ARCH := x86",
                   "KBUILD_CPPFLAGS += -I$(srctree)/$(HOST_DIR)/include",
               ])),
        _check("UML x86-64 acquire-after-control emits LFENCE", True,
               _ordered(um_x86_barrier, [
                   "#else /* CONFIG_X86_32 */",
                   '#define rmb()\tasm volatile("lfence" : : : "memory")',
               ])),
        _check("kernel config helper provides explicit enable operation", True,
               "--enable|-e)" in config_script),
        _check("generic acquire-after-control is explicit", True,
               "#define smp_acquire__after_ctrl_dep()\t\tsmp_rmb()" in barrier),
        _check("LKMM defines release fetch-sub", True,
               "atomic_fetch_sub_release(V,X) __atomic_fetch_op{RELEASE}(X,-,V)"
               in model_def),
        _check("LKMM defines relaxed compare/exchange", True,
               "atomic_cmpxchg_relaxed(X,V,W) __cmpxchg{ONCE}(X,V,W)"
               in model_def),
        _check("LKMM does not directly spell try-CAS", False,
               "atomic_try_cmpxchg_relaxed" in model_def),
        _check("LKMM enforces RMW atomicity", True,
               "empty rmw & (fre ; coe) as atomic" in model_cat),
    ])

    checks.extend([
        _check("positive model initializes sole reference", 1,
               positive.count("atomic_t refs = ATOMIC_INIT(1);")),
        _check("positive model has one final decrement", 1,
               positive.count("atomic_fetch_sub_release(1, refs)")),
        _check("positive model has one bounded relaxed CAS", 1,
               positive.count("atomic_cmpxchg_relaxed(refs, 1, 2)")),
        _check("positive model exposes mutual-success condition", 1,
               positive.count(model["condition"])),
        _check("positive model does not model RCU callback", False,
               "call_rcu" in positive),
        _check("unsafe control preserves final decrement", 1,
               negative.count("atomic_fetch_sub_release(1, refs)")),
        _check("unsafe control has one unconditional resurrection", 1,
               negative.count("atomic_fetch_inc_relaxed(refs)")),
        _check("unsafe control exposes identical condition", 1,
               negative.count(model["condition"])),
    ])
    return checks, {
        "get_function_tokens": len(concurrency_c2.c_tokens(get_body)),
        "put_function_tokens": len(concurrency_c2.c_tokens(put_body)),
        "inc_not_zero_implementation_tokens": len(concurrency_c2.c_tokens(add_nz)),
        "dec_and_test_implementation_tokens": len(concurrency_c2.c_tokens(sub_test)),
        "source_get_count": get_body.count(prop["get_source"]),
        "source_put_count": put_body.count(prop["put_test_source"]),
        "source_destroy_count": put_body.count(prop["put_destroy_source"]),
        "positive_decrement_count": positive.count("atomic_fetch_sub_release(1, refs)"),
        "positive_get_count": positive.count("atomic_cmpxchg_relaxed(refs, 1, 2)"),
        "negative_resurrection_count": negative.count("atomic_fetch_inc_relaxed(refs)"),
        "architecture_source_mappings": list(_PROFILE_SPECS),
    }


def _run_profile(
    root: Path,
    kernel: dict[str, Any],
    profile: dict[str, Any],
    output: Path,
    timeout: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build and inspect one architecture profile without sharing make state."""
    profile_id = profile["id"]
    output.mkdir()
    tools_output = output / "tools"
    build_output = output / "build"
    tools_output.mkdir()
    build_output.mkdir()
    checks: list[dict[str, Any]] = []

    def profile_check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
        return _check(f"{profile_id}: {name}", expected, actual)

    tool_inventory: dict[str, dict[str, Any]] = {}
    tool_commands = {
        "make-version": [profile["make"]["binary"], "--version"],
        "compiler-version": [profile["compiler"]["binary"], "--version"],
        "compiler-target": [profile["compiler"]["binary"], "-dumpmachine"],
        "objdump-version": [profile["objdump"]["binary"], "--version"],
    }
    for name, argv in tool_commands.items():
        directory = tools_output / name
        directory.mkdir()
        process = concurrency_c3_lkmm._run(argv, root, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, root, process)
        tool_inventory[name] = process
        checks.extend([
            profile_check(f"{name} timed out", False, process["timed_out"]),
            profile_check(f"{name} exit", 0, process["returncode"]),
        ])
    for tool_name in ("make", "compiler", "objdump"):
        tool = profile[tool_name]
        binary = Path(tool["binary"])
        checks.extend([
            profile_check(
                f"{tool_name} realpath", tool["realpath"], str(binary.resolve())
            ),
            profile_check(f"{tool_name} identity", tool["sha256"], _sha256(binary)),
        ])

    def first_line(name: str) -> str | None:
        lines = tool_inventory[name]["stdout"].splitlines()
        return lines[0] if lines else None

    checks.extend([
        profile_check(
            "make version line", profile["make"]["version_line"],
            first_line("make-version"),
        ),
        profile_check(
            "compiler version line", profile["compiler"]["version_line"],
            first_line("compiler-version"),
        ),
        profile_check(
            "compiler target", profile["compiler"]["target"],
            tool_inventory["compiler-target"]["stdout"].strip(),
        ),
        profile_check(
            "objdump version line", profile["objdump"]["version_line"],
            first_line("objdump-version"),
        ),
    ])

    source_root = root / kernel["source_root"]
    build_directory = _declared_path(
        root, profile["build_directory"], f"{profile_id} build directory"
    )
    if build_directory.is_symlink():
        raise ConcurrencyC3IpcRefcountError(
            f"{profile_id} build directory must not be a symlink"
        )
    build_directory.mkdir(parents=True, exist_ok=True)
    common_make = [
        profile["make"]["binary"], "-C", str(source_root),
        f"O={build_directory}", f"ARCH={profile['arch']}",
    ]
    if profile["subarch"] is not None:
        common_make.append(f"SUBARCH={profile['subarch']}")
    if profile["cross_compile"] is not None:
        common_make.append(f"CROSS_COMPILE={profile['cross_compile']}")
    common_make.append(f"CC={profile['compiler']['binary']}")
    configuration = profile["configuration"]
    build_diagnostics: dict[str, dict[str, Any]] = {}

    def run_build_step(
        name: str, argv: list[str], diagnostic_class: str, *, label: str | None = None
    ) -> dict[str, Any]:
        directory = build_output / name
        directory.mkdir()
        process = concurrency_c3_lkmm._run(argv, root, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, root, process)
        observed = _diagnostic_lines(process)
        allowed = profile["allowed_diagnostics"][diagnostic_class]
        unexpected = [line for line in observed if line not in allowed]
        build_diagnostics[name] = {
            "class": diagnostic_class,
            "allowed": allowed,
            "observed": observed,
            "unexpected": unexpected,
        }
        check_label = label or name
        checks.extend([
            profile_check(f"{check_label} timed out", False, process["timed_out"]),
            profile_check(f"{check_label} exit", 0, process["returncode"]),
            profile_check(f"{check_label} undeclared diagnostics", [], unexpected),
        ])
        return process

    run_build_step(
        "base-config", [*common_make, configuration["base_recipe"]],
        "base-config",
    )
    config_path = _declared_path(root, profile["config"], f"{profile_id} config")
    config_script = source_root / "scripts/config"
    for index, mutation in enumerate(configuration["mutations"], start=1):
        operation = mutation["operation"]
        symbol = mutation["symbol"]
        run_build_step(
            f"config-mutation-{index:02d}-{symbol.lower()}",
            [str(config_script), "--file", str(config_path),
             f"--{operation}", symbol],
            "config-mutation",
            label=f"config mutation {index}: {symbol}={operation}",
        )
    run_build_step(
        "finalize-config", [*common_make, configuration["finalize_recipe"]],
        "finalize-config",
    )

    config_exists = config_path.is_file() and not config_path.is_symlink()
    config_hash = _sha256(config_path) if config_exists else None
    checks.extend([
        profile_check("configured profile produced config", True, config_exists),
        profile_check("configured config identity", profile["config_sha256"],
                      config_hash),
    ])
    config_values = concurrency_c2.parse_kconfig(
        config_path.read_text() if config_exists else ""
    )
    for name, expected in profile["required_config"].items():
        checks.append(profile_check(
            f"kernel config: {name}", expected, config_values.get(name, "absent")
        ))

    compile_record = profile["configured_compile"]
    object_argv = [*common_make, f"-j{profile['jobs']}", compile_record["target"]]
    object_process = run_build_step(
        "object", object_argv, "object", label="configured object build"
    )
    object_path = _declared_path(
        root, compile_record["object"], f"{profile_id} configured object"
    )
    object_exists = object_path.is_file() and not object_path.is_symlink()
    checks.append(profile_check("configured object exists", True, object_exists))
    elf = concurrency_c3_trace._elf_identity(object_path) if object_exists else {
        "elf": False, "class": None, "data": None, "machine": None,
    }
    checks.extend([
        profile_check("configured object is ELF", True, elf["elf"]),
        profile_check("configured object class", compile_record["elf_class"],
                      elf["class"]),
        profile_check("configured object byte order", compile_record["elf_data"],
                      elf["data"]),
        profile_check("configured object machine", compile_record["elf_machine"],
                      elf["machine"]),
        profile_check("configured object identity",
                      compile_record["object_sha256"], elf.get("sha256")),
    ])
    command_path = _declared_path(
        root, compile_record["command_file"], f"{profile_id} compile command"
    )
    command_exists = command_path.is_file() and not command_path.is_symlink()
    command_text = command_path.read_text() if command_exists else ""
    checks.extend([
        profile_check("configured command exists", True, command_exists),
        profile_check(
            "configured command identity", compile_record["command_sha256"],
            _sha256(command_path) if command_exists else None,
        ),
    ])
    for token in compile_record["required_command_tokens"]:
        checks.append(profile_check(
            f"configured command token: {token}", True, token in command_text
        ))

    disassembly_directory = output / "disassembly"
    symbols_directory = output / "symbols"
    disassembly_directory.mkdir()
    symbols_directory.mkdir()
    selected_disassembly: dict[str, str] = {}
    for name, function in compile_record["functions"].items():
        directory = disassembly_directory / name
        directory.mkdir()
        argv = [
            profile["objdump"]["binary"], "-dr", "--no-show-raw-insn",
            f"--disassemble={name}", str(object_path),
        ]
        process = concurrency_c3_lkmm._run(argv, root, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, root, process)
        block = process["stdout"]
        selected_disassembly[name] = block
        checks.extend([
            profile_check(f"{name} disassembly timed out", False,
                          process["timed_out"]),
            profile_check(f"{name} disassembly exit", 0, process["returncode"]),
            profile_check(f"{name} disassembly stderr empty", "",
                          process["stderr"]),
            profile_check(f"{name} unique disassembly header", 1,
                          block.count(f"<{name}>:")),
            profile_check(f"{name} instruction order", True,
                          _ordered(block, function["disassembly_order"])),
        ])
    symbols_argv = [profile["objdump"]["binary"], "-t", str(object_path)]
    symbols_process = concurrency_c3_lkmm._run(symbols_argv, root, timeout)
    concurrency_c3_lkmm._write_process(
        symbols_directory, symbols_argv, root, symbols_process
    )
    checks.extend([
        profile_check("symbol inventory timed out", False,
                      symbols_process["timed_out"]),
        profile_check("symbol inventory exit", 0, symbols_process["returncode"]),
        profile_check("symbol inventory stderr empty", "",
                      symbols_process["stderr"]),
    ])
    expected_symbols = {
        name: {key: function[key] for key in ("section", "value", "size")}
        for name, function in compile_record["functions"].items()
    }
    observed_symbols = _function_symbols(
        symbols_process["stdout"], set(compile_record["functions"]),
        8 if compile_record["elf_class"] == 1 else 16,
    )
    checks.append(profile_check(
        "configured function symbols", expected_symbols, observed_symbols
    ))
    _json(output / "selected-disassembly.json", {
        "functions": selected_disassembly,
        "symbols": observed_symbols,
    })
    result = {
        "id": profile_id,
        "arch": profile["arch"],
        "subarch": profile["subarch"],
        "cross_compile": profile["cross_compile"],
        "configured_object": elf,
        "configured_config_sha256": config_hash,
        "configured_functions": observed_symbols,
        "disassembly_mode": "target-objdump-per-function",
        "execution_scope": profile["execution_scope"],
        "build_diagnostics": build_diagnostics,
        "checks": checks,
        "accepted": all(item["passed"] for item in checks),
    }
    _json(output / "profile-result.json", result)
    return checks, result


def render_summary(result: dict[str, Any]) -> str:
    passed = sum(item["passed"] for item in result["checks"])
    lines = [
        "# System V IPC refcount C3 lifetime and bounded-progress pilot",
        "",
        f"Overall source-linked gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Accepted kernel properties: **{result['kernel_verification_count']}**",
        f"Accepted lifetime properties: **{result['lifetime_verification_count']}**",
        f"Accepted bounded-progress properties: **{result['progress_verification_count']}**",
        f"Checked architecture mappings: **{result['architecture_mapping_count']}**",
        f"Progress implementation mappings: **{result['progress_implementation_mapping_count']}**",
        f"LKMM functional cases: **{len(result['cases'])}**",
        "",
        "| Architecture profile | Kernel ARCH | Scope | Object | Gate |",
        "|---|---|---|---|---|",
    ]
    for profile in result["profiles"]:
        elf = profile["configured_object"]
        architecture = profile["arch"]
        if profile["subarch"] is not None:
            architecture += f" (SUBARCH={profile['subarch']})"
        lines.append(
            f"| `{profile['id']}` | `{architecture}` | "
            f"`{profile['execution_scope']}` | "
            f"ELF{(elf.get('class') or 0) * 32}, machine {elf.get('machine')} | "
            f"{'PASS' if profile['accepted'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        "| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |",
        "|---|---|---|---:|---:|---|",
    ])
    for case in result["cases"]:
        parsed = case["parsed"] or {}
        lines.append(
            f"| `{case['id']}` | {case['role']} | "
            f"{parsed.get('observation', 'unparsed')} | "
            f"{parsed.get('positive', '?')}/{parsed.get('negative', '?')} | "
            f"{parsed.get('states', '?')} | {'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        "| Progress case | Role | Finite schedules | Nontermination | Max CAS attempts | Gate |",
        "|---|---|---:|---:|---:|---|",
    ])
    for case in result["progress"]["cases"]:
        actual = case["actual"]
        nontermination = actual.get("nonterminating")
        if nontermination is None:
            nontermination = (
                f"cycle/{actual.get('cycle_length', '?')}"
                if actual.get("cycle_found") else "none"
            )
        lines.append(
            f"| `{case['id']}` | {case['role']} | "
            f"{actual.get('total_schedules', '—')} | {nontermination} | "
            f"{actual.get('max_cas_attempts', '—')} | "
            f"{'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        f"Evidence checks: **{passed}/{len(result['checks'])} passed**.",
        "",
        "Starting with the IPC contract's sole reference, the selected final put",
        "and get-unless-zero cannot both decide that destruction should be scheduled",
        "and that a reference was acquired. LKMM reports the mutual-success outcome",
        "`Never` (0/2 witnesses). The unsafe unconditional-increment control can",
        "resurrect zero and reports `Sometimes` (1/1).",
        "",
        "A separate finite-state check enumerates 340 bounded interference",
        "schedules for the source retry loop. With strong compare/exchange",
        "mismatch updating the expected value, every schedule terminates in at",
        "most four CAS attempts. A stale-expected variant has 117 quiescent",
        "nonterminating schedules; spurious failure and unbounded interference",
        "separately expose one-state and two-state cycles.",
        "",
        "The gate pins the IPC helper and locking contract, refcount implementation,",
        "LKMM RMW axiom, and nine configured SMP profiles: x86-64, arm64,",
        "riscv64, s390x, ARM32, PowerPC32, SuperH, Alpha, and UML x86-64.",
        "Each mapping pins both function symbols and target disassembly,",
        "including alternative atomic paths where the architecture emits them.",
        "The caller-locking prerequisite is assumed. Callback execution and RCU",
        "grace periods are not modeled.",
        "",
        "No allocator reuse, arbitrary refcount population, unbounded progress,",
        "wait-freedom, LL/SC liveness, unlisted architecture, whole-IPC, whole-RCU,",
        "or whole-kernel property is accepted.",
        "No runtime kernel was used; nothing was installed and no privileged",
        "operation was performed.",
        "",
    ])
    return "\n".join(lines)


def run_c3_ipc_refcount(
    root: Path, output: Path, timeout: int = 120
) -> dict[str, Any]:
    """Run the LKMM baseline, IPC/refcount gates, configured build, and A/B pair."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyC3IpcRefcountError(
            f"IPC refcount C3 output already exists: {output}"
        )
    if type(timeout) is not int or timeout < 1:
        raise ConcurrencyC3IpcRefcountError(
            "IPC refcount C3 timeout must be a positive integer"
        )
    output.mkdir(parents=True, exist_ok=False)
    profiles_output = output / "profiles"
    cases_output = output / "cases"
    profiles_output.mkdir()
    cases_output.mkdir()

    kernel = manifest["kernel"]
    model = manifest["model"]
    checks: list[dict[str, Any]] = []

    baseline_result = concurrency_c3_lkmm.run_c3_lkmm(
        root, output / "baseline", timeout
    )
    checks.extend([
        _check("baseline target", manifest["baseline"]["id"], baseline_result["target"]),
        _check("baseline capability accepted", True,
               baseline_result[manifest["baseline"]["required_capability"]]),
        _check("baseline accepts no kernel property", 0,
               baseline_result["kernel_verification_count"]),
    ])

    for name, expected in kernel["source_identities"].items():
        checks.append(_check(
            f"source identity: {name}", expected,
            _sha256(_relative(root, name, "IPC source identity")),
        ))
    receipt = _strict_json(_relative(root, kernel["source_receipt"], "source receipt"))
    checks.extend([
        _check("source receipt revision", kernel["revision"], receipt.get("revision")),
        _check("source receipt tree", kernel["git_tree"], receipt.get("git_tree")),
        _check("source receipt requires content rechecks", True,
               receipt.get("contents_must_be_rechecked")),
    ])
    semantic_checks, source_model_evidence = _semantic_checks(root, manifest)
    checks.extend(semantic_checks)
    profile_results: list[dict[str, Any]] = []
    # Deliberately sequential: each kernel invocation owns its make jobserver and
    # architecture output directory, so no cross-profile FIFO/state is shared.
    for profile in manifest["profiles"]:
        profile_checks, profile_result = _run_profile(
            root, kernel, profile, profiles_output / profile["id"], timeout
        )
        checks.extend(profile_checks)
        profile_results.append(profile_result)

    progress_result = _run_progress_model(
        root, manifest, profile_results, output / "progress"
    )
    checks.extend(progress_result["checks"])

    baseline_manifest = concurrency_c3_lkmm.load_manifest(root)
    baseline_provider = baseline_manifest["provider"]
    herd_binary = Path(baseline_provider["binary"])
    model_directory = root / baseline_manifest["kernel"]["model_directory"]
    library_directory = root / baseline_provider["library_directory"]
    fixed_arguments = [
        str(library_directory) if value == "{library_directory}" else value
        for value in baseline_provider["fixed_arguments"]
    ]
    case_results: list[dict[str, Any]] = []
    for case in model["cases"]:
        directory = cases_output / case["id"]
        directory.mkdir()
        source_path = _relative(root, case["path"], f"model for {case['id']}")
        source = concurrency_c3_lkmm._code_without_comments(source_path.read_text())
        argv = [str(herd_binary), *fixed_arguments, str(source_path)]
        process = concurrency_c3_lkmm._run(argv, model_directory, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, model_directory, process)
        try:
            parsed = concurrency_c3_lkmm.parse_herd_output(process["stdout"])
            parse_error = None
        except concurrency_c3_lkmm.ConcurrencyC3LkmmError as exc:
            parsed = None
            parse_error = str(exc)
        case_checks = [
            _check("model identity", case["sha256"], _sha256(source_path)),
            _check("timed out", False, process["timed_out"]),
            _check("exit code", 0, process["returncode"]),
            _check("stderr empty", "", process["stderr"]),
            _check("parse error", None, parse_error),
            _check("semantic result", case["expected"],
                   concurrency_c3_lkmm._core_result(parsed)),
            _check("only positive case is verification candidate",
                   case["id"] == "refcount_put_get_positive",
                   case["verification_candidate"]),
        ]
        for operation in case["required_operations"]:
            case_checks.append(_check(
                f"required operation: {operation}", True,
                concurrency_c3_lkmm._operation_present(source, operation),
            ))
        for operation in case["forbidden_operations"]:
            case_checks.append(_check(
                f"forbidden operation: {operation}", False,
                concurrency_c3_lkmm._operation_present(source, operation),
            ))
        case_result = {
            "id": case["id"],
            "role": case["role"],
            "verification_candidate": case["verification_candidate"],
            "control_for": case["control_for"],
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "parsed": parsed,
            "parse_error": parse_error,
            "checks": case_checks,
            "passed": all(item["passed"] for item in case_checks),
        }
        _json(directory / "result.json", case_result)
        case_results.append(case_result)

    by_id = {case["id"]: case for case in case_results}
    positive_result = by_id[model["pair"]["positive"]]
    negative_result = by_id[model["pair"]["negative"]]
    pair_checks = [
        _check("A/B cases both pass", True,
               positive_result["passed"] and negative_result["passed"]),
        _check("positive forbids mutual success", "Never",
               (positive_result["parsed"] or {}).get("observation")),
        _check("positive has zero bad witnesses", 0,
               (positive_result["parsed"] or {}).get("positive")),
        _check("unsafe control exposes mutual success", "Sometimes",
               (negative_result["parsed"] or {}).get("observation")),
        _check("unsafe control has a bad witness", True,
               (negative_result["parsed"] or {}).get("positive", 0) > 0),
        _check("A/B condition is identical",
               (positive_result["parsed"] or {}).get("condition"),
               (negative_result["parsed"] or {}).get("condition")),
    ]
    checks.extend(item for case in case_results for item in case["checks"])
    checks.extend(pair_checks)
    accepted = all(item["passed"] for item in checks)

    identity_names = sorted(set([
        *kernel["source_identities"],
        manifest["baseline"]["manifest"],
        "config/concurrency-c3-ipc-refcount.json",
        "fragma/__main__.py",
        "fragma/concurrency_c2.py",
        "fragma/concurrency_c2_irq.py",
        "fragma/concurrency_c3_lkmm.py",
        "fragma/concurrency_c3_trace.py",
        "fragma/concurrency_c3_module_stats.py",
        "fragma/concurrency_c3_ipc_refcount.py",
        "tests/test_concurrency_c3_ipc_refcount.py",
        *[case["path"] for case in model["cases"]],
    ]))
    identities = {
        name: {
            "sha256": _sha256(_relative(root, name, "IPC C3 input identity")),
            "size": _relative(root, name, "IPC C3 input identity").stat().st_size,
        }
        for name in identity_names
    }
    for profile in manifest["profiles"]:
        for name in ("make", "compiler", "objdump"):
            binary = Path(profile[name]["binary"])
            identities[str(binary)] = {
                "sha256": _sha256(binary),
                "size": binary.stat().st_size,
                "realpath": str(binary.resolve()),
            }
    identities[str(herd_binary)] = {
        "sha256": _sha256(herd_binary),
        "size": herd_binary.stat().st_size,
        "realpath": str(herd_binary.resolve()),
    }
    _json(output / "manifest.json", manifest)
    _json(output / "input-identities.json", identities)
    _json(output / "source-model-evidence.json", source_model_evidence)
    result = {
        "schema_version": 5,
        "kind": "ipc-refcount-c3-lifetime-progress-multiarch-pilot",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": manifest["id"],
        "kernel_revision": kernel["revision"],
        "kernel_tree": kernel["git_tree"],
        "kernel_profiles": [profile["id"] for profile in manifest["profiles"]],
        "property": manifest["property"],
        "model_abstraction": model["abstraction"],
        "source_model_evidence": source_model_evidence,
        "progress": progress_result,
        "profiles": profile_results,
        "configured_objects": {
            profile["id"]: profile["configured_object"]
            for profile in profile_results
        },
        "configured_config_sha256": {
            profile["id"]: profile["configured_config_sha256"]
            for profile in profile_results
        },
        "cases": case_results,
        "pair_checks": pair_checks,
        "checks": checks,
        "input_identities": identities,
        "baseline": {
            "accepted": baseline_result["accepted"],
            "checks": len(baseline_result["checks"]),
            "output": baseline_result["output"],
        },
        "accepted": accepted,
        "architecture_mapping_count": sum(
            profile["accepted"] for profile in profile_results
        ),
        "kernel_verification_count": 2 if accepted else 0,
        "lifetime_verification_count": 1 if accepted else 0,
        "progress_verification_count": 1 if accepted else 0,
        "detecting_control_count": 4 if accepted else 0,
        "c3_lifetime_functional_pilot_complete": accepted,
        "c3_bounded_progress_pilot_complete": accepted,
        "c3_selected_architecture_mappings_complete": accepted,
        "progress_implementation_mapping_count": (
            len(progress_result["implementation_profiles"]) if accepted else 0
        ),
        "c3_stage_complete": False,
        "remaining_c3": [
            "Unbounded progress, scheduler fairness, wait-freedom and LL/SC implementation liveness",
            "Implementation mappings for Linux architectures beyond x86-64, arm64, riscv64, s390x, ARM32, PowerPC32, SuperH, Alpha, and UML x86-64",
            "Broader lock-free functional protocol coverage",
        ],
        "call_rcu_modeled": False,
        "klitmus_or_runtime_used": False,
        "sudo_or_install_used": False,
        "output": str(output),
    }
    result["raw_artifacts"] = concurrency_c3_module_stats._artifact_hashes(output)
    _json(output / "summary.json", result)
    _json(output / "pilot-audit.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c3-ipc-refcount-{stamp}"
