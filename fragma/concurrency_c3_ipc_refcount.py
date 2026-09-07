"""Source-linked C3 LKMM pilot for the System V IPC refcount lifetime gate."""

from __future__ import annotations

from datetime import datetime, timezone
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


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and aggressively validate the sole IPC lifetime pilot."""
    root = root.resolve()
    manifest = _strict_json(root / "config/concurrency-c3-ipc-refcount.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema_version", "id", "kernel", "baseline", "profile",
            "property", "model",
        }
        or manifest["schema_version"] != 1
        or manifest["id"] != "linux-ipc-refcount-lifetime-x86_64-c3"
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
    if not isinstance(identities, dict) or len(identities) != 15:
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

    profile = manifest["profile"]
    if not isinstance(profile, dict) or set(profile) != {
        "id", "arch", "jobs", "build_directory", "config", "config_sha256",
        "configuration", "required_config", "make", "compiler", "objdump",
        "configured_compile",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC build profile is not exact")
    if (
        profile["id"] != "x86_64-ipc-refcount-c3"
        or profile["arch"] != "x86_64"
        or type(profile["jobs"]) is not int
        or not 1 <= profile["jobs"] <= 256
    ):
        raise ConcurrencyC3IpcRefcountError("unexpected IPC build profile")
    build_directory = _declared_path(root, profile["build_directory"], "build directory")
    config_path = _declared_path(root, profile["config"], "kernel config")
    try:
        config_path.resolve().relative_to(build_directory.resolve())
    except ValueError as exc:
        raise ConcurrencyC3IpcRefcountError(
            "kernel config is outside build directory"
        ) from exc
    _digest(profile["config_sha256"], "kernel config identity")
    configuration = profile["configuration"]
    if (
        not isinstance(configuration, dict)
        or configuration != {
            "base_recipe": "x86_64_defconfig",
            "finalize_recipe": "olddefconfig",
        }
    ):
        raise ConcurrencyC3IpcRefcountError("unexpected IPC config recipe")
    required_config = profile["required_config"]
    if not isinstance(required_config, dict) or set(required_config) != {
        "CONFIG_64BIT", "CONFIG_X86_64", "CONFIG_SMP", "CONFIG_SYSVIPC",
        "CONFIG_TREE_RCU", "CONFIG_PREEMPT_RCU", "CONFIG_RCU_EXPERT",
        "CONFIG_KCSAN", "CONFIG_CC_IS_GCC",
    }:
        raise ConcurrencyC3IpcRefcountError("IPC config requirements are not exact")
    if any(value not in {"y", "n", "m", "absent"} for value in required_config.values()):
        raise ConcurrencyC3IpcRefcountError("invalid IPC config value")
    for tool_name in ("make", "compiler", "objdump"):
        _validate_tool(profile[tool_name], tool_name, target=tool_name == "compiler")

    compile_record = profile["configured_compile"]
    if not isinstance(compile_record, dict) or set(compile_record) != {
        "target", "object", "command_file", "object_sha256", "command_sha256",
        "elf_class", "elf_data", "elf_machine", "required_command_tokens",
        "functions",
    }:
        raise ConcurrencyC3IpcRefcountError("configured IPC compile is not exact")
    if compile_record["target"] != "ipc/util.o":
        raise ConcurrencyC3IpcRefcountError("unexpected IPC object target")
    for key in ("object", "command_file"):
        path = _declared_path(root, compile_record[key], f"configured {key}")
        try:
            path.resolve().relative_to(build_directory.resolve())
        except ValueError as exc:
            raise ConcurrencyC3IpcRefcountError(
                f"configured {key} is outside build"
            ) from exc
    _digest(compile_record["object_sha256"], "configured object identity")
    _digest(compile_record["command_sha256"], "configured command identity")
    if [compile_record[key] for key in ("elf_class", "elf_data", "elf_machine")] != [2, 1, 62]:
        raise ConcurrencyC3IpcRefcountError(
            "configured object must be ELF64 little-endian x86-64"
        )
    _strings(compile_record["required_command_tokens"], "compile command tokens")
    functions = compile_record["functions"]
    if not isinstance(functions, dict) or set(functions) != {
        "ipc_rcu_getref", "ipc_rcu_putref",
    }:
        raise ConcurrencyC3IpcRefcountError("configured function inventory is not exact")
    for name, function in functions.items():
        if (
            not isinstance(function, dict)
            or set(function) != {"section", "value", "size", "disassembly_order"}
            or function["section"] != ".text"
            or not re.fullmatch(r"[0-9a-f]{16}", function["value"])
            or type(function["size"]) is not int
            or function["size"] < 1
        ):
            raise ConcurrencyC3IpcRefcountError(f"invalid configured function {name}")
        _strings(function["disassembly_order"], f"{name} disassembly order")

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
    exclusions = " ".join(_strings(prop["exclusions"], "property exclusions")).lower()
    for boundary in (
        "caller-locking", "third refcount update", "rcu grace", "saturation",
        "control-dependency", "detecting control", "architecture", "progress",
        "whole-kernel",
    ):
        if boundary not in exclusions:
            raise ConcurrencyC3IpcRefcountError(
                f"IPC property omits {boundary} exclusion"
            )

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


def _function_symbols(value: str, names: set[str]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^(?P<value>[0-9a-f]{16})\s+g\s+F\s+"
        r"(?P<section>\.[A-Za-z0-9_.]+)\s+"
        r"(?P<size>[0-9a-f]{16})\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)$",
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
    }


def render_summary(result: dict[str, Any]) -> str:
    passed = sum(item["passed"] for item in result["checks"])
    lines = [
        "# System V IPC refcount C3 lifetime pilot",
        "",
        f"Overall source-linked gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Accepted kernel lifetime properties: **{result['kernel_verification_count']}**",
        f"LKMM functional cases: **{len(result['cases'])}**",
        "",
        "| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |",
        "|---|---|---|---:|---:|---|",
    ]
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
        f"Evidence checks: **{passed}/{len(result['checks'])} passed**.",
        "",
        "Starting with the IPC contract's sole reference, the selected final put",
        "and get-unless-zero cannot both decide that destruction should be scheduled",
        "and that a reference was acquired. LKMM reports the mutual-success outcome",
        "`Never` (0/2 witnesses). The unsafe unconditional-increment control can",
        "resurrect zero and reports `Sometimes` (1/1).",
        "",
        "The gate pins the IPC helper and locking contract, refcount implementation,",
        "LKMM RMW axiom, configured x86-64 object, both function symbols, and its",
        "`lock cmpxchg`/`lock xadd` lowering. The caller-locking prerequisite is an",
        "assumption. Callback execution and RCU grace periods are not modeled.",
        "",
        "No allocator reuse, arbitrary refcount population, progress, other",
        "architecture, whole-IPC, whole-RCU, or whole-kernel property is accepted.",
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
    build_output = output / "build"
    cases_output = output / "cases"
    build_output.mkdir()
    cases_output.mkdir()

    kernel = manifest["kernel"]
    profile = manifest["profile"]
    configuration = profile["configuration"]
    compile_record = profile["configured_compile"]
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

    tool_inventory: dict[str, dict[str, Any]] = {}
    tool_commands = {
        "make_version": [profile["make"]["binary"], "--version"],
        "compiler_version": [profile["compiler"]["binary"], "--version"],
        "compiler_target": [profile["compiler"]["binary"], "-dumpmachine"],
        "objdump_version": [profile["objdump"]["binary"], "--version"],
    }
    for name, argv in tool_commands.items():
        directory = build_output / name
        directory.mkdir()
        process = concurrency_c3_lkmm._run(argv, root, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, root, process)
        tool_inventory[name] = process
        checks.extend([
            _check(f"{name} timed out", False, process["timed_out"]),
            _check(f"{name} exit", 0, process["returncode"]),
        ])
    for tool_name in ("make", "compiler", "objdump"):
        tool = profile[tool_name]
        binary = Path(tool["binary"])
        checks.extend([
            _check(f"{tool_name} realpath", tool["realpath"], str(binary.resolve())),
            _check(f"{tool_name} identity", tool["sha256"], _sha256(binary)),
        ])
    checks.extend([
        _check("make version line", profile["make"]["version_line"],
               tool_inventory["make_version"]["stdout"].splitlines()[0]),
        _check("compiler version line", profile["compiler"]["version_line"],
               tool_inventory["compiler_version"]["stdout"].splitlines()[0]),
        _check("compiler target", profile["compiler"]["target"],
               tool_inventory["compiler_target"]["stdout"].strip()),
        _check("objdump version line", profile["objdump"]["version_line"],
               tool_inventory["objdump_version"]["stdout"].splitlines()[0]),
    ])

    source_root = root / kernel["source_root"]
    build_directory = _declared_path(root, profile["build_directory"], "build directory")
    if build_directory.is_symlink():
        raise ConcurrencyC3IpcRefcountError("IPC build directory must not be a symlink")
    build_directory.mkdir(parents=True, exist_ok=True)
    common_make = [
        profile["make"]["binary"], "-C", str(source_root),
        f"O={build_directory}", f"ARCH={profile['arch']}",
        f"CC={profile['compiler']['binary']}",
    ]
    build_steps = [
        ("base_config", [*common_make, configuration["base_recipe"]]),
        ("finalize_config", [*common_make, configuration["finalize_recipe"]]),
    ]
    for name, argv in build_steps:
        directory = build_output / name
        directory.mkdir()
        process = concurrency_c3_lkmm._run(argv, root, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, root, process)
        checks.extend([
            _check(f"{name} timed out", False, process["timed_out"]),
            _check(f"{name} exit", 0, process["returncode"]),
        ])

    config_path = _declared_path(root, profile["config"], "kernel config")
    config_exists = config_path.is_file() and not config_path.is_symlink()
    checks.append(_check("configured profile produced config", True, config_exists))
    config_hash = _sha256(config_path) if config_exists else None
    checks.append(_check("configured config identity", profile["config_sha256"], config_hash))
    config_values = concurrency_c2.parse_kconfig(config_path.read_text() if config_exists else "")
    for name, expected in profile["required_config"].items():
        checks.append(_check(
            f"kernel config: {name}", expected, config_values.get(name, "absent")
        ))

    object_directory = build_output / "object"
    object_directory.mkdir()
    object_argv = [*common_make, f"-j{profile['jobs']}", compile_record["target"]]
    object_process = concurrency_c3_lkmm._run(object_argv, root, timeout)
    concurrency_c3_lkmm._write_process(object_directory, object_argv, root, object_process)
    checks.extend([
        _check("configured object build timed out", False, object_process["timed_out"]),
        _check("configured object build exit", 0, object_process["returncode"]),
    ])
    object_path = _declared_path(root, compile_record["object"], "configured object")
    object_exists = object_path.is_file() and not object_path.is_symlink()
    checks.append(_check("configured object exists", True, object_exists))
    elf = concurrency_c3_trace._elf_identity(object_path) if object_exists else {
        "elf": False, "class": None, "data": None, "machine": None,
    }
    checks.extend([
        _check("configured object is ELF", True, elf["elf"]),
        _check("configured object class", compile_record["elf_class"], elf["class"]),
        _check("configured object byte order", compile_record["elf_data"], elf["data"]),
        _check("configured object machine", compile_record["elf_machine"], elf["machine"]),
        _check("configured object identity", compile_record["object_sha256"],
               elf.get("sha256")),
    ])
    command_path = _declared_path(root, compile_record["command_file"], "compile command")
    command_exists = command_path.is_file() and not command_path.is_symlink()
    command_text = command_path.read_text() if command_exists else ""
    checks.extend([
        _check("configured command exists", True, command_exists),
        _check("configured command identity", compile_record["command_sha256"],
               _sha256(command_path) if command_exists else None),
    ])
    for token in compile_record["required_command_tokens"]:
        checks.append(_check(
            f"configured command token: {token}", True, token in command_text
        ))

    disassembly_directory = build_output / "disassembly"
    symbols_directory = build_output / "symbols"
    disassembly_directory.mkdir()
    symbols_directory.mkdir()
    disassembly_argv = [
        profile["objdump"]["binary"], "-dr", "--no-show-raw-insn", str(object_path)
    ]
    symbols_argv = [profile["objdump"]["binary"], "-t", str(object_path)]
    disassembly_process = concurrency_c3_lkmm._run(disassembly_argv, root, timeout)
    symbols_process = concurrency_c3_lkmm._run(symbols_argv, root, timeout)
    concurrency_c3_lkmm._write_process(
        disassembly_directory, disassembly_argv, root, disassembly_process
    )
    concurrency_c3_lkmm._write_process(
        symbols_directory, symbols_argv, root, symbols_process
    )
    checks.extend([
        _check("disassembly timed out", False, disassembly_process["timed_out"]),
        _check("disassembly exit", 0, disassembly_process["returncode"]),
        _check("disassembly stderr empty", "", disassembly_process["stderr"]),
        _check("symbol inventory timed out", False, symbols_process["timed_out"]),
        _check("symbol inventory exit", 0, symbols_process["returncode"]),
        _check("symbol inventory stderr empty", "", symbols_process["stderr"]),
    ])
    selected_disassembly: dict[str, str] = {}
    disassembly_errors: dict[str, str] = {}
    for name, function in compile_record["functions"].items():
        try:
            block = concurrency_c3_trace._function_block(
                disassembly_process["stdout"], name
            )
        except concurrency_c3_trace.ConcurrencyC3TraceError as exc:
            block = ""
            disassembly_errors[name] = str(exc)
        selected_disassembly[name] = block
        checks.extend([
            _check(f"{name} disassembly parser error", None,
                   disassembly_errors.get(name)),
            _check(f"{name} instruction order", True,
                   _ordered(block, function["disassembly_order"])),
        ])
    expected_symbols = {
        name: {key: function[key] for key in ("section", "value", "size")}
        for name, function in compile_record["functions"].items()
    }
    observed_symbols = _function_symbols(
        symbols_process["stdout"], set(compile_record["functions"])
    )
    checks.append(_check("configured function symbols", expected_symbols, observed_symbols))
    _json(build_output / "selected-disassembly.json", {
        "functions": selected_disassembly,
        "symbols": observed_symbols,
    })

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
        "schema_version": 1,
        "kind": "ipc-refcount-c3-lifetime-functional-pilot",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": manifest["id"],
        "kernel_revision": kernel["revision"],
        "kernel_tree": kernel["git_tree"],
        "kernel_profile": profile["id"],
        "property": manifest["property"],
        "model_abstraction": model["abstraction"],
        "source_model_evidence": source_model_evidence,
        "configured_object": elf,
        "configured_config_sha256": config_hash,
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
        "kernel_verification_count": 1 if accepted else 0,
        "detecting_control_count": 1 if accepted else 0,
        "c3_lifetime_functional_pilot_complete": accepted,
        "c3_stage_complete": False,
        "remaining_c3": [
            "Any separately justified progress property",
            "Refcount and other C3 implementation mappings beyond x86-64",
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
