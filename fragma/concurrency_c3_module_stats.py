"""Source-linked C3 LKMM pilot for the module-failure atomic counter."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import re
from typing import Any

from . import concurrency_c2, concurrency_c2_irq, concurrency_c3_lkmm
from . import concurrency_c3_trace


class ConcurrencyC3ModuleStatsError(ValueError):
    """The module-statistics declaration, source, build, or evidence is invalid."""


_CASE_IDS = {
    "atomic_inc_positive",
    "split_once_negative",
    "atomic_return_mb_positive",
    "atomic_return_relaxed_negative",
}
_CASE_ROLES = {
    "verification_candidate",
    "required_weakened_control",
    "ordered_calibration",
    "weakened_calibration",
}
_PAIR_IDS = {"module_stats_atomicity", "return_ordering_calibration"}


def _strict_json(path: Path) -> Any:
    try:
        return concurrency_c3_lkmm._strict_json(path)
    except concurrency_c3_lkmm.ConcurrencyC3LkmmError as exc:
        raise ConcurrencyC3ModuleStatsError(str(exc)) from exc


def _json(path: Path, value: Any) -> None:
    concurrency_c3_lkmm._json(path, value)


def _sha256(path: Path) -> str:
    return concurrency_c3_lkmm._sha256(path)


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyC3ModuleStatsError(f"{role} must be a nonempty string")
    return value


def _digest(value: Any, role: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        rf"[0-9a-f]{{{length}}}", value
    ):
        raise ConcurrencyC3ModuleStatsError(
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
        raise ConcurrencyC3ModuleStatsError(
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
        raise ConcurrencyC3ModuleStatsError(str(exc)) from exc


def _declared_path(root: Path, value: Any, role: str) -> Path:
    if not isinstance(value, str):
        raise ConcurrencyC3ModuleStatsError(f"{role} must be project-relative")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC3ModuleStatsError(
            f"{role} must be project-relative: {value!r}"
        )
    path = root.joinpath(*pure.parts)
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ConcurrencyC3ModuleStatsError(
            f"{role} escapes the project root"
        ) from exc
    return path


def _validate_tool(record: Any, name: str, *, target: bool = False) -> None:
    keys = {"binary", "realpath", "sha256", "version_line"}
    if target:
        keys.add("target")
    if not isinstance(record, dict) or set(record) != keys:
        raise ConcurrencyC3ModuleStatsError(f"{name} tool record is not exact")
    for key in ("binary", "realpath"):
        path = Path(_nonempty(record[key], f"{name} {key}"))
        if not path.is_absolute() or (key == "binary" and not path.is_file()):
            raise ConcurrencyC3ModuleStatsError(f"{name} {key} must be absolute")
    _digest(record["sha256"], f"{name} identity")
    _nonempty(record["version_line"], f"{name} version")
    if target:
        _nonempty(record["target"], f"{name} target")


def _validate_expected(expected: Any, case_id: str) -> None:
    if not isinstance(expected, dict) or set(expected) != {
        "test", "disposition", "states", "marker", "positive", "negative",
        "flags", "condition", "observation", "hash",
    }:
        raise ConcurrencyC3ModuleStatsError(
            f"expected output for {case_id} is not exact"
        )
    for key in ("test", "disposition", "marker", "condition", "observation"):
        _nonempty(expected[key], f"{case_id} expected {key}")
    for key in ("states", "positive", "negative"):
        if type(expected[key]) is not int or expected[key] < 0:
            raise ConcurrencyC3ModuleStatsError(
                f"{case_id} expected {key} is invalid"
            )
    if (
        not isinstance(expected["flags"], list)
        or any(not isinstance(flag, str) or not flag for flag in expected["flags"])
        or len(expected["flags"]) != len(set(expected["flags"]))
    ):
        raise ConcurrencyC3ModuleStatsError(f"{case_id} flags are invalid")
    _digest(expected["hash"], f"{case_id} herd hash", 32)


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and aggressively validate the sole source-linked atomic pilot."""
    root = root.resolve()
    manifest = _strict_json(root / "config/concurrency-c3-module-stats.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema_version", "id", "kernel", "baseline", "profile",
            "property", "model",
        }
        or manifest["schema_version"] != 1
        or manifest["id"] != "linux-module-stats-atomic-rmw-x86_64-c3"
    ):
        raise ConcurrencyC3ModuleStatsError("unsupported module-statistics C3 schema")

    kernel = manifest["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
        "revision", "git_tree", "source_root", "source_receipt",
        "source_identities",
    }:
        raise ConcurrencyC3ModuleStatsError("module-statistics kernel record is not exact")
    _digest(kernel["revision"], "kernel revision", 40)
    _digest(kernel["git_tree"], "kernel tree", 40)
    source_root = _relative(root, kernel["source_root"], "kernel source", directory=True)
    receipt = _relative(root, kernel["source_receipt"], "source receipt")
    try:
        receipt.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ConcurrencyC3ModuleStatsError(
            "source receipt is outside kernel source"
        ) from exc
    identities = kernel["source_identities"]
    if not isinstance(identities, dict) or len(identities) != 12:
        raise ConcurrencyC3ModuleStatsError(
            "module-statistics source identity set is not exact"
        )
    for name, digest in identities.items():
        _relative(root, name, "module-statistics source identity")
        _digest(digest, f"source identity for {name}")

    baseline = manifest["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != {
        "manifest", "id", "required_capability",
    }:
        raise ConcurrencyC3ModuleStatsError("atomic pilot baseline link is not exact")
    _relative(root, baseline["manifest"], "C3 baseline manifest")
    if (
        baseline["id"] != "linux-lkmm-herd7-c3-calibration"
        or baseline["required_capability"] != "c3_capability_baseline_complete"
    ):
        raise ConcurrencyC3ModuleStatsError("atomic pilot names the wrong baseline")

    profile = manifest["profile"]
    if not isinstance(profile, dict) or set(profile) != {
        "id", "arch", "jobs", "build_directory", "config", "config_sha256",
        "configuration", "required_config", "make", "compiler", "objdump",
        "configured_compile",
    }:
        raise ConcurrencyC3ModuleStatsError("atomic build profile is not exact")
    if (
        profile["id"] != "x86_64-module-stats-c3"
        or profile["arch"] != "x86_64"
        or type(profile["jobs"]) is not int
        or not 1 <= profile["jobs"] <= 256
    ):
        raise ConcurrencyC3ModuleStatsError("unexpected atomic build profile")
    build_directory = _declared_path(root, profile["build_directory"], "build directory")
    config_path = _declared_path(root, profile["config"], "kernel config")
    try:
        config_path.resolve().relative_to(build_directory.resolve())
    except ValueError as exc:
        raise ConcurrencyC3ModuleStatsError(
            "kernel config is outside build directory"
        ) from exc
    _digest(profile["config_sha256"], "kernel config identity")

    configuration = profile["configuration"]
    if not isinstance(configuration, dict) or set(configuration) != {
        "base_recipe", "config_tool", "config_tool_sha256", "enable",
        "finalize_recipe",
    }:
        raise ConcurrencyC3ModuleStatsError("configuration recipe is not exact")
    if (
        configuration["base_recipe"] != "x86_64_defconfig"
        or configuration["finalize_recipe"] != "olddefconfig"
        or configuration["enable"] != ["DEBUG_FS", "MODULE_DEBUG", "MODULE_STATS"]
    ):
        raise ConcurrencyC3ModuleStatsError("unexpected module-statistics config recipe")
    config_tool = _relative(root, configuration["config_tool"], "kernel config tool")
    try:
        config_tool.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ConcurrencyC3ModuleStatsError(
            "kernel config tool is outside source snapshot"
        ) from exc
    _digest(configuration["config_tool_sha256"], "config tool identity")

    required_config = profile["required_config"]
    if not isinstance(required_config, dict) or set(required_config) != {
        "CONFIG_64BIT", "CONFIG_X86_64", "CONFIG_SMP", "CONFIG_MODULES",
        "CONFIG_DEBUG_FS", "CONFIG_MODULE_DEBUG", "CONFIG_MODULE_STATS",
        "CONFIG_KCSAN", "CONFIG_CC_IS_GCC",
    }:
        raise ConcurrencyC3ModuleStatsError("atomic config requirements are not exact")
    if any(value not in {"y", "n", "m", "absent"} for value in required_config.values()):
        raise ConcurrencyC3ModuleStatsError("invalid atomic config value")
    for tool_name in ("make", "compiler", "objdump"):
        _validate_tool(profile[tool_name], tool_name, target=tool_name == "compiler")

    compile_record = profile["configured_compile"]
    if not isinstance(compile_record, dict) or set(compile_record) != {
        "target", "object", "command_file", "object_sha256", "command_sha256",
        "elf_class", "elf_data", "elf_machine", "required_command_tokens",
        "function_disassembly_order", "local_symbols",
    }:
        raise ConcurrencyC3ModuleStatsError("configured atomic compile is not exact")
    if compile_record["target"] != "kernel/module/stats.o":
        raise ConcurrencyC3ModuleStatsError("unexpected atomic object target")
    for key in ("object", "command_file"):
        path = _declared_path(root, compile_record[key], f"configured {key}")
        try:
            path.resolve().relative_to(build_directory.resolve())
        except ValueError as exc:
            raise ConcurrencyC3ModuleStatsError(
                f"configured {key} is outside build"
            ) from exc
    _digest(compile_record["object_sha256"], "configured object identity")
    _digest(compile_record["command_sha256"], "configured command identity")
    if [compile_record[key] for key in ("elf_class", "elf_data", "elf_machine")] != [2, 1, 62]:
        raise ConcurrencyC3ModuleStatsError(
            "configured object must be ELF64 little-endian x86-64"
        )
    _strings(compile_record["required_command_tokens"], "compile command tokens")
    _strings(compile_record["function_disassembly_order"], "disassembly order")
    symbols = compile_record["local_symbols"]
    if not isinstance(symbols, dict) or set(symbols) != {
        "failed_load_modules", "invalid_mod_bytes",
    }:
        raise ConcurrencyC3ModuleStatsError("configured symbol inventory is not exact")
    expected_sizes = {"failed_load_modules": 4, "invalid_mod_bytes": 8}
    for name, symbol in symbols.items():
        if (
            not isinstance(symbol, dict)
            or set(symbol) != {"section", "value", "size"}
            or symbol["section"] != ".bss"
            or not re.fullmatch(r"[0-9a-f]{16}", symbol["value"])
            or symbol["size"] != expected_sizes[name]
        ):
            raise ConcurrencyC3ModuleStatsError(f"invalid configured symbol {name}")

    prop = manifest["property"]
    if not isinstance(prop, dict) or set(prop) != {
        "kind", "claim", "source_file", "source_function", "caller_file",
        "caller_function", "counter", "source_update", "model_update",
        "concurrency_argument", "lifetime_argument", "implementation_argument",
        "exclusions",
    }:
        raise ConcurrencyC3ModuleStatsError("atomic property record is not exact")
    if (
        prop["kind"] != "kernel_atomic_rmw_no_lost_update"
        or prop["source_function"] != "mod_stat_bump_invalid"
        or prop["caller_function"] != "load_module"
        or prop["counter"] != "failed_load_modules"
        or prop["source_update"] != "atomic_inc(&failed_load_modules);"
        or prop["model_update"] != "atomic_inc(counter);"
    ):
        raise ConcurrencyC3ModuleStatsError("unexpected module-statistics property")
    _relative(root, prop["source_file"], "property source file")
    _relative(root, prop["caller_file"], "property caller file")
    for key in (
        "claim", "concurrency_argument", "lifetime_argument",
        "implementation_argument",
    ):
        _nonempty(prop[key], f"property {key}")
    exclusions = _strings(prop["exclusions"], "atomic property exclusions")
    excluded = " ".join(exclusions).lower()
    for boundary in (
        "third update", "debugfs", "ordering", "wraparound", "architecture",
        "progress", "whole-kernel",
    ):
        if boundary not in excluded:
            raise ConcurrencyC3ModuleStatsError(
                f"atomic property omits {boundary} exclusion"
            )

    model = manifest["model"]
    if not isinstance(model, dict) or set(model) != {
        "atomicity_condition", "ordering_condition", "abstraction", "pairs",
        "cases",
    }:
        raise ConcurrencyC3ModuleStatsError("atomic model record is not exact")
    if (
        model["atomicity_condition"] != "exists ([counter]=1)"
        or model["ordering_condition"] != "exists (0:r0=0 /\\ 1:r0=0)"
    ):
        raise ConcurrencyC3ModuleStatsError("unexpected atomic model conditions")
    abstraction = model["abstraction"]
    if not isinstance(abstraction, dict) or set(abstraction) != {
        "counter", "threads", "bad_atomicity_outcome", "omitted",
    }:
        raise ConcurrencyC3ModuleStatsError("atomic abstraction is not exact")
    for key, value in abstraction.items():
        _nonempty(value, f"atomic abstraction {key}")

    cases = model["cases"]
    if not isinstance(cases, list) or len(cases) != 4:
        raise ConcurrencyC3ModuleStatsError("atomic pilot requires four cases")
    by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id", "path", "sha256", "role", "verification_candidate",
            "control_for", "required_operations", "forbidden_operations",
            "expected",
        }:
            raise ConcurrencyC3ModuleStatsError("atomic case record is not exact")
        case_id = case["id"]
        if case_id not in _CASE_IDS or case_id in by_id:
            raise ConcurrencyC3ModuleStatsError(
                f"invalid or duplicate atomic case {case_id!r}"
            )
        by_id[case_id] = case
        _relative(root, case["path"], f"model for {case_id}")
        _digest(case["sha256"], f"model identity for {case_id}")
        if case["role"] not in _CASE_ROLES:
            raise ConcurrencyC3ModuleStatsError(f"invalid role for {case_id}")
        required = _strings(case["required_operations"], f"{case_id} required operations")
        forbidden = _strings(case["forbidden_operations"], f"{case_id} forbidden operations")
        if set(required) & set(forbidden):
            raise ConcurrencyC3ModuleStatsError(f"contradictory operations for {case_id}")
        _validate_expected(case["expected"], case_id)
        if case["expected"]["disposition"] != "Allowed":
            raise ConcurrencyC3ModuleStatsError(f"{case_id} must use Allowed query")
    if set(by_id) != _CASE_IDS:
        raise ConcurrencyC3ModuleStatsError("atomic case inventory is incomplete")

    expected_roles = {
        "atomic_inc_positive": ("verification_candidate", True, None, "Never", 0),
        "split_once_negative": (
            "required_weakened_control", False, "atomic_inc_positive", "Sometimes", 2,
        ),
        "atomic_return_mb_positive": (
            "ordered_calibration", False, None, "Never", 0,
        ),
        "atomic_return_relaxed_negative": (
            "weakened_calibration", False, "atomic_return_mb_positive", "Sometimes", 1,
        ),
    }
    for case_id, (role, candidate, control, observation, minimum_positive) in expected_roles.items():
        case = by_id[case_id]
        expected = case["expected"]
        if (
            case["role"] != role
            or case["verification_candidate"] is not candidate
            or case["control_for"] != control
            or expected["observation"] != observation
            or expected["flags"] != []
            or (observation == "Never" and expected["positive"] != 0)
            or (observation == "Sometimes" and expected["positive"] < minimum_positive)
            or expected["marker"] != ("No" if observation == "Never" else "Ok")
        ):
            raise ConcurrencyC3ModuleStatsError(
                f"atomic case {case_id} cannot satisfy its evidence role"
            )
    if (
        by_id["atomic_inc_positive"]["expected"]["condition"]
        != model["atomicity_condition"]
        or by_id["split_once_negative"]["expected"]["condition"]
        != model["atomicity_condition"]
        or by_id["atomic_return_mb_positive"]["expected"]["condition"]
        != model["ordering_condition"]
        or by_id["atomic_return_relaxed_negative"]["expected"]["condition"]
        != model["ordering_condition"]
    ):
        raise ConcurrencyC3ModuleStatsError("atomic A/B condition drift")

    pairs = model["pairs"]
    if not isinstance(pairs, list) or len(pairs) != 2:
        raise ConcurrencyC3ModuleStatsError("atomic pilot requires two A/B pairs")
    observed_pairs: set[str] = set()
    members: set[str] = set()
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {
            "id", "positive", "negative", "expected_transition", "source_linked",
        }:
            raise ConcurrencyC3ModuleStatsError("atomic pair record is not exact")
        pair_id = pair["id"]
        if pair_id not in _PAIR_IDS or pair_id in observed_pairs:
            raise ConcurrencyC3ModuleStatsError(f"invalid atomic pair {pair_id!r}")
        observed_pairs.add(pair_id)
        if (
            pair["positive"] not in by_id
            or pair["negative"] not in by_id
            or pair["positive"] == pair["negative"]
            or pair["expected_transition"] != "Sometimes->Never"
            or type(pair["source_linked"]) is not bool
        ):
            raise ConcurrencyC3ModuleStatsError(f"invalid members for pair {pair_id}")
        if by_id[pair["negative"]]["control_for"] != pair["positive"]:
            raise ConcurrencyC3ModuleStatsError(f"unlinked control for pair {pair_id}")
        members.update((pair["positive"], pair["negative"]))
    if observed_pairs != _PAIR_IDS or members != _CASE_IDS:
        raise ConcurrencyC3ModuleStatsError("atomic pair inventory is incomplete")
    source_pair = next(pair for pair in pairs if pair["id"] == "module_stats_atomicity")
    if (
        source_pair["positive"] != "atomic_inc_positive"
        or source_pair["negative"] != "split_once_negative"
        or source_pair["source_linked"] is not True
    ):
        raise ConcurrencyC3ModuleStatsError("wrong source-linked atomic pair")
    calibration_pair = next(
        pair for pair in pairs if pair["id"] == "return_ordering_calibration"
    )
    if calibration_pair["source_linked"] is not False:
        raise ConcurrencyC3ModuleStatsError("ordering pair cannot claim source linkage")
    return manifest


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {
        "name": name,
        "expected": expected,
        "actual": actual,
        "passed": expected == actual,
    }


def _ordered(text: str, snippets: list[str]) -> bool:
    return concurrency_c3_trace._ordered(text, snippets)


def _function_source(path: Path, function: str) -> str:
    try:
        return concurrency_c2_irq.extract_function(path.read_text(), function)
    except concurrency_c2_irq.ConcurrencyC2IrqError as exc:
        raise ConcurrencyC3ModuleStatsError(str(exc)) from exc


def _token_file_inventory(source_root: Path, token: bytes) -> list[dict[str, Any]]:
    return concurrency_c3_trace._token_file_inventory(source_root, token)


def _semantic_checks(
    root: Path, manifest: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kernel = manifest["kernel"]
    prop = manifest["property"]
    model = manifest["model"]
    source_root = root / kernel["source_root"]
    stats_path = _relative(root, prop["source_file"], "statistics source")
    caller_path = _relative(root, prop["caller_file"], "statistics caller")
    stats_source = stats_path.read_text()
    stats_code = concurrency_c3_lkmm._code_without_comments(stats_source)
    source_function = _function_source(stats_path, prop["source_function"])
    caller_function = _function_source(caller_path, prop["caller_function"])
    add_unformed = _function_source(caller_path, "add_unformed_module")
    positive_path = _relative(
        root,
        next(case for case in model["cases"] if case["id"] == "atomic_inc_positive")["path"],
        "atomic positive model",
    )
    positive_model = concurrency_c3_lkmm._code_without_comments(
        positive_path.read_text()
    )
    checks: list[dict[str, Any]] = []

    checks.extend([
        _check("source update is unique in selected function", 1,
               source_function.count(prop["source_update"])),
        _check("model has exactly two selected updates", 2,
               positive_model.count(prop["model_update"])),
        _check("static atomic counter declaration", 1, len(re.findall(
            r"^static atomic_t failed_load_modules;\s*$", stats_code, re.MULTILINE
        ))),
        _check("counter has one atomic increment", 1,
               stats_code.count("atomic_inc(&failed_load_modules);")),
        _check("counter has one atomic snapshot read", 1,
               stats_code.count("atomic_read(&failed_load_modules)")),
        _check("counter has one debugfs exposure", 1,
               stats_code.count("mod_debug_add_atomic(failed_load_modules);")),
        _check("counter has no explicit initializer or direct assignment", False,
               re.search(r"\bfailed_load_modules\s*=", stats_code) is not None),
        _check("counter has no reset/decrement/exchange", False, any(
            re.search(rf"\b{operation}\s*\([^;]*failed_load_modules", stats_code)
            for operation in (
                "atomic_set", "atomic_dec", "atomic_sub", "atomic_xchg",
                "atomic_cmpxchg", "WRITE_ONCE",
            )
        )),
        _check("statistics explicitly require incremental counters", True,
               "All counters are designed to be incremental. Atomic counters are used so to\n"
               " * remain simple and avoid delays and deadlocks." in stats_source),
        _check("statistics explicitly document concurrent failure races", True,
               "Races in theory could\n *    still exist here" in stats_source),
    ])

    call_inventory = _token_file_inventory(source_root, b"mod_stat_bump_invalid(")
    checks.extend([
        _check("definition/callsite inventory", [
            {"path": "kernel/module/main.c", "count": 1},
            {"path": "kernel/module/stats.c", "count": 1},
        ], call_inventory),
        _check("selected caller invokes statistics update once", 1,
               caller_function.count("mod_stat_bump_invalid(info, flags);")),
        _check("selected call is on allocated-module cleanup path", True,
               _ordered(caller_function, [
                   "module_allocated = true;", "err = add_unformed_module(mod);",
                   "goto free_module;", "free_module:",
                   "mod_stat_bump_invalid(info, flags);",
               ])),
        _check("list insertion lock is released before returning", True,
               _ordered(add_unformed, [
                   "mutex_lock(&module_mutex);", "module_patient_check_exists",
                   "out:", "mutex_unlock(&module_mutex);", "return err;",
               ])),
        _check("legacy init_module syscall can enter load_module", True,
               "SYSCALL_DEFINE3(init_module" in caller_path.read_text() and
               "return load_module(&info, uargs, 0);" in caller_path.read_text()),
        _check("finit_module path can enter load_module", True,
               "SYSCALL_DEFINE3(finit_module" in caller_path.read_text() and
               "return load_module(&info, uargs, flags);" in caller_path.read_text()),
    ])

    makefile = (source_root / "kernel/module/Makefile").read_text()
    kconfig = (source_root / "kernel/module/Kconfig").read_text()
    internal = (source_root / "kernel/module/internal.h").read_text()
    atomic_doc = (source_root / "Documentation/atomic_t.txt").read_text()
    instrumented = (
        source_root / "include/linux/atomic/atomic-instrumented.h"
    ).read_text()
    fallback = (
        source_root / "include/linux/atomic/atomic-arch-fallback.h"
    ).read_text()
    x86_atomic = (source_root / "arch/x86/include/asm/atomic.h").read_text()
    model_def = (source_root / "tools/memory-model/linux-kernel.def").read_text()
    model_cat = (source_root / "tools/memory-model/linux-kernel.cat").read_text()
    checks.extend([
        _check("Kconfig makes module statistics explicit", True,
               _ordered(kconfig, [
                   "config MODULE_STATS", "depends on DEBUG_FS",
                   "select MODULE_DEBUGFS",
               ])),
        _check("Makefile selects statistics object", True,
               "obj-$(CONFIG_MODULE_STATS) += stats.o" in makefile),
        _check("enabled header selects external implementation", True,
               _ordered(internal, [
                   "#ifdef CONFIG_MODULE_STATS",
                   "void mod_stat_bump_invalid(struct load_info *info, int flags);",
                   "#else",
                   "static inline void mod_stat_bump_invalid",
               ])),
        _check("atomic_t contract covers inter-CPU RMW", True,
               "RMW operations between CPUs" in atomic_doc),
        _check("atomic_t contract forbids lost intermediate state", True,
               "All these operations are SMP atomic; that is, the operations (for a single\n"
               "atomic variable) can be fully ordered and no intermediate state is lost or\n"
               "visible." in atomic_doc),
        _check("atomic_t contract classifies no-return ordering", True,
               "RMW operations that have no return value are unordered" in atomic_doc),
        _check("instrumented atomic_inc routes to raw atomic_inc", True,
               _ordered(instrumented, [
                   "atomic_inc(atomic_t *v)", "instrument_atomic_read_write",
                   "raw_atomic_inc(v);",
               ])),
        _check("raw atomic_inc routes to architecture operation", True,
               _ordered(fallback, [
                   "raw_atomic_inc(atomic_t *v)", "#if defined(arch_atomic_inc)",
                   "arch_atomic_inc(v);",
               ])),
        _check("x86 atomic_inc uses locked increment", True,
               _ordered(x86_atomic, [
                   "arch_atomic_inc(atomic_t *v)",
                   "asm_inline volatile(LOCK_PREFIX \"incl %0\"",
                   ': "+m" (v->counter) :: "memory");',
               ])),
        _check("LKMM defines atomic_inc as one no-return RMW", True,
               "atomic_inc(X)   { __atomic_op{NORETURN}(X,+,1); }" in model_def),
        _check("LKMM enforces RMW atomicity", True,
               "empty rmw & (fre ; coe) as atomic" in model_cat),
        _check("LKMM distinguishes full and relaxed return operations", True,
               _ordered(model_def, [
                   "atomic_inc_return(X) __atomic_op_return{MB}(X,+,1)",
                   "atomic_inc_return_relaxed(X) __atomic_op_return{ONCE}(X,+,1)",
               ])),
    ])
    return checks, {
        "source_function_tokens": len(concurrency_c2.c_tokens(source_function)),
        "caller_function_tokens": len(concurrency_c2.c_tokens(caller_function)),
        "definition_callsite_inventory": call_inventory,
        "counter_code_occurrences": len(re.findall(
            r"\bfailed_load_modules\b", stats_code
        )),
        "source_update_count": source_function.count(prop["source_update"]),
        "model_update_count": positive_model.count(prop["model_update"]),
    }


def _artifact_hashes(output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name not in {"summary.json", "SUMMARY.md"}:
            result[path.relative_to(output).as_posix()] = {
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
    return result


def render_summary(result: dict[str, Any]) -> str:
    passed = sum(item["passed"] for item in result["checks"])
    lines = [
        "# Module-statistics C3 atomic/RMW pilot",
        "",
        f"Overall source-linked gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Accepted kernel atomicity properties: **{result['kernel_verification_count']}**",
        f"LKMM atomic/RMW cases: **{len(result['cases'])}**",
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
        "The accepted source claim is deliberately small: from zero, two selected",
        "concurrent `atomic_inc(&failed_load_modules)` operations cannot finish at",
        "one. LKMM reports the lost-update condition `Never` (0/2 witnesses); the",
        "split once-access control reports `Sometimes` (2/2). Witness totals count",
        "executions and are intentionally distinct from the number of final states.",
        "",
        "A supplemental ordering pair reports `Never` for fully ordered",
        "`atomic_inc_return()` and `Sometimes` for its relaxed variant. The source",
        "gate pins the counter inventory, caller path, atomic_t contract, LKMM RMW",
        "axiom, configured object, local symbols, and x86 `lock incl` lowering.",
        "",
        "No arbitrary debugfs snapshot, cross-object ordering, counter-overflow case,",
        "other architecture, progress, module-loader correctness, or whole-kernel",
        "race-freedom property is accepted. No runtime kernel or module was used;",
        "nothing was installed and no privileged operation was performed.",
        "",
    ])
    return "\n".join(lines)


def run_c3_module_stats(
    root: Path, output: Path, timeout: int = 120
) -> dict[str, Any]:
    """Run the LKMM baseline, source/build gates, and two atomic A/B pairs."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyC3ModuleStatsError(
            f"module-statistics C3 output already exists: {output}"
        )
    if type(timeout) is not int or timeout < 1:
        raise ConcurrencyC3ModuleStatsError(
            "module-statistics C3 timeout must be a positive integer"
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
            _sha256(_relative(root, name, "atomic source identity")),
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
        raise ConcurrencyC3ModuleStatsError("atomic build directory must not be a symlink")
    build_directory.mkdir(parents=True, exist_ok=True)
    common_make = [
        profile["make"]["binary"], "-C", str(source_root),
        f"O={build_directory}", f"ARCH={profile['arch']}",
        f"CC={profile['compiler']['binary']}",
    ]
    build_steps = [
        ("base_config", [*common_make, configuration["base_recipe"]], root),
        ("enable_config", [
            str(root / configuration["config_tool"]), "--file",
            str(root / profile["config"]),
            *[
                item
                for option in configuration["enable"]
                for item in ("--enable", option)
            ],
        ], root),
        ("finalize_config", [*common_make, configuration["finalize_recipe"]], root),
    ]
    checks.append(_check(
        "config tool identity", configuration["config_tool_sha256"],
        _sha256(root / configuration["config_tool"]),
    ))
    for name, argv, cwd in build_steps:
        directory = build_output / name
        directory.mkdir()
        process = concurrency_c3_lkmm._run(argv, cwd, timeout)
        concurrency_c3_lkmm._write_process(directory, argv, cwd, process)
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
    concurrency_c3_lkmm._write_process(
        object_directory, object_argv, root, object_process
    )
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
    checks.append(_check("configured command exists", True, command_exists))
    command_text = command_path.read_text() if command_exists else ""
    checks.append(_check(
        "configured command identity", compile_record["command_sha256"],
        _sha256(command_path) if command_exists else None,
    ))
    for token in compile_record["required_command_tokens"]:
        checks.append(_check(
            f"configured command token: {token}", True, token in command_text
        ))

    disassembly_directory = build_output / "disassembly"
    disassembly_directory.mkdir()
    disassembly_argv = [
        profile["objdump"]["binary"], "-dr", "--no-show-raw-insn",
        str(object_path),
    ]
    disassembly_process = concurrency_c3_lkmm._run(disassembly_argv, root, timeout)
    concurrency_c3_lkmm._write_process(
        disassembly_directory, disassembly_argv, root, disassembly_process
    )
    symbols_directory = build_output / "symbols"
    symbols_directory.mkdir()
    symbols_argv = [profile["objdump"]["binary"], "-t", str(object_path)]
    symbols_process = concurrency_c3_lkmm._run(symbols_argv, root, timeout)
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
    try:
        function_block = concurrency_c3_trace._function_block(
            disassembly_process["stdout"], manifest["property"]["source_function"]
        )
        disassembly_error = None
    except concurrency_c3_trace.ConcurrencyC3TraceError as exc:
        function_block = ""
        disassembly_error = str(exc)
    observed_symbols = concurrency_c3_trace._symbols(
        symbols_process["stdout"], set(compile_record["local_symbols"])
    )
    checks.extend([
        _check("disassembly parser error", None, disassembly_error),
        _check("atomic instruction/relocation order", True,
               _ordered(function_block, compile_record["function_disassembly_order"])),
        _check("local atomic symbols", compile_record["local_symbols"], observed_symbols),
    ])
    _json(build_output / "selected-disassembly.json", {
        "function": manifest["property"]["source_function"],
        "disassembly": function_block,
        "local_symbols": observed_symbols,
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
            _check("only named source case is verification candidate",
                   case["id"] == "atomic_inc_positive",
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
    pair_checks: list[dict[str, Any]] = []
    for pair in model["pairs"]:
        positive = by_id[pair["positive"]]
        negative = by_id[pair["negative"]]
        prefix = pair["id"]
        pair_checks.extend([
            _check(f"{prefix}: both cases pass", True,
                   positive["passed"] and negative["passed"]),
            _check(f"{prefix}: positive forbids bad result", "Never",
                   (positive["parsed"] or {}).get("observation")),
            _check(f"{prefix}: positive has zero bad witnesses", 0,
                   (positive["parsed"] or {}).get("positive")),
            _check(f"{prefix}: negative exposes bad result", "Sometimes",
                   (negative["parsed"] or {}).get("observation")),
            _check(f"{prefix}: negative has a bad witness", True,
                   (negative["parsed"] or {}).get("positive", 0) > 0),
            _check(f"{prefix}: condition is identical",
                   (positive["parsed"] or {}).get("condition"),
                   (negative["parsed"] or {}).get("condition")),
        ])
    checks.extend(item for case in case_results for item in case["checks"])
    checks.extend(pair_checks)
    accepted = all(item["passed"] for item in checks)

    identity_names = sorted(set([
        *kernel["source_identities"],
        manifest["baseline"]["manifest"],
        "config/concurrency-c3-module-stats.json",
        "fragma/__main__.py",
        "fragma/concurrency_c2.py",
        "fragma/concurrency_c2_irq.py",
        "fragma/concurrency_c3_lkmm.py",
        "fragma/concurrency_c3_trace.py",
        "fragma/concurrency_c3_module_stats.py",
        "tests/test_concurrency_c3_lkmm.py",
        "tests/test_concurrency_c3_module_stats.py",
        configuration["config_tool"],
        *[case["path"] for case in model["cases"]],
    ]))
    identities = {
        name: {
            "sha256": _sha256(_relative(root, name, "atomic C3 input identity")),
            "size": _relative(root, name, "atomic C3 input identity").stat().st_size,
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
        "kind": "module-stats-c3-atomic-rmw-pilot",
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
        "supplemental_calibration_count": 2 if accepted else 0,
        "c3_atomic_rmw_pilot_complete": accepted,
        "c3_stage_complete": False,
        "remaining_c3": [
            "A lifetime-sensitive lock-free functional case",
            "Any separately justified progress property",
            "Atomic/RMW and publication implementation mappings beyond x86-64",
            "Broader production protocol coverage",
        ],
        "klitmus_or_runtime_used": False,
        "sudo_or_install_used": False,
        "output": str(output),
    }
    result["raw_artifacts"] = _artifact_hashes(output)
    _json(output / "summary.json", result)
    _json(output / "pilot-audit.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c3-module-stats-{stamp}"
