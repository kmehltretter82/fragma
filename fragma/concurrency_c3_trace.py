"""Source-linked C3 LKMM pilot for tracing's tgid-map publication."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import struct
from typing import Any

from . import concurrency_c2, concurrency_c2_irq, concurrency_c3_lkmm


class ConcurrencyC3TraceError(ValueError):
    """The trace publication declaration, source, build, or evidence is invalid."""


_SOURCE_ROLE_NAMES = {
    "producer_payload",
    "producer_publish",
    "consumer_observe",
    "consumer_payload",
}
_CASE_IDS = {"release_acquire_positive", "once_once_negative"}


def _strict_json(path: Path) -> Any:
    try:
        return concurrency_c3_lkmm._strict_json(path)
    except concurrency_c3_lkmm.ConcurrencyC3LkmmError as exc:
        raise ConcurrencyC3TraceError(str(exc)) from exc


def _json(path: Path, value: Any) -> None:
    concurrency_c3_lkmm._json(path, value)


def _sha256(path: Path) -> str:
    return concurrency_c3_lkmm._sha256(path)


def _digest(value: Any, role: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        rf"[0-9a-f]{{{length}}}", value
    ):
        raise ConcurrencyC3TraceError(f"{role} is not a {length}-digit hex digest")
    return value


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyC3TraceError(f"{role} must be a nonempty string")
    return value


def _strings(value: Any, role: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ConcurrencyC3TraceError(
            f"{role} must be a nonempty unique string list"
        )
    return value


def _relative(root: Path, value: Any, role: str, *, directory: bool = False) -> Path:
    try:
        return concurrency_c3_lkmm._relative(
            root, value, role, directory=directory
        )
    except concurrency_c3_lkmm.ConcurrencyC3LkmmError as exc:
        raise ConcurrencyC3TraceError(str(exc)) from exc


def _declared_path(root: Path, value: Any, role: str) -> Path:
    if not isinstance(value, str):
        raise ConcurrencyC3TraceError(f"{role} must be project-relative")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC3TraceError(f"{role} must be project-relative: {value!r}")
    path = root.joinpath(*pure.parts)
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ConcurrencyC3TraceError(f"{role} escapes the project root") from exc
    return path


def _validate_tool(record: Any, name: str, *, target: bool = False) -> None:
    keys = {"binary", "realpath", "sha256", "version_line"}
    if target:
        keys.add("target")
    if not isinstance(record, dict) or set(record) != keys:
        raise ConcurrencyC3TraceError(f"{name} tool record is not exact")
    for key in ("binary", "realpath"):
        path = Path(_nonempty(record[key], f"{name} {key}"))
        if not path.is_absolute() or (key == "binary" and not path.is_file()):
            raise ConcurrencyC3TraceError(f"{name} {key} must be absolute")
    _digest(record["sha256"], f"{name} identity")
    _nonempty(record["version_line"], f"{name} version")
    if target:
        _nonempty(record["target"], f"{name} target")


def _validate_expected(expected: Any, case_id: str) -> None:
    if not isinstance(expected, dict) or set(expected) != {
        "test", "disposition", "states", "marker", "positive", "negative",
        "flags", "condition", "observation", "hash",
    }:
        raise ConcurrencyC3TraceError(f"expected output for {case_id} is not exact")
    for key in ("test", "disposition", "marker", "condition", "observation"):
        _nonempty(expected[key], f"{case_id} expected {key}")
    for key in ("states", "positive", "negative"):
        if type(expected[key]) is not int or expected[key] < 0:
            raise ConcurrencyC3TraceError(f"{case_id} expected {key} is invalid")
    if (
        not isinstance(expected["flags"], list)
        or any(not isinstance(flag, str) or not flag for flag in expected["flags"])
        or len(expected["flags"]) != len(set(expected["flags"]))
    ):
        raise ConcurrencyC3TraceError(f"{case_id} flags are invalid")
    _digest(expected["hash"], f"{case_id} herd hash", 32)
    if expected["positive"] + expected["negative"] != expected["states"]:
        raise ConcurrencyC3TraceError(f"{case_id} witness count is inconsistent")


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and aggressively validate the sole source-linked trace pilot."""
    root = root.resolve()
    manifest = _strict_json(root / "config/concurrency-c3-trace-tgid.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema_version", "id", "kernel", "baseline", "profile", "property",
            "model",
        }
        or manifest["schema_version"] != 1
        or manifest["id"] != "linux-trace-tgid-publication-x86_64-c3"
    ):
        raise ConcurrencyC3TraceError("unsupported trace C3 schema")

    kernel = manifest["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
        "revision", "git_tree", "source_root", "source_receipt",
        "source_identities",
    }:
        raise ConcurrencyC3TraceError("trace C3 kernel record is not exact")
    _digest(kernel["revision"], "kernel revision", 40)
    _digest(kernel["git_tree"], "kernel tree", 40)
    source_root = _relative(root, kernel["source_root"], "kernel source", directory=True)
    receipt = _relative(root, kernel["source_receipt"], "source receipt")
    try:
        receipt.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ConcurrencyC3TraceError("source receipt is outside kernel source") from exc
    identities = kernel["source_identities"]
    if not isinstance(identities, dict) or len(identities) != 11:
        raise ConcurrencyC3TraceError("trace C3 source identity set is not exact")
    for name, digest in identities.items():
        _relative(root, name, "trace C3 source identity")
        _digest(digest, f"source identity for {name}")

    baseline = manifest["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != {
        "manifest", "id", "required_capability",
    }:
        raise ConcurrencyC3TraceError("trace C3 baseline link is not exact")
    _relative(root, baseline["manifest"], "C3 baseline manifest")
    if (
        baseline["id"] != "linux-lkmm-herd7-c3-calibration"
        or baseline["required_capability"] != "c3_capability_baseline_complete"
    ):
        raise ConcurrencyC3TraceError("trace C3 names the wrong semantic baseline")

    profile = manifest["profile"]
    if not isinstance(profile, dict) or set(profile) != {
        "id", "arch", "config_recipe", "jobs", "build_directory", "config",
        "config_sha256", "required_config", "make", "compiler", "objdump",
        "configured_compile",
    }:
        raise ConcurrencyC3TraceError("trace C3 profile is not exact")
    if (
        profile["id"] != "x86_64-trace-c3"
        or profile["arch"] != "x86_64"
        or profile["config_recipe"] != "x86_64_defconfig"
        or type(profile["jobs"]) is not int
        or not 1 <= profile["jobs"] <= 256
    ):
        raise ConcurrencyC3TraceError("unexpected trace C3 build profile")
    build_directory = _declared_path(root, profile["build_directory"], "build directory")
    config = _declared_path(root, profile["config"], "kernel config")
    try:
        config.resolve().relative_to(build_directory.resolve())
    except ValueError as exc:
        raise ConcurrencyC3TraceError("kernel config is outside build directory") from exc
    _digest(profile["config_sha256"], "kernel config identity")
    required_config = profile["required_config"]
    if not isinstance(required_config, dict) or set(required_config) != {
        "CONFIG_64BIT", "CONFIG_X86_64", "CONFIG_SMP",
        "CONFIG_CONTEXT_SWITCH_TRACER", "CONFIG_TRACING", "CONFIG_FTRACE",
        "CONFIG_KCSAN", "CONFIG_CC_IS_GCC",
    }:
        raise ConcurrencyC3TraceError("trace C3 config requirements are not exact")
    if any(value not in {"y", "n", "m", "absent"} for value in required_config.values()):
        raise ConcurrencyC3TraceError("invalid trace C3 config value")
    for tool_name in ("make", "compiler", "objdump"):
        _validate_tool(profile[tool_name], tool_name, target=tool_name == "compiler")

    compile_record = profile["configured_compile"]
    if not isinstance(compile_record, dict) or set(compile_record) != {
        "target", "object", "command_file", "object_sha256", "command_sha256",
        "elf_class", "elf_data", "elf_machine", "required_command_tokens",
        "producer_disassembly_order", "consumer_disassembly_order", "local_symbols",
    }:
        raise ConcurrencyC3TraceError("configured trace compile record is not exact")
    if compile_record["target"] != "kernel/trace/trace_sched_switch.o":
        raise ConcurrencyC3TraceError("unexpected configured trace object target")
    for key in ("object", "command_file"):
        path = _declared_path(root, compile_record[key], f"configured {key}")
        try:
            path.resolve().relative_to(build_directory.resolve())
        except ValueError as exc:
            raise ConcurrencyC3TraceError(f"configured {key} is outside build") from exc
    _digest(compile_record["object_sha256"], "configured object identity")
    _digest(compile_record["command_sha256"], "configured command identity")
    if [compile_record[key] for key in ("elf_class", "elf_data", "elf_machine")] != [2, 1, 62]:
        raise ConcurrencyC3TraceError("configured object must be ELF64 little-endian x86-64")
    for key in (
        "required_command_tokens", "producer_disassembly_order",
        "consumer_disassembly_order",
    ):
        _strings(compile_record[key], f"configured compile {key}")
    symbols = compile_record["local_symbols"]
    if not isinstance(symbols, dict) or set(symbols) != {"tgid_map", "tgid_map_max"}:
        raise ConcurrencyC3TraceError("configured symbol inventory is not exact")
    for name, symbol in symbols.items():
        if (
            not isinstance(symbol, dict)
            or set(symbol) != {"section", "value", "size"}
            or symbol["section"] != ".bss"
            or not re.fullmatch(r"[0-9a-f]{16}", symbol["value"])
            or symbol["size"] != 8
        ):
            raise ConcurrencyC3TraceError(f"invalid configured symbol {name}")

    prop = manifest["property"]
    if not isinstance(prop, dict) or set(prop) != {
        "kind", "claim", "producer", "consumer", "published_object",
        "payload_object", "source_roles", "producer_serialization", "lifetime",
        "compiler_architecture_argument", "exclusions",
    }:
        raise ConcurrencyC3TraceError("trace C3 property record is not exact")
    if (
        prop["kind"] != "kernel_release_acquire_publication_ordering"
        or prop["producer"] != "trace_alloc_tgid_map"
        or prop["consumer"] != "trace_find_tgid_ptr"
        or prop["published_object"] != "tgid_map"
        or prop["payload_object"] != "tgid_map_max"
    ):
        raise ConcurrencyC3TraceError("unexpected trace C3 property")
    _nonempty(prop["claim"], "trace C3 claim")
    roles = prop["source_roles"]
    if not isinstance(roles, dict) or set(roles) != _SOURCE_ROLE_NAMES:
        raise ConcurrencyC3TraceError("trace source/model role map is not exact")
    for role_name, role in roles.items():
        if not isinstance(role, dict) or set(role) != {
            "file", "function", "source_snippet", "model_snippet", "argument",
        }:
            raise ConcurrencyC3TraceError(f"trace role {role_name} is not exact")
        _relative(root, role["file"], f"source file for {role_name}")
        for key in ("function", "source_snippet", "model_snippet", "argument"):
            _nonempty(role[key], f"{role_name} {key}")
    serialization = prop["producer_serialization"]
    if not isinstance(serialization, dict) or set(serialization) != {
        "callsite_file", "callsite_function", "required_call", "required_guard",
        "argument",
    }:
        raise ConcurrencyC3TraceError("producer serialization record is not exact")
    _relative(root, serialization["callsite_file"], "producer callsite")
    for key in ("callsite_function", "required_call", "required_guard", "argument"):
        _nonempty(serialization[key], f"producer serialization {key}")
    for section_name in ("lifetime", "compiler_architecture_argument"):
        section = prop[section_name]
        if not isinstance(section, dict) or not section:
            raise ConcurrencyC3TraceError(f"trace {section_name} is missing")
        for key, value in section.items():
            _nonempty(key, f"trace {section_name} key")
            _nonempty(value, f"trace {section_name} value")
    exclusions = _strings(prop["exclusions"], "trace C3 exclusions")
    excluded = " ".join(exclusions).lower()
    for boundary in ("architecture", "progress", "reclamation", "whole"):
        if boundary not in excluded:
            raise ConcurrencyC3TraceError(f"trace C3 omits {boundary} exclusion")

    model = manifest["model"]
    if not isinstance(model, dict) or set(model) != {
        "ordered_path", "ordered_sha256", "weakened_path", "weakened_sha256",
        "same_condition", "abstraction", "cases",
    }:
        raise ConcurrencyC3TraceError("trace C3 model record is not exact")
    for kind in ("ordered", "weakened"):
        _relative(root, model[f"{kind}_path"], f"{kind} trace model")
        _digest(model[f"{kind}_sha256"], f"{kind} trace model identity")
    _nonempty(model["same_condition"], "trace model condition")
    abstraction = model["abstraction"]
    if not isinstance(abstraction, dict) or set(abstraction) != {
        "tgid_map", "tgid_map_max", "consumer_guard", "omitted",
    }:
        raise ConcurrencyC3TraceError("trace C3 abstraction is not exact")
    for key, value in abstraction.items():
        _nonempty(value, f"trace abstraction {key}")
    cases = model["cases"]
    if not isinstance(cases, list) or len(cases) != 2:
        raise ConcurrencyC3TraceError("trace C3 requires one A/B pair")
    by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id", "path", "role", "verification_candidate", "control_for",
            "required_operations", "forbidden_operations", "expected",
        }:
            raise ConcurrencyC3TraceError("trace C3 case record is not exact")
        case_id = case["id"]
        if case_id not in _CASE_IDS or case_id in by_id:
            raise ConcurrencyC3TraceError(f"invalid or duplicate trace case {case_id!r}")
        by_id[case_id] = case
        _relative(root, case["path"], f"trace model for {case_id}")
        required = _strings(case["required_operations"], f"{case_id} required operations")
        forbidden = _strings(case["forbidden_operations"], f"{case_id} forbidden operations")
        if set(required) & set(forbidden):
            raise ConcurrencyC3TraceError(f"contradictory operations for {case_id}")
        _validate_expected(case["expected"], case_id)
        if case["expected"]["condition"] != model["same_condition"]:
            raise ConcurrencyC3TraceError(f"trace condition drift in {case_id}")
    if set(by_id) != _CASE_IDS:
        raise ConcurrencyC3TraceError("trace C3 case inventory is incomplete")
    positive = by_id["release_acquire_positive"]
    negative = by_id["once_once_negative"]
    if (
        positive["role"] != "verification_candidate"
        or positive["verification_candidate"] is not True
        or positive["control_for"] is not None
        or positive["path"] != model["ordered_path"]
        or positive["expected"]["observation"] != "Never"
        or positive["expected"]["positive"] != 0
        or positive["expected"]["flags"] != []
    ):
        raise ConcurrencyC3TraceError("trace positive is not a clean Never candidate")
    if (
        negative["role"] != "required_weakened_control"
        or negative["verification_candidate"] is not False
        or negative["control_for"] != positive["id"]
        or negative["path"] != model["weakened_path"]
        or negative["expected"]["observation"] != "Sometimes"
        or negative["expected"]["positive"] < 1
        or negative["expected"]["flags"] != ["data-race"]
    ):
        raise ConcurrencyC3TraceError("trace negative is not a detecting data-race control")
    return manifest


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {
        "name": name,
        "expected": expected,
        "actual": actual,
        "passed": expected == actual,
    }


def _ordered(text: str, snippets: list[str]) -> bool:
    position = -1
    for snippet in snippets:
        position = text.find(snippet, position + 1)
        if position < 0:
            return False
    return True


def _function_block(disassembly: str, name: str) -> str:
    start = re.search(rf"^[0-9a-f]+ <{re.escape(name)}>:\n", disassembly, re.MULTILINE)
    if not start:
        raise ConcurrencyC3TraceError(f"objdump omits function {name}")
    tail = disassembly[start.start():]
    next_function = re.search(r"\n[0-9a-f]+ <[^>]+>:\n", tail[1:])
    return tail if not next_function else tail[:next_function.start() + 1]


def _symbols(value: str, names: set[str]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    pattern = re.compile(
        r"^(?P<value>[0-9a-f]{16})\s+l\s+O\s+"
        r"(?P<section>\.[A-Za-z0-9_.]+)\s+"
        r"(?P<size>[0-9a-f]{16})\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(value):
        name = match.group("name")
        if name in names:
            if name in found:
                raise ConcurrencyC3TraceError(f"duplicate object symbol {name}")
            found[name] = {
                "section": match.group("section"),
                "value": match.group("value"),
                "size": int(match.group("size"), 16),
            }
    return found


def _elf_identity(path: Path) -> dict[str, Any]:
    value = path.read_bytes()
    if len(value) < 20 or value[:4] != b"\x7fELF" or value[5] not in {1, 2}:
        return {"elf": False, "class": None, "data": None, "machine": None}
    byteorder = "<" if value[5] == 1 else ">"
    return {
        "elf": True,
        "class": value[4],
        "data": value[5],
        "machine": struct.unpack_from(byteorder + "H", value, 18)[0],
        "sha256": _sha256(path),
        "size": len(value),
    }


def _function_source(path: Path, function: str) -> str:
    try:
        return concurrency_c2_irq.extract_function(path.read_text(), function)
    except concurrency_c2_irq.ConcurrencyC2IrqError as exc:
        raise ConcurrencyC3TraceError(str(exc)) from exc


def _token_file_inventory(source_root: Path, token: bytes) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for path in sorted(source_root.rglob("*.c")):
        if path.is_symlink() or not path.is_file():
            continue
        value = path.read_bytes()
        count = value.count(token)
        if count:
            found.append({
                "path": path.relative_to(source_root).as_posix(),
                "count": count,
            })
    return found


def _semantic_checks(
    root: Path, manifest: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kernel = manifest["kernel"]
    prop = manifest["property"]
    source_root = root / kernel["source_root"]
    trace_path = source_root / "kernel/trace/trace_sched_switch.c"
    trace_source = trace_path.read_text()
    ordered_model = _relative(root, manifest["model"]["ordered_path"], "ordered model").read_text()
    checks: list[dict[str, Any]] = []
    role_evidence: dict[str, Any] = {}
    functions: dict[tuple[str, str], str] = {}
    for role_name, role in prop["source_roles"].items():
        path = _relative(root, role["file"], f"source for {role_name}")
        key = (str(path), role["function"])
        body = functions.setdefault(key, _function_source(path, role["function"]))
        source_count = body.count(role["source_snippet"])
        model_count = ordered_model.count(role["model_snippet"])
        checks.extend([
            _check(f"unique source role: {role_name}", 1, source_count),
            _check(f"unique model role: {role_name}", 1, model_count),
        ])
        role_evidence[role_name] = {
            "source_file": role["file"],
            "source_function": role["function"],
            "source_snippet_count": source_count,
            "model_snippet_count": model_count,
            "argument": role["argument"],
        }

    producer = _function_source(trace_path, prop["producer"])
    consumer = _function_source(trace_path, prop["consumer"])
    checks.extend([
        _check(
            "producer payload/allocation/publication source order", True,
            _ordered(producer, [
                "tgid_map_max = init_pid_ns.pid_max;",
                "map = kvzalloc_objs(*tgid_map, tgid_map_max + 1);",
                "if (!map)",
                "smp_store_release(&tgid_map, map);",
            ]),
        ),
        _check(
            "consumer acquire/guard/payload source order", True,
            _ordered(consumer, [
                "int *map = smp_load_acquire(&tgid_map);",
                "if (unlikely(!map || pid > tgid_map_max))",
            ]),
        ),
        _check("tgid_map has static zero initialization", 1,
               len(re.findall(r"^static int \*tgid_map;\s*$", trace_source, re.MULTILINE))),
        _check("tgid_map_max has static zero initialization", 1,
               len(re.findall(r"^static size_t tgid_map_max;\s*$", trace_source, re.MULTILINE))),
        _check("tgid_map_max has one explicit assignment", 1,
               len(re.findall(r"\btgid_map_max\s*=", trace_source))),
        _check("published map has no direct NULL replacement", False,
               re.search(r"\btgid_map\s*=\s*NULL\b", trace_source) is not None),
        _check("published map has no direct deallocation", False,
               any(token in trace_source for token in (
                   "kfree(tgid_map)", "kvfree(tgid_map)", "vfree(tgid_map)"))),
        _check("positive PID maximum abstraction", True,
               "#define PID_MAX_DEFAULT (IS_ENABLED(CONFIG_BASE_SMALL) ? 0x1000 : 0x8000)"
               in (source_root / "include/linux/threads.h").read_text()),
        _check("initial namespace uses positive PID maximum", True,
               ".pid_max = PID_MAX_DEFAULT" in (source_root / "kernel/pid.c").read_text()),
        _check("source documents exact release/acquire pairing", True,
               "Pairs with smp_load_acquire()" in producer and
               "Pairs with the smp_store_release" in consumer),
    ])

    serialization = prop["producer_serialization"]
    callsite = _relative(root, serialization["callsite_file"], "producer callsite")
    callsite_body = _function_source(callsite, serialization["callsite_function"])
    inventory = _token_file_inventory(source_root, b"trace_alloc_tgid_map(")
    checks.extend([
        _check("allocator definition/callsite inventory", [
            {"path": "kernel/trace/trace.c", "count": 1},
            {"path": "kernel/trace/trace_sched_switch.c", "count": 1},
        ], inventory),
        _check("callsite has required event-mutex assertion", True,
               serialization["required_guard"] in callsite_body),
        _check("callsite invokes allocator only in function once", 1,
               callsite_body.count(serialization["required_call"] + "(")),
        _check("allocator preserves already-published pointer", True,
               _ordered(producer, ["if (tgid_map)", "return 0;", "tgid_map_max ="])),
    ])

    barriers = (source_root / "Documentation/memory-barriers.txt").read_text()
    x86_barrier = (source_root / "arch/x86/include/asm/barrier.h").read_text()
    generic_barrier = (source_root / "include/asm-generic/barrier.h").read_text()
    rwonce = (source_root / "include/asm-generic/rwonce.h").read_text()
    checks.extend([
        _check("kernel contract names load acquire", True,
               "ACQUIRE operations include LOCK operations and both smp_load_acquire()" in barriers),
        _check("kernel contract names store release", True,
               "RELEASE operations include UNLOCK operations and\n     smp_store_release() operations" in barriers),
        _check("kernel contract guarantees prior-release visibility", True,
               "all memory accesses preceding any prior\n     RELEASE on that same variable are guaranteed to be visible" in barriers),
        _check("generic SMP API routes store release", True,
               "#define smp_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)" in generic_barrier),
        _check("generic SMP API routes load acquire", True,
               "#define smp_load_acquire(p) __smp_load_acquire(p)" in generic_barrier),
        _check("x86 release is compiler barrier then WRITE_ONCE", True,
               _ordered(x86_barrier, ["#define __smp_store_release", "barrier();", "WRITE_ONCE(*p, v)"])),
        _check("x86 acquire is READ_ONCE then compiler barrier", True,
               _ordered(x86_barrier, ["#define __smp_load_acquire", "READ_ONCE(*p)", "barrier();"])),
        _check("READ_ONCE is volatile scalar access", True,
               "#define __READ_ONCE(x)\t(*(const volatile __unqual_scalar_typeof(x) *)&(x))" in rwonce),
        _check("WRITE_ONCE is volatile scalar access", True,
               "#define __WRITE_ONCE(x, val)" in rwonce and "*(volatile typeof(x) *)&(x) = (val)" in rwonce),
    ])
    evidence = {
        "roles": role_evidence,
        "producer_tokens": len(concurrency_c2.c_tokens(producer)),
        "consumer_tokens": len(concurrency_c2.c_tokens(consumer)),
        "allocator_token_inventory": inventory,
    }
    return checks, evidence


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
    checks = result["checks"]
    passed = sum(item["passed"] for item in checks)
    lines = [
        "# Trace tgid-map C3 release/acquire pilot",
        "",
        f"Overall source-linked gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Accepted kernel ordering properties: **{result['kernel_verification_count']}**",
        "",
        "| Case | Role | Outcome | LKMM flags | Bad witnesses | Gate |",
        "|---|---|---|---|---:|---|",
    ]
    for case in result["cases"]:
        parsed = case["parsed"] or {}
        lines.append(
            f"| `{case['id']}` | {case['role']} | "
            f"{parsed.get('observation', 'unparsed')} | "
            f"{', '.join(parsed.get('flags', [])) or 'none'} | "
            f"{parsed.get('positive', '?')} | {'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        f"Evidence checks: **{passed}/{len(checks)} passed**.",
        "",
        "The accepted property is narrow: after the acquire observes the pointer",
        "published by the successful release, the guarded `tgid_map_max` read cannot",
        "see its static pre-publication zero. The release/acquire model is `Never`",
        "with no LKMM flag; replacing only those primitives yields `Sometimes`, one",
        "bad witness, and `Flag data-race`.",
        "",
        "The gate binds this model to exact source statements, the sole allocator",
        "callsite, static lifetime, kernel barrier contracts, x86 macro definitions,",
        "a configured SMP x86-64 compile, local ELF symbols, and instruction order.",
        "It does not verify array contents, bounds, allocation, all tracing behavior,",
        "other architectures, progress, or any future replacement/reclamation design.",
        "",
        "No module was generated or loaded; no runtime kernel, package installation,",
        "or privileged operation was used.",
        "",
    ])
    return "\n".join(lines)


def run_c3_trace(root: Path, output: Path, timeout: int = 120) -> dict[str, Any]:
    """Run baseline, source/model gates, configured build, and trace A/B pair."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyC3TraceError(f"trace C3 output already exists: {output}")
    if type(timeout) is not int or timeout < 1:
        raise ConcurrencyC3TraceError("trace C3 timeout must be a positive integer")
    output.mkdir(parents=True, exist_ok=False)
    build_output = output / "build"
    cases_output = output / "cases"
    build_output.mkdir()
    cases_output.mkdir()

    kernel = manifest["kernel"]
    profile = manifest["profile"]
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
            _sha256(_relative(root, name, "trace source identity")),
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

    tool_inventory: dict[str, Any] = {}
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
        raise ConcurrencyC3TraceError("trace C3 build directory must not be a symlink")
    build_directory.mkdir(parents=True, exist_ok=True)
    common_make = [
        profile["make"]["binary"], "-C", str(source_root),
        f"O={build_directory}", f"ARCH={profile['arch']}",
        f"CC={profile['compiler']['binary']}",
    ]
    configure_directory = build_output / "configure"
    configure_directory.mkdir()
    configure_argv = [*common_make, profile["config_recipe"]]
    configure_process = concurrency_c3_lkmm._run(configure_argv, root, timeout)
    concurrency_c3_lkmm._write_process(
        configure_directory, configure_argv, root, configure_process
    )
    checks.extend([
        _check("configured profile timed out", False, configure_process["timed_out"]),
        _check("configured profile exit", 0, configure_process["returncode"]),
    ])
    config_path = _declared_path(root, profile["config"], "kernel config")
    config_exists = config_path.is_file() and not config_path.is_symlink()
    checks.append(_check("configured profile produced config", True, config_exists))
    config_hash = _sha256(config_path) if config_exists else None
    checks.append(_check("configured config identity", profile["config_sha256"], config_hash))
    config_values = concurrency_c2.parse_kconfig(config_path.read_text() if config_exists else "")
    for name, expected in profile["required_config"].items():
        checks.append(_check(f"kernel config: {name}", expected,
                             config_values.get(name, "absent")))

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
    elf = _elf_identity(object_path) if object_exists else {
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
    checks.append(_check("configured command identity", compile_record["command_sha256"],
                         _sha256(command_path) if command_exists else None))
    for token in compile_record["required_command_tokens"]:
        checks.append(_check(f"configured command token: {token}", True,
                             token in command_text))

    disassembly_directory = build_output / "disassembly"
    disassembly_directory.mkdir()
    disassembly_argv = [
        profile["objdump"]["binary"], "-dr", "--no-show-raw-insn", str(object_path)
    ]
    disassembly_process = concurrency_c3_lkmm._run(
        disassembly_argv, root, timeout
    )
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
        producer_block = _function_block(
            disassembly_process["stdout"], manifest["property"]["producer"]
        )
        consumer_block = _function_block(disassembly_process["stdout"], "trace_find_tgid")
        disassembly_error = None
    except ConcurrencyC3TraceError as exc:
        producer_block = ""
        consumer_block = ""
        disassembly_error = str(exc)
    observed_symbols = _symbols(
        symbols_process["stdout"], set(compile_record["local_symbols"])
    )
    checks.extend([
        _check("disassembly parser error", None, disassembly_error),
        _check("producer instruction/relocation order", True,
               _ordered(producer_block, compile_record["producer_disassembly_order"])),
        _check("consumer instruction/relocation order", True,
               _ordered(consumer_block, compile_record["consumer_disassembly_order"])),
        _check("local publication symbols", compile_record["local_symbols"], observed_symbols),
    ])
    _json(build_output / "selected-disassembly.json", {
        "producer": producer_block,
        "consumer_inlined_into": "trace_find_tgid",
        "consumer": consumer_block,
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
            _check("timed out", False, process["timed_out"]),
            _check("exit code", 0, process["returncode"]),
            _check("stderr empty", "", process["stderr"]),
            _check("parse error", None, parse_error),
            _check("semantic result", case["expected"],
                   concurrency_c3_lkmm._core_result(parsed)),
            _check("case cannot change verification role", case["verification_candidate"],
                   case["id"] == "release_acquire_positive"),
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
        result = {
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
        _json(directory / "result.json", result)
        case_results.append(result)
    positive, negative = case_results
    pair_checks = [
        _check("positive and negative cases passed", True,
               positive["passed"] and negative["passed"]),
        _check("positive forbids stale outcome", "Never",
               (positive["parsed"] or {}).get("observation")),
        _check("positive has no bad witnesses", 0,
               (positive["parsed"] or {}).get("positive")),
        _check("positive has no LKMM flag", [],
               (positive["parsed"] or {}).get("flags")),
        _check("negative exposes stale outcome", "Sometimes",
               (negative["parsed"] or {}).get("observation")),
        _check("negative has a bad witness", True,
               (negative["parsed"] or {}).get("positive", 0) > 0),
        _check("negative exposes data race", ["data-race"],
               (negative["parsed"] or {}).get("flags")),
        _check("A/B condition is identical",
               (positive["parsed"] or {}).get("condition"),
               (negative["parsed"] or {}).get("condition")),
    ]
    checks.extend(item for case in case_results for item in case["checks"])
    checks.extend(pair_checks)
    accepted = all(item["passed"] for item in checks)

    identity_names = sorted(set([
        *kernel["source_identities"],
        manifest["baseline"]["manifest"],
        "config/concurrency-c3-trace-tgid.json",
        "fragma/__main__.py",
        "fragma/concurrency_c2.py",
        "fragma/concurrency_c2_irq.py",
        "fragma/concurrency_c3_lkmm.py",
        "fragma/concurrency_c3_trace.py",
        "tests/test_concurrency_c3_lkmm.py",
        "tests/test_concurrency_c3_trace.py",
        model["ordered_path"],
        model["weakened_path"],
    ]))
    identities = {
        name: {
            "sha256": _sha256(_relative(root, name, "trace C3 input identity")),
            "size": _relative(root, name, "trace C3 input identity").stat().st_size,
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
        "kind": "trace-tgid-c3-release-acquire-pilot",
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
        "c3_source_linked_pilot_complete": accepted,
        "c3_stage_complete": False,
        "remaining_c3": [
            "Additional atomic/RMW and lock-free functional cases",
            "An explicitly scoped lifetime-sensitive lock-free case",
            "Any separately claimed progress property",
            "Architecture mappings beyond configured SMP x86-64",
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
    return root / "results" / f"concurrency-c3-trace-{stamp}"
