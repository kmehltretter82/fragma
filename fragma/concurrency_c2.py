"""Narrow C2 Linux mutex integration pilot for ``DO_ONCE_SLEEPABLE``.

The accepted property is deliberately smaller than functional exactly-once
execution: the shared ``done`` accesses in two token-identical kernel helper
bodies are protected by one reviewed mutex abstraction for the pinned UP,
preemptible process-context profile.  A lock-elided run must expose the same
accesses as unprotected before the positive result can be accepted.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
from typing import Any

from . import concurrency, concurrency_evidence


class ConcurrencyC2Error(ValueError):
    """The C2 manifest, source, model, or output is unusable."""


_TOKEN = re.compile(
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+(?:[uUlL]+)?|"
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r"==|!=|<=|>=|->|\+\+|--|&&|\|\||<<|>>|\+=|-=|\*=|/=|%=|"
    r"&=|\|=|\^=|<<=|>>=|\.\.\.|\S"
)


def _strict_json(path: Path) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ConcurrencyC2Error(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(), object_pairs_hook=pairs)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConcurrencyC2Error(f"cannot load {path}: {exc}") from exc


def _json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative_file(root: Path, value: str, role: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ConcurrencyC2Error(f"{role} must be project-relative: {value!r}")
    path = root.joinpath(*pure.parts)
    if not path.is_file() or path.is_symlink():
        raise ConcurrencyC2Error(f"{role} is missing or not a regular file: {value}")
    return path


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyC2Error(f"{role} must be a nonempty string")
    return value


def _string_list(value: Any, role: str, *, nonempty: bool = False,
                 unique: bool = True) -> list[str]:
    if (not isinstance(value, list) or
            any(not isinstance(item, str) or not item for item in value) or
            (unique and len(set(value)) != len(value)) or (nonempty and not value)):
        qualifier = "unique " if unique else ""
        raise ConcurrencyC2Error(f"{role} must be a {qualifier}string list")
    return value


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and structurally validate the single C2 pilot declaration."""
    root = root.resolve()
    path = root / "config/concurrency-c2.json"
    manifest = _strict_json(path)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ConcurrencyC2Error("unsupported concurrency C2 schema")
    for key in ("id", "kernel", "model", "property", "cases"):
        if key not in manifest:
            raise ConcurrencyC2Error(f"C2 manifest lacks {key}")
    _nonempty(manifest["id"], "C2 id")

    kernel = manifest["kernel"]
    required_kernel = {
        "revision", "source_root", "profile", "build_receipt", "config",
        "required_config", "source_identities", "copied_functions",
        "caller_contract", "configured_compile",
    }
    if not isinstance(kernel, dict) or not required_kernel.issubset(kernel):
        raise ConcurrencyC2Error("C2 kernel record is incomplete")
    if not re.fullmatch(r"[0-9a-f]{40}", _nonempty(kernel["revision"], "revision")):
        raise ConcurrencyC2Error("C2 revision must be a full lowercase commit id")
    source_root = PurePosixPath(_nonempty(kernel["source_root"], "source root"))
    if source_root.is_absolute() or ".." in source_root.parts:
        raise ConcurrencyC2Error("source root must be project-relative")
    source_directory = root.joinpath(*source_root.parts)
    if not source_directory.is_dir() or source_directory.is_symlink():
        raise ConcurrencyC2Error("C2 source root is missing")
    _relative_file(root, kernel["build_receipt"], "build receipt")
    _relative_file(root, kernel["config"], "kernel config")
    if not isinstance(kernel["required_config"], dict) or not kernel["required_config"]:
        raise ConcurrencyC2Error("required_config must be nonempty")
    if any(not re.fullmatch(r"CONFIG_[A-Z0-9_]+", key) or
           value not in {"y", "m", "n", "absent"}
           for key, value in kernel["required_config"].items()):
        raise ConcurrencyC2Error("invalid required kernel configuration")
    identities = kernel["source_identities"]
    if not isinstance(identities, dict) or not identities:
        raise ConcurrencyC2Error("source identities must be nonempty")
    for filename, digest in identities.items():
        _relative_file(root, filename, "source identity")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ConcurrencyC2Error(f"invalid source digest for {filename}")
    functions = _string_list(kernel["copied_functions"], "copied functions", nonempty=True)
    if functions != ["__do_once_sleepable_start", "__do_once_sleepable_done"]:
        raise ConcurrencyC2Error("C2 must bind exactly the two sleepable-once helpers")

    caller = kernel["caller_contract"]
    if (not isinstance(caller, dict) or
            set(caller) != {"file", "macro", "ordered_calls"}):
        raise ConcurrencyC2Error("invalid C2 caller contract")
    _relative_file(root, caller["file"], "caller contract")
    if caller["macro"] != "DO_ONCE_SLEEPABLE":
        raise ConcurrencyC2Error("unexpected C2 caller macro")
    if caller["ordered_calls"] != [
            "__do_once_sleepable_start", "func", "__do_once_sleepable_done"]:
        raise ConcurrencyC2Error("C2 caller ordering is not explicit")

    compile_record = kernel["configured_compile"]
    required_compile = {
        "target", "object", "command_file", "elf_class", "elf_data", "elf_machine",
    }
    if not isinstance(compile_record, dict) or set(compile_record) != required_compile:
        raise ConcurrencyC2Error("invalid configured compile record")
    if compile_record["target"] != "lib/once.o":
        raise ConcurrencyC2Error("C2 configured target must be lib/once.o")
    for key in ("object", "command_file"):
        value = PurePosixPath(_nonempty(compile_record[key], f"compile {key}"))
        if value.is_absolute() or ".." in value.parts:
            raise ConcurrencyC2Error(f"compile {key} must be project-relative")

    model = manifest["model"]
    required_model = {
        "c1_model_id", "fixture", "fixture_sha256", "thread_library",
        "common_options", "verification_gate", "static_key_abstraction", "context",
    }
    if not isinstance(model, dict) or set(model) != required_model:
        raise ConcurrencyC2Error("invalid C2 model record")
    fixture = _relative_file(root, model["fixture"], "C2 fixture")
    if (not re.fullmatch(r"[0-9a-f]{64}", model.get("fixture_sha256", "")) or
            _sha256(fixture) != model["fixture_sha256"]):
        raise ConcurrencyC2Error("C2 fixture identity drift")
    if model["thread_library"] != "pthreads":
        raise ConcurrencyC2Error("C2 requires the calibrated pthread entry adapter")
    _string_list(model["common_options"], "C2 analyzer options", nonempty=True,
                 unique=False)
    gate = model["verification_gate"]
    if not isinstance(gate, dict) or set(gate) != {
            "target", "dimensions", "primitive_models"}:
        raise ConcurrencyC2Error("invalid C2 verification gate")
    gate_target = gate["target"]
    if (not isinstance(gate_target, dict) or set(gate_target) != {
            "evidence_kind", "required_dimensions", "required_primitives"} or
            gate_target["evidence_kind"] != "verification" or
            gate_target["required_dimensions"] != [
                "sequential", "mutex_protected_concurrency"] or
            gate_target["required_primitives"] != [
                "two_process_context_entries", "linux_once_mutex"]):
        raise ConcurrencyC2Error("C2 verification dependencies are not exact")
    dimensions = gate["dimensions"]
    if not isinstance(dimensions, dict) or set(dimensions) != set(
            gate_target["required_dimensions"]):
        raise ConcurrencyC2Error("C2 verification dimensions are incomplete")
    for name, record in dimensions.items():
        if not isinstance(record, dict) or set(record) != {
                "status", "scope", "limitations"} or record["status"] != "supported":
            raise ConcurrencyC2Error(f"C2 dimension {name} is not narrowly supported")
        _nonempty(record["scope"], f"C2 dimension {name} scope")
        _string_list(record["limitations"], f"C2 dimension {name} limitations",
                     nonempty=True)
    primitives = gate["primitive_models"]
    if not isinstance(primitives, dict) or set(primitives) != set(
            gate_target["required_primitives"]):
        raise ConcurrencyC2Error("C2 verification primitives are incomplete")
    for name, record in primitives.items():
        if (not isinstance(record, dict) or set(record) != {
                "status", "semantics", "conservative_argument", "limitations",
                "empty_stub_allowed"} or record["status"] != "supported" or
                record["empty_stub_allowed"] is not False):
            raise ConcurrencyC2Error(
                f"C2 primitive {name} is not supported with a nonempty model")
        for key in ("semantics", "conservative_argument"):
            _nonempty(record[key], f"C2 primitive {name} {key}")
        _string_list(record["limitations"], f"C2 primitive {name} limitations",
                     nonempty=True)
    static_key = model["static_key_abstraction"]
    if not isinstance(static_key, dict) or static_key.get("status") != "excluded":
        raise ConcurrencyC2Error("static-key behavior must remain excluded")
    for key in ("semantics", "conservative_argument"):
        _nonempty(static_key.get(key), f"static-key {key}")
    _string_list(static_key.get("limitations"), "static-key limitations", nonempty=True)
    context = model["context"]
    if not isinstance(context, dict) or set(context) != {
            "ordinary_tasks", "preemption", "interrupts", "inter_cpu", "lifetime"}:
        raise ConcurrencyC2Error("C2 context must cover task/IRQ/CPU/lifetime dimensions")
    for key, value in context.items():
        _nonempty(value, f"C2 context {key}")

    prop = manifest["property"]
    if not isinstance(prop, dict) or set(prop) != {
            "kind", "claim", "accepted_assertions", "shared_object",
            "required_mutex", "exclusions"}:
        raise ConcurrencyC2Error("invalid C2 property scope")
    for key in ("kind", "claim", "shared_object", "required_mutex"):
        _nonempty(prop[key], f"C2 property {key}")
    accepted_assertions = _string_list(
        prop["accepted_assertions"], "accepted assertions", nonempty=True)
    required_assertions = [
        "c2_mutex_lock_succeeds",
        "c2_mutex_unlock_succeeds",
        "c2_start_true_path_done_false",
        "c2_done_published_before_unlock",
    ]
    if accepted_assertions != required_assertions:
        raise ConcurrencyC2Error("C2 accepted assertion inventory is not exact")
    _string_list(prop["exclusions"], "C2 exclusions", nonempty=True)

    cases = manifest["cases"]
    if not isinstance(cases, list) or [case.get("id") for case in cases
                                      if isinstance(case, dict)] != [
            "linux_mutex_positive", "lock_elided_negative"]:
        raise ConcurrencyC2Error("C2 requires ordered positive and lock-elided cases")
    for case in cases:
        if set(case) != {
                "id", "cpp_defines", "expected_assertions", "expected_protection",
                "verification_candidate"}:
            raise ConcurrencyC2Error(f"invalid C2 case record: {case.get('id')}")
        _string_list(case["cpp_defines"], f"{case['id']} definitions")
        expected = case["expected_assertions"]
        if (not isinstance(expected, dict) or not expected or
                any(status not in {"valid", "invalid", "unknown"}
                    for status in expected.values())):
            raise ConcurrencyC2Error(f"invalid assertions for {case['id']}")
        if case["expected_protection"] not in {"protected", "unprotected"}:
            raise ConcurrencyC2Error(f"invalid protection for {case['id']}")
        if not isinstance(case["verification_candidate"], bool):
            raise ConcurrencyC2Error(f"invalid candidate flag for {case['id']}")
    if (list(cases[0]["expected_assertions"]) != accepted_assertions or
            any(status != "valid"
                for status in cases[0]["expected_assertions"].values()) or
            cases[0]["expected_protection"] != "protected" or
            not cases[0]["verification_candidate"] or
            cases[1]["expected_assertions"] != {
                "c2_start_true_path_done_false": "unknown",
                "c2_done_published_before_unlock": "valid",
            } or
            cases[1]["expected_protection"] != "unprotected" or
            cases[1]["verification_candidate"] or
            cases[1]["cpp_defines"] != ["FRAGMA_C2_ELIDE_MUTEX_NEGATIVE"]):
        raise ConcurrencyC2Error("C2 A/B roles do not enforce the acceptance boundary")
    return manifest


def _strip_c_comments(text: str) -> str:
    """Remove C comments while preserving literals for provenance tokenization."""
    output: list[str] = []
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "*":
                state = "block"
                output.append(" ")
                index += 2
                continue
            if char == "/" and following == "/":
                state = "line"
                output.append(" ")
                index += 2
                continue
            output.append(char)
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
        elif state == "block":
            if char == "*" and following == "/":
                state = "code"
                index += 2
                continue
            if char == "\n":
                output.append("\n")
        elif state == "line":
            if char == "\n":
                output.append("\n")
                state = "code"
        else:
            output.append(char)
            if char == "\\" and index + 1 < len(text):
                output.append(text[index + 1])
                index += 2
                continue
            quote = '"' if state == "string" else "'"
            if char == quote:
                state = "code"
        index += 1
    if state in {"block", "string", "char"}:
        raise ConcurrencyC2Error("unterminated C comment or literal")
    return "".join(output)


def c_tokens(text: str) -> list[str]:
    """Return a whitespace/comment-insensitive token stream for small C slices."""
    return _TOKEN.findall(_strip_c_comments(text))


def extract_function(text: str, name: str) -> str:
    """Extract a named top-level function through its balanced closing brace."""
    matches = list(re.finditer(rf"(?m)^(?:bool|void)\s+{re.escape(name)}\s*\(", text))
    if len(matches) != 1:
        raise ConcurrencyC2Error(f"expected one definition of {name}, found {len(matches)}")
    start = matches[0].start()
    opening = text.find("{", matches[0].end())
    if opening < 0:
        raise ConcurrencyC2Error(f"missing body for {name}")
    depth = 0
    index = opening
    state = "code"
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "*":
                state = "block"
                index += 2
                continue
            if char == "/" and following == "/":
                state = "line"
                index += 2
                continue
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:index + 1]
        elif state == "block":
            if char == "*" and following == "/":
                state = "code"
                index += 2
                continue
        elif state == "line":
            if char == "\n":
                state = "code"
        else:
            if char == "\\":
                index += 2
                continue
            quote = '"' if state == "string" else "'"
            if char == quote:
                state = "code"
        index += 1
    raise ConcurrencyC2Error(f"unterminated body for {name}")


def extract_macro(text: str, name: str) -> str:
    """Extract one continued object/function-like preprocessor definition."""
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines)
              if re.match(rf"^\s*#\s*define\s+{re.escape(name)}\b", line)]
    if len(starts) != 1:
        raise ConcurrencyC2Error(f"expected one definition of macro {name}")
    selected: list[str] = []
    index = starts[0]
    while index < len(lines):
        selected.append(lines[index])
        if not lines[index].rstrip().endswith("\\"):
            break
        index += 1
    return "\n".join(selected)


def ordered_token_positions(tokens: list[str], names: list[str]) -> list[int]:
    """Find successive token occurrences, ignoring earlier macro parameters."""
    positions: list[int] = []
    cursor = 0
    for name in names:
        try:
            position = tokens.index(name, cursor)
        except ValueError:
            return []
        positions.append(position)
        cursor = position + 1
    return positions


def parse_kconfig(text: str) -> dict[str, str]:
    """Parse y/m/value and explicit-not-set records from a kernel .config."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        enabled = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.*)", line)
        disabled = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if enabled:
            values[enabled.group(1)] = enabled.group(2)
        elif disabled:
            values[disabled.group(1)] = "n"
    return values


def final_mutex_protection(text: str, shared: str, mutex: str) -> str:
    """Classify a shared object's last Mthread mutex summary."""
    starts = list(re.finditer(r"^\[mt\] Mutexes for concurrent accesses:\s*$",
                              text, flags=re.MULTILINE))
    if not starts:
        return "missing"
    tail = text[starts[-1].end():]
    end = re.search(r"^\[mt\] Detailed shared zones protections\s*$", tail,
                    flags=re.MULTILINE)
    section = tail[:end.start()] if end else tail
    match = re.search(rf"(?m)^\s*{re.escape(shared)}\s+([^\n]+)", section)
    if not match:
        return "missing"
    value = match.group(1).strip()
    if value == "unprotected":
        return "unprotected"
    if value == f"protected by {mutex}":
        return "protected"
    return f"other:{value}"


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {"name": name, "expected": expected, "actual": actual,
            "passed": expected == actual}


def _elf_identity(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return {"elf": False, "class": None, "data": None, "machine": None}
    byteorder = "<" if data[5] == 1 else ">"
    return {
        "elf": True,
        "class": data[4],
        "data": data[5],
        "machine": struct.unpack_from(byteorder + "H", data, 18)[0],
        "sha256": _sha256(path),
        "size": len(data),
    }


def _artifact_hashes(root: Path, output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name not in {"summary.json", "SUMMARY.md"}:
            name = path.relative_to(root).as_posix()
            result[name] = {"sha256": _sha256(path), "size": path.stat().st_size}
    return result


def render_summary(result: dict[str, Any]) -> str:
    positive, negative = result["cases"]
    checks = result["checks"]
    passed = sum(item["passed"] for item in checks)
    lines = [
        "# Linux `DO_ONCE_SLEEPABLE` C2 mutex pilot",
        "",
        f"Overall C2 pilot gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Accepted kernel concurrency properties: **{result['kernel_verification_count']}**",
        "",
        "This accepts only mutex protection of the shared `done` accesses in the",
        "token-identical sleepable-once helper bodies, for two correctly paired",
        "process-context callers in the pinned UP/preemptible x86_64 profile.",
        "",
        "| Run | Assertions | `done` protection | Role | Gate |",
        "|---|---|---|---|---|",
    ]
    for case in (positive, negative):
        assertions = ", ".join(
            f"{name}={status}" for name, status in case["assertions"].items())
        role = "candidate" if case["verification_candidate"] else "required negative"
        lines.append(
            f"| `{case['id']}` | {assertions} | {case['protection']} | {role} | "
            f"{'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        f"Evidence checks: **{passed}/{len(checks)} passed**.",
        "",
        "Not accepted: end-to-end exactly-once callback execution, callback data,",
        "static-key behavior, real subsystem call sites, IRQ/NMI/SMP, weak memory,",
        "atomics, RCU, lock-free behavior, deadlock freedom, progress, termination",
        "or post-join state. The lock-elided adapter is used only as a negative",
        "control and can never be a verification candidate.",
        "",
        "Raw analyzer/build output, report CSVs, commands, input identities and",
        "artifact hashes are retained beside this summary.",
        "",
    ])
    return "\n".join(lines)


def run_c2(root: Path, output: Path, timeout: int = 120) -> dict[str, Any]:
    """Run the configured compile plus positive/negative C2 evidence gate."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyC2Error(f"C2 output already exists: {output}")
    if timeout < 1:
        raise ConcurrencyC2Error("C2 timeout must be positive")
    output.mkdir(parents=True, exist_ok=False)
    (output / "build").mkdir()
    (output / "cases").mkdir()

    kernel = manifest["kernel"]
    model = manifest["model"]
    prop = manifest["property"]
    checks: list[dict[str, Any]] = []

    for name, expected in kernel["source_identities"].items():
        checks.append(_check(f"source identity: {name}", expected,
                             _sha256(_relative_file(root, name, "source identity"))))
    fixture = _relative_file(root, model["fixture"], "C2 fixture")
    checks.append(_check("fixture identity", model["fixture_sha256"], _sha256(fixture)))

    receipt = _strict_json(_relative_file(root, kernel["build_receipt"], "build receipt"))
    checks.extend([
        _check("build receipt revision", kernel["revision"], receipt.get("revision")),
        _check("build receipt profile", kernel["profile"], receipt.get("profile_id")),
        _check("build receipt source", str((root / kernel["source_root"]).resolve()),
               receipt.get("source")),
        _check("build receipt status", "prepared", receipt.get("status")),
    ])
    config_values = parse_kconfig(
        _relative_file(root, kernel["config"], "kernel config").read_text())
    for name, expected in kernel["required_config"].items():
        checks.append(_check(f"kernel config: {name}", expected,
                             config_values.get(name, "absent")))

    once_source = _relative_file(
        root, f"{kernel['source_root']}/lib/once.c", "kernel once source").read_text()
    fixture_source = fixture.read_text()
    provenance: dict[str, Any] = {}
    for name in kernel["copied_functions"]:
        kernel_tokens = c_tokens(extract_function(once_source, name))
        fixture_tokens = c_tokens(extract_function(fixture_source, name))
        token_hash = hashlib.sha256("\0".join(kernel_tokens).encode()).hexdigest()
        same = kernel_tokens == fixture_tokens
        provenance[name] = {"token_sha256": token_hash,
                            "token_count": len(kernel_tokens), "identical": same}
        checks.append(_check(f"token-identical body: {name}", True, same))
    checks.append(_check("same static once_mutex declaration", True,
                         re.search(r"static\s+DEFINE_MUTEX\s*\(\s*once_mutex\s*\)\s*;",
                                   once_source) is not None and
                         re.search(r"static\s+DEFINE_MUTEX\s*\(\s*once_mutex\s*\)\s*;",
                                   fixture_source) is not None))

    caller = kernel["caller_contract"]
    macro = extract_macro(_relative_file(root, caller["file"], "caller macro").read_text(),
                          caller["macro"])
    macro_tokens = c_tokens(macro)
    positions = ordered_token_positions(macro_tokens, caller["ordered_calls"])
    checks.append(_check("caller macro ordered start/callback/done", True,
                         len(positions) == 3 and positions == sorted(positions) and
                         len(set(positions)) == 3))

    mutex_source = _relative_file(
        root, f"{kernel['source_root']}/kernel/locking/mutex.c",
        "configured mutex source").read_text()
    mutex_docs = _relative_file(
        root, f"{kernel['source_root']}/Documentation/locking/mutex-design.rst",
        "mutex documentation").read_text()
    semantic_tokens = {
        "documented single owner": "Only one task can hold the mutex at a time.",
        "documented interrupt exclusion":
            "Mutexes may not be used in hardware or software interrupt",
        "configured lock fast path": "if (!__mutex_trylock_fast(lock))",
        "configured lock slow path": "__mutex_lock_slowpath(lock);",
        "configured unlock fast path": "if (__mutex_unlock_fast(lock))",
        "unlock lifetime warning":
            "The caller must ensure that the mutex stays alive until this function has",
    }
    for name, token in semantic_tokens.items():
        haystack = mutex_docs if name.startswith("documented") else mutex_source
        checks.append(_check(name, True, token in haystack))
    checks.extend([
        _check("scoped mutex dimension support", "supported",
               model["verification_gate"]["dimensions"]
               ["mutex_protected_concurrency"]["status"]),
        _check("mutex adapter supported only through scoped gate", "supported",
               model["verification_gate"]["primitive_models"]
               ["linux_once_mutex"]["status"]),
        _check("mutex adapter is not an empty stub", False,
               model["verification_gate"]["primitive_models"]
               ["linux_once_mutex"]["empty_stub_allowed"]),
        _check("static key remains excluded", "excluded",
               model["static_key_abstraction"]["status"]),
    ])

    c1_models, _, _ = concurrency_evidence.load_registries(root)
    selected_models = [item for item in c1_models["models"]
                       if item["id"] == model["c1_model_id"]]
    if len(selected_models) != 1:
        raise ConcurrencyC2Error("C2 names no unique C1 provider model")
    c1_model = selected_models[0]
    c0 = concurrency.load_manifest(root)
    binary = _relative_file(root, c0["provider"]["binary"], "Frama-C provider")
    checks.append(_check("provider binary identity", c1_model["provider_binary_sha256"],
                         _sha256(binary)))

    build = kernel["configured_compile"]
    source_root = root / kernel["source_root"]
    build_dir = root / "build/kernel" / kernel["profile"]
    build_argv = [
        "make", "-C", str(source_root), f"O={build_dir}", "ARCH=x86",
        "CC=/usr/bin/gcc", build["target"],
    ]
    build_process = concurrency._run(build_argv, root, timeout)
    concurrency._write_process(output / "build", build_argv, build_process)
    checks.extend([
        _check("configured build timed out", False, build_process["timed_out"]),
        _check("configured build exit", 0, build_process["returncode"]),
    ])
    object_path = root / build["object"]
    if object_path.is_file() and not object_path.is_symlink():
        elf = _elf_identity(object_path)
    else:
        elf = {"elf": False, "class": None, "data": None, "machine": None}
    checks.extend([
        _check("configured object is ELF", True, elf["elf"]),
        _check("configured object ELF class", build["elf_class"], elf["class"]),
        _check("configured object ELF byte order", build["elf_data"], elf["data"]),
        _check("configured object ELF machine", build["elf_machine"], elf["machine"]),
    ])
    command_path = root / build["command_file"]
    command_text = command_path.read_text() if command_path.is_file() else ""
    checks.extend([
        _check("configured command names once.c", True,
               str(source_root / "lib/once.c") in command_text),
        _check("configured command uses pinned compiler", True,
               "/usr/bin/gcc" in command_text),
        _check("configured command is x86_64", True, "-m64" in command_text),
    ])

    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        case_dir = output / "cases" / case["id"]
        case_dir.mkdir()
        report_path = case_dir / "report.csv"
        cpp_options = [
            f"-cpp-extra-args={' '.join('-D' + item for item in case['cpp_defines'])}"
        ] if case["cpp_defines"] else []
        argv = [str(binary), *cpp_options, *model["common_options"],
                "-mt-threads-lib", model["thread_library"], model["fixture"],
                "-then", "-report", "-report-csv", str(report_path)]
        process = concurrency._run(argv, root, timeout)
        concurrency._write_process(case_dir, argv, process)
        combined = process["stdout"] + "\n" + process["stderr"]
        report = (concurrency.parse_report_csv(report_path, fixture)
                  if report_path.is_file() else None)
        assertions = report["assertions"] if report else {}
        protection = final_mutex_protection(
            combined, prop["shared_object"], prop["required_mutex"])
        case_checks = [
            _check("timed out", False, process["timed_out"]),
            _check("exit code", 0, process["returncode"]),
            _check("report present", True, report is not None),
            _check("assertions", case["expected_assertions"], assertions),
            _check("final shared-object protection", case["expected_protection"],
                   protection),
            _check("analysis fixpoint", True, "******* Analysis performed" in combined),
        ]
        if case["verification_candidate"]:
            case_checks.extend([
                _check("positive mutex initialization", True,
                       "Initializing mutex linux-once-mutex" in combined),
                _check("positive no manual synchronization gap", False,
                       "Statements needing manual synchronisation" in combined),
                _check("positive no invalid mutex warning", False,
                       "already unlocked" in combined or
                       "possibly uninitialized mutex" in combined),
            ])
        else:
            case_checks.extend([
                _check("negative adapter selected", True,
                       "Monitored event: negative lock elided" in combined),
                _check("negative manual synchronization gap", True,
                       "Statements needing manual synchronisation" in combined),
                _check("negative cannot be verification candidate", False,
                       case["verification_candidate"]),
            ])
        value = {
            "id": case["id"],
            "verification_candidate": case["verification_candidate"],
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "assertions": assertions,
            "protection": protection,
            "checks": case_checks,
            "passed": all(item["passed"] for item in case_checks),
        }
        _json(case_dir / "result.json", value)
        case_results.append(value)

    checks.extend(item for case in case_results for item in case["checks"])
    prerequisites = all(item["passed"] for item in checks)
    positive, negative = case_results
    evidence_ok = (
        prerequisites and positive["passed"] and positive["verification_candidate"] and
        negative["passed"] and not negative["verification_candidate"]
    )
    gate_decision = concurrency_evidence.acceptance_decision(
        model["verification_gate"]["target"], model["verification_gate"], evidence_ok)
    verification = gate_decision["verification_accepted"]

    identity_paths = sorted(set(
        list(kernel["source_identities"]) + [
            "config/concurrency-c2.json", "config/concurrency-c0.json",
            "config/concurrency-models.json", "config/concurrency-scopes.json",
            "toolchain/lock.json", "fragma/__main__.py", "fragma/concurrency.py",
            "fragma/concurrency_evidence.py", "fragma/concurrency_c2.py",
            "tests/test_concurrency_c2.py", model["fixture"], c0["provider"]["binary"],
            *c0["provider"]["model_files"], *c0["provider"]["implementation_files"],
        ]
    ))
    identities = {
        name: {"sha256": _sha256(_relative_file(root, name, "C2 identity")),
               "size": _relative_file(root, name, "C2 identity").stat().st_size}
        for name in identity_paths
    }
    _json(output / "manifest.json", manifest)
    _json(output / "input-identities.json", identities)
    result = {
        "schema_version": 1,
        "kind": "linux-once-sleepable-c2-mutex-pilot",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": manifest["id"],
        "kernel_revision": kernel["revision"],
        "kernel_profile": kernel["profile"],
        "property": prop,
        "context": model["context"],
        "model": {
            "provider": c1_model["id"],
            "provider_version": c1_model["provider_version"],
            "verification_gate": model["verification_gate"],
            "static_key_abstraction": model["static_key_abstraction"],
        },
        "provenance": provenance,
        "input_identities": identities,
        "configured_object": elf,
        "cases": case_results,
        "checks": checks,
        "gate_decision": gate_decision,
        "accepted": verification,
        "kernel_verification_count": 1 if verification else 0,
        "c2_stage_complete": False,
        "remaining_c2": [
            "A separate Linux spinlock/IRQ masking pilot with handler interference",
            "Any SMP/inter-CPU extension of this UP-only mutex property",
            "End-to-end functional once semantics beyond access protection",
        ],
        "output": str(output),
    }
    result["raw_artifacts"] = _artifact_hashes(root, output)
    _json(output / "summary.json", result)
    _json(output / "pilot-audit.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c2-{stamp}"
