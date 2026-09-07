"""Source-bound C2 hard-IRQ/spinlock pilot for the OMAP HDQ driver.

The accepted result is deliberately site based.  It checks locksets on the
accesses inside two token-identical Linux critical sections.  It does not turn
the whole ``hdq_irqstatus`` object, handler, or driver into a race-free claim.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
from typing import Any

from . import concurrency, concurrency_c2, concurrency_evidence


class ConcurrencyC2IrqError(ValueError):
    """The IRQ pilot declaration, inputs, or observed evidence is unusable."""


def _strict_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConcurrencyC2IrqError(
                    f"duplicate JSON key {key!r} in {path}"
                )
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConcurrencyC2IrqError(f"cannot load {path}: {exc}") from exc


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
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC2IrqError(
            f"{role} must be project-relative: {value!r}"
        )
    path = root.joinpath(*pure.parts)
    if not path.is_file() or path.is_symlink():
        raise ConcurrencyC2IrqError(
            f"{role} is missing or not a regular file: {value}"
        )
    return path


def _relative_path(root: Path, value: str, role: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC2IrqError(
            f"{role} must be project-relative: {value!r}"
        )
    return root.joinpath(*pure.parts)


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyC2IrqError(f"{role} must be a nonempty string")
    return value


def _strings(value: Any, role: str, *, nonempty: bool = False,
             unique: bool = True) -> list[str]:
    if (not isinstance(value, list) or (nonempty and not value) or
            any(not isinstance(item, str) or not item for item in value) or
            (unique and len(value) != len(set(value)))):
        qualifier = "unique " if unique else ""
        raise ConcurrencyC2IrqError(
            f"{role} must be a {qualifier}string list"
        )
    return value


def _validate_gate(gate: Any) -> None:
    if not isinstance(gate, dict) or set(gate) != {
            "target", "dimensions", "primitive_models"}:
        raise ConcurrencyC2IrqError("invalid IRQ verification gate")
    target = gate["target"]
    if not isinstance(target, dict) or set(target) != {
            "evidence_kind", "required_dimensions", "required_primitives"}:
        raise ConcurrencyC2IrqError("invalid IRQ verification target")
    if target["evidence_kind"] != "verification":
        raise ConcurrencyC2IrqError("IRQ target must be verification evidence")
    dimensions = _strings(
        target["required_dimensions"], "required IRQ dimensions", nonempty=True)
    primitives = _strings(
        target["required_primitives"], "required IRQ primitives", nonempty=True)
    if set(dimensions) != set(gate["dimensions"]):
        raise ConcurrencyC2IrqError("IRQ support dimensions are not exact")
    if set(primitives) != set(gate["primitive_models"]):
        raise ConcurrencyC2IrqError("IRQ primitive models are not exact")
    for name, record in gate["dimensions"].items():
        if (not isinstance(record, dict) or set(record) != {
                "status", "scope", "limitations"} or
                record["status"] != "supported"):
            raise ConcurrencyC2IrqError(
                f"IRQ dimension {name} is not narrowly supported"
            )
        _nonempty(record["scope"], f"IRQ dimension {name} scope")
        _strings(record["limitations"], f"IRQ dimension {name} limitations",
                 nonempty=True)
    for name, record in gate["primitive_models"].items():
        if (not isinstance(record, dict) or set(record) != {
                "status", "semantics", "conservative_argument", "limitations",
                "empty_stub_allowed"} or record["status"] != "supported" or
                record["empty_stub_allowed"] is not False):
            raise ConcurrencyC2IrqError(
                f"IRQ primitive {name} is not supported with a nonempty model"
            )
        _nonempty(record["semantics"], f"IRQ primitive {name} semantics")
        _nonempty(record["conservative_argument"],
                  f"IRQ primitive {name} conservative argument")
        _strings(record["limitations"], f"IRQ primitive {name} limitations",
                 nonempty=True)


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and aggressively validate the single C2 IRQ declaration."""
    root = root.resolve()
    manifest = _strict_json(root / "config/concurrency-c2-irq.json")
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or
            set(manifest) != {"schema_version", "id", "kernel", "model",
                              "property", "cases"}):
        raise ConcurrencyC2IrqError("unsupported concurrency C2 IRQ schema")
    if manifest["id"] != "omap-hdq-hardirq-spinlock-arm-smp-c2":
        raise ConcurrencyC2IrqError("unexpected C2 IRQ target id")

    kernel = manifest["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
            "revision", "git_tree", "source_root", "source_receipt", "profile",
            "source_identities", "copied_functions", "probe_contract",
            "configured_compile"}:
        raise ConcurrencyC2IrqError("C2 IRQ kernel record is not exact")
    if not re.fullmatch(r"[0-9a-f]{40}", kernel["revision"]):
        raise ConcurrencyC2IrqError("IRQ kernel revision must be a full commit id")
    if not re.fullmatch(r"[0-9a-f]{40}", kernel["git_tree"]):
        raise ConcurrencyC2IrqError("IRQ kernel tree must be a full git tree id")
    source_root = _relative_path(root, kernel["source_root"], "IRQ source root")
    if not source_root.is_dir() or source_root.is_symlink():
        raise ConcurrencyC2IrqError("IRQ source root is missing")
    _relative_file(root, kernel["source_receipt"], "IRQ source receipt")

    identities = kernel["source_identities"]
    if not isinstance(identities, dict) or not identities:
        raise ConcurrencyC2IrqError("IRQ source identities must be nonempty")
    for name, digest in identities.items():
        _relative_file(root, name, "IRQ source identity")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ConcurrencyC2IrqError(f"invalid source digest for {name}")

    profile = kernel["profile"]
    required_profile = {
        "id", "arch", "config_recipe", "build_dir", "config", "config_sha256",
        "compiler", "compiler_realpath", "compiler_sha256",
        "compiler_version_line", "cross_compile", "required_config",
    }
    if not isinstance(profile, dict) or set(profile) != required_profile:
        raise ConcurrencyC2IrqError("IRQ build profile is not exact")
    if (profile["id"] != "arm-omap2plus-c2" or profile["arch"] != "arm" or
            profile["config_recipe"] != "omap2plus_defconfig"):
        raise ConcurrencyC2IrqError("unexpected IRQ ARM build profile")
    build_dir = _relative_path(root, profile["build_dir"], "IRQ build directory")
    config = _relative_path(root, profile["config"], "IRQ kernel config")
    if config.parent != build_dir:
        raise ConcurrencyC2IrqError("IRQ config is not inside its build directory")
    for key in ("compiler", "compiler_realpath", "cross_compile"):
        if not Path(_nonempty(profile[key], f"IRQ {key}")).is_absolute():
            raise ConcurrencyC2IrqError(f"IRQ {key} must be absolute")
    for key in ("config_sha256", "compiler_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", profile[key]):
            raise ConcurrencyC2IrqError(f"invalid IRQ {key}")
    required_config = profile["required_config"]
    if not isinstance(required_config, dict) or not required_config:
        raise ConcurrencyC2IrqError("IRQ required config must be nonempty")
    if any(not re.fullmatch(r"CONFIG_[A-Z0-9_]+", key) or
           value not in {"y", "m", "n", "absent"}
           for key, value in required_config.items()):
        raise ConcurrencyC2IrqError("invalid IRQ required config value")
    for required in ("CONFIG_ARM", "CONFIG_ARCH_OMAP2PLUS", "CONFIG_SMP",
                     "CONFIG_HDQ_MASTER_OMAP", "CONFIG_PREEMPT_RT"):
        if required not in required_config:
            raise ConcurrencyC2IrqError(f"IRQ profile omits {required}")

    if kernel["copied_functions"] != ["hdq_reset_irqstatus", "hdq_isr"]:
        raise ConcurrencyC2IrqError("IRQ copied-function inventory is not exact")
    contract = kernel["probe_contract"]
    if (not isinstance(contract, dict) or set(contract) != {
            "function", "ordered_calls", "registered_handler",
            "first_process_caller", "selected_process_helper"} or
            contract["function"] != "omap_hdq_probe" or
            contract["ordered_calls"] != ["devm_kzalloc", "spin_lock_init",
                                          "devm_request_irq", "omap_hdq_break"] or
            contract["registered_handler"] != "hdq_isr" or
            contract["first_process_caller"] != "omap_hdq_break" or
            contract["selected_process_helper"] != "hdq_reset_irqstatus"):
        raise ConcurrencyC2IrqError("IRQ probe/caller contract is not exact")

    compile_record = kernel["configured_compile"]
    if not isinstance(compile_record, dict) or set(compile_record) != {
            "target", "object", "command_file", "elf_class", "elf_data",
            "elf_machine", "required_command_tokens"}:
        raise ConcurrencyC2IrqError("IRQ configured compile record is not exact")
    if compile_record["target"] != "drivers/w1/masters/omap_hdq.o":
        raise ConcurrencyC2IrqError("unexpected IRQ configured object target")
    for key in ("object", "command_file"):
        _relative_path(root, compile_record[key], f"IRQ compile {key}")
    if [compile_record[key] for key in ("elf_class", "elf_data", "elf_machine")] != [1, 1, 40]:
        raise ConcurrencyC2IrqError("IRQ object must be ELF32 little-endian ARM")
    _strings(compile_record["required_command_tokens"],
             "IRQ command tokens", nonempty=True)

    model = manifest["model"]
    if not isinstance(model, dict) or set(model) != {
            "c1_model_id", "fixture", "fixture_sha256", "thread_library",
            "common_options", "entry_adapter", "verification_gate", "context"}:
        raise ConcurrencyC2IrqError("IRQ model record is not exact")
    if model["c1_model_id"] != "framac-33-mthread-eva-c0":
        raise ConcurrencyC2IrqError("unexpected IRQ provider model")
    fixture = _relative_file(root, model["fixture"], "IRQ fixture")
    if (not re.fullmatch(r"[0-9a-f]{64}", model["fixture_sha256"]) or
            _sha256(fixture) != model["fixture_sha256"]):
        raise ConcurrencyC2IrqError("IRQ fixture identity drift")
    if model["thread_library"] != "pthreads":
        raise ConcurrencyC2IrqError("IRQ pilot requires its post-init pthread entry")
    _strings(model["common_options"], "IRQ analyzer options", nonempty=True,
             unique=False)
    adapter = model["entry_adapter"]
    if (not isinstance(adapter, dict) or set(adapter) != {
            "kind", "automatic_handler_status", "automatic_handler_calibration",
            "argument"} or
            adapter["kind"] != "one_post_init_pthread_hardirq_entry" or
            adapter["automatic_handler_status"] != "excluded_initialization_gap" or
            adapter["automatic_handler_calibration"] !=
            "interrupt_registered_exclusion_gap"):
        raise ConcurrencyC2IrqError("IRQ entry adapter does not preserve the gap")
    _nonempty(adapter["argument"], "IRQ entry adapter argument")
    _validate_gate(model["verification_gate"])
    required_context = {"process", "handler", "same_cpu", "remote_cpu",
                        "preemption", "lifetime", "memory_order"}
    if not isinstance(model["context"], dict) or set(model["context"]) != required_context:
        raise ConcurrencyC2IrqError("IRQ context inventory is not exact")
    for key, value in model["context"].items():
        _nonempty(value, f"IRQ context {key}")

    prop = manifest["property"]
    if not isinstance(prop, dict) or set(prop) != {
            "kind", "claim", "shared_object", "required_spinlock", "access_roles",
            "accepted_roles", "diagnostic_only_roles", "exclusions"}:
        raise ConcurrencyC2IrqError("IRQ property record is not exact")
    for key in ("kind", "claim", "shared_object", "required_spinlock"):
        _nonempty(prop[key], f"IRQ property {key}")
    if prop["required_spinlock"] != "hdq-spinlock":
        raise ConcurrencyC2IrqError("IRQ property requires the wrong spinlock")
    roles = prop["access_roles"]
    if not isinstance(roles, dict) or not roles:
        raise ConcurrencyC2IrqError("IRQ access roles must be nonempty")
    for name, role in roles.items():
        _nonempty(name, "IRQ access role")
        if (not isinstance(role, dict) or set(role) != {
                "object", "operation", "line_contains"} or
                role["operation"] not in {"read", "write"}):
            raise ConcurrencyC2IrqError(f"invalid IRQ access role {name}")
        _nonempty(role["object"], f"IRQ access role {name} object")
        _nonempty(role["line_contains"], f"IRQ access role {name} source line")
    accepted_roles = _strings(prop["accepted_roles"], "accepted IRQ roles",
                              nonempty=True)
    diagnostic_roles = _strings(
        prop["diagnostic_only_roles"], "diagnostic IRQ roles", nonempty=True)
    if (set(accepted_roles) & set(diagnostic_roles) or
            set(accepted_roles) | set(diagnostic_roles) != set(roles)):
        raise ConcurrencyC2IrqError("IRQ role partition is not exact")
    if "handler_post_unlock_read" not in diagnostic_roles:
        raise ConcurrencyC2IrqError("unlocked handler read must stay diagnostic-only")
    _strings(prop["exclusions"], "IRQ property exclusions", nonempty=True)
    exclusions = " ".join(prop["exclusions"])
    for required in ("Whole-variable", "nesting", "Softirq", "weak-memory",
                     "PREEMPT_RT", "lifetime"):
        if required not in exclusions:
            raise ConcurrencyC2IrqError(
                f"IRQ exclusions do not state the {required} boundary"
            )

    cases = manifest["cases"]
    case_ids = [case.get("id") for case in cases if isinstance(case, dict)] \
        if isinstance(cases, list) else []
    expected_ids = ["same_cpu_positive", "same_cpu_mask_elided_negative",
                    "remote_cpu_positive", "remote_cpu_spin_elided_negative"]
    if case_ids != expected_ids:
        raise ConcurrencyC2IrqError("IRQ A/B case inventory is not exact")
    expected_defines = {
        "same_cpu_positive": [],
        "same_cpu_mask_elided_negative": [
            "FRAGMA_C2_IRQ_ELIDE_MASK_NEGATIVE"],
        "remote_cpu_positive": ["FRAGMA_C2_IRQ_REMOTE_CPU"],
        "remote_cpu_spin_elided_negative": [
            "FRAGMA_C2_IRQ_REMOTE_CPU", "FRAGMA_C2_IRQ_ELIDE_SPIN_NEGATIVE"],
    }
    for case in cases:
        if set(case) != {"id", "cpp_defines", "verification_candidate",
                         "control_for", "expected_assertions",
                         "expected_access_locks",
                         "expected_manual_synchronisation", "required_events"}:
            raise ConcurrencyC2IrqError(f"invalid IRQ case {case.get('id')}")
        case_id = case["id"]
        if case["cpp_defines"] != expected_defines[case_id]:
            raise ConcurrencyC2IrqError(f"unexpected definitions for {case_id}")
        if not isinstance(case["verification_candidate"], bool):
            raise ConcurrencyC2IrqError(f"invalid candidate flag for {case_id}")
        if not isinstance(case["expected_manual_synchronisation"], bool):
            raise ConcurrencyC2IrqError(f"invalid manual-sync flag for {case_id}")
        if (not isinstance(case["expected_assertions"], dict) or
                any(status not in {"valid", "invalid", "unknown"}
                    for status in case["expected_assertions"].values())):
            raise ConcurrencyC2IrqError(f"invalid assertions for {case_id}")
        lock_map = case["expected_access_locks"]
        if not isinstance(lock_map, dict) or not lock_map:
            raise ConcurrencyC2IrqError(f"invalid access map for {case_id}")
        if any(role not in roles for role in lock_map):
            raise ConcurrencyC2IrqError(f"unknown access role in {case_id}")
        for role, locks in lock_map.items():
            _strings(locks, f"{case_id}/{role} locks")
            if any(lock not in {"cpu0-local-irq", "hdq-spinlock"}
                   for lock in locks):
                raise ConcurrencyC2IrqError(f"unknown lock in {case_id}/{role}")
        _strings(case["required_events"], f"{case_id} events")

    same, mask, remote, spin = cases
    if (not same["verification_candidate"] or same["control_for"] is not None or
            mask["verification_candidate"] or
            mask["control_for"] != "linux_local_irq_mask" or
            not remote["verification_candidate"] or
            remote["control_for"] is not None or
            spin["verification_candidate"] or
            spin["control_for"] != "linux_hdq_spinlock"):
        raise ConcurrencyC2IrqError("IRQ positive/control roles are not exact")
    for positive in (same, remote):
        for role in accepted_roles:
            if prop["required_spinlock"] not in positive["expected_access_locks"][role]:
                raise ConcurrencyC2IrqError(
                    f"positive case {positive['id']} lacks spinlock on {role}"
                )
    if remote["expected_access_locks"]["handler_post_unlock_read"] != []:
        raise ConcurrencyC2IrqError("remote unlocked handler read must remain visible")
    for role in accepted_roles:
        if prop["required_spinlock"] in spin["expected_access_locks"][role]:
            raise ConcurrencyC2IrqError(
                f"spin-elided control still claims the spinlock on {role}"
            )
    if (mask["expected_access_locks"]["same_cpu_process_marker_set"] or
            mask["expected_access_locks"]["same_cpu_process_marker_clear"]):
        raise ConcurrencyC2IrqError("mask-elided marker writes must be unprotected")
    return manifest


_FUNCTION_HEAD = re.compile(
    r"(?m)^[ \t]*(?:static[ \t]+)?"
    r"(?:[A-Za-z_]\w*(?:[ \t]+|[ \t]*\*+[ \t]*))+"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*\("
)


def _matching_paren(text: str, opening: int) -> int:
    depth = 0
    state = "code"
    index = opening
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
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
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
            if char == ('"' if state == "string" else "'"):
                state = "code"
        index += 1
    raise ConcurrencyC2IrqError("unterminated C parameter list")


def _balanced_body(text: str, start: int, opening: int) -> str:
    depth = 0
    state = "code"
    index = opening
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
            if char == ('"' if state == "string" else "'"):
                state = "code"
        index += 1
    raise ConcurrencyC2IrqError("unterminated C function body")


def extract_function(text: str, name: str) -> str:
    """Extract one named C definition, skipping matching prototypes."""
    definitions: list[str] = []
    for match in _FUNCTION_HEAD.finditer(text):
        if match.group("name") != name:
            continue
        opening_paren = text.find("(", match.start("name"))
        closing_paren = _matching_paren(text, opening_paren)
        brace = text.find("{", closing_paren + 1)
        semicolon = text.find(";", closing_paren + 1)
        if semicolon >= 0 and (brace < 0 or semicolon < brace):
            continue
        if brace < 0:
            continue
        definitions.append(_balanced_body(text, match.start(), brace))
    if len(definitions) != 1:
        raise ConcurrencyC2IrqError(
            f"expected one definition of {name}, found {len(definitions)}"
        )
    return definitions[0]


def line_for_snippet(source: str, snippet: str) -> int:
    """Return the unique one-based source line containing ``snippet``."""
    matches = [index for index, line in enumerate(source.splitlines(), start=1)
               if snippet in line]
    if len(matches) != 1:
        raise ConcurrencyC2IrqError(
            f"expected one line containing {snippet!r}, found {len(matches)}"
        )
    return matches[0]


def unique_suffix_path(paths: list[str], suffix: str) -> str:
    """Select one declared dependency by suffix without relying on list order."""
    matches = [path for path in paths if path.endswith(suffix)]
    if len(matches) != 1:
        raise ConcurrencyC2IrqError(
            f"expected one dependency ending in {suffix!r}, found {len(matches)}"
        )
    return matches[0]


_ACCESS = re.compile(
    r"^    (?P<operation>read|write) by (?P<actor>.+?) at "
    r"(?P<file>.+):(?P<start>\d+)(?:-(?P<end>\d+))?,(?P<trailing>.*)$"
)


def parse_final_accesses(text: str) -> list[dict[str, Any]]:
    """Parse individual access locksets from Mthread's last race section."""
    start = text.rfind("[mt] Possible read/write data races:")
    if start < 0:
        raise ConcurrencyC2IrqError("missing Mthread read/write access section")
    end = text.find("[mt] Possible write/write data races:", start)
    if end < 0:
        raise ConcurrencyC2IrqError("unterminated Mthread read/write access section")
    lines = text[start:end].splitlines()[1:]
    current_object: str | None = None
    records: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        heading = re.fullmatch(r"  ([^:]+):", line)
        if heading:
            current_object = heading.group(1)
            index += 1
            continue
        access = _ACCESS.fullmatch(line)
        if access:
            if current_object is None:
                raise ConcurrencyC2IrqError("Mthread access precedes its object")
            protection = access.group("trailing").strip()
            if not protection and index + 1 < len(lines):
                continuation = lines[index + 1].strip()
                if (continuation == "unprotected" or
                        continuation.startswith("protected by ")):
                    protection = continuation
                    index += 1
            if protection == "unprotected":
                locks: list[str] = []
            elif protection.startswith("protected by "):
                locks = protection.removeprefix("protected by ").split()
            else:
                raise ConcurrencyC2IrqError(
                    f"unclassified Mthread access protection: {protection!r}"
                )
            records.append({
                "object": current_object,
                "operation": access.group("operation"),
                "actor": access.group("actor"),
                "file": access.group("file"),
                "line_start": int(access.group("start")),
                "line_end": int(access.group("end") or access.group("start")),
                "locks": locks,
                "protection": protection,
            })
        index += 1
    if not records:
        raise ConcurrencyC2IrqError("Mthread final access section is empty")
    return records


def resolve_access_roles(source: str, roles: dict[str, Any],
                         accesses: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Map declared source-site roles to their unique observed locksets."""
    result: dict[str, list[str]] = {}
    for name, role in roles.items():
        line = line_for_snippet(source, role["line_contains"])
        selected = [record for record in accesses
                    if record["object"] == role["object"] and
                    record["operation"] == role["operation"] and
                    record["line_start"] == line]
        if len(selected) != 1:
            raise ConcurrencyC2IrqError(
                f"access role {name} matched {len(selected)} Mthread records"
            )
        result[name] = selected[0]["locks"]
    return result


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
            result[path.relative_to(root).as_posix()] = {
                "sha256": _sha256(path), "size": path.stat().st_size}
    return result


def _semantic_checks(root: Path, manifest: dict[str, Any],
                     fixture_source: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kernel = manifest["kernel"]
    source_root = root / kernel["source_root"]
    driver_path = source_root / "drivers/w1/masters/omap_hdq.c"
    driver = driver_path.read_text()
    checks: list[dict[str, Any]] = []
    provenance: dict[str, Any] = {}
    for name in kernel["copied_functions"]:
        kernel_tokens = concurrency_c2.c_tokens(extract_function(driver, name))
        fixture_tokens = concurrency_c2.c_tokens(
            extract_function(fixture_source, name))
        identical = kernel_tokens == fixture_tokens
        provenance[name] = {
            "token_sha256": hashlib.sha256(
                "\0".join(kernel_tokens).encode()).hexdigest(),
            "token_count": len(kernel_tokens),
            "identical": identical,
        }
        checks.append(_check(f"token-identical body: {name}", True, identical))

    contract = kernel["probe_contract"]
    probe_tokens = concurrency_c2.c_tokens(
        extract_function(driver, contract["function"]))
    positions = concurrency_c2.ordered_token_positions(
        probe_tokens, contract["ordered_calls"])
    checks.append(_check(
        "probe allocates, initializes, registers, then calls process path",
        True,
        len(positions) == len(contract["ordered_calls"]) and
        positions == sorted(positions) and len(set(positions)) == len(positions),
    ))
    request_sequence = concurrency_c2.ordered_token_positions(
        probe_tokens, ["devm_request_irq", contract["registered_handler"]])
    checks.append(_check("probe registers selected handler", True,
                         len(request_sequence) == 2 and
                         request_sequence == sorted(request_sequence)))
    caller_tokens = concurrency_c2.c_tokens(
        extract_function(driver, contract["first_process_caller"]))
    checks.append(_check(
        "first post-registration process path calls selected helper", True,
        contract["selected_process_helper"] in caller_tokens,
    ))

    makefile = (source_root / "drivers/w1/masters/Makefile").read_text()
    kconfig = (source_root / "drivers/w1/masters/Kconfig").read_text()
    checks.extend([
        _check("HDQ Makefile config maps object", True,
               "obj-$(CONFIG_HDQ_MASTER_OMAP)" in makefile and
               "omap_hdq.o" in makefile),
        _check("HDQ Kconfig is OMAP-scoped", True,
               "config HDQ_MASTER_OMAP" in kconfig and
               "depends on ARCH_OMAP || COMPILE_TEST" in kconfig),
    ])

    spinlock_h = (source_root / "include/linux/spinlock.h").read_text()
    lock_api = (source_root / "include/linux/spinlock_api_smp.h").read_text()
    irqflags = (source_root / "arch/arm/include/asm/irqflags.h").read_text()
    lock_tokens = concurrency_c2.c_tokens(
        extract_function(lock_api, "__raw_spin_lock_irqsave"))
    unlock_tokens = concurrency_c2.c_tokens(
        extract_function(lock_api, "__raw_spin_unlock_irqrestore"))
    lock_order = concurrency_c2.ordered_token_positions(
        lock_tokens, ["local_irq_save", "preempt_disable", "LOCK_CONTENDED"])
    unlock_order = concurrency_c2.ordered_token_positions(
        unlock_tokens, ["spin_release", "do_raw_spin_unlock",
                        "local_irq_restore", "preempt_enable"])
    checks.extend([
        _check("spin_lock_irqsave maps to raw SMP API", True,
               "#define spin_lock_irqsave(lock, flags)" in spinlock_h and
               "raw_spin_lock_irqsave(spinlock_check(lock), flags)" in spinlock_h),
        _check("spin_unlock_irqrestore maps to raw SMP API", True,
               "raw_spin_unlock_irqrestore(&lock->rlock, flags)" in spinlock_h),
        _check("configured raw lock orders IRQ/preemption/spin acquire", True,
               len(lock_order) == 3 and lock_order == sorted(lock_order)),
        _check("configured raw unlock orders spin/IRQ/preemption release", True,
               len(unlock_order) == 4 and unlock_order == sorted(unlock_order)),
        _check("ARMv6+ local IRQ save executes cpsid i", True,
               "#if __LINUX_ARM_ARCH__ >= 6" in irqflags and
               '"\tcpsid\ti"' in irqflags and
               ': "=r" (flags) : : "memory", "cc"' in irqflags),
        _check("ARM local IRQ restore writes interrupt mask", True,
               '"\tmsr\t" IRQMASK_REG_NAME_W' in irqflags and
               ': "memory", "cc"' in irqflags),
    ])
    return checks, provenance


def render_summary(result: dict[str, Any]) -> str:
    checks = result["checks"]
    passed = sum(check["passed"] for check in checks)
    lines = [
        "# OMAP HDQ C2 hard-IRQ/spinlock pilot",
        "",
        f"Overall C2 IRQ gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Accepted kernel concurrency properties: **{result['kernel_verification_count']}**",
        "",
        "The accepted property covers only the selected accesses inside the",
        "token-identical `hdq_reset_irqstatus()` critical section and the locked",
        "update in `hdq_isr()`, under one post-initialization process/handler pair.",
        "",
        "| Run | Role | Critical accesses carry `hdq-spinlock` | Unlocked handler read | Gate |",
        "|---|---|---|---|---|",
    ]
    accepted_roles = result["property"]["accepted_roles"]
    for case in result["cases"]:
        critical = all("hdq-spinlock" in case["access_locks"][role]
                       for role in accepted_roles)
        unlocked = case["access_locks"]["handler_post_unlock_read"]
        role = "candidate" if case["verification_candidate"] else \
            f"negative: {case['control_for']}"
        lines.append(
            f"| `{case['id']}` | {role} | {'yes' if critical else 'no'} | "
            f"{', '.join(unlocked) if unlocked else 'unprotected'} | "
            f"{'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        f"Evidence checks: **{passed}/{len(checks)} passed**.",
        "",
        "The same-CPU no-overlap assertion is deliberately retained as `Unknown`;",
        "acceptance uses Mthread's per-access locksets, not that functional assertion.",
        "The mask-elided control exposes the model marker, and the remote-CPU",
        "spin-elided control removes the common lock from all selected accesses.",
        "",
        "The unlocked `hdq_isr()` status read is protected by the CPU gate only in",
        "the same-CPU case and remains unprotected in the remote-CPU case. It is a",
        "preserved source observation outside the accepted property, not a confirmed",
        "kernel defect. Logging, wait predicates, MMIO and the status protocol are",
        "not modeled.",
        "",
        "Unsupported: automatic handler registration after probe-time initialization,",
        "handler recurrence/nesting/priorities, softirq, threaded IRQ, FIQ/NMI,",
        "PREEMPT_RT, affinity migration, CPU hotplug, teardown lifetime, LKMM/ARM",
        "weak memory, atomics, RCU, deadlock, progress and whole-driver race freedom.",
        "",
        "The ARM object/config build, commands, raw analyzer output, report CSVs,",
        "source/model identities and per-case decisions are retained beside this file.",
        "No package installation or privileged command is performed.",
        "",
    ])
    return "\n".join(lines)


def run_c2_irq(root: Path, output: Path, timeout: int = 120) -> dict[str, Any]:
    """Run source/config/build gates and all four IRQ A/B analyses."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyC2IrqError(f"C2 IRQ output already exists: {output}")
    if timeout < 1:
        raise ConcurrencyC2IrqError("C2 IRQ timeout must be positive")
    output.mkdir(parents=True, exist_ok=False)
    build_output = output / "build"
    cases_output = output / "cases"
    build_output.mkdir()
    cases_output.mkdir()

    kernel = manifest["kernel"]
    profile = kernel["profile"]
    model = manifest["model"]
    prop = manifest["property"]
    checks: list[dict[str, Any]] = []

    for name, expected in kernel["source_identities"].items():
        checks.append(_check(f"source identity: {name}", expected,
                             _sha256(_relative_file(
                                 root, name, "IRQ source identity"))))
    source_receipt = _strict_json(_relative_file(
        root, kernel["source_receipt"], "IRQ source receipt"))
    checks.extend([
        _check("source receipt revision", kernel["revision"],
               source_receipt.get("revision")),
        _check("source receipt tree", kernel["git_tree"],
               source_receipt.get("git_tree")),
        _check("source receipt requires content checks", True,
               source_receipt.get("contents_must_be_rechecked")),
    ])
    fixture = _relative_file(root, model["fixture"], "IRQ fixture")
    fixture_source = fixture.read_text()
    checks.append(_check("fixture identity", model["fixture_sha256"],
                         _sha256(fixture)))
    semantic_checks, provenance = _semantic_checks(root, manifest, fixture_source)
    checks.extend(semantic_checks)

    compiler = Path(profile["compiler"])
    compiler_exists = compiler.is_file()
    checks.append(_check("pinned ARM compiler exists", True, compiler_exists))
    compiler_realpath = str(compiler.resolve()) if compiler_exists else None
    compiler_hash = _sha256(compiler) if compiler_exists else None
    checks.extend([
        _check("pinned ARM compiler realpath", profile["compiler_realpath"],
               compiler_realpath),
        _check("pinned ARM compiler identity", profile["compiler_sha256"],
               compiler_hash),
    ])
    version_dir = build_output / "compiler-version"
    version_dir.mkdir()
    version_argv = [profile["compiler"], "--version"]
    version_process = concurrency._run(version_argv, root, timeout)
    concurrency._write_process(version_dir, version_argv, version_process)
    version_line = version_process["stdout"].splitlines()[0] \
        if version_process["stdout"].splitlines() else ""
    checks.extend([
        _check("compiler version timed out", False, version_process["timed_out"]),
        _check("compiler version exit", 0, version_process["returncode"]),
        _check("compiler version line", profile["compiler_version_line"],
               version_line),
    ])

    source_root = root / kernel["source_root"]
    build_dir = _relative_path(root, profile["build_dir"], "IRQ build directory")
    if build_dir.is_symlink():
        raise ConcurrencyC2IrqError("IRQ build directory must not be a symlink")
    build_dir.mkdir(parents=True, exist_ok=True)
    common_make = [
        "make", "-C", str(source_root), f"O={build_dir}",
        f"ARCH={profile['arch']}", f"CC={profile['compiler']}",
        f"CROSS_COMPILE={profile['cross_compile']}",
    ]
    configure_dir = build_output / "configure"
    configure_dir.mkdir()
    configure_argv = [*common_make, profile["config_recipe"]]
    configure_process = concurrency._run(configure_argv, root, timeout)
    concurrency._write_process(configure_dir, configure_argv, configure_process)
    checks.extend([
        _check("configured profile timed out", False,
               configure_process["timed_out"]),
        _check("configured profile exit", 0, configure_process["returncode"]),
    ])
    config_path = _relative_path(root, profile["config"], "IRQ kernel config")
    config_exists = config_path.is_file() and not config_path.is_symlink()
    checks.append(_check("configured profile produced .config", True, config_exists))
    config_hash = _sha256(config_path) if config_exists else None
    checks.append(_check("configured profile identity", profile["config_sha256"],
                         config_hash))
    config_values = concurrency_c2.parse_kconfig(
        config_path.read_text() if config_exists else "")
    for name, expected in profile["required_config"].items():
        checks.append(_check(f"kernel config: {name}", expected,
                             config_values.get(name, "absent")))

    object_dir = build_output / "object"
    object_dir.mkdir()
    compile_record = kernel["configured_compile"]
    object_argv = [*common_make, compile_record["target"]]
    object_process = concurrency._run(object_argv, root, timeout)
    concurrency._write_process(object_dir, object_argv, object_process)
    checks.extend([
        _check("configured object build timed out", False,
               object_process["timed_out"]),
        _check("configured object build exit", 0, object_process["returncode"]),
    ])
    object_path = _relative_path(root, compile_record["object"],
                                 "IRQ configured object")
    if object_path.is_file() and not object_path.is_symlink():
        elf = _elf_identity(object_path)
    else:
        elf = {"elf": False, "class": None, "data": None, "machine": None}
    checks.extend([
        _check("configured object is ELF", True, elf["elf"]),
        _check("configured object ELF class", compile_record["elf_class"],
               elf["class"]),
        _check("configured object ELF byte order", compile_record["elf_data"],
               elf["data"]),
        _check("configured object ELF machine", compile_record["elf_machine"],
               elf["machine"]),
    ])
    command_path = _relative_path(root, compile_record["command_file"],
                                  "IRQ command file")
    command_text = command_path.read_text() \
        if command_path.is_file() and not command_path.is_symlink() else ""
    checks.append(_check("configured command names exact source", True,
                         str(source_root / "drivers/w1/masters/omap_hdq.c")
                         in command_text))
    for token in compile_record["required_command_tokens"]:
        checks.append(_check(f"configured command token: {token}", True,
                             token in command_text))

    c1_models, _, _ = concurrency_evidence.load_registries(root)
    selected = [item for item in c1_models["models"]
                if item["id"] == model["c1_model_id"]]
    if len(selected) != 1:
        raise ConcurrencyC2IrqError("IRQ pilot names no unique C1 provider")
    c1_model = selected[0]
    c0 = concurrency.load_manifest(root)
    binary = _relative_file(root, c0["provider"]["binary"], "Frama-C provider")
    gap_cases = [case for case in c0["cases"]
                 if case["id"] == model["entry_adapter"]
                 ["automatic_handler_calibration"]]
    checks.extend([
        _check("provider binary identity", c1_model["provider_binary_sha256"],
               _sha256(binary)),
        _check("automatic interrupt dimension remains partial", "partial",
               c1_model["dimensions"]["interrupts"]["status"]),
        _check("automatic registration gap calibration exists", 1,
               len(gap_cases)),
        _check("automatic registration gap expects unknown assertions", True,
               len(gap_cases) == 1 and
               set(gap_cases[0]["expected_assertions"].values()) == {"unknown"}),
    ])
    hooks_path = unique_suffix_path(
        c1_model["file_groups"]["core"], "/mt_analysis_hooks.ml")
    hooks = _relative_file(root, hooks_path, "Mthread analysis hooks").read_text()
    checks.extend([
        _check("provider registers handlers at main entry", True,
               "On the first iteration, also register the interrupt handlers"
               in hooks),
        _check("provider passes current initial state to handler", True,
               "let th = interrupt_thread kf_interrupt state" in hooks),
    ])

    role_lines = {
        name: line_for_snippet(fixture_source, role["line_contains"])
        for name, role in prop["access_roles"].items()
    }
    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        case_dir = cases_output / case["id"]
        case_dir.mkdir()
        report_path = case_dir / "report.csv"
        cpp_options = []
        if case["cpp_defines"]:
            cpp_options.append(
                "-cpp-extra-args=" + ",".join(
                    "-D" + item for item in case["cpp_defines"]))
        argv = [str(binary), *cpp_options, *model["common_options"],
                "-mt-threads-lib", model["thread_library"], model["fixture"],
                "-then", "-report", "-report-csv", str(report_path)]
        process = concurrency._run(argv, root, timeout)
        concurrency._write_process(case_dir, argv, process)
        combined = process["stdout"] + "\n" + process["stderr"]
        report = concurrency.parse_report_csv(report_path, fixture) \
            if report_path.is_file() else None
        assertions = report["assertions"] if report else {}
        try:
            accesses = parse_final_accesses(combined)
            selected_locks = resolve_access_roles(
                fixture_source,
                {name: prop["access_roles"][name]
                 for name in case["expected_access_locks"]},
                accesses,
            )
            access_error = None
        except ConcurrencyC2IrqError as exc:
            accesses = []
            selected_locks = {}
            access_error = str(exc)
        manual = "Statements needing manual synchronisation" in combined
        diagnostics = concurrency.parse_diagnostics(combined)
        case_checks = [
            _check("timed out", False, process["timed_out"]),
            _check("exit code", 0, process["returncode"]),
            _check("report present", True, report is not None),
            _check("assertions", case["expected_assertions"], assertions),
            _check("access parser error", None, access_error),
            _check("selected access locksets", case["expected_access_locks"],
                   selected_locks),
            _check("manual synchronisation diagnostic",
                   case["expected_manual_synchronisation"], manual),
            _check("analysis fixpoint", True, diagnostics["fixpoint_reached"]),
            _check("unsupported primitive diagnostic", False,
                   diagnostics["unsupported"]),
            _check("provider user error", False, diagnostics["user_error"]),
            _check("invalid/uninitialized mutex warning", False,
                   "already unlocked" in combined or
                   "possibly uninitialized mutex" in combined),
        ]
        for event in case["required_events"]:
            case_checks.append(_check(f"required event: {event}", True,
                                      event in combined))
        if case["verification_candidate"]:
            case_checks.extend([
                _check("positive initializes local IRQ gate", True,
                       "Initializing mutex cpu0-local-irq" in combined),
                _check("positive initializes HDQ spinlock", True,
                       "Initializing mutex hdq-spinlock" in combined),
                _check("positive contains no negative event", False,
                       "Monitored event: negative" in combined),
            ])
        else:
            case_checks.append(_check(
                "negative cannot be verification candidate", False,
                case["verification_candidate"]))
        value = {
            "id": case["id"],
            "verification_candidate": case["verification_candidate"],
            "control_for": case["control_for"],
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "assertions": assertions,
            "access_locks": selected_locks,
            "all_accesses": accesses,
            "diagnostics": diagnostics,
            "checks": case_checks,
            "passed": all(check["passed"] for check in case_checks),
        }
        _json(case_dir / "result.json", value)
        case_results.append(value)

    checks.extend(check for case in case_results for check in case["checks"])
    evidence_ok = all(check["passed"] for check in checks)
    gate_decision = concurrency_evidence.acceptance_decision(
        model["verification_gate"]["target"], model["verification_gate"],
        evidence_ok)
    verification = gate_decision["verification_accepted"]

    identity_paths = sorted(set([
        *kernel["source_identities"],
        "config/concurrency-c2-irq.json", "config/concurrency-c0.json",
        "config/concurrency-models.json", "config/concurrency-scopes.json",
        "toolchain/lock.json", "fragma/__main__.py", "fragma/concurrency.py",
        "fragma/concurrency_c2.py", "fragma/concurrency_c2_irq.py",
        "fragma/concurrency_evidence.py", "tests/test_concurrency_c2_irq.py",
        model["fixture"], c0["provider"]["binary"],
        *c0["provider"]["model_files"],
        *c0["provider"]["implementation_files"],
    ]))
    identities = {
        name: {"sha256": _sha256(_relative_file(root, name, "IRQ identity")),
               "size": _relative_file(root, name, "IRQ identity").stat().st_size}
        for name in identity_paths
    }
    _json(output / "manifest.json", manifest)
    _json(output / "input-identities.json", identities)
    _json(output / "role-lines.json", role_lines)
    result = {
        "schema_version": 1,
        "kind": "omap-hdq-c2-hardirq-spinlock-pilot",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": manifest["id"],
        "kernel_revision": kernel["revision"],
        "kernel_tree": kernel["git_tree"],
        "kernel_profile": profile["id"],
        "property": prop,
        "context": model["context"],
        "entry_adapter": model["entry_adapter"],
        "model": {
            "provider": c1_model["id"],
            "provider_version": c1_model["provider_version"],
            "verification_gate": model["verification_gate"],
        },
        "provenance": provenance,
        "role_lines": role_lines,
        "input_identities": identities,
        "configured_object": elf,
        "configured_config_sha256": config_hash,
        "cases": case_results,
        "checks": checks,
        "gate_decision": gate_decision,
        "accepted": verification,
        "kernel_verification_count": 1 if verification else 0,
        "c2_stage_complete": verification,
        "remaining_concurrency": [
            "C3 weak-memory, atomics and lock-free reasoning",
            "C4 RCU lifetime and combined concurrency coverage",
            "Broader IRQ classes, recurrence, nesting, priorities and teardown",
            "The preserved unlocked HDQ status accesses require separate review",
        ],
        "sudo_or_install_used": False,
        "output": str(output),
    }
    result["raw_artifacts"] = _artifact_hashes(root, output)
    _json(output / "summary.json", result)
    _json(output / "pilot-audit.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c2-irq-{stamp}"
