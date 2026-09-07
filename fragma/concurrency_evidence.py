"""C1 identity, scope, support-dimension, and freshness gates for concurrency."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from . import concurrency


class ConcurrencyEvidenceError(ValueError):
    """The C1 registry, C0 evidence, or output request is unusable."""


SUPPORT_STATUSES = {"supported", "calibrated", "partial", "unsupported", "not_assessed"}
REQUIRED_DIMENSIONS = {
    "sequential",
    "mutex_protected_concurrency",
    "interrupts",
    "weak_memory_atomics",
    "rcu",
    "lock_free_algorithms",
}


def _strict_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConcurrencyEvidenceError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConcurrencyEvidenceError(f"cannot load {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular(root: Path, value: str, role: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyEvidenceError(f"{role} must be project-relative: {value!r}")
    path = root.joinpath(*pure.parts)
    if not path.is_file() or path.is_symlink():
        raise ConcurrencyEvidenceError(f"{role} is missing or not regular: {value}")
    return path


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyEvidenceError(f"{role} must be a nonempty string")
    return value


def _string_list(value: Any, role: str, *, nonempty: bool = False) -> list[str]:
    if (not isinstance(value, list) or (nonempty and not value) or
            any(not isinstance(item, str) or not item.strip() for item in value) or
            len(value) != len(set(value))):
        raise ConcurrencyEvidenceError(f"{role} must be a unique string list")
    return value


def load_registries(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load and cross-check the model, target, and C0 manifests."""
    root = root.resolve()
    model_doc = _strict_json(root / "config/concurrency-models.json")
    target_doc = _strict_json(root / "config/concurrency-scopes.json")
    if not isinstance(model_doc, dict) or model_doc.get("schema_version") != 1:
        raise ConcurrencyEvidenceError("unsupported concurrency-model registry")
    if not isinstance(target_doc, dict) or target_doc.get("schema_version") != 1:
        raise ConcurrencyEvidenceError("unsupported concurrency-target registry")
    models = model_doc.get("models")
    targets = target_doc.get("targets")
    if (not isinstance(models, list) or len(models) != 1 or
            not isinstance(targets, list) or not targets):
        raise ConcurrencyEvidenceError(
            "C1 registries require exactly one model and a nonempty target list"
        )

    model_map: dict[str, dict[str, Any]] = {}
    for model in models:
        if not isinstance(model, dict):
            raise ConcurrencyEvidenceError("model entry must be an object")
        model_id = _nonempty(model.get("id"), "model id")
        if not re.fullmatch(r"[a-z][a-z0-9-]*", model_id) or model_id in model_map:
            raise ConcurrencyEvidenceError(f"invalid or duplicate model id: {model_id!r}")
        _nonempty(model.get("provider_version"), f"{model_id} provider version")
        digest = model.get("provider_binary_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ConcurrencyEvidenceError(f"{model_id} has invalid provider digest")
        _nonempty(model.get("execution_model"), f"{model_id} execution model")

        groups = model.get("file_groups")
        if not isinstance(groups, dict) or not groups:
            raise ConcurrencyEvidenceError(f"{model_id} requires file groups")
        flattened: list[str] = []
        for group, paths in groups.items():
            _nonempty(group, f"{model_id} file-group name")
            for value in _string_list(paths, f"{model_id}/{group} paths", nonempty=True):
                _regular(root, value, f"{model_id}/{group} dependency")
                flattened.append(value)
        if len(flattened) != len(set(flattened)):
            raise ConcurrencyEvidenceError(f"{model_id} file groups overlap")

        dimensions = model.get("dimensions")
        if not isinstance(dimensions, dict) or set(dimensions) != REQUIRED_DIMENSIONS:
            raise ConcurrencyEvidenceError(
                f"{model_id} must declare exactly the required support dimensions"
            )
        for dimension, record in dimensions.items():
            if not isinstance(record, dict) or record.get("status") not in SUPPORT_STATUSES:
                raise ConcurrencyEvidenceError(f"invalid {model_id}/{dimension} status")
            _nonempty(record.get("scope"), f"{model_id}/{dimension} scope")
            _string_list(record.get("evidence_cases"),
                         f"{model_id}/{dimension} evidence cases")
            _string_list(record.get("limitations"),
                         f"{model_id}/{dimension} limitations", nonempty=True)

        primitives = model.get("primitive_models")
        if not isinstance(primitives, dict) or not primitives:
            raise ConcurrencyEvidenceError(f"{model_id} requires primitive models")
        for primitive, record in primitives.items():
            _nonempty(primitive, f"{model_id} primitive name")
            if not isinstance(record, dict) or record.get("status") not in SUPPORT_STATUSES:
                raise ConcurrencyEvidenceError(f"invalid {model_id}/{primitive} status")
            for key in ("semantics", "conservative_argument"):
                _nonempty(record.get(key), f"{model_id}/{primitive} {key}")
            _string_list(record.get("limitations"),
                         f"{model_id}/{primitive} limitations", nonempty=True)
            if record.get("empty_stub_allowed") is not False:
                raise ConcurrencyEvidenceError(
                    f"{model_id}/{primitive} must explicitly forbid empty stubs"
                )
        model_map[model_id] = model

    c0 = concurrency.load_manifest(root)
    c0_cases = {case["id"]: case for case in c0["cases"]}
    c0_model_paths = set(c0["provider"]["model_files"] +
                         c0["provider"]["implementation_files"])
    for model_id, model in model_map.items():
        registry_paths = {
            path for paths in model["file_groups"].values() for path in paths
        }
        if registry_paths != c0_model_paths:
            raise ConcurrencyEvidenceError(
                f"{model_id} dependencies differ from the C0 provider inventory"
            )

    target_map: dict[str, dict[str, Any]] = {}
    required_target_keys = {
        "id", "c0_case_id", "model_id", "source", "evidence_kind",
        "kernel_scope", "property_scope", "model_dependency_groups",
        "required_dimensions", "required_primitives", "synchronization_model",
        "synchronization_argument", "memory_order_assumptions", "context",
        "shared_objects", "external_interference",
    }
    for target in targets:
        if not isinstance(target, dict) or not required_target_keys.issubset(target):
            raise ConcurrencyEvidenceError("C1 target lacks required scope metadata")
        target_id = _nonempty(target["id"], "target id")
        if target_id in target_map or target.get("c0_case_id") != target_id:
            raise ConcurrencyEvidenceError(f"invalid or duplicate target: {target_id}")
        case = c0_cases.get(target_id)
        if case is None or target.get("source") != case["source"]:
            raise ConcurrencyEvidenceError(f"{target_id} does not match its C0 case")
        model = model_map.get(target.get("model_id"))
        if model is None:
            raise ConcurrencyEvidenceError(f"{target_id} names an unknown model")
        if target.get("evidence_kind") not in {"calibration", "verification"}:
            raise ConcurrencyEvidenceError(f"{target_id} has invalid evidence kind")
        if not isinstance(target.get("kernel_scope"), bool):
            raise ConcurrencyEvidenceError(f"{target_id} kernel_scope must be boolean")
        scope = target.get("property_scope")
        if not isinstance(scope, dict) or set(scope) != {"kind", "claim", "exclusions"}:
            raise ConcurrencyEvidenceError(f"{target_id} has invalid property scope")
        _nonempty(scope["kind"], f"{target_id} property kind")
        _nonempty(scope["claim"], f"{target_id} property claim")
        _string_list(scope["exclusions"], f"{target_id} exclusions", nonempty=True)
        groups = _string_list(target["model_dependency_groups"],
                              f"{target_id} model groups", nonempty=True)
        if any(group not in model["file_groups"] for group in groups):
            raise ConcurrencyEvidenceError(f"{target_id} names an unknown model group")
        dimensions = _string_list(target["required_dimensions"],
                                  f"{target_id} dimensions", nonempty=True)
        if any(dimension not in model["dimensions"] for dimension in dimensions):
            raise ConcurrencyEvidenceError(f"{target_id} names an unknown dimension")
        primitives = _string_list(target["required_primitives"],
                                  f"{target_id} primitives", nonempty=True)
        if any(primitive not in model["primitive_models"] for primitive in primitives):
            raise ConcurrencyEvidenceError(f"{target_id} names an unknown primitive")
        _nonempty(target["synchronization_model"], f"{target_id} synchronization model")
        _nonempty(target["synchronization_argument"],
                  f"{target_id} synchronization argument")
        _string_list(target["memory_order_assumptions"],
                     f"{target_id} memory-order assumptions", nonempty=True)
        context = target["context"]
        if (not isinstance(context, dict) or
                set(context) != {"ordinary_threads", "interrupt_handlers", "preemption"} or
                not isinstance(context["ordinary_threads"], bool) or
                not isinstance(context["interrupt_handlers"], bool)):
            raise ConcurrencyEvidenceError(f"{target_id} has invalid execution context")
        _nonempty(context["preemption"], f"{target_id} preemption context")
        if not isinstance(target["shared_objects"], list):
            raise ConcurrencyEvidenceError(f"{target_id} shared_objects must be a list")
        names: set[str] = set()
        for shared in target["shared_objects"]:
            if not isinstance(shared, dict) or set(shared) != {
                    "name", "ownership", "external_interference"}:
                raise ConcurrencyEvidenceError(f"{target_id} has invalid shared object")
            name = _nonempty(shared["name"], f"{target_id} shared object name")
            if name in names:
                raise ConcurrencyEvidenceError(f"{target_id} repeats shared object {name}")
            names.add(name)
            _nonempty(shared["ownership"], f"{target_id}/{name} ownership")
            _nonempty(shared["external_interference"],
                      f"{target_id}/{name} interference")
        _nonempty(target["external_interference"], f"{target_id} interference scope")
        target_map[target_id] = target

    if set(target_map) != set(c0_cases):
        raise ConcurrencyEvidenceError("C1 targets do not cover exactly the C0 cases")
    for model in model_map.values():
        for dimension, record in model["dimensions"].items():
            if any(case not in target_map for case in record["evidence_cases"]):
                raise ConcurrencyEvidenceError(
                    f"{model['id']}/{dimension} names unknown evidence"
                )
    return model_doc, target_doc, c0


def identity_drift(expected: dict[str, Any], current: dict[str, Any],
                   paths: list[str]) -> list[str]:
    """Return dependencies whose recorded SHA/size identity changed or vanished."""
    changed: list[str] = []
    for path in paths:
        before = expected.get(path)
        after = current.get(path)
        if not isinstance(before, dict) or not isinstance(after, dict):
            changed.append(path)
            continue
        if before.get("sha256") != after.get("sha256") or before.get("size") != after.get("size"):
            changed.append(path)
    return changed


def acceptance_decision(target: dict[str, Any], model: dict[str, Any],
                        evidence_ok: bool) -> dict[str, Any]:
    """Keep calibration success separate from property verification support."""
    blockers = [
        {"kind": "dimension", "name": name,
         "status": model["dimensions"][name]["status"]}
        for name in target["required_dimensions"]
        if model["dimensions"][name]["status"] != "supported"
    ]
    blockers.extend(
        {"kind": "primitive", "name": name,
         "status": model["primitive_models"][name]["status"]}
        for name in target["required_primitives"]
        if model["primitive_models"][name]["status"] != "supported"
    )
    calibration = evidence_ok and target["evidence_kind"] == "calibration"
    verification = (
        evidence_ok and target["evidence_kind"] == "verification" and not blockers
    )
    return {
        "evidence_accepted": evidence_ok,
        "calibration_accepted": calibration,
        "verification_accepted": verification,
        "blocking_support": blockers,
    }


def _dependency_paths(target: dict[str, Any], model: dict[str, Any]) -> list[str]:
    paths = [target["source"]]
    for group in target["model_dependency_groups"]:
        paths.extend(model["file_groups"][group])
    return sorted(set(paths))


def _identity_digest(records: dict[str, Any]) -> str:
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _render(result: dict[str, Any]) -> str:
    lines = [
        "# Concurrency C1 evidence and scope gate",
        "",
        f"Overall C1 infrastructure gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        "A PASS means the C0 observations were re-parsed, their dependencies are",
        "current, and every calibration carries explicit scope/context/model metadata.",
        "It does not accept a concurrent Linux kernel target.",
        "",
        f"Accepted kernel concurrency targets: **{result['kernel_verification_count']}**",
        "",
        "| Support dimension | Status | Scope |",
        "|---|---|---|",
    ]
    for name, record in result["support_dimensions"].items():
        lines.append(f"| `{name}` | **{record['status']}** | {record['scope']} |")
    lines.extend([
        "",
        "| Calibration | Evidence | Stale dependencies | Verification | Blocking support |",
        "|---|---|---|---|---|",
    ])
    for target in result["targets"]:
        blockers = ", ".join(
            f"{item['name']}={item['status']}" for item in target["blocking_support"]
        ) or "none"
        stale = ", ".join(target["stale_dependencies"]) or "none"
        lines.append(
            f"| `{target['id']}` | "
            f"{'accepted' if target['evidence_accepted'] else 'rejected'} | "
            f"{stale} | "
            f"{'accepted' if target['verification_accepted'] else 'not accepted'} | "
            f"{blockers} |"
        )
    lines.extend([
        "",
        "All current targets are project-owned capability calibrations. Calibrated,",
        "partial, unsupported, or not-assessed dimensions block verification claims;",
        "only an explicitly `supported` required dimension/primitive can clear that",
        "future gate. Model/source/runner drift invalidates the dependent evidence.",
        "",
    ])
    return "\n".join(lines)


def audit_c1(root: Path, c0_output: Path, output: Path) -> dict[str, Any]:
    root = root.resolve()
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyEvidenceError(f"C1 output already exists: {output}")
    c0_output = c0_output if c0_output.is_absolute() else root / c0_output
    if not c0_output.is_dir() or c0_output.is_symlink():
        raise ConcurrencyEvidenceError(f"C0 output is missing or unsafe: {c0_output}")

    model_doc, target_doc, current_manifest = load_registries(root)
    models = {model["id"]: model for model in model_doc["models"]}
    targets = {target["id"]: target for target in target_doc["targets"]}
    retained_manifest = _strict_json(c0_output / "manifest.json")
    identities = _strict_json(c0_output / "input-identities.json")
    c0_summary = _strict_json(c0_output / "summary.json")
    if not isinstance(identities, dict) or not isinstance(c0_summary, dict):
        raise ConcurrencyEvidenceError("C0 retained identity or summary is malformed")

    checks: list[dict[str, Any]] = []

    def add(name: str, expected: Any, actual: Any) -> None:
        checks.append({"name": name, "expected": expected, "actual": actual,
                       "passed": expected == actual})

    manifest_current = current_manifest == retained_manifest
    summary_accepted = c0_summary.get("accepted") is True
    output_current = c0_summary.get("output") == str(c0_output)
    inventory = c0_summary.get("inventory_checks")
    inventory_accepted = (
        isinstance(inventory, list) and bool(inventory) and
        all(isinstance(item, dict) and item.get("passed") is True for item in inventory)
    )
    add("C0 manifest is current", True, manifest_current)
    add("C0 summary accepted", True, summary_accepted)
    add("C0 output identity", str(c0_output), c0_summary.get("output"))
    add("C0 inventory checks", True, inventory_accepted)
    c0_cases = c0_summary.get("cases")
    if not isinstance(c0_cases, list):
        raise ConcurrencyEvidenceError("C0 summary lacks cases")
    if any(not isinstance(case, dict) or not isinstance(case.get("id"), str)
           for case in c0_cases):
        raise ConcurrencyEvidenceError("C0 summary contains a malformed case")
    case_map = {case.get("id"): case for case in c0_cases if isinstance(case, dict)}
    unique_cases = len(case_map) == len(c0_cases)
    add("C0 case inventory", sorted(targets), sorted(case_map))
    add("C0 case identities unique", True, unique_cases)

    current_identities: dict[str, dict[str, Any]] = {}
    for value in identities:
        path = _regular(root, value, "C0 identity input")
        current_identities[value] = {"sha256": _sha256(path), "size": path.stat().st_size}
    global_drift = identity_drift(identities, current_identities, sorted(identities))
    add("C0 input freshness", [], global_drift)

    provider = current_manifest["provider"]
    provider_binary = _regular(root, provider["binary"], "C0 provider binary")
    model = next(iter(models.values()))
    recorded_version = c0_summary.get("provider", {}).get("version")
    recorded_provider_digest = c0_summary.get("provider", {}).get("binary_sha256")
    current_provider_digest = _sha256(provider_binary)
    provider_current = (
        recorded_version == model["provider_version"] and
        recorded_provider_digest == model["provider_binary_sha256"] and
        current_provider_digest == model["provider_binary_sha256"]
    )
    add("C0 provider version", model["provider_version"], recorded_version)
    add("C0 provider recorded digest", model["provider_binary_sha256"],
        recorded_provider_digest)
    add("C0 provider current digest", model["provider_binary_sha256"],
        current_provider_digest)
    base_evidence_ok = (
        manifest_current and summary_accepted and output_current and
        inventory_accepted and unique_cases and provider_current and
        sorted(targets) == sorted(case_map)
    )

    raw_identities: dict[str, dict[str, Any]] = {}
    target_results: list[dict[str, Any]] = []
    for target_id in [target["id"] for target in target_doc["targets"]]:
        target = targets[target_id]
        model = models[target["model_id"]]
        case = case_map.get(target_id)
        if not isinstance(case, dict):
            raise ConcurrencyEvidenceError(f"missing C0 case: {target_id}")
        directory = c0_output / "cases" / target_id
        for name in ("result.json", "command.json", "stdout.txt", "stderr.txt"):
            path = directory / name
            if not path.is_file() or path.is_symlink():
                raise ConcurrencyEvidenceError(f"missing C0 raw artifact: {path}")
            raw_identities[str(path.relative_to(c0_output))] = {
                "sha256": _sha256(path), "size": path.stat().st_size,
            }
        retained_case = _strict_json(directory / "result.json")
        command = _strict_json(directory / "command.json")
        if not isinstance(retained_case, dict) or not isinstance(command, dict):
            raise ConcurrencyEvidenceError(f"malformed retained case: {target_id}")
        stdout = (directory / "stdout.txt").read_text()
        stderr = (directory / "stderr.txt").read_text()
        case_consistent = case == retained_case
        add(f"{target_id} retained case", True, case_consistent)
        c0_case = next(item for item in current_manifest["cases"] if item["id"] == target_id)
        report_path = directory / "report.csv"
        if report_path.is_symlink():
            raise ConcurrencyEvidenceError(f"unsafe C0 report artifact: {report_path}")
        if report_path.is_file():
            raw_identities[str(report_path.relative_to(c0_output))] = {
                "sha256": _sha256(report_path), "size": report_path.stat().st_size,
            }
            report = concurrency.parse_report_csv(report_path, root / target["source"])
        else:
            report = None
        diagnostics = concurrency.parse_diagnostics(stdout + "\n" + stderr)
        recomputed = concurrency.evaluate_case(
            c0_case, command.get("returncode"), command.get("timed_out"),
            report, diagnostics, stdout + "\n" + stderr,
        )
        report_consistent = retained_case.get("report") == report
        diagnostics_consistent = retained_case.get("diagnostics") == diagnostics
        checks_consistent = retained_case.get("checks") == recomputed
        terminal_pass = retained_case.get("passed") is True
        add(f"{target_id} parsed report", True, report_consistent)
        add(f"{target_id} parsed diagnostics", True, diagnostics_consistent)
        add(f"{target_id} recomputed checks", True, checks_consistent)
        add(f"{target_id} terminal pass", True, retained_case.get("passed"))

        expected_argv = [
            str(provider_binary), *current_manifest["common_options"],
            "-mt-threads-lib", c0_case["thread_library"], *c0_case["options"],
            c0_case["source"], "-then", "-report", "-report-csv", str(report_path),
        ]
        command_argv_current = command.get("argv") == expected_argv
        command_cwd_current = command.get("cwd") == "."
        expected_environment = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"}
        command_environment_current = command.get("environment") == expected_environment
        add(f"{target_id} command argv", True, command_argv_current)
        add(f"{target_id} command cwd", True, command_cwd_current)
        add(f"{target_id} command environment", True,
            command_environment_current)

        semantic_globals = [
            path for path in (
                "config/concurrency-c0.json", "toolchain/lock.json",
                "fragma/__main__.py", "fragma/concurrency.py",
            ) if path in identities
        ]
        dependencies = sorted(set(_dependency_paths(target, model) + semantic_globals))
        drift = identity_drift(identities, current_identities, dependencies)
        dependency_records = {path: identities.get(path) for path in dependencies}
        evidence_ok = (
            base_evidence_ok and case_consistent and report_consistent and
            diagnostics_consistent and checks_consistent and terminal_pass and
            command_argv_current and command_cwd_current and
            command_environment_current and not drift and
            all(item.get("passed") is True for item in recomputed)
        )
        decision = acceptance_decision(target, model, evidence_ok)
        compact_races = {
            name: {
                "reported": record["reported"],
                "unprotected": record["unprotected"],
            }
            for name, record in diagnostics["races"].items()
        }
        compact_diagnostics = {
            name: value for name, value in diagnostics.items() if name != "races"
        }
        compact_diagnostics["races"] = compact_races
        target_results.append({
            "id": target_id,
            "model_id": target["model_id"],
            "source": target["source"],
            "evidence_kind": target["evidence_kind"],
            "kernel_scope": target["kernel_scope"],
            "property_scope": target["property_scope"],
            "synchronization_model": target["synchronization_model"],
            "synchronization_argument": target["synchronization_argument"],
            "memory_order_assumptions": target["memory_order_assumptions"],
            "context": target["context"],
            "shared_objects": target["shared_objects"],
            "external_interference": target["external_interference"],
            "required_dimensions": target["required_dimensions"],
            "required_primitives": target["required_primitives"],
            "dependency_paths": dependencies,
            "dependency_digest": _identity_digest(dependency_records),
            "stale_dependencies": drift,
            "observed": {
                "outcome_kind": retained_case.get("outcome_kind"),
                "returncode": retained_case.get("returncode"),
                "assertions": report["assertions"] if report else {},
                "considered_valid_assumptions": (
                    report["considered_valid_assumptions"] if report else 0
                ),
                "diagnostics": compact_diagnostics,
            },
            **decision,
        })

    for name in ("manifest.json", "input-identities.json", "summary.json"):
        path = c0_output / name
        raw_identities[name] = {"sha256": _sha256(path), "size": path.stat().st_size}
    c1_inputs = {}
    for value in (
        "config/concurrency-models.json", "config/concurrency-scopes.json",
        "fragma/concurrency_evidence.py", "tests/test_concurrency_evidence.py",
    ):
        path = _regular(root, value, "C1 implementation input")
        c1_inputs[value] = {"sha256": _sha256(path), "size": path.stat().st_size}

    accepted = (
        all(check["passed"] for check in checks) and
        all(target["evidence_accepted"] for target in target_results)
    )
    kernel_count = sum(
        target["kernel_scope"] and target["verification_accepted"]
        for target in target_results
    )
    model = next(iter(models.values()))
    result = {
        "schema_version": 1,
        "kind": "concurrency-c1-evidence-scope-gate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "accepted": accepted,
        "c0_output": str(c0_output),
        "model_id": model["id"],
        "support_dimensions": model["dimensions"],
        "primitive_models": model["primitive_models"],
        "targets": target_results,
        "checks": checks,
        "c0_input_identities": identities,
        "c0_input_identity_digest": _identity_digest(current_identities),
        "c0_stale_inputs": global_drift,
        "c0_raw_artifact_identities": raw_identities,
        "c1_input_identities": c1_inputs,
        "kernel_verification_count": kernel_count,
        "sequential_results_upgraded": False,
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "pilot-audit.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (output / "SUMMARY.md").write_text(_render(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c1-{stamp}"
