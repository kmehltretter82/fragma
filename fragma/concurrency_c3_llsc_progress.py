"""Fail-closed LL/SC progress capability audit for the C3 IPC pilot."""

from __future__ import annotations

from datetime import datetime, timezone
from itertools import product
from pathlib import Path
import re
from typing import Any

from . import concurrency_c3_ipc_refcount as ipc
from . import concurrency_c3_lkmm as lkmm
from . import concurrency_c3_module_stats as module_stats


class ConcurrencyC3LlscProgressError(ValueError):
    """Raised when LL/SC capability evidence is malformed or stale."""


_PROFILE_SCOPE = {
    "arm64-ipc-refcount-c3": ("arm64", "runtime_dual_native_cas_llsc"),
    "riscv64-ipc-refcount-c3": ("riscv64", "runtime_dual_native_cas_llsc"),
    "arm32-ipc-refcount-c3": ("arm32", "llsc_only_selected_object"),
    "powerpc32-smp-ipc-refcount-c3": (
        "powerpc32", "llsc_only_selected_object",
    ),
    "sh-smp-ipc-refcount-c3": ("superh", "llsc_only_selected_object"),
    "alpha-smp-ipc-refcount-c3": (
        "alpha", "llsc_only_selected_object_with_trampoline",
    ),
}

_PROFILE_IDS = list(_PROFILE_SCOPE)

_ALLOWED_KINDS = {
    "runtime_dual_native_cas_llsc",
    "llsc_only_selected_object",
    "llsc_only_selected_object_with_trampoline",
}


def _strict_json(path: Path) -> Any:
    return ipc._strict_json(path)


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return ipc._check(name, expected, actual)


def _strings(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ConcurrencyC3LlscProgressError(f"{label} must be nonempty strings")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ConcurrencyC3LlscProgressError(f"{label} must be a SHA-256 digest")
    return value


def load_manifest(root: Path) -> dict[str, Any]:
    """Load the closed LL/SC audit manifest before reading evidence inputs."""
    manifest = _strict_json(root / "config/concurrency-c3-llsc-progress.json")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "id", "kernel", "base", "documentation",
        "conditional_diagnostic", "profiles", "exclusions",
    }:
        raise ConcurrencyC3LlscProgressError("LL/SC manifest is not exact")
    if (
        manifest["schema_version"] != 1
        or manifest["id"] != "linux-ipc-refcount-llsc-progress-capability-c3"
    ):
        raise ConcurrencyC3LlscProgressError("unsupported LL/SC manifest schema")

    kernel = manifest["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
        "revision", "git_tree", "source_root",
    }:
        raise ConcurrencyC3LlscProgressError("LL/SC kernel record is not exact")
    if (
        kernel["revision"] != "b9b3e33b70b71e516930117e21de3ad2a7723747"
        or kernel["git_tree"] != "054b6818c409ab20ae89b1031a1a7c358f673d87"
        or kernel["source_root"] != "build/sources/linux-b9b3e33b70b71"
    ):
        raise ConcurrencyC3LlscProgressError("unexpected LL/SC kernel identity")

    base = manifest["base"]
    if not isinstance(base, dict) or set(base) != {
        "target", "schema_version", "evidence_checks", "input_identity_count",
        "raw_artifact_count", "architecture_mapping_count",
        "kernel_verification_count", "progress_kernel_verification_count",
        "progress_implementation_mapping_count",
        "progress_implementation_profiles",
    }:
        raise ConcurrencyC3LlscProgressError("LL/SC base requirements are not exact")
    if (
        base["target"] != "linux-ipc-refcount-lifetime-multiarch-c3"
        or base["schema_version"] != 5
        or base["evidence_checks"] != 848
        or base["input_identity_count"] != 77
        or base["raw_artifact_count"] != 331
        or base["architecture_mapping_count"] != 9
        or base["kernel_verification_count"] != 2
        or base["progress_kernel_verification_count"] != 1
        or base["progress_implementation_mapping_count"] != 3
        or base["progress_implementation_profiles"] != [
            "x86_64-ipc-refcount-c3",
            "s390x-ipc-refcount-c3",
            "um-x86_64-smp-ipc-refcount-c3",
        ]
    ):
        raise ConcurrencyC3LlscProgressError("unexpected LL/SC base scope")

    documentation = manifest["documentation"]
    if not isinstance(documentation, dict) or set(documentation) != {
        "path", "sha256", "required_order",
    }:
        raise ConcurrencyC3LlscProgressError("LL/SC documentation record is not exact")
    if documentation["path"] != (
        "build/sources/linux-b9b3e33b70b71/Documentation/atomic_t.txt"
    ):
        raise ConcurrencyC3LlscProgressError("unexpected LL/SC documentation path")
    _digest(documentation["sha256"], "LL/SC documentation identity")
    _strings(documentation["required_order"], "LL/SC documentation tokens")

    diagnostic = manifest["conditional_diagnostic"]
    if not isinstance(diagnostic, dict) or set(diagnostic) != {
        "kind", "verification_candidate", "premise", "source_cas_attempts",
        "max_store_conditional_failures_per_cas", "expected",
        "unbounded_failure_control",
    }:
        raise ConcurrencyC3LlscProgressError("LL/SC diagnostic is not exact")
    expected = {
        "finite_schedules": 120,
        "max_source_cas_attempts": 4,
        "max_store_conditional_attempts": 12,
        "max_store_conditional_failures": 8,
        "nonterminating": 0,
    }
    control_expected = {
        "cycle_found": True,
        "cycle_length": 1,
        "state": {"refs": 1, "expected": 1, "reservation": "lost"},
    }
    control = diagnostic["unbounded_failure_control"]
    if (
        diagnostic["kind"] != "bounded_store_conditional_failure_diagnostic"
        or diagnostic["verification_candidate"] is not False
        or not isinstance(diagnostic["premise"], str)
        or "no selected Linux profile establishes" not in diagnostic["premise"]
        or diagnostic["source_cas_attempts"] != [1, 2, 3, 4]
        or diagnostic["max_store_conditional_failures_per_cas"] != 2
        or diagnostic["expected"] != expected
        or not isinstance(control, dict)
        or set(control) != {"role", "verification_candidate", "expected"}
        or control["role"] != "required_nontermination_control"
        or control["verification_candidate"] is not False
        or control["expected"] != control_expected
    ):
        raise ConcurrencyC3LlscProgressError(
            "LL/SC diagnostic cannot satisfy its evidence role"
        )

    profiles = manifest["profiles"]
    if (
        not isinstance(profiles, list)
        or [item.get("id") if isinstance(item, dict) else None for item in profiles]
        != _PROFILE_IDS
    ):
        raise ConcurrencyC3LlscProgressError("LL/SC profile inventory is not exact")
    source_paths: set[str] = set()
    for profile in profiles:
        if set(profile) != {
            "id", "architecture", "implementation_kind", "source_checks",
            "disassembly_order", "verification_candidate", "decision",
            "blocking_reason",
        }:
            raise ConcurrencyC3LlscProgressError(
                f"LL/SC profile {profile.get('id')} is not exact"
            )
        if (
            (profile["architecture"], profile["implementation_kind"])
            != _PROFILE_SCOPE[profile["id"]]
            or profile["implementation_kind"] not in _ALLOWED_KINDS
            or profile["verification_candidate"] is not False
            or profile["decision"] != "not_promoted"
            or not isinstance(profile["blocking_reason"], str)
            or "without" not in profile["blocking_reason"].lower()
            or "failure" not in profile["blocking_reason"].lower()
        ):
            raise ConcurrencyC3LlscProgressError(
                f"LL/SC profile {profile['id']} cannot be promoted"
            )
        _strings(profile["disassembly_order"], f"{profile['id']} disassembly")
        source_checks = profile["source_checks"]
        if not isinstance(source_checks, list) or not source_checks:
            raise ConcurrencyC3LlscProgressError(
                f"{profile['id']} source checks are empty"
            )
        for source in source_checks:
            if not isinstance(source, dict) or set(source) != {
                "path", "sha256", "ordered_tokens",
            }:
                raise ConcurrencyC3LlscProgressError(
                    f"{profile['id']} source check is not exact"
                )
            if source["path"] in source_paths:
                raise ConcurrencyC3LlscProgressError(
                    f"duplicate LL/SC source path: {source['path']}"
                )
            source_paths.add(source["path"])
            _digest(source["sha256"], f"{source['path']} identity")
            _strings(source["ordered_tokens"], f"{source['path']} tokens")

    exclusions = " ".join(_strings(manifest["exclusions"], "LL/SC exclusions")).lower()
    for boundary in (
        "no ll/sc profile", "hypothetical", "native lse", "zacas",
        "scheduler fairness", "wait-freedom", "rcu progress", "whole-kernel",
    ):
        if boundary not in exclusions:
            raise ConcurrencyC3LlscProgressError(
                f"LL/SC exclusions omit {boundary}"
            )
    return manifest


def _bounded_diagnostic(diagnostic: dict[str, Any]) -> dict[str, Any]:
    """Enumerate a hypothetical finite reservation-failure premise."""
    maximum = diagnostic["max_store_conditional_failures_per_cas"]
    rows: list[dict[str, Any]] = []
    for source_attempts in diagnostic["source_cas_attempts"]:
        for failures in product(range(maximum + 1), repeat=source_attempts):
            rows.append({
                "source_cas_attempts": source_attempts,
                "store_conditional_failures": sum(failures),
                "store_conditional_attempts": sum(value + 1 for value in failures),
                "failure_schedule": list(failures),
                "outcome": "completed_under_hypothetical_bound",
            })
    max_attempts = max(row["store_conditional_attempts"] for row in rows)
    max_failures = max(row["store_conditional_failures"] for row in rows)
    return {
        "finite_schedules": len(rows),
        "max_source_cas_attempts": max(row["source_cas_attempts"] for row in rows),
        "max_store_conditional_attempts": max_attempts,
        "max_store_conditional_failures": max_failures,
        "nonterminating": sum(row["outcome"] == "nonterminating" for row in rows),
        "maximum_witness": next(
            row for row in rows if row["store_conditional_attempts"] == max_attempts
        ),
    }


def _unbounded_failure_cycle() -> dict[str, Any]:
    state = {"refs": 1, "expected": 1, "reservation": "lost"}
    after = dict(state)
    return {
        "cycle_found": state == after,
        "cycle_length": 1,
        "state": after,
        "trace": [
            {"event": "load-linked", "refs": 1, "expected": 1},
            {"event": "store-conditional-failure", "reservation": "lost"},
            {"event": "retry-same-cas", **after},
        ],
    }


def _safe_result_file(base: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ConcurrencyC3LlscProgressError("base artifact path is not relative")
    path = base / name
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError as exc:
        raise ConcurrencyC3LlscProgressError(
            f"base artifact escapes result: {name}"
        ) from exc
    if not path.is_file() or path.is_symlink():
        raise ConcurrencyC3LlscProgressError(
            f"base artifact is not a regular file: {name}"
        )
    return path


def _verify_base(
    root: Path, base_result: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    if base_result.is_symlink() or not base_result.is_dir():
        raise ConcurrencyC3LlscProgressError("IPC base result must be a directory")
    audit_path = _safe_result_file(base_result, "pilot-audit.json")
    audit = _strict_json(audit_path)
    required = manifest["base"]
    checks = [
        _check("base audit accepted", True, audit.get("accepted")),
        _check("base target", required["target"], audit.get("target")),
        _check("base schema", required["schema_version"], audit.get("schema_version")),
        _check("base kernel revision", manifest["kernel"]["revision"],
               audit.get("kernel_revision")),
        _check("base kernel tree", manifest["kernel"]["git_tree"],
               audit.get("kernel_tree")),
        _check("base evidence check count", required["evidence_checks"],
               len(audit.get("checks", []))),
        _check("base evidence checks pass", required["evidence_checks"],
               sum(item.get("passed") is True for item in audit.get("checks", []))),
        _check("base architecture mappings", required["architecture_mapping_count"],
               audit.get("architecture_mapping_count")),
        _check("base kernel verification count", required["kernel_verification_count"],
               audit.get("kernel_verification_count")),
        _check("base lifetime pilot complete", True,
               audit.get("c3_lifetime_functional_pilot_complete")),
        _check("base progress pilot complete", True,
               audit.get("c3_bounded_progress_pilot_complete")),
        _check("base architecture mapping pilot complete", True,
               audit.get("c3_selected_architecture_mappings_complete")),
        _check("base progress result accepted", True,
               (audit.get("progress") or {}).get("accepted")),
        _check("base progress kernel verification count",
               required["progress_kernel_verification_count"],
               (audit.get("progress") or {}).get("kernel_verification_count")),
        _check("base progress implementation mapping count",
               required["progress_implementation_mapping_count"],
               audit.get("progress_implementation_mapping_count")),
        _check("base progress implementations",
               required["progress_implementation_profiles"],
               (audit.get("progress") or {}).get("implementation_profiles")),
        _check("base remains partial C3", False, audit.get("c3_stage_complete")),
        _check("base used no install or sudo", False, audit.get("sudo_or_install_used")),
    ]
    identities = audit.get("input_identities")
    artifacts = audit.get("raw_artifacts")
    if not isinstance(identities, dict) or not isinstance(artifacts, dict):
        raise ConcurrencyC3LlscProgressError("base identity inventories are malformed")
    checks.extend([
        _check("base input identity count", required["input_identity_count"],
               len(identities)),
        _check("base raw artifact count", required["raw_artifact_count"],
               len(artifacts)),
    ])
    input_readback: dict[str, Any] = {}
    for name, expected in identities.items():
        path = Path(name) if Path(name).is_absolute() else root / name
        actual = None
        if path.is_file():
            actual = {"sha256": ipc._sha256(path), "size": path.stat().st_size}
            if "realpath" in expected:
                actual["realpath"] = str(path.resolve())
        input_readback[name] = actual
        checks.append(_check(f"base input readback: {name}", expected, actual))
    artifact_readback: dict[str, Any] = {}
    for name, expected in artifacts.items():
        path = _safe_result_file(base_result, name)
        actual = {"sha256": ipc._sha256(path), "size": path.stat().st_size}
        artifact_readback[name] = actual
        checks.append(_check(f"base artifact readback: {name}", expected, actual))
    return audit, checks, {
        "audit_sha256": ipc._sha256(audit_path),
        "audit_size": audit_path.stat().st_size,
        "input_readback": input_readback,
        "artifact_readback": artifact_readback,
    }


def _run_profile_assessment(
    root: Path,
    profile: dict[str, Any],
    base_profile: dict[str, Any],
    accepted_profile: dict[str, Any],
    output: Path,
    timeout: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    output.mkdir()
    checks: list[dict[str, Any]] = []
    source_results: list[dict[str, Any]] = []
    for source in profile["source_checks"]:
        path = ipc._relative(root, source["path"], "LL/SC source")
        text = path.read_text()
        source_checks = [
            _check(f"{profile['id']} source identity: {source['path']}",
                   source["sha256"], ipc._sha256(path)),
            _check(f"{profile['id']} source order: {source['path']}", True,
                   ipc._ordered(text, source["ordered_tokens"])),
        ]
        checks.extend(source_checks)
        source_results.append({
            "path": source["path"],
            "checks": source_checks,
            "passed": all(item["passed"] for item in source_checks),
        })

    objdump = base_profile["objdump"]["binary"]
    object_path = ipc._relative(
        root, base_profile["configured_compile"]["object"], "LL/SC object"
    )
    accepted_object = accepted_profile.get("configured_object") or {}
    object_sha256 = ipc._sha256(object_path)
    object_size = object_path.stat().st_size
    checks.extend([
        _check(f"{profile['id']} accepted object identity",
               accepted_object.get("sha256"), object_sha256),
        _check(f"{profile['id']} accepted object size",
               accepted_object.get("size"), object_size),
    ])
    argv = [objdump, "-dr", "--no-show-raw-insn", str(object_path)]
    process = lkmm._run(argv, root, timeout)
    disassembly_output = output / "disassembly"
    disassembly_output.mkdir()
    lkmm._write_process(disassembly_output, argv, root, process)
    command_checks = [
        _check(f"{profile['id']} disassembly timed out", False,
               process["timed_out"]),
        _check(f"{profile['id']} disassembly exit", 0, process["returncode"]),
        _check(f"{profile['id']} disassembly stderr", "", process["stderr"]),
        _check(f"{profile['id']} LL/SC control flow", True,
               ipc._ordered(process["stdout"], profile["disassembly_order"])),
        _check(f"{profile['id']} remains ineligible", False,
               profile["verification_candidate"]),
        _check(f"{profile['id']} decision", "not_promoted", profile["decision"]),
    ]
    checks.extend(command_checks)
    result = {
        "id": profile["id"],
        "architecture": profile["architecture"],
        "implementation_kind": profile["implementation_kind"],
        "source_results": source_results,
        "object": str(object_path.relative_to(root)),
        "object_sha256": object_sha256,
        "object_size": object_size,
        "blocking_reason": profile["blocking_reason"],
        "verification_candidate": False,
        "decision": "not_promoted",
        "checks": checks,
        "passed": all(item["passed"] for item in checks),
    }
    ipc._json(output / "assessment.json", result)
    return checks, result


def render_summary(result: dict[str, Any]) -> str:
    passed = sum(item["passed"] for item in result["checks"])
    lines = [
        "# C3 LL/SC progress capability audit",
        "",
        f"Overall evidence gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Assessed LL/SC profiles: **{result['llsc_profile_assessment_count']}**",
        f"New kernel progress properties: **{result['kernel_verification_count']}**",
        f"Promoted LL/SC mappings: **{result['progress_implementation_mapping_count']}**",
        f"Detecting controls: **{result['detecting_control_count']}**",
        "",
        "| Profile | Implementation | Decision | Gate |",
        "|---|---|---|---|",
    ]
    for profile in result["profiles"]:
        lines.append(
            f"| `{profile['id']}` | `{profile['implementation_kind']}` | "
            f"{profile['decision']} | {'PASS' if profile['passed'] else 'FAIL'} |"
        )
    diagnostic = result["conditional_diagnostic"]
    lines.extend([
        "",
        f"Evidence checks: **{passed}/{len(result['checks'])} passed**.",
        "",
        "The kernel's pinned atomic documentation says that simple compare/exchange",
        "loops are expected to progress, but explicitly warns that this does not",
        "automatically transfer to LL/SC implementations. A failed comparison branch",
        "can itself invalidate a reservation; unbounded conditional-store failure",
        "therefore remains a one-state retry cycle in the detecting control.",
        "",
        f"The diagnostic enumerates {diagnostic['actual']['finite_schedules']} finite",
        "failure schedules under a hypothetical at-most-two-failures-per-CAS premise.",
        f"That artificial premise gives a maximum of "
        f"{diagnostic['actual']['max_store_conditional_attempts']} conditional-store",
        "attempts across four source CAS calls, but no selected profile establishes",
        "the premise. The diagnostic is permanently ineligible as kernel verification.",
        "",
        "ARM64 and RISC-V contain runtime-selectable native-CAS and LL/SC paths.",
        "ARM32, PowerPC32, SuperH and Alpha expose direct LL/SC retry paths; Alpha's",
        "cold retry edge is checked through its emitted subsection trampoline.",
        "No profile is promoted merely because its lifetime mapping passes.",
        "",
        "No scheduler fairness, wait-freedom, unbounded lock-free progress, RCU",
        "progress, interrupt/NMI progress or whole-kernel liveness is accepted.",
        "No package was installed and no privileged or running-kernel action occurred.",
        "",
    ])
    return "\n".join(lines)


def audit_llsc_progress(
    root: Path, base_result: Path, output: Path, timeout: int = 120
) -> dict[str, Any]:
    """Audit six LL/SC mappings without promoting an unproved progress claim."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    base_result = base_result if base_result.is_absolute() else root / base_result
    if output.exists() or output.is_symlink():
        raise ConcurrencyC3LlscProgressError(
            f"LL/SC progress output already exists: {output}"
        )
    if type(timeout) is not int or timeout < 1:
        raise ConcurrencyC3LlscProgressError(
            "LL/SC progress timeout must be a positive integer"
        )
    output.mkdir(parents=True, exist_ok=False)
    profiles_output = output / "profiles"
    profiles_output.mkdir()

    base_audit, base_checks, base_readback = _verify_base(
        root, base_result, manifest
    )
    checks = list(base_checks)
    documentation = manifest["documentation"]
    documentation_path = ipc._relative(
        root, documentation["path"], "LL/SC documentation"
    )
    documentation_text = documentation_path.read_text()
    checks.extend([
        _check("LL/SC documentation identity", documentation["sha256"],
               ipc._sha256(documentation_path)),
        _check("LL/SC documentation warning order", True,
               ipc._ordered(documentation_text, documentation["required_order"])),
    ])

    base_manifest = ipc.load_manifest(root)
    base_profiles = {item["id"]: item for item in base_manifest["profiles"]}
    accepted_profiles = {
        item["id"]: item for item in base_audit.get("profiles", [])
    }
    profile_results: list[dict[str, Any]] = []
    for profile in manifest["profiles"]:
        checks.append(_check(
            f"{profile['id']} base profile accepted", True,
            accepted_profiles.get(profile["id"], {}).get("accepted"),
        ))
        profile_checks, profile_result = _run_profile_assessment(
            root, profile, base_profiles[profile["id"]],
            accepted_profiles.get(profile["id"], {}),
            profiles_output / profile["id"], timeout,
        )
        checks.extend(profile_checks)
        profile_results.append(profile_result)

    diagnostic = manifest["conditional_diagnostic"]
    bounded = _bounded_diagnostic(diagnostic)
    control = _unbounded_failure_cycle()
    bounded_core = {
        key: bounded[key] for key in diagnostic["expected"]
    }
    control_core = {
        key: control[key]
        for key in diagnostic["unbounded_failure_control"]["expected"]
    }
    diagnostic_checks = [
        _check("bounded LL/SC diagnostic result", diagnostic["expected"], bounded_core),
        _check("bounded LL/SC diagnostic is not verification", False,
               diagnostic["verification_candidate"]),
        _check("unbounded LL/SC failure exposes retry cycle",
               diagnostic["unbounded_failure_control"]["expected"], control_core),
        _check("unbounded LL/SC control is not verification", False,
               diagnostic["unbounded_failure_control"]["verification_candidate"]),
        _check("no LL/SC profile is promoted", 0,
               sum(item["verification_candidate"] for item in profile_results)),
    ]
    checks.extend(diagnostic_checks)
    conditional_result = {
        "kind": diagnostic["kind"],
        "premise": diagnostic["premise"],
        "verification_candidate": False,
        "actual": bounded,
        "unbounded_failure_control": control,
        "checks": diagnostic_checks,
        "passed": all(item["passed"] for item in diagnostic_checks),
    }
    ipc._json(output / "conditional-diagnostic.json", conditional_result)

    accepted = all(item["passed"] for item in checks)
    identity_names = sorted({
        "config/concurrency-c3-llsc-progress.json",
        "config/concurrency-c3-ipc-refcount.json",
        "fragma/__main__.py",
        "fragma/concurrency_c3_llsc_progress.py",
        "fragma/concurrency_c3_ipc_refcount.py",
        "fragma/concurrency_c3_lkmm.py",
        "fragma/concurrency_c3_module_stats.py",
        "tests/test_concurrency_c3_llsc_progress.py",
        documentation["path"],
        *(
            source["path"]
            for profile in manifest["profiles"]
            for source in profile["source_checks"]
        ),
    })
    identities = {
        name: {
            "sha256": ipc._sha256(ipc._relative(root, name, "LL/SC audit input")),
            "size": ipc._relative(root, name, "LL/SC audit input").stat().st_size,
        }
        for name in identity_names
    }
    base_audit_path = _safe_result_file(base_result, "pilot-audit.json")
    identities[str(base_audit_path)] = {
        "sha256": ipc._sha256(base_audit_path),
        "size": base_audit_path.stat().st_size,
    }
    ipc._json(output / "manifest.json", manifest)
    ipc._json(output / "input-identities.json", identities)
    result = {
        "schema_version": 1,
        "kind": "c3-llsc-progress-capability-audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": manifest["id"],
        "kernel_revision": manifest["kernel"]["revision"],
        "kernel_tree": manifest["kernel"]["git_tree"],
        "base_result": str(base_result.resolve()),
        "base_readback": base_readback,
        "documentation": documentation,
        "conditional_diagnostic": conditional_result,
        "profiles": profile_results,
        "checks": checks,
        "input_identities": identities,
        "exclusions": manifest["exclusions"],
        "accepted": accepted,
        "evaluation_complete": accepted,
        "llsc_profile_assessment_count": len(profile_results) if accepted else 0,
        "kernel_verification_count": 0,
        "progress_implementation_mapping_count": 0,
        "conditional_diagnostic_verification_count": 0,
        "detecting_control_count": 1 if accepted else 0,
        "sudo_or_install_used": False,
        "runtime_kernel_used": False,
        "remaining": [
            "Architecture-backed forward-progress evidence or a reviewed bounded premise for each LL/SC path",
            "Runtime-path-specific treatment of ARM64 LSE and RISC-V Zacas without promoting their LL/SC alternatives",
            "Unbounded progress, scheduler fairness, wait-freedom and broader lockless protocol coverage",
        ],
        "output": str(output),
    }
    result["raw_artifacts"] = module_stats._artifact_hashes(output)
    ipc._json(output / "summary.json", result)
    ipc._json(output / "pilot-audit.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c3-llsc-progress-{stamp}"
