"""Source-bound Mthread+Eva calibration for ARM32 cache-clean publication."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from . import (concurrency, concurrency_c2, concurrency_evidence, inputs,
               profiles, provenance, toolchain)


class Arm32CacheMthreadError(ValueError):
    """The ARM32 cache manifest, inputs, or analysis output is unusable."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _relative_file(root: Path, value: str, role: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise Arm32CacheMthreadError(f"{role} must be project-relative")
    path = root.joinpath(*pure.parts)
    if not path.is_file() or path.is_symlink():
        raise Arm32CacheMthreadError(f"missing {role}: {value}")
    return path


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {"name": name, "expected": expected, "actual": actual,
            "passed": expected == actual}


def load_manifest(root: Path) -> dict[str, Any]:
    path = root.resolve() / "config/arm32-cache-mthread.json"
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Arm32CacheMthreadError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise Arm32CacheMthreadError("unsupported ARM32 cache schema")
    if value.get("classification") != "known-fix-detection-calibration-no-new-bug":
        raise Arm32CacheMthreadError("cache pilot must remain a known-fix calibration")

    kernel = value.get("kernel")
    model = value.get("model")
    prop = value.get("property")
    cases = value.get("cases")
    if not all(isinstance(item, dict) for item in (kernel, model, prop)):
        raise Arm32CacheMthreadError("cache manifest sections are incomplete")
    if not isinstance(cases, list) or [case.get("id") for case in cases] != [
            "current_source", "early_publication_negative"]:
        raise Arm32CacheMthreadError("cache pilot requires ordered current/negative cases")
    if not re.fullmatch(r"[0-9a-f]{40}", str(kernel.get("revision", ""))):
        raise Arm32CacheMthreadError("kernel revision must be a full commit ID")
    for field in ("source_sha256", "function_token_sha256",
                  "build_receipt_sha256", "config_sha256", "object_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(kernel.get(field, ""))):
            raise Arm32CacheMthreadError(f"invalid kernel {field}")
    for field in ("build_receipt", "config", "object"):
        item = _relative_file(root, kernel.get(field, ""), field)
        expected = kernel[field + "_sha256"]
        if _sha256(item) != expected:
            raise Arm32CacheMthreadError(f"{field} identity drift")
    source = _relative_file(
        root, f"{kernel['source_root']}/{kernel['source']}", "kernel source")
    if _sha256(source) != kernel["source_sha256"]:
        raise Arm32CacheMthreadError("kernel source identity drift")
    fixture = _relative_file(root, model.get("fixture", ""), "cache fixture")
    if (_sha256(fixture) != model.get("fixture_sha256") or
            not re.fullmatch(r"[0-9a-f]{64}", str(model.get("fixture_sha256", "")))):
        raise Arm32CacheMthreadError("cache fixture identity drift")
    if model.get("thread_library") != "pthreads":
        raise Arm32CacheMthreadError("cache pilot requires the pthread adapter")
    options = model.get("common_options")
    if not isinstance(options, list) or not options or not all(
            isinstance(option, str) and option for option in options):
        raise Arm32CacheMthreadError("invalid cache analyzer options")
    labels = set(concurrency.assertion_lines(fixture).values())
    if labels != {prop.get("assertion")}:
        raise Arm32CacheMthreadError("fixture assertion inventory is not exact")
    expected = [("valid", "protected"), ("invalid", "missing")]
    for case, (status, protection) in zip(cases, expected):
        if (case.get("expected_assertions") != {prop["assertion"]: status} or
                case.get("expected_protection") != protection or
                not isinstance(case.get("cpp_defines"), list) or
                not all(re.fullmatch(r"[A-Z][A-Z0-9_]*", define)
                        for define in case.get("cpp_defines", []))):
            raise Arm32CacheMthreadError(f"invalid expectations for {case.get('id')}")
    if cases[0]["cpp_defines"] or not cases[0].get("current_source_candidate"):
        raise Arm32CacheMthreadError("positive case must be the unchanged fixture")
    if (cases[1]["cpp_defines"] != ["FRAGMA_ARM32_CACHE_EARLY_SET_NEGATIVE"] or
            cases[1].get("current_source_candidate")):
        raise Arm32CacheMthreadError("negative adapter is not exact")
    return value


def _artifact_hashes(output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name not in {"summary.json", "SUMMARY.md"}:
            result[path.relative_to(output).as_posix()] = {
                "sha256": _sha256(path), "size": path.stat().st_size}
    return result


def render_summary(result: dict[str, Any]) -> str:
    lines = [
        "# ARM32 `__sync_icache_dcache()` Mthread + Eva pilot",
        "",
        f"Overall gate: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        "This is a source-bound detection calibration for an already fixed race,",
        "not a new Linux bug report. The current source publishes the modeled",
        "clean bit after its per-caller flush; the early-publication control must",
        "make that same property fail.",
        "",
        "| Case | Publication property | Flag-word protection | Role | Gate |",
        "|---|---|---|---|---|",
    ]
    for case in result["cases"]:
        status = case["assertions"].get(
            result["property_assertion"], "missing")
        role = "current source" if case["current_source_candidate"] else "negative control"
        lines.append(
            f"| `{case['id']}` | {status} | {case['protection']} | {role} | "
            f"{'PASS' if case['passed'] else 'FAIL'} |")
    lines.extend([
        "",
        f"Known-fix detection calibrations passed: **{result['known_fix_detection_count']}**",
        "New bugs found by this pilot: **0**",
        "",
        "The abstract mutex represents only indivisible accesses to one Linux",
        "page-flag word. Cache instructions, ARM/LKMM ordering, concurrent dirty",
        "clears, folio lifetime, interrupts and progress remain outside the claim.",
        "The negative assertion stops Eva propagation before Mthread's final",
        "shared-object table, so `missing` protection is required only for that",
        "deliberately invalid control.",
        "",
    ])
    return "\n".join(lines)


def run(root: Path, kernel_repo: Path, output: Path, timeout: int = 180) -> dict[str, Any]:
    root = root.resolve()
    kernel_repo = kernel_repo.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise Arm32CacheMthreadError(f"output already exists: {output}")
    if timeout < 1:
        raise Arm32CacheMthreadError("timeout must be positive")
    output.mkdir(parents=True)
    (output / "cases").mkdir()
    checks: list[dict[str, Any]] = []

    kernel = manifest["kernel"]
    model = manifest["model"]
    prop = manifest["property"]
    source = _relative_file(
        root, f"{kernel['source_root']}/{kernel['source']}", "kernel source")
    fixture = _relative_file(root, model["fixture"], "cache fixture")
    source_function = provenance.extract_function(source.read_text(), kernel["function"])
    fixture_function = provenance.extract_function(fixture.read_text(), kernel["function"])
    checks.extend([
        _check("kernel function token hash", kernel["function_token_sha256"],
               provenance.token_hash(source_function.tokens)),
        _check("fixture function token identity", source_function.tokens,
               fixture_function.tokens),
        _check("fixture declaration identity", source_function.declaration_prefix,
               fixture_function.declaration_prefix),
    ])
    positions = []
    for token in ("test_bit", "__flush_dcache_folio", "set_bit"):
        try:
            positions.append(source_function.tokens.index(
                token, positions[-1] + 1 if positions else 0))
        except ValueError:
            positions.append(-1)
    checks.extend([
        _check("current source test/flush/set ordering", True,
               positions == sorted(positions) and min(positions) >= 0),
        _check("current source lacks early test-and-set", False,
               "test_and_set_bit" in source_function.tokens),
    ])

    build = inputs.load_build(root, kernel["profile"], kernel["revision"],
                              kernel["build_id"])
    checks.extend([
        _check("build receipt identity", kernel["build_receipt_sha256"],
               _sha256(root / kernel["build_receipt"])),
        _check("configured object identity", kernel["object_sha256"],
               _sha256(root / kernel["object"])),
    ])
    config = concurrency_c2.parse_kconfig((root / kernel["config"]).read_text())
    for name, expected in kernel["required_config"].items():
        checks.append(_check(f"kernel config: {name}", expected,
                             config.get(name, "absent")))

    git_dir = output / "git-source"
    git_dir.mkdir()
    git_source_argv = ["git", "-C", str(kernel_repo), "show",
                       f"{kernel['revision']}:{kernel['source']}"]
    git_source = concurrency._run(git_source_argv, root, timeout)
    concurrency._write_process(git_dir, git_source_argv, git_source)
    checks.extend([
        _check("pinned git source command", 0, git_source["returncode"]),
        _check("snapshot equals pinned git blob", source.read_text(),
               git_source["stdout"]),
    ])
    trigger_dir = output / "trigger"
    trigger_dir.mkdir()
    trigger_argv = ["git", "-C", str(kernel_repo), "show", "-s",
                    "--format=%s", kernel["trigger_commit"]]
    trigger = concurrency._run(trigger_argv, root, timeout)
    concurrency._write_process(trigger_dir, trigger_argv, trigger)
    checks.extend([
        _check("trigger commit command", 0, trigger["returncode"]),
        _check("trigger subject", kernel["trigger_subject"],
               trigger["stdout"].strip()),
    ])

    models, _, _ = concurrency_evidence.load_registries(root)
    c1 = [item for item in models["models"] if item["id"] == model["c1_model_id"]]
    if len(c1) != 1:
        raise Arm32CacheMthreadError("no unique calibrated Mthread provider model")
    c0 = concurrency.load_manifest(root)
    binary = _relative_file(root, c0["provider"]["binary"], "Frama-C provider")
    checks.append(_check("Mthread provider identity",
                         c1[0]["provider_binary_sha256"], _sha256(binary)))

    env = toolchain.prepare_environment(root)
    profile_result = profiles.validate_profile(
        root, kernel["profile"], kernel=kernel_repo,
        output=output / "profile", kernel_build=Path(build["path"]), env=env,
        frama_c=binary)
    if (profile_result.get("status") != "passed" or
            "analysis" not in profile_result):
        gaps = "; ".join(profile_result.get("gaps", []))
        raise Arm32CacheMthreadError(f"ARM profile validation failed: {gaps}")
    checks.extend([
        _check("ARM profile status", "passed", profile_result.get("status")),
        _check("ARM profile level", "L1", profile_result.get("level")),
        _check("ARM profile width", 4,
               profile_result.get("machdep", {}).get("checked_fields", {})
               .get("sizeof_ptr")),
    ])
    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        directory = output / "cases" / case["id"]
        directory.mkdir()
        report_path = directory / "report.tsv"
        cpp = (["-cpp-extra-args=" + " ".join(
            "-D" + name for name in case["cpp_defines"])]
               if case["cpp_defines"] else [])
        argv = [str(binary), "-machdep", profile_result["analysis"]["machdep"],
                *cpp, *model["common_options"], "-mt-threads-lib",
                model["thread_library"], model["fixture"], "-then", "-report",
                "-report-csv", str(report_path)]
        process = concurrency._run(argv, root, timeout)
        concurrency._write_process(directory, argv, process)
        combined = process["stdout"] + "\n" + process["stderr"]
        report = (concurrency.parse_report_csv(report_path, fixture)
                  if report_path.is_file() else None)
        assertions = report["assertions"] if report else {}
        protection = concurrency_c2.final_mutex_protection(
            combined, prop["shared_objects"][0], prop["required_mutex"])
        diagnostics = concurrency.parse_diagnostics(combined)
        case_checks = [
            _check("timed out", False, process["timed_out"]),
            _check("exit code", 0, process["returncode"]),
            _check("report present", True, report is not None),
            _check("assertions", case["expected_assertions"], assertions),
            _check("flag-word protection", case["expected_protection"], protection),
            _check("unprotected read/write race", False,
                   diagnostics["races"]["read_write"]["unprotected"]),
            _check("unprotected write/write race", False,
                   diagnostics["races"]["write_write"]["unprotected"]),
            _check("analysis fixpoint", True, diagnostics["fixpoint_reached"]),
            _check("no unsupported primitive", False, diagnostics["unsupported"]),
            _check("atomic adapter initialized", True,
                   f"Initializing mutex {prop['required_mutex']}" in combined),
        ]
        case_results.append({
            "id": case["id"], "cpp_defines": case["cpp_defines"],
            "current_source_candidate": case["current_source_candidate"],
            "returncode": process["returncode"], "timed_out": process["timed_out"],
            "assertions": assertions, "protection": protection,
            "diagnostics": diagnostics, "checks": case_checks,
            "passed": all(item["passed"] for item in case_checks),
        })
        _json(directory / "result.json", case_results[-1])

    all_checks = [*checks, *(check for case in case_results for check in case["checks"])]
    accepted = all(check["passed"] for check in all_checks)
    known_fix = int(accepted and case_results[0]["assertions"] ==
                    {prop["assertion"]: "valid"} and
                    case_results[1]["assertions"] ==
                    {prop["assertion"]: "invalid"})
    result = {
        "schema_version": 1,
        "kind": "fragma-arm32-cache-mthread-known-fix-calibration",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": manifest["classification"],
        "kernel_revision": kernel["revision"],
        "property_assertion": prop["assertion"],
        "checks": checks,
        "cases": case_results,
        "known_fix_detection_count": known_fix,
        "new_bug_count": 0,
        "accepted": accepted,
        "output": str(output),
        "limitations": prop["exclusions"],
        "profile": profile_result,
    }
    _json(output / "manifest.json", manifest)
    result["artifact_hashes"] = _artifact_hashes(output)
    _json(output / "summary.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"arm32-cache-mthread-{stamp}"
