"""One-command proof runs with provenance, build/model gates, and durable reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time

from . import analysis_policy, common24, common24_calibration, frontend_policy, inputs, integrity, native_sensitivity, profiles, provenance, report, sources, toolchain


class SuiteError(ValueError):
    pass


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    os.replace(temporary, path)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SuiteError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SuiteError(f"unsupported schema: {path}")
    return value


def load_registry(root: Path) -> tuple[str, dict, dict]:
    paths = [root / "config/targets.json", *sorted((root / "config").glob("*-targets.json"))]
    targets, assumptions = {}, {}
    revision = None
    for path in [*paths, root / "config/assumptions.json", root / "toolchain/assumptions.json"]:
        data = read_json(path)
        if "kernel_revision" in data:
            if revision and data["kernel_revision"] != revision:
                raise SuiteError(f"target manifests disagree on pinned revision: {path}")
            revision = data["kernel_revision"]
        for field, collection in (("targets", targets), ("assumptions", assumptions)):
            for item in data.get(field, []):
                identifier = item.get("id")
                if not isinstance(identifier, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]+", identifier):
                    raise SuiteError(f"invalid {field} ID in {path}")
                if identifier in collection:
                    raise SuiteError(f"duplicate {field} ID: {identifier}")
                collection[identifier] = item
    if not revision or not re.fullmatch("[0-9a-f]{40}", revision):
        raise SuiteError("targets must pin a full git commit ID")
    registered_profiles = profiles.load_profiles(root)
    for target in targets.values():
        if target.get("profile") not in registered_profiles:
            raise SuiteError(f"unknown profile for {target['id']}")
        if target.get("analysis") not in ("wp", "eva"):
            raise SuiteError(f"unsupported analysis for {target['id']}")
        for name in target.get("assumptions", []):
            if name not in assumptions:
                raise SuiteError(f"undeclared assumption {name} for {target['id']}")
        for field in ("harness", "driver", "specs", "kernel_model_check", "wp_strategy_file"):
            if target.get(field):
                path = (root / target[field]).resolve()
                if not path.is_relative_to(root) or not path.is_file():
                    raise SuiteError(f"invalid or missing {field} for {target['id']}: {path}")
        strategy_options(target, "alt-ergo,z3")
        try:
            frontend_policy.identity(target, root=root)
            if target.get("frontend_policy") is not None:
                common24.check_target(target)
                if common24_calibration.identity(target, root=root) is None:
                    raise common24_calibration.CalibrationError("registered common24 targets require compiler calibration")
            else:
                common24_calibration.identity(target, root=root)
            for filename in frontend_policy.required_files(target):
                if not (root / filename).is_file():
                    raise sources.SourceError("missing frontend policy input: " + filename)
            for filename in common24_calibration.required_files(target):
                if not (root / filename).is_file():
                    raise common24_calibration.CalibrationError("missing compiler calibration input: " + filename)
        except (sources.SourceError, common24.Common24Error, common24_calibration.CalibrationError) as exc:
            raise SuiteError(f"invalid frontend policy for {target['id']}: {exc}") from exc
        try:
            analysis_policy.pipeline_identity(target)
        except analysis_policy.AnalysisPolicyError as exc:
            raise SuiteError(f"invalid analysis pipeline for {target['id']}: {exc}") from exc
        companion_id = target.get("required_companion")
        mapping = target.get("companion_property_map", {})
        expected = target.get("expected_unresolved", [])
        if companion_id or mapping or expected:
            companion = targets.get(companion_id) if isinstance(companion_id, str) else None
            if (not companion or target.get("role") != "calibration" or
                    not isinstance(expected, list) or not expected or
                    not isinstance(mapping, dict) or set(mapping) != set(expected) or
                    not all(isinstance(name, str) and name for name in mapping.values()) or
                    not set(mapping.values()) <= set(companion.get("expected_invalid", [])) or
                    companion.get("role") != "calibration" or
                    companion.get("analysis") == target["analysis"] or
                    companion.get("profile") != target["profile"] or
                    companion.get("source") != target["source"] or
                    set(companion.get("functions", [])) != set(target.get("functions", [])) or
                    not isinstance(target.get("companion_mapping_reason"), str) or
                    not target["companion_mapping_reason"].strip()):
                raise SuiteError(f"invalid or unexplained calibration companion mapping for {target['id']}")
    return revision, targets, assumptions


def strategy_options(target: dict, provers: str) -> tuple[list[str], str, str]:
    """Return bounded proof-search options without permitting arbitrary flags.

    TIP is Frama-C's tactic engine, not an additional external solver. Strategies
    declare their own external portfolio; both declarations and strategy source
    remain run inputs. No cached script or hand-authored verdict is imported.
    """
    strategy = target.get("wp_strategy")
    if not strategy:
        if any(key in target for key in ("wp_strategy_file", "wp_strategy_provers", "wp_auto_depth")):
            raise SuiteError("strategy settings require a named WP strategy")
        return [], provers, provers
    if target.get("analysis") != "wp" or not isinstance(strategy, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", strategy):
        raise SuiteError("invalid or non-WP proof strategy")
    if not isinstance(target.get("wp_strategy_file"), str) or not target["wp_strategy_file"]:
        raise SuiteError("WP strategy must declare its source file")
    portfolio = target.get("wp_strategy_provers")
    if not isinstance(portfolio, list) or not portfolio or not all(isinstance(name, str) for name in portfolio) or len(set(portfolio)) != len(portfolio) or not set(portfolio) <= {"alt-ergo", "z3", "cvc5"}:
        raise SuiteError("WP strategy must declare a distinct supported external prover portfolio")
    depth, smoke_timeout = target.get("wp_auto_depth", 64), target.get("wp_smoke_timeout", 2)
    if type(depth) is not int or not 1 <= depth <= 256 or type(smoke_timeout) is not int or not 1 <= smoke_timeout <= 60:
        raise SuiteError("invalid bounded WP strategy depth/smoke timeout")
    # Default strategies deliberately do not apply to smoke obligations in
    # Frama-C 33. Keep real external attempts alongside TIP; TIP alone leaves
    # such smoke goals unattempted with verdict 'none'.
    return ["-wp-strategy", strategy, "-wp-auto-depth", str(depth),
            "-wp-smoke-timeout", str(smoke_timeout)], ",".join(["tip", *portfolio]), ",".join(portfolio)


def analysis_limits(timeout: int, jobs: int, wall_timeout: int | None) -> dict:
    """Keep per-prover search limits separate from the analyzer process cap."""
    if type(timeout) is not int or not 1 <= timeout <= 3600 or type(jobs) is not int or not 1 <= jobs <= 256:
        raise SuiteError("invalid solver timeout or job count")
    if wall_timeout is None:
        wall_timeout = min(86400, max(180, timeout * 60))
    if type(wall_timeout) is not int or not 1 <= wall_timeout <= 86400:
        raise SuiteError("wall timeout must be between 1 and 86400 seconds")
    return {"wall_timeout_seconds": wall_timeout, "solver_timeout_seconds": timeout, "jobs": jobs}


def select_targets(targets: dict, *, ids: list[str], suites: list[str],
                   profile_ids: list[str]) -> list[dict]:
    if set(ids) - targets.keys():
        raise SuiteError("unknown targets: " + ", ".join(sorted(set(ids) - targets.keys())))
    known_suites = {t["suite"] for t in targets.values()}
    if set(suites) - known_suites:
        raise SuiteError("unknown suites: " + ", ".join(sorted(set(suites) - known_suites)))
    selected = {key: value for key, value in targets.items()
                if (not ids or key in ids) and (not suites or value["suite"] in suites)
                and (not profile_ids or value["profile"] in profile_ids)}
    if not selected:
        raise SuiteError("selection contains no registered targets")
    pending = list(selected.values())
    while pending:
        target = pending.pop()
        companion = target.get("required_companion")
        if companion and companion not in selected:
            if companion not in targets:
                raise SuiteError(f"missing registered companion {companion}")
            selected[companion] = targets[companion]
            pending.append(targets[companion])
    return list(selected.values())


def select_native_targets(receipt: dict, selected: list[dict]) -> set[str]:
    """Inventory routing only; each used case still needs full revalidation."""
    if receipt.get("kind") == "fragma-native-spec-sensitivity":
        cases = receipt.get("cases")
    elif receipt.get("kind") == "fragma-s390-spec-sensitivity":
        cases = [{"target_id": receipt.get("target_id")}]
    else:
        raise SuiteError("unsupported native calibration evidence kind")
    if not isinstance(cases, list) or not cases or not all(isinstance(case, dict) and isinstance(case.get("target_id"), str) for case in cases):
        raise SuiteError("native calibration evidence contains no target inventory")
    ids = {case["target_id"] for case in cases}
    if len(ids) != len(cases) or not ids & {target["id"] for target in selected}:
        raise SuiteError("native evidence has duplicate targets or covers no selected target")
    if any(target["id"] in ids and (target["role"], target["analysis"]) != ("calibration", "eva")
           for target in selected):
        raise SuiteError("native evidence may only corroborate selected EVA calibrations")
    return ids


def native_evidence_routes(evidence: Path | list[Path] | None, selected: list[dict]) -> tuple[dict, list[Path]]:
    """Route explicit receipts without choosing between competing witnesses."""
    paths = [] if evidence is None else [evidence] if isinstance(evidence, Path) else evidence
    if not isinstance(paths, (list, tuple)) or not all(isinstance(path, Path) for path in paths):
        raise SuiteError("native evidence must be an explicit path or list of paths")
    resolved = [path.resolve() for path in paths]
    if len(set(resolved)) != len(resolved):
        raise SuiteError("duplicate native evidence receipt")
    routes, selected_ids = {}, {target["id"] for target in selected}
    for path in resolved:
        matching = select_native_targets(read_json(path), selected) & selected_ids
        if matching & routes.keys():
            raise SuiteError("multiple native receipts cover the same selected target")
        routes.update({identifier: path for identifier in matching})
    return routes, resolved


def validate_native_evidence(root, kernel, target, revision, model, build, path):
    """Dispatch only to a fixed, fully validating calibration provider."""
    kind = read_json(path).get("kind")
    if kind == "fragma-native-spec-sensitivity":
        validator = native_sensitivity.validate_native_receipt
    elif kind == "fragma-s390-spec-sensitivity":
        from . import s390_sensitivity
        validator = s390_sensitivity.validate_native_receipt
    else:
        raise SuiteError("unsupported native calibration evidence kind")
    return validator(root, kernel, target, revision, model, build, path)


def warnings_from_log(path: Path) -> list[dict]:
    """Preserve located and multiline analyzer/compiler diagnostics."""
    result = []
    active = None
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        match = re.match(r"\[([^]]+)\]\s+(?:(.+?):(\d+)(?::\d+)?:\s*)?"
                         r"(Warning|Error|User Error|Internal Error):\s*(.*)", line)
        if match:
            active = {"plugin": match[1], "severity": "warning" if match[4] == "Warning" else "error",
                      "message": match[5], "log_line": number, "raw_lines": [line]}
            if match[2]:
                active.update(path=match[2], line=int(match[3]))
            result.append(active)
            continue
        compiler = re.match(r"(.+?):(?:(\d+):(?:(\d+):)?)?\s*(warning|error|fatal error):\s*(.*)", line)
        if compiler:
            active = {"plugin": "compiler", "severity": "warning" if compiler[4] == "warning" else "error",
                      "message": compiler[5], "path": compiler[1], "log_line": number, "raw_lines": [line]}
            if compiler[2]:
                active["line"] = int(compiler[2])
            result.append(active)
            continue
        if active and line[:1].isspace() and line.strip():
            active["raw_lines"].append(line)
            if active["plugin"] != "compiler":
                active["message"] = (active["message"] + " " + line.strip()).strip()
        else:
            active = None
    return result


def assumption_records(root: Path, target: dict, ledger: dict, provers: str) -> list[dict]:
    names = list(target.get("assumptions", []))
    names += ["toolchain-proof-engine-soundness", "toolchain-native-runtime"]
    if "cvc5" in provers.split(","):
        names += ["toolchain-cvc5-driver-compatibility"]
    result = []
    for name in dict.fromkeys(names):
        item = ledger[name]
        files = []
        for filename in item.get("files", []):
            path = root / filename
            if not path.is_file():
                raise SuiteError(f"missing assumption input: {path}")
            files.append({"path": filename, "absolute_path": str(path), "sha256": sources.sha256(path)})
        result.append({**item, "input_files": files, "record_sha256": digest(item)})
    return result


def execute_target(root: Path, kernel: Path, revision: str, target: dict,
                   model: dict, build: dict, tools: dict, ledger: dict, output: Path,
                   env: dict, *, timeout: int, jobs: int, provers: str,
                   native_evidence: Path | None = None, wall_timeout: int | None = None) -> dict:
    output.mkdir()
    evidence = {"target": target, "schema_version": 1, "status": "running"}
    write_json(output / "result.json", evidence)
    try:
        limits = analysis_limits(timeout, jobs, wall_timeout)
        evidence["analysis_limits"] = limits
        analysis_policy.model_identity(model["analysis"])
        analysis_policy.pipeline_identity(target)
        frontend_policy.identity(target, root=root)
        compiler_setting = common24_calibration.identity(target, root=root)
        if frontend_policy.identity(target, root=root) is not None and compiler_setting is None:
            raise SuiteError("registered common24 target requires compiler calibration")
        search_options, engine_provers, assumption_provers = strategy_options(target, provers)
        gate = provenance.check_target(target, kernel, revision, root)
        evidence["provenance"] = gate
        if not gate["passed"]:
            raise SuiteError("source-identity gate failed: " + "; ".join(gate["errors"]))
        if frontend_policy.identity(target, root=root) is not None:
            evidence["common24_source"] = common24.check_source(target,
                source_path=root / target["harness"], source_text=(root / target["harness"]).read_text(),
                strategy_text=(root / target["wp_strategy_file"]).read_text())
        assumptions = assumption_records(root, target, ledger, assumption_provers)
        evidence["assumptions"] = assumptions
        evidence["kernel_model_check"] = inputs.kernel_model_check(root, target, build, kernel,
                                                                     revision, output, env)
        prepared = inputs.prepare_input(root, target, model, build, kernel, revision, output, env)
        evidence["input"] = prepared
        if target.get("wp_strategy_file"):
            strategy_path = (root / target["wp_strategy_file"]).resolve()
            if str(strategy_path) not in {item["absolute_path"] for item in prepared["inputs"]}:
                raise SuiteError("declared WP strategy file is not a consumed proof input")
        review = integrity.validate_review(root, target, revision, model, build, tools, prepared)
        evidence["validated_review"] = review
        compiler = None
        if compiler_setting is not None:
            calibration_output = output / "compiler-calibration"
            compiler = common24_calibration.run(root, target, model, build, kernel, revision,
                calibration_output, common24_calibration.compiler_environment(calibration_output),
                kernel_model_gate=evidence["kernel_model_check"], kernel_model_output=output)
            evidence["validated_compiler_calibration"] = compiler
            if compiler.get("status") != common24_calibration.STATUS:
                raise SuiteError("required compiler calibration failed: " + str(compiler.get("receipt")))
        native = validate_native_evidence(root, kernel, target, revision,
            model, build, native_evidence) if native_evidence else None
        evidence["validated_native"] = native
        tracked = [integrity.receipt(root / target[field])
                   for field in ("harness", "specs", "driver", "kernel_model_check", "wp_strategy_file") if target.get(field)]
        tracked += [integrity.receipt(Path(build["path"]) / filename, expected)
                    for filename, expected in build["files"].items()]
        tracked.append(integrity.receipt(Path(build["path"]) / "fragma-build.json", build["receipt_sha256"]))
        tracked += integrity.metadata_records([assumptions, prepared, evidence["kernel_model_check"]])
        tracked += integrity.profile_records(root, model)
        if review:
            tracked += review["tracked_files"]
        if native:
            tracked += native["tracked_files"]
        if compiler:
            tracked += compiler["tracked_files"]
        evidence["integrity_inputs"] = integrity.merge_records(tracked)
        changes = integrity.changed_files(evidence["integrity_inputs"])
        if changes:
            raise SuiteError("required inputs changed before analysis: " + ", ".join(item["absolute_path"] for item in changes))
        frama_c = tools["tools"]["frama-c"]["path"]
        command = [frama_c, "-machdep", model["analysis"]["machdep"],
                   *analysis_policy.analyzer_flags(model["analysis"]), "-cpp-frama-c-compliant",
                   "-cpp-command", prepared["frama_cpp_command"], "-cpp-extra-args=-std=gnu11",
                   "-pp-annot", "-keep-temp-files", "-audit-prepare", str(output / "audit.json"),
                   prepared["frama_input"]]
        driver_paths = []
        if target.get("driver"):
            driver_paths = [root / target["driver"]]
            command += [str(path) for path in driver_paths]
        if target["analysis"] == "wp":
            command += ["-wp", "-wp-fct", ",".join(target.get("analysis_functions", target["functions"])),
                        "-wp-model", model["analysis"]["wp_model"], "-wp-rte", "-wp-split",
                        "-wp-smoke-tests", "-wp-prover", engine_provers, "-wp-timeout", str(timeout),
                        "-wp-par", str(jobs), "-wp-cache", "none", "-wp-out", str(output / "wp"),
                        "-wp-why3-config", str(root / "toolchain/why3.conf"), "-wp-no-why3-detect",
                        "-wp-report-json", str(output / "wp.json"), *search_options]
            if search_options:
                command += ["-wp-session", str(output / "proof-session")]
        else:
            command += analysis_policy.before_eva_options(target)
            command += ["-eva", "-main", target["entry"], "-eva-slevel", "100"]
            if target.get("eva_auto_builtins") is False:
                command += ["-eva-no-builtins-auto"]
            if target.get("eva_builtins"):
                command += ["-eva-builtin", ",".join(target["eva_builtins"])]
        command += ["-then", "-report", "-report-absolute-path", "-report-csv", str(output / "properties.tsv")]
        (output / "tmp").mkdir()
        analysis_env = {**env, "TMPDIR": str(output / "tmp")}
        command_receipt = inputs.run_recorded(command, cwd=Path(prepared["cwd"]), env=analysis_env, log=output / "analysis.log",
                                               timeout=limits["wall_timeout_seconds"])
        evidence["analysis_command"] = command_receipt
        warnings = warnings_from_log(output / "analysis.log")
        evidence["warnings"] = warnings
        if command_receipt["returncode"] != 0:
            raise SuiteError("analyzer timed out" if command_receipt["timed_out"] else
                             f"analyzer exited with status {command_receipt['returncode']}")
        audit = inputs.audit_inputs(root, kernel, revision, build, output, prepared, target)
        evidence["analyzer_audit"] = audit
        evidence["validated_analysis_policy"] = analysis_policy.validate_actual_policy(
            model["analysis"], target, command_receipt["argv"], audit["parameters"])
        frontend = frontend_policy.validate_actual(root, target, model, prepared,
            evidence["kernel_model_check"], command_receipt, audit)
        if frontend is not None:
            evidence["validated_frontend_policy"] = frontend
        evidence["integrity_inputs"] = integrity.merge_records(evidence["integrity_inputs"],
                                                                 integrity.metadata_records(audit))
        goals = report.parse_wp_report(output / "wp.json") if target["analysis"] == "wp" else []
        properties = report.parse_properties(output / "properties.tsv",
            source_files=[root / target["harness"], *driver_paths], source_root=Path(prepared["cwd"]),
            selected_functions=[*target.get("analysis_functions", target["functions"]),
                                *([target["entry"]] if target["analysis"] == "eva" else [])])
        evaluation = report.evaluate_target(target, goals, properties,
            returncode=command_receipt["returncode"], warnings=warnings, validated_review=review,
            validated_native=native)
        if frontend is not None:
            inventory = common24.evaluate_inventory(target, goals, properties, evaluation,
                source_path=root / target["harness"], source_text=(root / target["harness"]).read_text(),
                strategy_text=(root / target["wp_strategy_file"]).read_text())
            evidence["common24_inventory"] = inventory
            evaluation = common24.apply_policy(evaluation, inventory)
        evaluation["proof_policy_passed"] = evaluation["local_policy_passed"]
        reviews = [item["id"] for item in assumptions
                   if item.get("review_status") not in ("reviewed", "reviewed-assumption")]
        if reviews:
            evaluation["issues"].append({"kind": "review-required", "message": "Trusted assumptions require review",
                                          "assumptions": reviews})
            evaluation.update(accepted=False, verified=False, local_policy_passed=False)
            if evaluation["status"] in ("passed", "calibration-passed", "needs-companion"):
                evaluation["status"] = "review-required"
        if model.get("level") != "L1" or model.get("status") != "passed":
            evaluation["issues"].append({"kind": "incomplete", "message": "Profile has not passed configured L1 checks"})
            evaluation.update(status="incomplete", accepted=False, verified=False, local_policy_passed=False)
        # Mandatory preflight, source and model gates have now preceded proof
        # classification. Every remaining assumed implementation stays visible.
        evidence.update(evaluation=evaluation, goals=goals, properties=properties,
                        status=evaluation["status"], accepted=evaluation["accepted"])
        evidence["fingerprint"] = digest({"target": target, "revision": revision,
            "profile_fingerprint": model["fingerprint"], "build": build,
            "toolchain": tools, "assumptions": assumptions, "input": prepared,
            "command": command, "analysis_limits": limits})
    except (OSError, ValueError, KeyError) as exc:
        status = "tool-error" if "analysis_command" in evidence else "error"
        evidence.update(status=status, accepted=False, error=str(exc),
            evaluation={"target_id": target["id"], "profile": target["profile"],
                        "source": target["source"], "role": target["role"],
                        "analysis": target["analysis"], "status": status, "accepted": False,
                        "verified": False, "local_policy_passed": False,
                        "issues": [{"kind": status, "message": str(exc)}]})
    write_json(output / "result.json", evidence)
    return evidence


def finalize_results(items: list[dict], shared_inputs: list[dict]) -> None:
    # Invalidate all changed inputs BEFORE resolving calibration dependencies.
    # A passing companion whose driver changed must never certify its parent.
    shared_changes = integrity.changed_files(shared_inputs)
    for item in items:
        integrity.invalidate(item, [*shared_changes,
            *integrity.changed_files(item.get("integrity_inputs", []))])
    finalized = report.finalize_companions([item["evaluation"] for item in items])
    for item, evaluation in zip(items, finalized):
        item.update(evaluation=evaluation, accepted=evaluation["accepted"], status=evaluation["status"])


def run_suite(root: Path, kernel: Path, *, ids: list[str], suites: list[str],
              profile_ids: list[str], output: Path | None = None,
              timeout: int = 20, jobs: int = 4, provers: str = "alt-ergo,z3",
              native_evidence: Path | list[Path] | None = None, wall_timeout: int | None = None) -> dict:
    root, kernel = root.resolve(), kernel.resolve()
    limits = analysis_limits(timeout, jobs, wall_timeout)
    if not set(provers.split(",")) <= {"alt-ergo", "z3", "cvc5"}:
        raise SuiteError("invalid timeout, jobs, or prover selection")
    # Configuration and runner code are themselves proof inputs. Capture before
    # loading registries so a concurrent edit cannot silently change a baseline.
    registry_files = sorted({*root.glob("fragma/*.py"), *root.glob("config/*.json"),
                             root / "toolchain/lock.json", root / "toolchain/why3.conf",
                             root / "toolchain/assumptions.json"})
    shared_inputs = [integrity.receipt(path) for path in registry_files]
    revision, targets, ledger = load_registry(root)
    known_profiles = profiles.load_profiles(root)
    if set(profile_ids) - known_profiles.keys():
        raise SuiteError("unknown profile selection")
    selected = select_targets(targets, ids=ids, suites=suites, profile_ids=profile_ids)
    native_routes, native_paths = native_evidence_routes(native_evidence, selected)
    shared_inputs.extend(integrity.receipt(path) for path in native_paths)
    if output:
        output = output.resolve()
        if output.exists():
            raise SuiteError(f"run directory already exists: {output}")
        output.mkdir(parents=True)
    else:
        (root / "results").mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
        output = Path(tempfile.mkdtemp(prefix=stamp, dir=root / "results"))
    summary = {"schema_version": 1, "revision": revision, "status": "running",
               "analysis_limits": limits,
               "output": str(output), "selected_targets": [target["id"] for target in selected],
               "native_evidence": str(native_paths[0]) if len(native_paths) == 1 else None,
               "native_evidence_paths": [str(path) for path in native_paths],
               "profiles": {}, "targets": [], "started_at": datetime.now(timezone.utc).isoformat()}
    write_json(output / "summary.json", summary)
    try:
        env = toolchain.prepare_environment(root)
        tools = toolchain.inventory(root, env)
    except (OSError, ValueError) as exc:
        env = {}
        tools = {"schema_version": 1, "ok": False,
                 "issues": ["Toolchain preflight could not complete: " + str(exc)],
                 "error_type": type(exc).__name__}
    shared_inputs = integrity.merge_records(shared_inputs, integrity.metadata_records(tools))
    summary["integrity_inputs"] = shared_inputs
    write_json(output / "toolchain.json", tools)
    if not tools["ok"]:
        summary.update(status="preflight-failed", errors=tools["issues"], accepted=False)
        for target in selected:
            summary["targets"].append({"schema_version": 1, "target": target,
                "status": "preflight-blocked", "accepted": False,
                "evaluation": {"target_id": target["id"], "profile": target["profile"],
                    "source": target["source"], "role": target["role"], "analysis": target["analysis"],
                    "status": "preflight-blocked", "accepted": False, "verified": False,
                    "local_policy_passed": False, "issues": [{"kind": "preflight-blocked",
                        "message": "Analysis was not attempted because toolchain preflight failed",
                        "preflight_errors": tools["issues"]}]}})
        return write_terminal_summary(summary)
    builds = {}
    for profile_id in dict.fromkeys(target["profile"] for target in selected):
        print(f"Checking profile {profile_id} ...", flush=True)
        try:
            builds[profile_id] = inputs.load_build(root, profile_id, revision)
            model = profiles.validate_profile(root, profile_id, kernel=kernel,
                frama_c=tools["tools"]["frama-c"]["path"], output=output / ("profile-" + profile_id),
                kernel_build=Path(builds[profile_id]["path"]), env=env)
        except (OSError, ValueError, KeyError) as exc:
            model = {"status": "failed", "level": "L0", "error": str(exc)}
        summary["profiles"][profile_id] = model
        write_json(output / "summary.json", summary)
    for target in selected:
        print(f"Analyzing {target['id']} ...", flush=True)
        model = summary["profiles"][target["profile"]]
        if model.get("status") != "passed" or model.get("level") != "L1":
            evidence = {"target": target, "status": "profile-blocked", "accepted": False,
                        "evaluation": {"target_id": target["id"], "accepted": False,
                                       "verified": False, "status": "profile-blocked"}}
        else:
            evidence = execute_target(root, kernel, revision, target, model, builds[target["profile"]],
                tools, ledger, output / target["id"], env, timeout=timeout, jobs=jobs, provers=provers,
                native_evidence=native_routes.get(target["id"]),
                wall_timeout=limits["wall_timeout_seconds"])
        summary["targets"].append(evidence)
        print(f"  {evidence['status']}", flush=True)
        write_json(output / "summary.json", summary)
    finalize_results(summary["targets"], shared_inputs)
    return write_terminal_summary(summary)


def write_terminal_summary(summary: dict) -> dict:
    """Retain selected-case results and dates even when no analysis can start."""
    output = Path(summary["output"])
    for item in summary["targets"]:
        directory = output / item["target"]["id"]
        directory.mkdir(exist_ok=True)
        write_json(directory / "result.json", item)
    if summary["status"] != "preflight-failed":
        summary["accepted"] = bool(summary["targets"]) and all(item["accepted"] for item in summary["targets"])
        summary["status"] = "passed" if summary["accepted"] else "incomplete"
    summary["counts"] = dict(Counter(item["status"] for item in summary["targets"]))
    summary["completed_at"] = datetime.now(timezone.utc).isoformat()
    write_json(output / "summary.json", summary)
    lines = ["# fragma run", "", f"Revision: `{summary['revision']}`", "", f"Result: **{summary['status']}**", "",
             "| Target | Profile | Result |", "| --- | --- | --- |"]
    lines += [f"| {item['target']['id']} | {item['target']['profile']} | {item['status']} |"
              for item in summary["targets"]]
    lines += ["", "See summary.json and each target's result.json for commands, assumptions,",
              "source hashes, dependencies, warnings, and individual goal outcomes.", ""]
    (output / "SUMMARY.md").write_text("\n".join(lines))
    return summary
