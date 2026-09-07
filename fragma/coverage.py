"""Explicit-evidence coverage inventory; never a proof or architecture certifier.

No result-directory discovery, installed-tool probing, subprocesses, or mutations
in generate_matrix. Architecture support levels are never awarded by this module.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re

from fragma import integrity, profiles, replay, report, suite


class CoverageError(ValueError):
    pass


DIMENSIONS = ("runtime-safety", "functional", "termination", "caller-preconditions")
HASH = re.compile(r"[0-9a-f]{64}")
TERMINAL = {"passed", "incomplete", "preflight-failed", "error", "cancelled"}


def _strict_json(text):
    result = replay.strict_json(text)
    pending = [result]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise CoverageError("non-finite JSON number")
    return result


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _date(value):
    if not isinstance(value, str):
        raise CoverageError("completed evidence requires an explicit timezone-aware date")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoverageError("invalid evidence date: " + value) from exc
    if result.tzinfo is None:
        raise CoverageError("evidence dates must include a timezone")
    return result.astimezone(timezone.utc)


class _Inputs:
    def __init__(self):
        self.observed = {}

    @staticmethod
    def hash(path):
        try:
            with Path(path).open("rb") as handle:
                value = hashlib.sha256()
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    value.update(block)
                return value.hexdigest()
        except OSError:
            return None

    def observe(self, path):
        name = str(Path(path).absolute())
        if name not in self.observed:
            self.observed[name] = self.hash(name)
        return self.observed[name]

    def json(self, path):
        path = Path(path).absolute()
        expected = self.observe(path)
        try:
            raw = path.read_bytes()
            data = _strict_json(raw)
        except (OSError, ValueError) as exc:
            raise CoverageError(f"cannot read evidence {path}: {exc}") from exc
        if hashlib.sha256(raw).hexdigest() != expected:
            raise CoverageError("evidence changed while reading: " + str(path))
        if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
                or data["schema_version"] != 1):
            raise CoverageError("unsupported evidence schema: " + str(path))
        return data

    def changes(self, records):
        try:
            records = integrity.merge_records(records)
        except ValueError as exc:
            raise CoverageError("malformed input-integrity records: " + str(exc)) from exc
        changed = []
        for item in records:
            actual = self.observe(item["absolute_path"])
            if actual != item["sha256"]:
                changed.append({**item, "actual_sha256": actual})
        return changed

    def finalize(self):
        for filename, expected in self.observed.items():
            if self.hash(filename) != expected:
                raise CoverageError("input changed during coverage generation: " + filename)
        return [{"absolute_path": key, "sha256": value}
                for key, value in sorted(self.observed.items()) if value is not None]


def _verdict(item):
    """Minimal failed rows are legal; contradictory green rows are not."""
    evaluation = item.get("evaluation", {})
    if not isinstance(evaluation, dict):
        raise CoverageError("malformed target evaluation")
    for value in (item, evaluation):
        for field in ("accepted", "verified", "local_policy_passed"):
            if field in value and type(value[field]) is not bool:
                raise CoverageError("non-Boolean target verdict: " + field)
    for field in ("accepted", "status"):
        if field in evaluation and evaluation[field] != item.get(field):
            raise CoverageError("target/evaluation verdicts disagree: " + field)
    accepted = item.get("accepted") is True
    role = item.get("target", {}).get("role")
    if accepted:
        expected = "passed" if role == "proof" else "calibration-passed"
        if (item.get("status") != expected or evaluation.get("status") != expected or
                evaluation.get("accepted") is not True or
                evaluation.get("verified") is not (role == "proof") or
                evaluation.get("local_policy_passed") is not True):
            raise CoverageError("inconsistent accepted/status/verified target fields")
    elif (item.get("status") in ("passed", "calibration-passed") or
          evaluation.get("verified") is True):
        raise CoverageError("unsuccessful target claims a passing status or verification")
    return accepted


def _retained_target(root, item, run, inputs):
    """Check byte-bound artifacts and reparse raw reports against saved rows.

    Legacy raw WP JSON/TSV have no receipt byte digest. Reparsed semantic rows
    must therefore equal the summary exactly; observed byte hashes are retained
    here without misrepresenting them as hashes captured by the original run.
    """
    directory = Path(run["path"]).parent / item["target"]["id"]
    artifacts = []

    def read(path, expected=None, *, binding="recorded-byte-sha256", binary=False):
        path = Path(path).absolute()
        if not path.is_relative_to(Path(run["path"]).parent) or path.is_symlink():
            raise CoverageError("retained artifact escapes run or is a symlink: " + str(path))
        actual = inputs.observe(path)
        if actual is None or (expected is not None and actual != expected):
            raise CoverageError("missing or changed retained artifact: " + str(path))
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != actual:
            raise CoverageError("retained artifact changed during read: " + str(path))
        artifacts.append({"path": str(path), "sha256": actual, "binding": binding})
        return data if binary else data.decode()

    try:
        if _strict_json(read(directory / "result.json", binding="equals-summary-object")) != item:
            raise CoverageError("retained target receipt differs from summary")
        profile = item["target"]["profile"]
        if _strict_json(read(directory.parent / ("profile-" + profile) / "profile.json",
                                  binding="equals-summary-object")) != run["data"]["profiles"][profile]:
            raise CoverageError("retained model receipt differs from summary")
        command = item["analysis_command"]
        if type(command["returncode"]) is not int or command["returncode"] != 0 or command["timed_out"] is not False:
            raise CoverageError("accepted analysis did not complete successfully")
        read(command["log"], command["log_sha256"])
        if suite.warnings_from_log(Path(command["log"])) != item["warnings"]:
            raise CoverageError("raw analyzer warnings differ from summary")
        audit = item["analyzer_audit"]
        raw_audit = _strict_json(read(audit["path"], audit["sha256"]))
        if {key: value for key, value in raw_audit.items() if key != "sources"} != audit["parameters"]:
            raise CoverageError("raw analyzer parameters differ from summary")
        observed_policy = replay.analysis_policy_observation(run["data"]["profiles"][profile],
            item["target"], item, replay.hash_records(run["data"].get("integrity_inputs", [])), root)
        raw_sources = raw_audit.get("sources")
        if (not isinstance(raw_sources, dict) or not raw_sources or
                not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value)
                        for value in raw_sources.values())):
            raise CoverageError("raw analyzer source inventory is malformed")
        cwd = Path(item["input"]["cwd"])
        source_paths = {str((Path(name) if Path(name).is_absolute() else cwd / name).resolve())
                        for name in raw_sources}
        if source_paths != {row["absolute_path"] for row in audit["inputs"]}:
            raise CoverageError("raw analyzer source inventory differs from summary")
        retained = audit["retained_preprocessing"]
        if not retained:
            raise CoverageError("actual preprocessing artifacts are missing")
        paths = {}
        for row in retained:
            path = Path(row["absolute_path"])
            if (not path.is_relative_to(directory / "tmp") or
                    path.relative_to(directory).as_posix() != row["path"] or str(path) in paths):
                raise CoverageError("invalid or duplicate retained preprocessing path")
            read(path, row["sha256"])
            paths[str(path)] = row["sha256"]
        if set(paths) != {str(path) for path in (directory / "tmp").rglob("*") if path.is_file()}:
            raise CoverageError("retained preprocessing inventory differs")
        target = item["target"]
        source_names = [target[field] for field in ("harness", "driver") if target.get(field)]
        if [row["source"] for row in audit["parsed_streams"]] != source_names:
            raise CoverageError("parsed-stream source inventory differs")
        if any(paths.get(row["absolute_path"]) != row["sha256"] or not row["path"].endswith(".pp")
               for row in audit["parsed_streams"]):
            raise CoverageError("parsed streams not bound to retained preprocessing")
        from fragma import common24_calibration, frontend_policy
        observed_frontend = frontend_policy.observation(root, target, run["data"]["profiles"][profile],
            item, replay.hash_records(run["data"].get("integrity_inputs", [])), read=read)
        observed_compiler = common24_calibration.observation(root, target, run["data"]["profiles"][profile],
            item, replay.hash_records(run["data"].get("integrity_inputs", [])), read=read)
        if target["analysis"] == "wp":
            _strict_json(read(directory / "wp.json", binding="reparsed-goals-equal-summary"))
            goals = report.parse_wp_report(directory / "wp.json")
        else:
            goals = []
        read(directory / "properties.tsv", binding="reparsed-properties-equal-summary")
        selected = [*target.get("analysis_functions", target["functions"])]
        if target.get("entry"):
            selected.append(target["entry"])
        properties = report.parse_properties(directory / "properties.tsv",
            source_files=[root / name for name in source_names], source_root=cwd,
            selected_functions=selected, predicate_starts=replay.assertion_predicate_starts(
                {row["absolute_path"]: row["sha256"] for row in run["data"].get("integrity_inputs", [])}, root))
        strip_row = lambda rows: [{key: value for key, value in row.items() if key != "report_row"}
                                  for row in rows]
        if goals != item["goals"] or strip_row(properties) != strip_row(item["properties"]):
            raise CoverageError("raw analyzer outcomes differ from saved rows")
        reevaluated = report.evaluate_target(target, goals, properties,
            returncode=command["returncode"], warnings=item["warnings"],
            validated_review=item.get("validated_review"), validated_native=item.get("validated_native"))
        reevaluated, observed_inventory = replay.common24_observation(root, target, item,
            goals, properties, reevaluated, replay.hash_records(run["data"].get("integrity_inputs", [])))
        if target["role"] == "proof" and any(reevaluated.get(field) != item["evaluation"].get(field)
                for field in ("status", "accepted", "verified", "local_policy_passed")):
            raise CoverageError("accepted proof disagrees with reparsed proof policy")
        return {"status": "passed", "artifacts": artifacts, "analysis_policy": observed_policy,
                **({"frontend_policy": observed_frontend} if observed_frontend is not None else {}),
                **({"common24_inventory": observed_inventory} if observed_inventory is not None else {}),
                **({"compiler_calibration": observed_compiler} if observed_compiler is not None else {}),
                "limitations": ["Raw WP/TSV byte digests were not recorded by the original suite; semantic equality is checked."]}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return {"status": "unavailable-or-mismatched", "error": str(exc), "artifacts": artifacts}


def _model_observation(root, model, registered, revision, inputs, origin, date=None,
                       run_inputs=()):
    identifier = model.get("profile_id")
    binding = []
    current = registered.get(identifier)
    if not current or model.get("profile_sha256") != _digest(current):
        binding.append("profile-definition-mismatch")
    if model.get("kernel_revision") != revision:
        binding.append("revision-mismatch")
    if current and model.get("architecture") != current["architecture"]:
        binding.append("architecture-mismatch")
    if type(model.get("schema_version")) is not int or model.get("schema_version") != 1:
        binding.append("model-schema-mismatch")
    def read_policy(path, expected):
        path = Path(path)
        if path.is_symlink() or inputs.observe(path) != expected:
            raise CoverageError("model analysis-policy audit missing or changed")
        return path.read_text()
    try:
        policy = replay.model_policy_observation(model, read_policy)
        if current and "runtime_checks" in current.get("analysis", {}):
            from fragma.analysis_policy import model_identity
            if (policy.get("status") != "checked" or
                    replay.canonical(policy.get("model")) != replay.canonical(model_identity(current["analysis"]))):
                raise CoverageError("model lacks the currently registered actual analysis policy")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        policy = {"status": "unavailable-or-mismatched", "error": str(exc)}
        binding.append("model-analysis-policy-unavailable-or-mismatched")
    try:
        records = integrity.merge_records(integrity.profile_records(root, model), list(run_inputs))
        stale = inputs.changes(records)
    except (KeyError, TypeError, ValueError):
        records, stale = [], []
        binding.append("model-input-evidence-unavailable")
    declared = model.get("level")
    checks = model.get("checks", [])
    eligible = (model.get("status") == "passed" and declared in ("L0", "L1")
                and bool(checks) and all(row.get("status") == "passed" for row in checks)
                and not binding and not stale)
    return {"origin": origin, "completed_at": date, "profile_id": identifier,
            "reported_status": model.get("status"), "reported_level": declared,
            "current_model_level": declared if eligible else None,
            "identity_issues": binding, "stale_inputs": stale,
            "analysis_policy": policy,
            "fingerprint": model.get("fingerprint"),
            "scope": current.get("model_scope") if current else None,
            "runtime_reported": model.get("runtime", {}).get("status"),
            "architecture_promotion": None}


def _target_observation(root, revision, target, item, run, registered, inputs, manifests):
    identifier = target["id"]
    model = run["data"].get("profiles", {}).get(target["profile"], {})
    evaluation = item.get("evaluation", {})
    reported = _verdict(item)
    proof = reported and target.get("role") == "proof" and evaluation.get("verified") is True
    binding = []
    if run["data"].get("revision") != revision:
        binding.append("revision-mismatch")
    if item.get("target") != target:
        binding.append("target-definition-mismatch")
    current_profile = registered[target["profile"]]
    if (model.get("profile_id") != target["profile"] or
            model.get("profile_sha256") != _digest(current_profile) or
            model.get("kernel_revision") != revision):
        binding.append("profile-identity-unavailable-or-mismatched")
    source = item.get("provenance", {}).get("source", {})
    provenance = item.get("provenance", {})
    if (provenance.get("passed") is not True or source.get("revision") != revision or
            source.get("path") != target["source"] or source.get("kind") != "git-blob" or
            not HASH.fullmatch(str(source.get("sha256", "")))):
        binding.append("source-identity-unavailable-or-mismatched")
    shared = run["data"].get("integrity_inputs", [])
    local = item.get("integrity_inputs", [])
    try:
        records = integrity.merge_records(shared, local)
        by_path = {row["absolute_path"]: row["sha256"] for row in records}
        stale = inputs.changes(records)
    except (TypeError, ValueError) as exc:
        records, by_path, stale = [], {}, []
        binding.append("invalid-integrity-records: " + str(exc))
    if not shared or not local:
        binding.append("input-integrity-evidence-unavailable")
    for path in manifests:
        if str(path) not in by_path:
            binding.append("manifest-binding-missing: " + str(path.relative_to(root)))
    for field in ("harness", "specs", "driver", "kernel_model_check", "wp_strategy_file"):
        if target.get(field) and str(root / target[field]) not in by_path:
            binding.append("declared-input-binding-missing: " + field)
    # A translation-unit copy need not consume the original source blob. Verify
    # its pinned provenance checksum against the configured snapshot separately,
    # without relabeling that original file as an analyzer-consumed input.
    source_content = {"status": "unavailable", "expected_sha256": source.get("sha256")}
    source_root = model.get("build", {}).get("source")
    if isinstance(source_root, str) and Path(source_root).is_absolute():
        source_path = Path(source_root) / target["source"]
        if source_path.is_relative_to(Path(source_root)):
            actual = inputs.observe(source_path)
            source_content.update(path=str(source_path), actual_sha256=actual,
                status="passed" if actual is not None and actual == source.get("sha256") else "mismatched")
    else:
        matching = [(name, expected) for name, expected in by_path.items()
                    if name.endswith("/" + target["source"]) and expected == source.get("sha256")]
        if len(matching) == 1:
            source_path, expected = matching[0]
            actual = inputs.observe(source_path)
            source_content.update(path=source_path, actual_sha256=actual,
                status="passed" if actual is not None and actual == expected else "mismatched")
    if source_content["status"] != "passed":
        binding.append("pinned-source-content-unavailable-or-mismatched")
    if not model or model.get("status") != "passed" or model.get("level") != "L1":
        binding.append("configured-L1-evidence-unavailable")
    if reported:
        model_check = _model_observation(root, model, registered, revision, inputs, run["path"])
        if model_check["current_model_level"] != "L1":
            binding.append("configured-model-input-evidence-unavailable-or-stale")
        artifacts = _retained_target(root, item, run, inputs)
        if artifacts["status"] != "passed":
            binding.append("retained-evidence-unavailable-or-mismatched")
        if artifacts.get("analysis_policy", {}).get("status") != "checked":
            binding.append("current-analysis-policy-unavailable-or-legacy")
    else:
        artifacts = {"status": "not-required-for-unsuccessful-observation", "artifacts": []}
    # A failed or partial item stays visible; successful-only evidence is never
    # required merely to list it. Missing evidence only blocks a green claim.
    freshness = "stale" if stale else "unbound" if binding else "current"
    if run["undated"]:
        binding.append("undated-failure-order-unknown")
        freshness = "unbound"
    status = item.get("status", "not-produced")
    current = reported and freshness == "current"
    goals = item.get("goals", [])
    properties = item.get("properties", [])
    return {"summary": run["path"], "summary_sha256": run["sha256"],
            "completed_at": run["data"].get("completed_at"),
            "reported_status": status, "reported_accepted": reported,
            "reported_verified": proof, "current_accepted": current,
            "current_verified": proof and current, "freshness": freshness,
            "identity_issues": binding, "stale_inputs": stale,
            "retained_evidence": artifacts,
            "target_sha256": _digest(item.get("target")),
            "source_identity": source, "profile_fingerprint": model.get("fingerprint"),
            "source_content_check": source_content,
            "recorded_kernel_functions": item.get("target", {}).get("functions", []),
            "issues": evaluation.get("issues", []), "error": item.get("error"),
            "assumptions": [{key: row.get(key) for key in
                            ("id", "kind", "review_status", "implementation_proved", "scope")}
                            for row in item.get("assumptions", [])],
            "unresolved_dependencies": evaluation.get("unresolved_dependencies", []),
            "counts": evaluation.get("counts", {}),
            "function_evidence": {name: {
                "ordinary_goals": sum(row.get("function") == name and not row.get("smoke")
                                      for row in goals),
                "properties": sum(row.get("function") == name for row in properties)}
                for name in [*target["functions"], *target.get("project_functions", [])]},
            "preconditions": {name: [{key: row.get(key) for key in
                              ("path", "line", "property", "status")}
                             for row in properties if row.get("function") == name
                             and row.get("kind") == "precondition"]
                              for name in [*target["functions"], *target.get("project_functions", [])]}}


def generate_matrix(root: Path, summary_paths: list[Path], *,
                    profile_paths: list[Path] = (), checked_at: str | None = None) -> dict:
    """Inventory current registrations using only explicitly supplied receipts.

    Historical acceptance is a report of the supplied trusted local runner, not
    an independent proof replay or a cryptographic attestation. Every changed
    recorded input blocks *current* coverage; historical results remain dated.
    """
    root = Path(root).resolve()
    checked = _date(checked_at) if checked_at else datetime.now(timezone.utc)
    inputs = _Inputs()
    manifests = sorted({*root.glob("config/*.json"), root / "toolchain/assumptions.json",
                        root / "toolchain/lock.json"})
    manifest_records = [{"path": str(path.relative_to(root)), "sha256": inputs.observe(path)}
                        for path in manifests]
    for path in manifests:
        inputs.json(path)  # reject duplicate keys/nonfinite values before registry merging
    revision, targets, _ = suite.load_registry(root)
    registered = profiles.load_profiles(root)
    roster = inputs.json(root / "config/architectures.json")
    if roster.get("kernel_revision") != revision:
        raise CoverageError("architecture roster and target revisions disagree")
    runs, observed_paths = [], set()
    for path in summary_paths:
        path = Path(path).absolute()
        if str(path) in observed_paths:
            raise CoverageError("duplicate supplied summary: " + str(path))
        observed_paths.add(str(path))
        data = inputs.json(path)
        if data.get("status") not in TERMINAL:
            raise CoverageError("supplied summary is not terminal: " + str(path))
        undated = data.get("completed_at") is None
        if undated and data.get("status") not in ("preflight-failed", "error", "cancelled"):
            raise CoverageError("completed summary has no completion date: " + str(path))
        completed = None if undated else _date(data["completed_at"])
        if completed and completed > checked:
            raise CoverageError("supplied evidence completes after coverage check time")
        if completed and _date(data.get("started_at")) > completed:
            raise CoverageError("summary completion precedes start")
        selected = data.get("selected_targets")
        items = data.get("targets")
        if (not isinstance(selected, list) or not selected or
                not all(isinstance(name, str) for name in selected) or
                len(set(selected)) != len(selected) or not isinstance(items, list)):
            raise CoverageError("malformed selected-target inventory: " + str(path))
        mapped = {}
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("target"), dict):
                raise CoverageError("malformed target result: " + str(path))
            name = item["target"].get("id")
            if name not in selected or name in mapped:
                raise CoverageError("duplicate or unselected target result: " + str(path))
            mapped[name] = item
            _verdict(item)
        if type(data.get("accepted")) is not bool:
            raise CoverageError("summary acceptance must be Boolean")
        if data["accepted"] and (data["status"] != "passed" or set(mapped) != set(selected)
                                  or not all(row.get("accepted") is True for row in mapped.values())):
            raise CoverageError("summary acceptance disagrees with target inventory")
        if data["status"] == "passed" and data["accepted"] is not True:
            raise CoverageError("passing summary is not accepted")
        if (data["status"] == "incomplete" and set(mapped) == set(selected)
                and all(row.get("accepted") is True for row in mapped.values())):
            raise CoverageError("incomplete summary contains only accepted targets")
        runs.append({"path": str(path), "sha256": inputs.observe(path), "data": data,
                     "items": mapped, "time": completed, "undated": undated})
    profile_rows = {name: {"id": name, "architecture": item["architecture"],
        "registration_status": item.get("status"), "abi": item["abi"],
        "profile_sha256": _digest(item), "model_evidence": [], "targets": [],
        "architecture_level": "not-assessed", "scope": item.get("model_scope")}
        for name, item in registered.items()}
    for run in runs:
        for name, model in run["data"].get("profiles", {}).items():
            if name in profile_rows:
                profile_rows[name]["model_evidence"].append(_model_observation(
                    root, model, registered, revision, inputs, run["path"],
                    run["data"].get("completed_at"), run["data"].get("integrity_inputs", [])))
    for path in profile_paths:
        path = Path(path).absolute()
        model = inputs.json(path)
        name = model.get("profile_id")
        if name not in profile_rows:
            raise CoverageError("standalone profile is not currently registered: " + str(name))
        profile_rows[name]["model_evidence"].append(_model_observation(
            root, model, registered, revision, inputs,
            {"path": str(path), "sha256": inputs.observe(path)}))
    for name, row in profile_rows.items():
        dated = [model for model in row["model_evidence"] if model["completed_at"]]
        dated.sort(key=lambda model: _date(model["completed_at"]))
        row["latest_dated_model"] = dated[-1] if dated else None
        row["undated_model_observations"] = [model for model in row["model_evidence"]
                                             if not model["completed_at"]]
        if len(dated) > 1 and _date(dated[-1]["completed_at"]) == _date(dated[-2]["completed_at"]):
            row["latest_dated_model"] = {"reported_status": "ambiguous-latest",
                "current_model_level": None, "completed_at": dated[-1]["completed_at"]}
        row["current_dated_model_level"] = (row["latest_dated_model"] or {}).get("current_model_level")
        row["undated_selected_runs"] = [run["path"] for run in runs if run["undated"]
            and any(targets.get(identifier, {}).get("profile") == name
                    for identifier in run["data"]["selected_targets"])]
        if row["undated_selected_runs"]:
            row["current_dated_model_level"] = None
    target_rows, function_rows = [], []
    for name, target in sorted(targets.items()):
        source = Path(target["source"])
        if source.is_absolute() or ".." in source.parts or not source.parts:
            raise CoverageError("target source must be a confined relative kernel path")
        history = []
        relevant = [run for run in runs if name in run["data"]["selected_targets"]]
        # An undated supplied terminal failure cannot be placed before a dated
        # success. Conservatively let it block current acceptance.
        relevant.sort(key=lambda run: (run["undated"], run["time"] or checked, run["path"]))
        for run in relevant:
            item = run["items"].get(name, {"target": target, "status": "not-produced",
                "accepted": False, "error": "selected target has no result in supplied terminal run"})
            history.append(_target_observation(root, revision, target, item, run,
                                               registered, inputs, manifests))
        latest = history[-1] if history else None
        ambiguous = bool(len(relevant) > 1 and
            relevant[-1]["undated"] == relevant[-2]["undated"] and
            relevant[-1]["time"] == relevant[-2]["time"])
        if ambiguous:
            latest = {**latest, "current_accepted": False, "current_verified": False,
                      "freshness": "ambiguous", "reported_status": "ambiguous-latest",
                      "identity_issues": [*latest["identity_issues"], "equal-time-observations"]}
        state = ("ambiguous-latest" if ambiguous else "not-run" if latest is None else
                 "accepted-current" if latest["current_accepted"] else
                 "accepted-" + latest["freshness"] if latest["reported_accepted"] else latest["reported_status"])
        row = {"id": name, "profile": target["profile"],
            "architecture": registered[target["profile"]]["architecture"],
            "source": target["source"], "harness": target["harness"],
            "role": target["role"], "analysis": target["analysis"],
            "target_sha256": _digest(target), "claims": target.get("claims", []),
            "caller_coverage_declared": target.get("caller_coverage", "unverified"),
            "state": state, "latest": latest, "history": history}
        target_rows.append(row)
        profile_rows[target["profile"]]["targets"].append(name)
        project = set(target.get("project_functions", []))
        for function in dict.fromkeys([*target["functions"], *target.get("project_functions", [])]):
            kind = ("calibration" if target["role"] != "proof" else
                    "project-witness" if function in project else "kernel")
            dimensions = {}
            for dimension in DIMENSIONS:
                if kind == "calibration":
                    value = "not-applicable"
                elif dimension == "caller-preconditions":
                    value = "unverified"  # no caller-closure evidence schema exists yet
                elif dimension not in target.get("claims", []):
                    value = "not-claimed"
                elif latest and latest["current_verified"]:
                    value = "accepted-current"
                elif (latest and latest["reported_verified"] and not ambiguous and
                      function in latest["recorded_kernel_functions"] and
                      latest["source_identity"].get("path") == target["source"]):
                    value = "accepted-historical-" + latest["freshness"]
                else:
                    value = "not-run" if latest is None else "unresolved"
                dimensions[dimension] = value
            function_rows.append({"target": name, "profile": target["profile"],
                "architecture": row["architecture"], "revision": revision,
                "source": target["source"], "function": function, "kind": kind,
                "dimensions": dimensions, "claims": target.get("claims", []),
                "caller_coverage_declared": row["caller_coverage_declared"],
                "preconditions": latest["preconditions"].get(function, []) if latest else [],
                "domain": "This target variant's explicit contract preconditions only; not all kernel callers.",
                "current_verified": bool(kind == "kernel" and latest and latest["current_verified"]),
                "latest_reported_verified": bool(kind == "kernel" and latest and not ambiguous and latest["reported_verified"]
                    and function in latest["recorded_kernel_functions"]
                    and latest["source_identity"].get("path") == target["source"]),
                "completed_at": latest["completed_at"] if latest else None,
                "evidence": latest["function_evidence"].get(function, {}) if latest else {}})
    architectures = []
    for architecture in roster["architectures"]:
        matching = [name for name, row in profile_rows.items()
                    if row["architecture"] == architecture["id"]]
        architectures.append({**architecture, "registered_profiles": sorted(matching),
            "state": "registered" if matching else "planned",
            "architecture_level": "not-assessed"})
    kernel_rows = [row for row in function_rows if row["kind"] == "kernel"]
    key = lambda row: (revision, row["source"], row["function"])
    inventory = {key(row) for row in kernel_rows}
    accepted = {key(row) for row in kernel_rows if row["current_verified"]}
    historical = {key(row) for row in kernel_rows if row["latest_reported_verified"]}
    result = {"schema_version": 1, "checked_at": checked.isoformat(),
        "registry": {"revision": revision, "manifests": manifest_records},
        "policy": {"latest": "Latest explicit completed target observation, regardless of success; undated failure blocks current green.",
            "freshness": "Every recorded run/target input hash must match, with exact target/profile/source/revision binding.",
            "counts": "Unique (revision, source path, kernel function); calibration and project witnesses excluded. One accepted variant is not full-API coverage.",
            "trust": "Summarizes trusted local runner receipts; not independent proof replay or tamper-resistant attestation.",
            "levels": "No architecture L2/L3 inference from proof subsets, profile calibration, or installed runtimes."},
        "supplied_runs": [{"path": run["path"], "sha256": run["sha256"],
            "status": run["data"]["status"], "started_at": run["data"].get("started_at"),
            "completed_at": run["data"].get("completed_at"),
            "unregistered_targets": sorted(set(run["data"]["selected_targets"]) - targets.keys())}
            for run in runs],
        "architectures": architectures, "profiles": list(profile_rows.values()),
        "targets": target_rows, "functions": function_rows,
        "counts": {"architectures": len(architectures), "registered_profiles": len(registered),
            "registered_targets": len(targets), "target_states": dict(Counter(row["state"] for row in target_rows)),
            "unique_kernel_functions": len(inventory),
            "unique_kernel_functions_with_current_accepted_variant": len(accepted),
            "unique_kernel_functions_with_latest_reported_accepted_variant": len(historical),
            "latest_reported_accepted_targets": sum(bool(row["latest"] and row["state"] != "ambiguous-latest"
                                                         and row["latest"]["reported_accepted"])
                                                    for row in target_rows),
            "unique_kernel_functions_without_current_accepted_variant": len(inventory - accepted),
            "calibration_rows_excluded": sum(row["kind"] == "calibration" for row in function_rows),
            "project_witness_rows_excluded": sum(row["kind"] == "project-witness" for row in function_rows)}}
    result["generation_inputs"] = inputs.finalize()
    return result


def render_markdown(matrix: dict) -> str:
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ")

    counts = matrix["counts"]
    lines = ["# Coverage matrix", "", f"Checked: {matrix['checked_at']}", "",
        f"Revision: `{matrix['registry']['revision']}`", "",
        f"{counts['unique_kernel_functions_with_current_accepted_variant']} of "
        f"{counts['unique_kernel_functions']} distinct kernel functions have at least one current accepted contract variant. "
        "This is not full-API or caller coverage. Calibration and project witnesses are excluded.", "",
        "## Architecture and profile inventory", "",
        "| Architecture | Registered profiles | State | Architecture level |",
        "| --- | --- | --- | --- |"]
    for row in matrix["architectures"]:
        lines.append("| " + " | ".join(map(cell, [row["id"], ", ".join(row["registered_profiles"]) or "none",
                     row["state"], row["architecture_level"]])) + " |")
    lines += ["", "## Configured model observations", "",
              "| Profile | Registration | Latest dated model | Current dated model level | Undated observations |",
              "| --- | --- | --- | --- | --- |"]
    for row in matrix["profiles"]:
        latest = row["latest_dated_model"] or {}
        description = (f"{latest.get('reported_status')} / {latest.get('reported_level', 'unknown')} / "
                       f"{latest.get('completed_at')}" if latest else "not supplied")
        lines.append("| " + " | ".join(map(cell, [row["id"], row["registration_status"], description,
                     row["current_dated_model_level"] or "none", len(row["undated_model_observations"])])) + " |")
    lines += ["", "## Target outcomes", "",
              "| Target | Profile | Role | Latest outcome | Completed | Freshness |",
              "| --- | --- | --- | --- | --- | --- |"]
    for row in matrix["targets"]:
        latest = row["latest"] or {}
        lines.append("| " + " | ".join(map(cell, [row["id"], row["profile"], row["role"],
                     row["state"], latest.get("completed_at") or "not dated/run",
                     latest.get("freshness", "not-run")])) + " |")
    lines += ["", "## Contract-variant property coverage", "",
              "| Target / function | Kind | Runtime safety | Functional | Termination | Caller preconditions |",
              "| --- | --- | --- | --- | --- | --- |"]
    for row in matrix["functions"]:
        lines.append("| " + " | ".join(map(cell, [row["target"] + " / " + row["function"], row["kind"],
                     *(row["dimensions"][name] for name in DIMENSIONS)])) + " |")
    lines += ["", "All property claims remain conditional on each target's declared input domain and trusted assumptions. "
              "Output NUL termination is not function termination. Detailed identity failures, changed inputs, "
              "dated historical observations, unresolved dependencies, and explicit source receipts are retained in JSON.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--summary", type=Path, action="append", default=[])
    parser.add_argument("--profile", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    matrix = generate_matrix(args.root, args.summary, profile_paths=args.profile)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "coverage.json").write_text(json.dumps(matrix, indent=2) + "\n")
    (args.output / "coverage.md").write_text(render_markdown(matrix))
    print(json.dumps(matrix["counts"], indent=2))
