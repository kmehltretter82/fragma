"""Hash-bound review approvals and final input-drift checks.

Reviews are scoped evidence, not a mechanism to rewrite analyzer outcomes.
No approval survives a changed source, specification, build, or analysis model.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re

from . import analysis_policy, frontend_policy
from .sources import SourceError, sha256


def _same_json(left: object, right: object) -> bool:
    """Compare review identities without treating JSON booleans as integers."""
    try:
        return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
            right, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return False


def receipt(path: Path, expected: str | None = None) -> dict:
    # Preserve a symlink's invocation path as well as any separately recorded
    # resolved path: retargeting the command must be caught by the final check.
    return {"absolute_path": str(path.absolute()), "sha256": expected or sha256(path)}


def merge_records(*groups: list[dict]) -> list[dict]:
    records = {}
    for group in groups:
        for item in group:
            filename, expected = item.get("absolute_path"), item.get("sha256")
            if not isinstance(filename, str) or not Path(filename).is_absolute() or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise SourceError("malformed input-integrity record")
            filename = str(Path(filename).absolute())
            if filename in records and records[filename]["sha256"] != expected:
                raise SourceError(f"conflicting observations of input: {filename}")
            records[filename] = {"absolute_path": filename, "sha256": expected}
    return [records[name] for name in sorted(records)]


def metadata_records(value: object) -> list[dict]:
    """Collect explicit absolute path/SHA-256 pairs from tool/model receipts."""
    result = []
    if isinstance(value, dict):
        filename = value.get("absolute_path", value.get("path", value.get("resolved_path")))
        expected = value.get("sha256")
        if isinstance(filename, str) and Path(filename).is_absolute() and isinstance(expected, str):
            result.append({"absolute_path": filename, "sha256": expected})
        directory = value.get("directory")
        if isinstance(directory, str) and Path(directory).is_absolute() and isinstance(value.get("files"), dict):
            result.extend(receipt(Path(directory) / name, checksum)
                          for name, checksum in value["files"].items())
        for key, item in value.items():
            if isinstance(key, str) and Path(key).is_absolute() and isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item):
                result.append({"absolute_path": key, "sha256": item})
            result.extend(metadata_records(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(metadata_records(item))
    return result


def profile_records(root: Path, model: dict) -> list[dict]:
    records = metadata_records(model)
    records.append(receipt(root / "profiles/calibration.c", model["fixture_sha256"]))
    generator = model["generator"]
    records.extend(receipt(Path(generator["path"]).parent / name, expected)
                   for name, expected in generator.get("probe_input_hashes", {}).items())
    return merge_records(records)


def changed_files(records: list[dict]) -> list[dict]:
    result = []
    for item in merge_records(records):
        path = Path(item["absolute_path"])
        actual = sha256(path) if path.is_file() else None
        if actual != item["sha256"]:
            result.append({**item, "actual_sha256": actual})
    return result


def validate_review(root: Path, target: dict, revision: str, model: dict,
                    build: dict, tools: dict, prepared: dict) -> dict | None:
    if not target.get("reviewed_smoke") and not target.get("reviewed_warnings"):
        return None
    context = target.get("review_context")
    if not isinstance(context, dict):
        raise SourceError("scoped reviews require a review context")
    if context.get("kernel_revision") != revision or context.get("profile") != target["profile"]:
        raise SourceError("review context source revision/profile mismatch")
    if context.get("toolchain_lock_sha256") != tools["lock_sha256"]:
        raise SourceError("review context toolchain lock mismatch")
    try:
        analysis = analysis_policy.model_identity(model["analysis"])
        pipeline = analysis_policy.pipeline_identity(target)
    except analysis_policy.AnalysisPolicyError as exc:
        raise SourceError(f"unsupported arithmetic/memory/runtime analysis policy: {exc}") from exc
    if not _same_json(context.get("analysis"), analysis):
        raise SourceError("review context arithmetic/memory/runtime model mismatch")
    if not _same_json(context.get("analysis_pipeline"), pipeline):
        raise SourceError("review context analysis pipeline mismatch")
    preprocessing = {"cpp_command": prepared["frama_cpp_command"],
                     "annotations": prepared["annotations"],
                     "input_mode": target["input_mode"], "extra_args": ["-std=gnu11"]}
    frontend = frontend_policy.identity(target)
    if frontend is not None:
        preprocessing["frontend_policy"] = frontend
    if not _same_json(context.get("preprocessing"), preprocessing):
        raise SourceError("review context preprocessing policy mismatch")
    from fragma import common24_calibration
    compiler_review = common24_calibration.review_identity(target)
    if not _same_json(context.get("compiler_calibration"), compiler_review):
        raise SourceError("review context compiler-calibration policy mismatch")
    search = {key: target[key] for key in ("wp_strategy", "wp_strategy_file", "wp_strategy_provers",
                                         "wp_auto_depth", "wp_smoke_timeout") if key in target}
    if not _same_json(context.get("proof_search", {}), search):
        raise SourceError("review context proof-search policy mismatch")
    hashes = context.get("file_hashes")
    if not isinstance(hashes, dict) or not hashes:
        raise SourceError("review context must bind its input hashes")
    required = [target[field] for field in ("harness", "specs", "driver", "kernel_model_check", "wp_strategy_file")
                if target.get(field)]
    required.append("fragma/analysis_policy.py")
    required += frontend_policy.required_files(target)
    required += common24_calibration.required_files(target)
    if frontend is not None:
        required.append("fragma/common24.py")
    required += [str((Path(build["source"]) / target["source"]).relative_to(root)),
                 str((Path(build["path"]) / "fragma-build.json").relative_to(root))]
    if not set(required) <= hashes.keys():
        raise SourceError("review context omits harness/specification/source/build identity")
    machines = [expected for filename, expected in hashes.items() if filename.endswith(".yaml")]
    if len(machines) != 1 or machines[0] != model["machdep"]["sha256"]:
        raise SourceError("review context does not match the fresh machine description")
    records = []

    def local_path(filename):
        if not isinstance(filename, str) or Path(filename).is_absolute():
            raise SourceError("review paths must be relative project files")
        path = (root / filename).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise SourceError(f"missing or out-of-project review input: {filename}")
        return path

    for section in [context, *target.get("reviewed_smoke", []), *target.get("reviewed_warnings", [])]:
        if not isinstance(section, dict) or not isinstance(section.get("file_hashes"), dict) or not section["file_hashes"]:
            raise SourceError("every review must bind explicit file hashes")
        for filename, expected in section["file_hashes"].items():
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise SourceError("invalid reviewed input digest")
            records.append(receipt(local_path(filename), expected))
        evidence = section.get("review_evidence")
        if not isinstance(evidence, list) or not evidence:
            raise SourceError("every review must identify inspectable evidence")
        records.extend(receipt(local_path(filename)) for filename in evidence)
    records = merge_records(records)
    changes = changed_files(records)
    if changes:
        raise SourceError("reviewed inputs changed: " + ", ".join(item["absolute_path"] for item in changes))
    return {"status": "passed", "target_id": target["id"], "profile": target["profile"],
            "analysis": target["analysis"], "source_root": str(root),
            "review_context": copy.deepcopy(context),
            "reviewed_smoke": copy.deepcopy(target.get("reviewed_smoke", [])),
            "reviewed_warnings": copy.deepcopy(target.get("reviewed_warnings", [])),
            "tracked_files": records}


def invalidate(evidence: dict, changes: list[dict]) -> None:
    if not changes:
        return
    evidence.update(status="input-changed", accepted=False, changed_inputs=changes)
    evaluation = evidence["evaluation"]
    evaluation.update(status="input-changed", accepted=False, verified=False, local_policy_passed=False)
    evaluation.setdefault("issues", []).append({"kind": "input-changed",
        "message": "A required input changed during the run", "files": changes})
