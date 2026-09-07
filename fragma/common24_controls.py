"""Two compile-only controls for the unchanged common24 genuine-header fixture.

The caller must freshly authenticate the positive gate's raw command, source,
ELF and dependencies before both run() and validate(). Its raw-gate digest is
bound here, not independently reconstructed from an unavailable raw receipt.
This module rechecks the supplied observation and all its files. It imports no
calibration provider and grants no proof, runtime or architecture acceptance.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re

from . import analysis_policy, elf, frontend_policy, inputs, integrity, replay, sources


class ControlsError(ValueError):
    pass


KIND = "fragma-common24-genuine-fixture-controls"
RECORDED = "compiler-controls-recorded"
CHECKED = "compiler-controls-checked"
NAMES = ("wrong-type", "wrong-inline")
FIXTURE_SHA256 = "860b5d09ec735ea48f67e8480d40af8bfd00db494cb01b247ac2eb33dbf49a9d"
HEADER_SHA256 = "12c7cbf03ddb8d3cebbbb09aee714c761c75b80c0724fcb72c57210c07ef9041"
DIAGNOSTICS = {
    "wrong-type": ((20, "common24 exact u32 type"), (28, "common24 exact BE24 read signature"),
                   (30, "common24 exact LE24 read signature"), (32, "common24 exact BE24 write signature"),
                   (34, "common24 exact LE24 write signature")),
    "wrong-inline": ((39, "common24 exact effective inline expansion"),),
}
CLANG_NOTES = {
    "wrong-type": (),
    "wrong-inline": ((40, 61, "expression evaluates to '-1 == 0'"),),
}
BOUNDARY = {"observation": "two-genuine-compiler-static-assertion-rejections",
            "positive_gate_authenticated_by_caller": True,
            "negative_dependencies": "unchanged-source closure from authenticated positive fixture",
            "native_executed": False, "analyzer_executed": False,
            "runtime_reachability": False, "full_domain_proof": False,
            "architecture_level_awarded": None}


def require(condition, message):
    if not condition:
        raise ControlsError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def same(left, right):
    return canonical(left) == canonical(right)


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "missing/non-regular/symlinked artifact: " + str(path))
    return path


def record(path):
    path = regular(Path(path).absolute())
    return {"absolute_path": str(path), "sha256": sources.sha256(path)}


def compiler_environment(output):
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(Path(output).resolve())}


def _timeout(timeout):
    require(type(timeout) is int and 1 <= timeout <= 600, "compiler timeout must be an integer from 1 to 600")


def _namespace(root, output):
    output = Path(output).absolute()
    require(output == output.resolve() and output.is_relative_to(root) and
            output.name == "compiler-controls" and output.parent.is_dir() and not output.is_symlink(),
            "controls require the explicit non-symlinked compiler-controls directory")
    return output


def _check_records(records):
    rows = integrity.merge_records(records)
    # Input invocation paths may legitimately be compiler symlinks. Check that
    # each resolves to a regular file before hashing; artifacts are stricter.
    require(all(Path(row["absolute_path"]).is_file() for row in rows), "missing/non-regular bound input")
    require(not integrity.changed_files(rows), "bound input changed")
    return rows


def context(root, kernel, target, model, build, binding, gate, output):
    """Recheck a caller-authenticated context/positive gate without importing it."""
    root, kernel = Path(root).resolve(), Path(kernel).resolve()
    output = _namespace(root, output)
    policy = frontend_policy.identity(target, root=root)
    require(policy is not None and target.get("functions") == list(frontend_policy.FUNCTIONS),
            "controls require exactly the selected common24 helpers")
    require(type(binding.get("schema_version")) is int and binding["schema_version"] == 1 and
            binding.get("target_sha256") == digest(target) and binding.get("model_sha256") == digest(model) and
            same(binding.get("frontend_target"), target), "caller context target/model identity differs")
    revision = binding.get("revision")
    require(model.get("status") == "passed" and model.get("level") == "L1" and
            model.get("kernel_revision") == revision == build.get("revision") and
            target.get("profile") == model.get("profile_id") == build.get("profile_id") == binding.get("profile"),
            "caller model/build/profile differs")
    analysis_policy.model_identity(model["analysis"])
    require(same(inputs.load_build(root, target["profile"], revision), build), "genuine build changed")
    entry = inputs.compile_entry(build, "lib/string.c")
    base = inputs.command_without_outputs(entry)
    require(entry in model["build"]["matched_commands"] and base[0] == model["compiler"]["path"] and
            Path(base[0]).is_file() and sources.sha256(Path(base[0])) == model["compiler"]["sha256"],
            "compiler identity or genuine entry differs")
    require(same(binding.get("base_argv"), base) and binding.get("cwd") == str(Path(build["path"]).resolve()),
            "caller base command differs")
    require(not any("FRAGMA_COMMON24" in arg for arg in base), "genuine base already overrides fixture controls")
    selector = frontend_policy.cpp_arguments(target)
    require(same(binding.get("frontend_options"), selector), "caller inline selector differs")
    fixture, header = root / frontend_policy.FIXTURE, root / frontend_policy.HEADER
    require(binding.get("fixture") == str(fixture) and record(fixture)["sha256"] == FIXTURE_SHA256 and
            record(header)["sha256"] == HEADER_SHA256, "fixed genuine fixture or inline header changed")
    require(isinstance(gate, dict) and set(gate) == {"record_sha256", "artifacts", "inputs", "fixture", "object_identity"}
            and isinstance(gate["record_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", gate["record_sha256"]),
            "missing caller-authenticated positive gate observation")
    positive = output.parent
    log, dep, obj = (positive / name for name in ("kernel-model.log", "model-headers.d", "kernel-model.o"))
    # Reject special files before any read, including hashing a diagnostics log.
    for path in (log, dep, obj):
        regular(path)
    require(log.read_bytes() == b"", "positive fixture has unexpected diagnostics")
    artifacts = [record(path) for path in (log, dep, obj)]
    paths = inputs.dependency_paths(dep, Path(build["path"]))
    required = {fixture.resolve(), header.resolve(),
                *(Path(build["source"]) / "include/linux" / name for name in
                  ("types.h", "unaligned.h", "compiler_types.h"))}
    require(required <= set(paths), "positive fixture omits required source/header dependencies")
    consumed = inputs.input_receipts(root, kernel, revision, build, paths)
    reconstructed = {"record_sha256": gate["record_sha256"], "artifacts": artifacts,
        "inputs": consumed, "fixture": record(fixture),
        "object_identity": frontend_policy.fixture_object(obj.read_bytes(), target, model)}
    require(same(gate, reconstructed), "positive gate observation or current artifacts differ")
    require(isinstance(binding.get("tracked_inputs"), list) and binding["tracked_inputs"],
            "caller context omits its authenticated input inventory")
    tracked = integrity.merge_records(binding["tracked_inputs"], integrity.metadata_records(gate),
        [record(path) for path in (fixture, header, Path(__file__), Path(frontend_policy.__file__),
            Path(analysis_policy.__file__), Path(elf.__file__), Path(inputs.__file__), Path(integrity.__file__),
            Path(replay.__file__), Path(sources.__file__))],
        [record(root / name) for name in frontend_policy.required_files(target)])
    tracked = _check_records(tracked)
    return {"schema_version": 1, "target_sha256": digest(target), "model_sha256": digest(model),
        "build_sha256": digest(build), "binding_sha256": digest(binding), "positive_gate": reconstructed,
        "base_argv": base, "cwd": binding["cwd"], "fixture": str(fixture), "selector": selector,
        "tracked_inputs": tracked}


def command_plan(context, target, output):
    output = Path(output).resolve()
    selector = frontend_policy.cpp_arguments(target)
    require(same(context["selector"], selector) and len(selector) == 1, "exact sole selector required")
    variant = frontend_policy.identity(target)["variant"]
    value = frontend_policy.VARIANTS[variant][0]
    require(value in (1, 2), "unreviewed inline variant")
    opposite = "-D" + frontend_policy.MACRO + "=" + str(3 - value)
    tail = ["-Werror", "-c", context["fixture"]]
    return [
        {"name": "wrong-type", "argv": [*context["base_argv"], *selector,
            "-DFRAGMA_COMMON24_EXPECT_U32=unsigned long", *tail, "-o", str(output / "wrong-type.o")]},
        {"name": "wrong-inline", "argv": [*context["base_argv"], opposite, *tail,
            "-o", str(output / "wrong-inline.o")]},
    ]


def validate_diagnostics(name, fixture, command, stderr, stdout, object_exists,
                         *, compiler_family="gcc"):
    """Require the exact five/one GCC or Clang static-assert diagnostics."""
    require(name in NAMES and type(command.get("returncode")) is int and command["returncode"] == 1 and
            command.get("timed_out") is False and object_exists is False and stdout == "",
            "control process/stdout/object outcome differs")
    require(compiler_family in {"gcc", "clang"}, "unknown compiler diagnostic family")
    require(isinstance(stderr, str) and not any(char in stderr for char in ("\x1b", "\x00", "\r")),
            "unsupported diagnostic encoding")
    observed, summaries = [], []
    lines = stderr.splitlines()
    for index, line in enumerate(lines):
        diagnostic = re.fullmatch(
            r"(.+):(\d+):(\d+): (fatal error|error|warning|note): (.*)", line)
        if diagnostic:
            observed.append((diagnostic[1], int(diagnostic[2]), int(diagnostic[3]), diagnostic[4], diagnostic[5]))
        elif compiler_family == "clang" and (summary := re.fullmatch(r"(\d+) errors? generated\.", line)):
            summaries.append((index, int(summary[1])))
        else:
            require(not re.search(r"\b(?:fatal error|error|warning):", line, re.I), "additional compiler diagnostic")
            require(line == "" or re.fullmatch(r"\s*\d+\s*\|.*", line) or re.fullmatch(r"\s*\|[\s^~]*", line),
                    "unexpected compiler diagnostic continuation")
    expected_sites = [(str(fixture), line, message) for line, message in DIAGNOSTICS[name]]
    if compiler_family == "gcc":
        expected = [(path, line, 1, "error", 'static assertion failed: "' + message + '"')
                    for path, line, message in expected_sites]
        require(observed == expected and summaries == [],
                "control lacks its exact ordered intended GCC diagnostics")
    else:
        errors = [row for row in observed if row[3] == "error"]
        notes = [row for row in observed if row[3] == "note"]
        require(not any(row[3] not in {"error", "note"} for row in observed) and
                [(path, line, column, severity)
                 for path, line, column, severity, _ in errors] ==
                [(path, line, 16, "error") for path, line, _ in expected_sites],
                "control lacks its exact ordered intended Clang diagnostic sites")
        for actual, (_, _, message) in zip(errors, expected_sites, strict=True):
            require(re.fullmatch(
                r"static assertion failed due to requirement '.+': " + re.escape(message),
                actual[4]) is not None,
                "control lacks its exact intended Clang diagnostic message")
        require(notes == [(str(fixture), line, column, "note", message)
                          for line, column, message in CLANG_NOTES[name]],
                "Clang diagnostic notes differ")
        require(summaries == [(len(lines) - 1, len(expected_sites))],
                "Clang diagnostic summary count or position differs")
    expected = expected_sites
    return {"name": name, "expected_errors": len(expected),
            "observed_errors": sum(row[3] == "error" for row in observed)}


def _artifacts(output):
    rows = []
    for path in sorted(output.iterdir()):
        if path.name == "receipt.json":
            regular(path)
            continue
        rows.append(record(path))
    return rows


def _write(path, data):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")
    os.replace(temporary, path)


def validate(root, kernel, target, model, build, binding, gate, receipt_path, *, timeout=60):
    """Read-only negative controls; caller must freshly authenticate positive gate."""
    root = Path(root).resolve(); receipt_path = Path(receipt_path).absolute()
    _timeout(timeout)
    require(receipt_path.name == "receipt.json", "explicit controls receipt required")
    output = _namespace(root, receipt_path.parent)
    saved = replay.strict_json(regular(receipt_path).read_text())
    required = {"schema_version", "kind", "status", "boundary", "output", "timeout", "environment",
        "started_at", "completed_at", "context", "plan", "intents", "commands", "initial_inputs",
        "final_inputs", "input_drift", "finalization_errors", "artifacts", "error"}
    require(isinstance(saved, dict) and set(saved) == required and type(saved["schema_version"]) is int and
            saved["schema_version"] == 1 and saved["kind"] == KIND and saved["status"] == RECORDED and
            same(saved["boundary"], BOUNDARY), "incomplete or malformed controls receipt")
    require(type(saved["timeout"]) is int and saved["timeout"] == timeout and saved["output"] == str(output) and
            same(saved["environment"], compiler_environment(output)), "controls environment/output/budget differs")
    start, end = (datetime.fromisoformat(saved[key]) for key in ("started_at", "completed_at"))
    require(start.tzinfo is not None and end.tzinfo is not None and end >= start, "invalid control timestamps")
    current = context(root, kernel, target, model, build, binding, gate, output)
    require(same(saved["context"], current), "current controls context differs")
    plan = command_plan(current, target, output)
    intents = [{**item, "cwd": current["cwd"], "timeout": timeout} for item in plan]
    require(same(saved["plan"], plan) and same(saved["intents"], intents), "control argv/intent inventory differs")
    require(isinstance(saved["commands"], list) and len(saved["commands"]) == 2, "exactly two compiler commands required")
    observations = []
    for expected, actual in zip(plan, saved["commands"], strict=True):
        keys = {"name", "argv", "cwd", "returncode", "timed_out", "seconds", "log", "log_sha256", "stdout", "stderr"}
        require(isinstance(actual, dict) and set(actual) == keys and actual["name"] == expected["name"] and
                same(actual["argv"], expected["argv"]) and actual["cwd"] == current["cwd"] and
                type(actual["seconds"]) in (int, float) and math.isfinite(actual["seconds"]) and actual["seconds"] >= 0,
                "malformed control command record")
        name = expected["name"]; stdout, stderr = (output / (name + "." + stream) for stream in ("stdout", "stderr"))
        require(same(actual["stdout"], record(stdout)) and same(actual["stderr"], record(stderr)) and
                actual["log"] == str(stderr) and actual["log_sha256"] == sources.sha256(stderr), "control raw stream identity differs")
        obj = output / (name + ".o")
        family = model.get("compiler", {}).get("compiler_family", "gcc")
        observations.append(validate_diagnostics(name, current["fixture"], actual,
            stderr.read_text(), stdout.read_text(), obj.exists() or obj.is_symlink(),
            compiler_family=family))
    artifacts = _artifacts(output)
    require([Path(row["absolute_path"]).name for row in artifacts] ==
            sorted(name + "." + stream for name in NAMES for stream in ("stderr", "stdout")) and
            same(saved["artifacts"], artifacts), "missing or unexpected control artifact")
    records = _check_records(current["tracked_inputs"])
    require(same(saved["initial_inputs"], records) and same(saved["final_inputs"], records) and
            saved["input_drift"] == [] and saved["finalization_errors"] == [] and saved["error"] is None,
            "controls have input drift or failed finalization")
    return {"schema_version": 1, "kind": KIND, "status": CHECKED, "receipt": record(receipt_path),
            "commands_checked": 2, "controls": observations, "positive_gate_sha256": gate["record_sha256"],
            "boundary": dict(BOUNDARY),
            "tracked_files": integrity.merge_records(records, artifacts, [record(receipt_path)])}


def run(root, kernel, target, model, build, binding, gate, output, *, timeout=60):
    """Record exactly two compiler invocations; never link or execute an object."""
    root = Path(root).resolve(); output = _namespace(root, output); _timeout(timeout)
    require(not output.exists(), "controls output already exists; no overwrites")
    output.mkdir()
    saved = {"schema_version": 1, "kind": KIND, "status": "running", "boundary": dict(BOUNDARY),
        "output": str(output), "timeout": timeout, "environment": compiler_environment(output),
        "started_at": datetime.now(timezone.utc).isoformat(), "completed_at": None,
        "context": None, "plan": [], "intents": [], "commands": [], "initial_inputs": [], "final_inputs": [],
        "input_drift": [], "finalization_errors": [], "artifacts": [], "error": None}
    receipt = output / "receipt.json"; _write(receipt, saved)
    interruption = None
    try:
        current = context(root, kernel, target, model, build, binding, gate, output)
        saved["context"] = current; saved["initial_inputs"] = current["tracked_inputs"]
        saved["plan"] = command_plan(current, target, output)
        _write(receipt, saved)
        for item in saved["plan"]:
            saved["intents"].append({**item, "cwd": current["cwd"], "timeout": timeout}); _write(receipt, saved)
            name = item["name"]; stdout, stderr = (output / (name + "." + stream) for stream in ("stdout", "stderr"))
            command = inputs.run_recorded(item["argv"], cwd=Path(current["cwd"]), env=compiler_environment(output),
                log=stderr, stdout_file=stdout, timeout=timeout)
            row = {"name": name, **command}; saved["commands"].append(row)
            row.update(stdout=record(stdout), stderr=record(stderr)); _write(receipt, saved)
            obj = output / (name + ".o")
            family = model.get("compiler", {}).get("compiler_family", "gcc")
            validate_diagnostics(name, current["fixture"], row, stderr.read_text(),
                                 stdout.read_text(), obj.exists() or obj.is_symlink(),
                                 compiler_family=family)
        saved["status"] = RECORDED
    except BaseException as exc:
        interruption = exc if not isinstance(exc, Exception) else None
        saved.update(status="interrupted" if interruption is not None else "error",
                     error={"type": type(exc).__name__, "message": str(exc)})
    try:
        saved["final_inputs"] = integrity.merge_records(saved["initial_inputs"])
        saved["input_drift"] = integrity.changed_files(saved["final_inputs"])
    except Exception as exc:
        saved["finalization_errors"].append("input inventory: " + str(exc))
    try:
        saved["artifacts"] = _artifacts(output)
    except Exception as exc:
        saved["finalization_errors"].append("artifacts: " + str(exc))
    if saved["input_drift"] or saved["finalization_errors"]:
        if interruption is None:
            saved["status"] = "error"
    saved["completed_at"] = datetime.now(timezone.utc).isoformat(); _write(receipt, saved)
    if interruption is not None:
        raise interruption
    if saved["status"] == RECORDED:
        try:
            return validate(root, kernel, target, model, build, binding, gate, receipt, timeout=timeout)
        except Exception as exc:
            saved.update(status="error", error={"type": type(exc).__name__, "message": str(exc)}); _write(receipt, saved)
    return {"schema_version": 1, "kind": KIND, "status": saved["status"], "receipt": record(receipt),
            "boundary": dict(BOUNDARY)}
