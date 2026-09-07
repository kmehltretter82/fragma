"""Pinned C0 capability calibration for Frama-C Mthread plus Eva.

The suite accepts expected negative controls as successful calibrations. It
does not turn an Invalid/Unknown property, a possible race, or an unsupported
primitive into a verified program. Raw process output and input hashes are
retained so those outcome classes remain independently inspectable.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any


class ConcurrencyError(ValueError):
    """The C0 manifest, provider, or output is unusable."""


_ASSERTION = re.compile(r"/\*@\s*assert\s+([A-Za-z_][A-Za-z_0-9]*):")
_NORMAL_STATUS = {
    "valid": "valid",
    "invalid": "invalid",
    "invalid or unreachable": "invalid",
    "unknown": "unknown",
}


def _json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative_path(root: Path, value: str, role: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ConcurrencyError(f"{role} must be a project-relative path: {value!r}")
    path = root.joinpath(*pure.parts)
    if not path.is_file() or path.is_symlink():
        raise ConcurrencyError(f"{role} is missing or not a regular file: {value}")
    return path


def assertion_lines(source: Path) -> dict[int, str]:
    """Return the unique single-line named ACSL assertions in a fixture."""
    found: dict[int, str] = {}
    labels: set[str] = set()
    for line, text in enumerate(source.read_text().splitlines(), 1):
        match = _ASSERTION.search(text)
        if match:
            label = match.group(1)
            if label in labels:
                raise ConcurrencyError(f"duplicate assertion label {label!r} in {source}")
            labels.add(label)
            found[line] = label
    return found


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "config/concurrency-c0.json"
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConcurrencyError(f"cannot load {path}: {exc}") from exc
    if manifest.get("schema_version") != 1:
        raise ConcurrencyError("unsupported concurrency C0 schema")
    provider = manifest.get("provider")
    cases = manifest.get("cases")
    if not isinstance(provider, dict) or not isinstance(cases, list) or not cases:
        raise ConcurrencyError("C0 manifest requires provider and nonempty cases")
    _relative_path(root, provider.get("binary", ""), "provider binary")
    for group in ("model_files", "implementation_files"):
        values = provider.get(group)
        if not isinstance(values, list) or not values:
            raise ConcurrencyError(f"provider {group} must be nonempty")
        for value in values:
            _relative_path(root, value, group)
    seen: set[str] = set()
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        if not isinstance(case_id, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", case_id):
            raise ConcurrencyError(f"invalid C0 case id: {case_id!r}")
        if case_id in seen:
            raise ConcurrencyError(f"duplicate C0 case id: {case_id}")
        seen.add(case_id)
        source = _relative_path(root, case.get("source", ""), f"source for {case_id}")
        labels = set(assertion_lines(source).values())
        expected = case.get("expected_assertions")
        if not isinstance(expected, dict) or set(expected) != labels:
            raise ConcurrencyError(
                f"{case_id} expected assertions {sorted(expected or {})} do not "
                f"match source labels {sorted(labels)}"
            )
        if any(value not in {"valid", "invalid", "unknown"}
               for value in expected.values()):
            raise ConcurrencyError(f"{case_id} has invalid expected assertion status")
        if case.get("thread_library") not in {"pthreads", "builtins-only"}:
            raise ConcurrencyError(f"{case_id} has invalid thread library")
        races = case.get("expected_unprotected_races")
        if not isinstance(races, dict) or set(races) != {"read_write", "write_write"}:
            raise ConcurrencyError(f"{case_id} requires both race expectations")
        if not all(isinstance(value, bool) for value in races.values()):
            raise ConcurrencyError(f"{case_id} race expectations must be boolean")
    return manifest


def parse_report_csv(path: Path, source: Path) -> dict[str, Any]:
    lines = assertion_lines(source)
    assertions: dict[str, str] = {}
    considered_valid = 0
    rows = 0
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        required = {"file", "line", "property kind", "status"}
        if reader.fieldnames is None or not required.issubset(reader.fieldnames):
            raise ConcurrencyError(f"malformed report CSV: {path}")
        for row in reader:
            rows += 1
            status = row["status"].strip()
            if status.casefold() == "considered valid":
                considered_valid += 1
            if row["property kind"].strip() != "user assertion":
                continue
            if PurePosixPath(row["file"].strip()).name != source.name:
                raise ConcurrencyError(
                    f"report assertion belongs to another file: {row['file']!r}"
                )
            try:
                line = int(row["line"])
            except ValueError as exc:
                raise ConcurrencyError(f"invalid assertion line in {path}") from exc
            label = lines.get(line)
            if label is None:
                raise ConcurrencyError(
                    f"report assertion at {source.name}:{line} has no source label"
                )
            normalized = _NORMAL_STATUS.get(status.casefold())
            if normalized is None:
                raise ConcurrencyError(f"unclassified assertion status {status!r}")
            if label in assertions:
                raise ConcurrencyError(f"duplicate report assertion {label!r}")
            assertions[label] = normalized
    return {
        "assertions": assertions,
        "considered_valid_assumptions": considered_valid,
        "csv_rows": rows,
    }


def parse_race_sections(text: str) -> dict[str, dict[str, Any]]:
    """Return the last Mthread read/write and write/write race summaries."""
    headings = list(re.finditer(
        r"^\[mt\] Possible (read/write|write/write) data races:\s*$", text,
        flags=re.MULTILINE,
    ))
    result = {
        "read_write": {"reported": False, "unprotected": False, "body": ""},
        "write_write": {"reported": False, "unprotected": False, "body": ""},
    }
    for heading in headings:
        following = re.search(r"^\[mt\] ", text[heading.end():], flags=re.MULTILINE)
        end = heading.end() + following.start() if following else len(text)
        body = text[heading.end():end].strip()
        key = "read_write" if heading.group(1) == "read/write" else "write_write"
        result[key] = {
            "reported": bool(body and body != "none"),
            "unprotected": bool(re.search(r"\bunprotected\b", body)),
            "body": body,
        }
    return result


def parse_diagnostics(text: str) -> dict[str, Any]:
    iterations = re.findall(r"Analysis (?:performed|stopped after),? (\d+) iterations", text)
    return {
        "races": parse_race_sections(text),
        "fixpoint_reached": "******* Analysis performed" in text,
        "analysis_stopped": "******* Analysis stopped after" in text,
        "iterations": int(iterations[-1]) if iterations else None,
        "unsupported": "Unsupported function" in text and "probably unsound" in text,
        "user_error": "User Error:" in text,
        "eva_alarm_count": text.count("[eva:alarm]"),
    }


def evaluate_case(case: dict[str, Any], returncode: int, timed_out: bool,
                  report: dict[str, Any] | None, diagnostics: dict[str, Any],
                  combined: str) -> list[dict[str, Any]]:
    """Evaluate observable results; a negative control passes only as expected."""
    checks: list[dict[str, Any]] = []

    def add(name: str, expected: Any, actual: Any) -> None:
        checks.append({"name": name, "expected": expected, "actual": actual,
                       "passed": expected == actual})

    add("timed_out", False, timed_out)
    add("exit_code", case["expected_exit"], returncode)
    add("report_present", case["report_expected"], report is not None)
    actual_assertions = report["assertions"] if report else {}
    add("assertions", case["expected_assertions"], actual_assertions)
    for kind, expected in case["expected_unprotected_races"].items():
        add(f"{kind}_unprotected_race", expected,
            diagnostics["races"][kind]["unprotected"])
    for token in case["required_diagnostics"]:
        add(f"required diagnostic: {token}", True, token in combined)
    for token in case["forbidden_diagnostics"]:
        add(f"forbidden diagnostic: {token}", False, token in combined)
    return checks


def _run(argv: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        process = subprocess.run(
            argv, cwd=cwd, env=environment, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
        return {"returncode": process.returncode, "stdout": process.stdout,
                "stderr": process.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"returncode": 124, "stdout": stdout, "stderr": stderr,
                "timed_out": True}


def _write_process(directory: Path, argv: list[str], process: dict[str, Any]) -> None:
    (directory / "stdout.txt").write_text(process["stdout"])
    (directory / "stderr.txt").write_text(process["stderr"])
    _json(directory / "command.json", {
        "argv": argv,
        "cwd": ".",
        "environment": {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        "returncode": process["returncode"],
        "timed_out": process["timed_out"],
    })


def render_summary(result: dict[str, Any]) -> str:
    lines = [
        "# Mthread + Eva C0 capability baseline",
        "",
        f"Overall calibration: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        "A PASS means every valid, invalid, unknown, race, and unsupported control",
        "matched its pinned expectation. It does not mean every fixture is safe.",
        "",
        f"Provider: Frama-C {result['provider']['version']}",
        f"Provider binary SHA-256: `{result['provider']['binary_sha256']}`",
        "",
        "| Case | Interpretation | Assertions | Unprotected R/W | Unprotected W/W | Exit | Gate |",
        "|---|---|---|---:|---:|---:|---|",
    ]
    for case in result["cases"]:
        assertions = case["report"]["assertions"] if case["report"] else {}
        shown = ", ".join(f"{key}={value}" for key, value in assertions.items()) or "none"
        races = case["diagnostics"]["races"]
        lines.append(
            f"| `{case['id']}` | {case['outcome_kind']} | {shown} | "
            f"{'yes' if races['read_write']['unprotected'] else 'no'} | "
            f"{'yes' if races['write_write']['unprotected'] else 'no'} | "
            f"{case['returncode']} | {'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        "Raw stdout, stderr, report CSV files, commands, manifest snapshot, and",
        "SHA-256 identities are retained beside this summary.",
        "",
    ])
    return "\n".join(lines)


def run_c0(root: Path, output: Path, timeout: int = 120) -> dict[str, Any]:
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyError(f"C0 output already exists: {output}")
    if timeout < 1:
        raise ConcurrencyError("C0 timeout must be positive")
    output.mkdir(parents=True, exist_ok=False)
    inventory_dir = output / "inventory"
    cases_dir = output / "cases"
    inventory_dir.mkdir()
    cases_dir.mkdir()

    provider = manifest["provider"]
    binary = _relative_path(root, provider["binary"], "provider binary")
    inventory_commands = {
        "version": [str(binary), "-version"],
        "plugins": [str(binary), "-plugins"],
        "mthread_help": [str(binary), "-mt-h"],
        "eva_domains": [str(binary), "-eva-domains", "help"],
        "report_help": [str(binary), "-report-h"],
    }
    inventory: dict[str, Any] = {}
    for name, argv in inventory_commands.items():
        directory = inventory_dir / name
        directory.mkdir()
        process = _run(argv, root, timeout)
        _write_process(directory, argv, process)
        inventory[name] = process
    version = inventory["version"]["stdout"].strip()
    plugins_text = inventory["plugins"]["stdout"] + inventory["plugins"]["stderr"]
    inventory_checks = [
        {"name": "provider version", "expected": provider["expected_version"],
         "actual": version, "passed": version == provider["expected_version"]},
    ]
    for token in provider["required_plugin_text"]:
        inventory_checks.append({
            "name": f"plugin text: {token}", "expected": True,
            "actual": token in plugins_text, "passed": token in plugins_text,
        })
    for name, process in inventory.items():
        inventory_checks.append({
            "name": f"inventory command {name}", "expected": 0,
            "actual": process["returncode"],
            "passed": process["returncode"] == 0 and not process["timed_out"],
        })

    identity_paths = [
        "config/concurrency-c0.json",
        "toolchain/lock.json",
        "fragma/__main__.py",
        "fragma/concurrency.py",
        "tests/test_concurrency.py",
    ]
    identity_paths.extend(provider["model_files"])
    identity_paths.extend(provider["implementation_files"])
    identity_paths.extend(case["source"] for case in manifest["cases"])
    identities = {
        value: {"sha256": _sha256(_relative_path(root, value, "identity input")),
                "size": _relative_path(root, value, "identity input").stat().st_size}
        for value in identity_paths
    }
    _json(output / "manifest.json", manifest)
    _json(output / "input-identities.json", identities)

    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        directory = cases_dir / case["id"]
        directory.mkdir()
        source = _relative_path(root, case["source"], "case source")
        csv_path = directory / "report.csv"
        argv = [str(binary), *manifest["common_options"], "-mt-threads-lib",
                case["thread_library"], *case["options"], case["source"],
                "-then", "-report", "-report-csv", str(csv_path)]
        process = _run(argv, root, timeout)
        _write_process(directory, argv, process)
        combined = process["stdout"] + "\n" + process["stderr"]
        report = parse_report_csv(csv_path, source) if csv_path.is_file() else None
        diagnostics = parse_diagnostics(combined)
        checks = evaluate_case(case, process["returncode"], process["timed_out"],
                               report, diagnostics, combined)
        value = {
            "id": case["id"],
            "source": case["source"],
            "outcome_kind": case["outcome_kind"],
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "report": report,
            "diagnostics": diagnostics,
            "checks": checks,
            "passed": all(check["passed"] for check in checks),
        }
        _json(directory / "result.json", value)
        case_results.append(value)

    result = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "provider": {
            "version": version,
            "binary": provider["binary"],
            "binary_sha256": _sha256(binary),
        },
        "inventory_checks": inventory_checks,
        "cases": case_results,
        "accepted": (all(check["passed"] for check in inventory_checks)
                     and all(case["passed"] for case in case_results)),
        "output": str(output),
    }
    _json(output / "summary.json", result)
    (output / "SUMMARY.md").write_text(render_summary(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c0-{stamp}"
