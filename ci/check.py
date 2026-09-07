#!/usr/bin/env python3
"""Run local unit tests and the actual registered verification suites.

This entry point never installs tools, prepares sources, executes native
witnesses, or updates an approved baseline. Explicit native receipts are only
passed to the common suite's read-only validators.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fragma import suite

MODES = {"core": ["core", "calibration"], "extended": ["extended"],
         "all": ["core", "calibration", "extended"]}


def now():
    return datetime.now(timezone.utc).isoformat()


def checksum(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def strict_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("non-finite JSON number: " + value)

    def finite(value):
        number = float(value)
        return number if math.isfinite(number) else invalid(value)

    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=invalid, parse_float=finite)


def write_receipt(path, value):
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    os.replace(temporary, path)


def snapshot_inputs(root, native_paths):
    paths = {Path(__file__).resolve(), Path(sys.executable).resolve(),
             *root.glob("ci/*.py"), *root.glob("tests/**/*.py"),
             *root.glob("fragma/*.py"), *root.glob("config/*.json"),
             root / "toolchain/lock.json", root / "toolchain/why3.conf",
             root / "toolchain/assumptions.json", *native_paths}
    return {str(path.absolute()): checksum(path) for path in sorted(paths)}


def run_command(argv, *, cwd, env, log, timeout=None):
    """Retain one argv-only child's output and clean its direct process group.

    A descendant that creates another session is outside this group. The suite
    owns its analyzer timeouts; this driver does not claim whole-tree cleanup.
    """
    receipt = {"argv": argv, "cwd": str(cwd), "log": str(log),
               "started_at": now(), "returncode": None, "timed_out": False,
               "cleanup_scope": "direct-child-process-group"}
    started = time.monotonic()
    process = None
    with log.open("xb") as stream:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            receipt["returncode"] = process.wait(timeout=timeout)
        except (KeyboardInterrupt, subprocess.TimeoutExpired) as exc:
            receipt["timed_out"] = isinstance(exc, subprocess.TimeoutExpired)
            receipt["interrupted"] = isinstance(exc, KeyboardInterrupt)
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
            receipt["returncode"] = 124 if receipt["timed_out"] else 130
        except OSError as exc:
            receipt.update(returncode=127, error=str(exc))
            stream.write((str(exc) + "\n").encode())
    receipt.update(completed_at=now(), seconds=time.monotonic() - started,
                   log_sha256=checksum(log))
    return receipt


def validate_summary(path, revision, selected, limits):
    """Check terminal raw selection/results, not the process exit code alone."""
    summary = strict_json(path)
    expected_ids = [target["id"] for target in selected]
    if (not isinstance(summary, dict) or type(summary.get("schema_version")) is not int or
            summary["schema_version"] != 1 or summary.get("revision") != revision or
            summary.get("output") != str(path.parent) or summary.get("status") != "passed" or
            summary.get("accepted") is not True or summary.get("selected_targets") != expected_ids or
            json.dumps(summary.get("analysis_limits"), sort_keys=True) != json.dumps(limits, sort_keys=True)):
        raise ValueError("suite summary is not a complete accepted run of the expected selection")
    for key in ("started_at", "completed_at"):
        value = summary.get(key)
        if not isinstance(value, str):
            raise ValueError("suite summary lacks terminal dates")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("suite summary date lacks timezone")
    if datetime.fromisoformat(summary["completed_at"]) < datetime.fromisoformat(summary["started_at"]):
        raise ValueError("suite summary completion precedes start")
    records = summary.get("targets")
    if not isinstance(records, list) or len(records) != len(selected):
        raise ValueError("suite target inventory is incomplete")
    for expected, record in zip(selected, records):
        status = "passed" if expected["role"] == "proof" else "calibration-passed"
        if (not isinstance(record, dict) or
                json.dumps(record.get("target"), sort_keys=True) != json.dumps(expected, sort_keys=True) or
                record.get("accepted") is not True or record.get("status") != status):
            raise ValueError("suite target is missing, changed, unaccepted or out of order")
        evaluation = record.get("evaluation")
        if (not isinstance(evaluation, dict) or evaluation.get("target_id") != expected["id"] or
                evaluation.get("accepted") is not True or evaluation.get("status") != status or
                evaluation.get("local_policy_passed") is not True or evaluation.get("issues") != [] or
                evaluation.get("verified") is not (expected["role"] == "proof") or
                any(evaluation.get(key) != expected[key] for key in ("profile", "source", "role", "analysis"))):
            raise ValueError("suite target evaluation is not accepted")
        retained = strict_json(path.parent / expected["id"] / "result.json")
        if json.dumps(retained, sort_keys=True) != json.dumps(record, sort_keys=True):
            raise ValueError("suite target record contradicts retained result")
    counts = dict(Counter(row["status"] for row in records))
    if json.dumps(summary.get("counts"), sort_keys=True) != json.dumps(counts, sort_keys=True):
        raise ValueError("suite result counts contradict target inventory")
    return {"path": str(path), "sha256": checksum(path), "selected_targets": expected_ids,
            "status": "passed", "accepted": True, "counts": counts}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mode", choices=MODES, default="core")
    result.add_argument("--output", type=Path, required=True, help="new directory; existing paths are never overwritten")
    result.add_argument("--kernel", type=Path, default=Path(os.environ.get(
        "FRAGMA_KERNEL_TREE", str(Path.home() / "linux-work/linux"))))
    result.add_argument("--native-evidence", type=Path, action="append", default=[],
                        help="explicit existing receipt, repeat for distinct providers; never execute native witnesses")
    result.add_argument("--timeout", type=int, default=20, help="per-prover seconds, 1..3600")
    result.add_argument("--wall-timeout", type=int, help="per-analyzer seconds, 1..86400")
    result.add_argument("--jobs", type=int, default=4, help="prover workers, 1..256")
    return result


def main(argv=None, *, root=ROOT, runner=run_command):
    args = parser().parse_args(argv)
    root = Path(root).resolve()
    try:
        limits = suite.analysis_limits(args.timeout, args.jobs, args.wall_timeout)
        if args.output.is_symlink():
            raise ValueError("output must not be a symlink")
        output = args.output.expanduser().resolve()
        kernel = args.kernel.expanduser().resolve()
        native_paths = [path.expanduser().resolve() for path in args.native_evidence]
        if output.exists():
            raise ValueError("CI output already exists: " + str(output))
        if not kernel.is_dir() or any(not path.is_file() for path in native_paths):
            raise ValueError("kernel directory or explicit native receipt is missing")
        if len(set(native_paths)) != len(native_paths):
            raise ValueError("duplicate explicit native receipt")
        env = dict(os.environ)
        prefix = env.get("FRAGMA_TOOLCHAIN_PREFIX")
        if prefix:
            env["FRAGMA_TOOLCHAIN_PREFIX"] = str(Path(prefix).expanduser().resolve())
        initial = snapshot_inputs(root, native_paths)
        revision, targets, _ = suite.load_registry(root)
        selected = suite.select_targets(targets, ids=[], suites=MODES[args.mode], profile_ids=[])
        output.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as exc:
        print("ci: " + str(exc), file=sys.stderr)
        return 2
    receipt = {"schema_version": 1, "kind": "fragma-local-ci", "status": "running",
        "accepted": False, "mode": args.mode, "suites": MODES[args.mode], "output": str(output),
        "revision": revision, "selected_targets": [target["id"] for target in selected],
        "analysis_limits": limits, "started_at": now(), "commands": [], "issues": [],
        "inputs": initial, "toolchain_prefix": env.get("FRAGMA_TOOLCHAIN_PREFIX"),
        "native_execution": False, "baseline_updated": False}
    write_receipt(output / "ci.json", receipt)
    try:
        unit = runner([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
                      cwd=root, env=env, log=output / "unit-tests.log", timeout=1800)
        receipt["commands"].append({"name": "unit-tests", **unit})
        write_receipt(output / "ci.json", receipt)
        if type(unit.get("returncode")) is not int or unit["returncode"] != 0 or unit.get("timed_out") is not False:
            raise ValueError("unit tests failed; verification suite was not started")
        command = [sys.executable, "-m", "fragma", "run", "--kernel", str(kernel),
                   "--output", str(output / "suite"), "--timeout", str(args.timeout),
                   "--wall-timeout", str(limits["wall_timeout_seconds"]), "--jobs", str(args.jobs)]
        for name in MODES[args.mode]:
            command += ["--suite", name]
        for path in native_paths:
            command += ["--native-evidence", str(path)]
        analysis = runner(command, cwd=root, env=env, log=output / "suite.log")
        receipt["commands"].append({"name": "verification-suite", **analysis})
        summary_path = output / "suite/summary.json"
        if summary_path.is_file():
            receipt["suite_summary"] = {"path": str(summary_path), "sha256": checksum(summary_path)}
        if type(analysis.get("returncode")) is not int or analysis["returncode"] != 0 or analysis.get("timed_out") is not False:
            raise ValueError("verification suite failed; inspect retained suite summary and logs")
        receipt["validated_suite"] = validate_summary(summary_path, revision, selected, limits)
        receipt.update(status="passed", accepted=True)
    except (OSError, ValueError, TypeError, KeyError, KeyboardInterrupt) as exc:
        receipt.update(status="failed", accepted=False)
        receipt["issues"].append("interrupted" if isinstance(exc, KeyboardInterrupt) else str(exc))
    try:
        final = snapshot_inputs(root, native_paths)
        changed = sorted(path for path in set(initial) | set(final) if initial.get(path) != final.get(path))
    except OSError as exc:
        changed = ["cannot complete input drift check: " + str(exc)]
    receipt["changed_inputs"] = changed
    if changed:
        receipt.update(status="failed", accepted=False)
        receipt["issues"].append("CI inputs changed during execution")
    receipt["completed_at"] = now()
    write_receipt(output / "ci.json", receipt)
    print(receipt["status"] + ": " + str(output / "ci.json"))
    return 0 if receipt["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
