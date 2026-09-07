#!/usr/bin/env python3
"""Run a bounded s390 proof experiment with durable, source-checked evidence.

This records ordinary proof progress, not the common suite's L2 certificate.
Strategy output and smoke checks never substitute for ordinary WP/TSV verdicts.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fragma.inputs import (audit_inputs, kernel_model_check, load_build,
                           prepare_input, run_recorded)
from fragma.provenance import check_target
from fragma.report import ReportError, parse_wp_report
from fragma.sources import sha256
from fragma.toolchain import prepare_environment


def progress(target: dict, goals: list[dict], properties: list[dict]) -> dict:
    """Require named goals and unconditional dependencies; never certify L2."""
    functions = set(target.get("analysis_functions", target["functions"]))
    ordinary = [g for g in goals if not g["smoke"]]
    selected = [p for p in properties if p["function"] in functions]
    missing = sorted(set(target["required_properties"]) - {g["property"] for g in ordinary})
    missing_functions = sorted(functions - {g["function"] for g in ordinary})
    complete = bool(ordinary and selected) and not (missing or missing_functions) and all(
        g["passed"] and g["verdict"] == "valid" for g in ordinary) and all(
        p["status"] == "Valid" for p in selected)
    return {"ordinary_counts": dict(Counter(g["verdict"] for g in ordinary)),
            "selected_property_counts": dict(Counter(p["status"] for p in selected)),
            "missing_properties": missing, "missing_functions": missing_functions,
            "ordinary_complete": bool(complete), "certified": False}


def run(target_id: str, output: Path, *, kernel: Path, strategy: str,
        prefix: Path, timeout: int, extra: list[str], target_override: dict | None = None,
        wall_timeout: int | None = None) -> dict:
    manifest = json.loads((ROOT / "config/s390-targets.json").read_text())
    target = target_override or next(t for t in manifest["targets"] if t["id"] == target_id)
    if target["analysis"] != "wp":
        raise ValueError("this experiment driver only accepts proof targets")
    revision = manifest["kernel_revision"]
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    model_path = ROOT / "build/profile-checks/s390x-gcc-configured/profile.json"
    model = json.loads(model_path.read_text())
    if model.get("level") != "L1" or model.get("status") != "passed":
        raise ValueError("configured s390x model has not passed")
    build = load_build(ROOT, "s390x-gcc", revision)
    env = prepare_environment(ROOT, environ={**os.environ,
        "FRAGMA_TOOLCHAIN_PREFIX": str(prefix.resolve())})
    receipt = {"target": target, "model": model, "build": build,
               "source_gate": check_target(target, kernel, revision, ROOT)}
    if not receipt["source_gate"]["passed"]:
        raise ValueError("pinned function-source gate failed")
    receipt["kernel_model_check"] = kernel_model_check(
        ROOT, target, build, kernel, revision, output, env)
    prepared = prepare_input(ROOT, target, model, build, kernel, revision, output, env)
    receipt["prepared"] = prepared
    functions = target.get("analysis_functions", target["functions"])
    argv = [shutil.which("frama-c", path=env["PATH"]),
        "-machdep", model["analysis"]["machdep"],
        *model["analysis"]["arithmetic_flags"], "-cpp-frama-c-compliant",
        "-cpp-command", prepared["frama_cpp_command"], "-cpp-extra-args=-std=gnu11",
        "-pp-annot", "-keep-temp-files", "-audit-prepare", str(output / "audit.json"),
        prepared["frama_input"], "-wp", "-wp-fct", ",".join(functions),
        "-wp-model", model["analysis"]["wp_model"], "-wp-rte", "-wp-split",
        # Frama-C 33 excludes smoke goals from default strategies. External
        # provers must remain scheduled alongside tip to attempt those checks.
        "-wp-prover", "tip,alt-ergo,z3" if strategy else "alt-ergo,z3",
        "-wp-par", "2", "-wp-timeout", str(timeout), "-wp-cache", "none",
        "-wp-smoke-tests", "-wp-smoke-timeout", "2",
        "-wp-why3-config", str(ROOT / "toolchain/why3.conf"), "-wp-no-why3-detect",
        "-wp-session", str(output / "session"),
        "-wp-msg-key", "strategy,script:allgoals",
        "-wp-report-json", str(output / "goals.json")]
    if strategy:
        argv += ["-wp-strategy", strategy, "-wp-auto-depth", "64"]
    argv += [*extra, "-then", "-report", "-report-absolute-path",
             "-report-csv", str(output / "properties.tsv")]
    receipt["command"] = run_recorded(argv, cwd=Path(prepared["cwd"]),
        env={**env, "TMPDIR": str(output / "tmp")}, log=output / "analysis.log",
        timeout=wall_timeout if wall_timeout is not None else max(180, timeout * 60))
    receipt["ordinary_complete"] = False
    if receipt["command"]["returncode"] == 0:
        receipt["audit"] = audit_inputs(ROOT, kernel, revision, build, output, prepared, target)
        try:
            goals = parse_wp_report(output / "goals.json")
            with (output / "properties.tsv").open() as stream:
                properties = list(csv.DictReader(stream, delimiter="\t"))
            receipt.update(progress(target, goals, properties))
        except (ReportError, OSError, csv.Error) as exc:
            # Keep the raw failed experiment and command receipt. Unknown
            # verdicts (including tip-only smoke's "none") are never normalized
            # into success or discarded to obtain a complete local result.
            receipt["report_error"] = str(exc)
    receipt["certified"] = False
    receipt["limitation"] = "Proof progress only; common suite warning/model/integrity policy remains required."
    receipt["file_hashes"] = {str(p): sha256(p) for p in [
        model_path, ROOT / target["harness"],
        ROOT / target.get("wp_strategy_file", "s390/annotated/bitproof.h"),
        ROOT / "toolchain/lock.json",
        ROOT / "toolchain/why3.conf", Path(argv[0]),
        *[Path(shutil.which(t, path=env["PATH"])) for t in ("why3", "alt-ergo", "z3")]]}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=["s390.tod_to_ns", "s390.unaligned24", "s390.unaligned48"])
    parser.add_argument("output", type=Path)
    parser.add_argument("--kernel", type=Path, default=Path(os.environ.get("FRAGMA_KERNEL_TREE", "/home/karl/linux-work/linux")))
    parser.add_argument("--prefix", type=Path, default=ROOT / "toolchain/verified-prefix")
    parser.add_argument("--strategy", default="fragma_scalar_math")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--wall-timeout", type=int,
                        help="overall experiment bound in seconds (default: max(180, timeout*60))")
    parser.add_argument("extra", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("timeout must be positive")
    if args.wall_timeout is not None and args.wall_timeout < 1:
        parser.error("wall-timeout must be positive")
    result = run(args.target, args.output, kernel=args.kernel.resolve(),
        prefix=args.prefix, strategy=args.strategy, timeout=args.timeout,
        extra=args.extra[1:] if args.extra[:1] == ["--"] else args.extra,
        wall_timeout=args.wall_timeout)
    print(json.dumps({k: result.get(k) for k in (
        "ordinary_complete", "ordinary_counts", "selected_property_counts", "certified")}, indent=2))
    sys.exit(0 if result["ordinary_complete"] else 2)
