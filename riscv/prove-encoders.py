#!/usr/bin/env python3
"""Bounded source-gated encoder proof baseline; not an L2 certificate."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fragma.inputs import audit_inputs, kernel_model_check, load_build, prepare_input, run_recorded
from fragma.profiles import validate_profile
from fragma.provenance import check_target
from fragma.report import evaluate_target, parse_properties, parse_wp_report
from fragma.sources import sha256
from fragma.suite import warnings_from_log
from fragma.toolchain import prepare_environment


def run(output: Path, kernel: Path, prefix: Path, timeout: int) -> dict:
    manifest = json.loads((ROOT / "config/riscv-targets.json").read_text())
    target, revision = manifest["targets"][0], manifest["kernel_revision"]
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    env = prepare_environment(ROOT, environ={**os.environ, "FRAGMA_TOOLCHAIN_PREFIX": str(prefix.resolve())})
    env = {key: value for key, value in env.items() if key not in
           ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH")}
    fc = shutil.which("frama-c", path=env["PATH"])
    if not fc:
        raise ValueError("selected toolchain has no Frama-C")
    build = load_build(ROOT, target["profile"], revision)
    source_gate = check_target(target, kernel, revision, ROOT)
    if not source_gate["passed"]:
        raise ValueError("pinned encoder-source gate failed: " + str(source_gate["errors"]))
    receipt = {"target": target, "source_gate": source_gate, "build": build,
               "certified": False, "ordinary_complete": False}
    (output / "source-gate.json").write_text(json.dumps(source_gate, indent=2) + "\n")
    model = validate_profile(ROOT, target["profile"], kernel=kernel,
        kernel_build=Path(build["path"]), frama_c=fc, output=output / "profile", env=env)
    receipt["model"] = model
    if model["status"] != "passed" or model["level"] != "L1":
        raise ValueError("fresh configured profile calibration failed: " + str(model["gaps"]))
    receipt["kernel_model_check"] = kernel_model_check(ROOT, target, build, kernel, revision, output, env)
    prepared = prepare_input(ROOT, target, model, build, kernel, revision, output, env)
    receipt["prepared"] = prepared
    argv = [fc, "-machdep", model["analysis"]["machdep"], *model["analysis"]["arithmetic_flags"],
        "-cpp-frama-c-compliant", "-cpp-command", prepared["frama_cpp_command"],
        "-cpp-extra-args=-std=gnu11", "-pp-annot", "-keep-temp-files",
        "-audit-prepare", str(output / "audit.json"), prepared["frama_input"],
        "-wp", "-wp-fct", ",".join(target["analysis_functions"]), "-wp-model", model["analysis"]["wp_model"],
        "-wp-rte", "-wp-split", "-wp-prover", ",".join(target["provers"]),
        "-wp-par", "2", "-wp-timeout", str(timeout), "-wp-cache", "none",
        "-wp-smoke-tests", "-wp-smoke-timeout", "2",
        "-wp-why3-config", str(ROOT / "toolchain/why3.conf"), "-wp-no-why3-detect",
        "-wp-session", str(output / "session"), "-wp-report-json", str(output / "goals.json"),
        "-then", "-report", "-report-absolute-path", "-report-csv", str(output / "properties.tsv")]
    receipt["command"] = run_recorded(argv, cwd=Path(prepared["cwd"]),
        env={**env, "TMPDIR": str(output / "tmp")}, log=output / "analysis.log", timeout=max(180, timeout * 80))
    if receipt["command"]["returncode"] == 0:
        receipt["audit"] = audit_inputs(ROOT, kernel, revision, build, output, prepared, target)
        goals = parse_wp_report(output / "goals.json")
        properties = parse_properties(output / "properties.tsv", source_files=[ROOT / target["harness"]])
        warnings = warnings_from_log(output / "analysis.log")
        receipt["evaluation"] = evaluate_target(target, goals, properties, returncode=0, warnings=warnings)
        ordinary = [goal for goal in goals if not goal["smoke"]]
        selected = [row for row in properties if row["function"] in target["analysis_functions"]]
        receipt["ordinary_counts"] = dict(Counter(goal["verdict"] for goal in ordinary))
        receipt["selected_property_counts"] = dict(Counter(row["status"] for row in selected))
        receipt["ordinary_complete"] = bool(ordinary and selected) and all(
            goal["verdict"] == "valid" for goal in ordinary) and all(row["status"] == "Valid" for row in selected)
    receipt["input_hashes"] = {str(path): sha256(path) for path in [ROOT / "config/riscv-targets.json",
        ROOT / "riscv/prove-encoders.py", ROOT / "toolchain/lock.json", ROOT / "toolchain/why3.conf", Path(fc)]}
    receipt["limitation"] = "Bounded proof progress only; common toolchain/assumption/integrity gates remain required. No target-runtime or L2 claim."
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--kernel", type=Path, default=ROOT.parent / "linux")
    parser.add_argument("--prefix", type=Path, default=ROOT / "toolchain/verified-prefix")
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 30:
        parser.error("bounded baseline timeout must be 1..30 seconds per prover goal")
    result = run(args.output, args.kernel.resolve(), args.prefix, args.timeout)
    print(json.dumps({key: result.get(key) for key in ("ordinary_complete", "ordinary_counts", "selected_property_counts", "certified")}, indent=2))
    sys.exit(0 if result["ordinary_complete"] else 2)
