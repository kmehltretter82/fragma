#!/usr/bin/env python3
"""One bounded I/U cast/bitfield strategy probe, preserving baseline contracts."""
import argparse
from collections import Counter
import copy
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fragma.inputs import run_recorded
from fragma.report import ReportError, parse_properties, parse_wp_report
from fragma.sources import sha256
from fragma.toolchain import prepare_environment


def summarize(output, functions):
    record = {"ordinary_complete": False, "certified": False}
    try:
        goals = parse_wp_report(output / "goals.json")
        properties = parse_properties(output / "properties.tsv")
    except ReportError as exc:
        # Raw counts help diagnose an unsupported tool verdict but are never
        # normalized into proof outcomes or substituted for strict parsing.
        record["report_error"] = str(exc)
        raw = json.loads((output / "goals.json").read_text())
        record["raw_ordinary_counts"] = dict(Counter(goal["verdict"] for goal in raw if not goal["smoke"]))
        record["raw_smoke_counts"] = dict(Counter(goal["verdict"] for goal in raw if goal["smoke"]))
        return record
    normal = [goal for goal in goals if not goal["smoke"]]
    selected = [prop for prop in properties if prop["function"] in functions]
    record["ordinary_counts"] = dict(Counter(goal["verdict"] for goal in normal))
    record["selected_property_counts"] = dict(Counter(prop["status"] for prop in selected))
    record["ordinary_complete"] = bool(normal and selected) and all(goal["verdict"] == "valid" for goal in normal) and all(prop["status"] == "Valid" for prop in selected)
    return record


def run(baseline, output):
    baseline, output = baseline.resolve(), output.resolve()
    original = json.loads((baseline / "receipt.json").read_text())
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    header = ROOT / "riscv/annotated/encoder-bitproof.h"
    functions = ["rv_i_insn", "rv_u_insn"]
    target = original["target"]
    if sha256(ROOT / target["harness"]) != original["source_gate"]["harness"]["sha256"]:
        raise ValueError("baseline harness changed; no strategy comparison")
    model = original["model"]
    if sha256(Path(model["machdep"]["path"])) != model["machdep"]["sha256"]:
        raise ValueError("baseline model changed")
    argv = list(original["command"]["argv"])
    for flag, value in (("-wp-fct", ",".join(functions)), ("-wp-prover", "tip"),
                        ("-wp-timeout", "2"), ("-wp-session", str(output / "session")),
                        ("-wp-report-json", str(output / "goals.json")),
                        ("-report-csv", str(output / "properties.tsv")),
                        ("-audit-prepare", str(output / "audit.json"))):
        argv[argv.index(flag) + 1] = value
    pos = argv.index("-wp")
    argv[pos:pos] = [str(header), "-wp-strategy", "fragma_encoder_fields", "-wp-auto-depth", "32",
                     "-wp-msg-key", "strategy,script:allgoals"]
    env = prepare_environment(ROOT, environ={**os.environ,
        "FRAGMA_TOOLCHAIN_PREFIX": str(ROOT / "toolchain/verified-prefix")})
    env = {key: value for key, value in env.items() if key not in
           ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH")}
    record = {"scope": functions, "baseline": str(baseline), "certified": False,
              "source_gate": copy.deepcopy(original["source_gate"]),
              "input_hashes": {str(path): sha256(path) for path in
                  (baseline / "receipt.json", ROOT / target["harness"], header, Path(model["machdep"]["path"]), Path(argv[0]))}}
    (output / "receipt.json").write_text(json.dumps({**record, "status": "running", "argv": argv}, indent=2) + "\n")
    record["command"] = run_recorded(argv, cwd=Path(original["prepared"]["cwd"]),
        env={**env, "TMPDIR": str(output / "tmp")}, log=output / "analysis.log", timeout=150)
    if record["command"]["returncode"] == 0:
        record.update(summarize(output, functions))
    record["changed_inputs"] = [path for path, expected in record["input_hashes"].items() if sha256(Path(path)) != expected]
    record["limitation"] = "Experimental search only: no amended verdicts, assumptions, proof certificates, or contract/domain changes."
    (output / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--summarize-only", action="store_true", help="write a new post-hoc summary, without replay or changing reports")
    args = parser.parse_args()
    if args.summarize_only:
        summary_path = args.output / "summary.json"
        if summary_path.exists():
            parser.error("post-hoc summary already exists; retain it")
        result = summarize(args.output, ["rv_i_insn", "rv_u_insn"])
        result.update(kind="post-hoc-report-summary", limitation="Not a process receipt or proof certificate.",
            report_hashes={name: sha256(args.output / name) for name in ("goals.json", "properties.tsv", "analysis.log")})
        summary_path.write_text(json.dumps(result, indent=2) + "\n")
    else:
        result = run(args.baseline, args.output)
    print(json.dumps({key: result[key] for key in ("ordinary_counts", "raw_ordinary_counts", "raw_smoke_counts",
        "selected_property_counts", "ordinary_complete", "changed_inputs", "report_error") if key in result}, indent=2))
