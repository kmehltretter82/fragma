#!/usr/bin/env python3
"""Retain 14 additional private Hexagon context pairs without awarding support.

Exactly 30 direct queries: two versions, 14 Clang textual LLVM IR emissions,
14 private core-only Frama-C parses with explicit pinned preprocessing.
No object/link/target execution, proof, kernel build, installation or promotion.
This is raw observation collection. Diagnostics, printed ASTs and disagreements
require subsequent review; return zero denotes complete transport/evidence only.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import types

BASE = Path(__file__).resolve().parent
RECORDER = BASE / "diagnose_candidate_context_v4.py"
RECORDER_SHA = "7ecdaa5762f22d1c7979f2aba81cb23b29246acf24c17e469da34a247cf10dde"
CLASSIFIER_SHA = "ca315f499eff71d75a05d1a1100cdb8ae5a51fa8d119870c0f63e7d778b7d8a8"
PREVIOUS_SHA = "51afd1958922a9daccd60ae0b2ada84a7acd49ad8363c7ef52ffe26eaac47e5e"
FIXTURES = BASE / "extra_context_fixtures.py"
QUERIES = 30
SECONDS = 300
SUCCESS = "private-extra-observations-complete-unclassified-not-support"


def load_recorder():
    if RECORDER.resolve() != RECORDER or RECORDER.stat().st_size > 65536:
        raise ValueError("Recorder path/size changed")
    data = RECORDER.read_bytes()
    if len(data) > 65536 or hashlib.sha256(data).hexdigest() != RECORDER_SHA:
        raise ValueError("Frozen recorder pin changed")
    module = types.ModuleType("fragma_extra_frozen_context_recorder")
    module.__file__ = str(RECORDER)
    exec(compile(data, str(RECORDER), "exec"), module.__dict__)
    return module


def snapshot(d, rt, c, h, old, specifications, sources, fixture_pin):
    original, binary = d.snapshot(rt, c, h, old, CLASSIFIER_SHA, d.OLD_RUN / "sources")
    previous, artifacts = d.retained_tree(c, h, BASE / "extra-context-run-2", PREVIOUS_SHA)
    d.require(previous["input_drift"] is False and not previous["cancelled"]
              and previous["status"] == SUCCESS and len(previous["commands"]) == QUERIES,
              "Previous raw extra context prerequisite changed")
    selected = {str(path): d.record(h, path) for path in (Path(__file__).resolve(), RECORDER, FIXTURES)}
    d.require(selected[str(RECORDER)]["sha256"] == RECORDER_SHA
              and selected[str(FIXTURES)]["sha256"] == fixture_pin, "New recorder/fixture inputs changed")
    actual = h.inventory(sources)
    d.require(set(actual) == {case["fixture"] + ".c" for case in specifications}, "Extra source inventory changed")
    for case in specifications:
        row = actual[case["fixture"] + ".c"]
        d.require(row["kind"] == "file"
                  and row["sha256"] == hashlib.sha256(case["source"].encode("utf-8")).hexdigest(),
                  "Extra source bytes differ from reviewed fixture inventory")
    return {"context_prerequisites": original, "previous_extra_artifacts": artifacts,
            "selected_extra": selected, "extra_sources": actual, "specifications": specifications}, binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fixtures-sha256", required=True)
    args = parser.parse_args()
    d = load_recorder()
    d.require(re.fullmatch(r"[0-9a-f]{64}", args.fixtures_sha256), "Need explicit reviewed fixture SHA")
    fixtures = d.load(FIXTURES, args.fixtures_sha256)
    rt = d.load(BASE / "check_candidate_runtime_v4.py", d.PINS[BASE / "check_candidate_runtime_v4.py"])
    c = rt.load_builder(d.PINS[BASE / "build_candidate_v4.py"])
    h = c.load_helper()
    old = d.load(d.OLD_BASE / "diagnose-v2.py", d.PINS[d.OLD_BASE / "diagnose-v2.py"])
    d.require(all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID"))
              and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "Need unreaped-leader process handling")
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)
    output = Path(os.path.abspath(args.output))
    d.require(output.parent == BASE and re.fullmatch(r"extra-context-run-[1-9][0-9]*", output.name)
              and not os.path.lexists(output), "Need fresh private extra-context-run-N")
    specifications = fixtures.inventory()
    d.require(len(specifications) == 14 and len({v["fixture"] for v in specifications}) == 14,
              "Need exactly 14 unique reviewed controls")
    for case in specifications:
        d.require(re.fullmatch(r"[a-z][a-z0-9-]*", case["fixture"])
                  and 0 < len(case["source"].encode("utf-8")) <= 8192
                  and not re.search(r"(?m)^\s*#\s*include\b", case["source"]),
                  "Unexpected extra fixture path/size/include")
    cases = [{k: v for k, v in case.items() if k != "source"} for case in specifications]
    output.mkdir(mode=0o700)
    report = {"schema_version": 1, "scope": __doc__, "status": "failed", "started_at": h.stamp(),
              "integration_eligible": False, "alignment_resolution_established": False,
              "semantic_validation_complete": False, "query_limit": QUERIES, "query_budget_seconds": SECONDS,
              "deadline_scope": "monitored queries; cleanup/final hashing may finish later",
              "commands": [], "input_drift": None, "launch": vars(args)}
    before = None
    try:
        h.save(output / "request.json", report)
        sources = output / "sources"
        sources.mkdir(mode=0o700)
        for case in specifications:
            with (sources / (case["fixture"] + ".c")).open("xb") as stream:
                stream.write(case["source"].encode("utf-8"))
        before, binary = snapshot(d, rt, c, h, old, specifications, sources, args.fixtures_sha256)
        h.save(output / "inputs-before.json", before)
        h.save(output / "case-inventory.json", cases)
        deadline = time.monotonic() + SECONDS
        for case in [None, *cases]:
            for tool in ("compiler", "analyzer"):
                index = len(report["commands"]) + 1
                d.require(index <= QUERIES, "Extra query count exceeded")
                row = d.invoke(rt, c, h, binary, tool, case, index, output, sources, deadline, report["commands"])
                d.require(not row.get("transport_error"), "Transport failed; no automatic retry")
                folder = Path(row["cwd"])
                read = lambda name: c.checked_bytes(h, folder / name, limit=d.FILE_LIMIT)[0].decode("utf-8")
                stdout, stderr = read("stdout"), read("stderr")
                observation = {"status": "raw-result-not-semantically-classified", "returncode": row["returncode"],
                               "stdout_bytes": len(stdout.encode("utf-8")), "stderr_bytes": len(stderr.encode("utf-8"))}
                if case is None:
                    expected = ((d.OLD_RUN / "command-001/stdout").read_text() if tool == "compiler"
                                else "33.0 (Arsenic)\n")
                    d.require(row["returncode"] == 0 and stdout == expected and not stderr, "Version gate failed")
                    observation["status"] = "version-checked"
                elif tool == "analyzer":
                    row["preprocessing"] = d.preprocess_evidence(c, h, row, case, folder, sources,
                        {v["absolute_path"] for v in before["context_prerequisites"]["libc_targets"].values()})
                    observation["printed_source"] = (d.record(h, folder / "printed.c")
                                                     if (folder / "printed.c").is_file() else None)
                row["observation"] = observation
                h.save(folder / "observation.json", {"observation": observation,
                                                     "preprocessing": row.get("preprocessing")})
                d.quota(h, output, d.TOTAL_BYTES, 10000)
        d.require(len(report["commands"]) == QUERIES, "Incomplete extra context inventory")
        report["raw_returncode_counts"] = dict(Counter(row["tool"] + ":" + str(row["returncode"])
            for row in report["commands"] if row["case"] is not None))
        report["status"] = SUCCESS
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = repr(exc)
    finally:
        errors = []
        if before is not None:
            try:
                after, _ = snapshot(d, rt, c, h, old, specifications, sources, args.fixtures_sha256)
                h.save(output / "inputs-after.json", after)
                report["input_drift"] = before != after
                d.require(before == after, "Extra context inputs changed")
            except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
                errors.append("inputs: " + repr(exc))
        try:
            d.quota(h, output, d.TOTAL_BYTES, 10000)
            report["artifacts"] = h.inventory(output)
        except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
            errors.append("artifacts: " + repr(exc))
        report["cancelled"] = h.CANCELLED
        report["cancellation_sampling_boundary"] = "after inventories, before receipt serialization"
        if errors or h.CANCELLED:
            report.update(status="failed", finalization_errors=errors)
        report["finished_at"] = h.stamp()
        try:
            h.save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({k: report.get(k) for k in ("status", "error", "raw_returncode_counts", "input_drift",
                                               "finalization_errors", "receipt_write_error")}
                     | {"cancelled_at_exit_sample": h.CANCELLED}))
    return 0 if report["status"] == SUCCESS and report["input_drift"] is False and not h.CANCELLED else 1


if __name__ == "__main__":
    raise SystemExit(main())
