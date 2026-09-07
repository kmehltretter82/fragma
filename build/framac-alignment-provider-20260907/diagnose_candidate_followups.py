#!/usr/bin/env python3
"""Retain 44 private followup controls and their conditional printed-C reparses.

A fixed 222-row plan permits at most 222 direct queries: two versions, then
Clang textual LLVM IR, core-only checked Frama-C with/without constfold, and
one matching-mode reparse of each successful parent's printed C per case.
Unavailable parent output causes an explicit no-child skip, never a retry.
No object/link/target execution, proof, kernel build, installation or promotion.
This is raw evidence collection, not semantic classification or support.
Selected closure/process-group checks are not hermetic descendant attestation.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import stat
import subprocess
import time
import types

BASE = Path(__file__).resolve().parent
RECORDER = BASE / "diagnose_candidate_context_v4.py"
RECORDER_SHA = "7ecdaa5762f22d1c7979f2aba81cb23b29246acf24c17e469da34a247cf10dde"
CLASSIFIER_SHA = "ca315f499eff71d75a05d1a1100cdb8ae5a51fa8d119870c0f63e7d778b7d8a8"
ARITHMETIC = BASE / "arithmetic_followup_fixtures.py"
VLA = BASE / "vla_followup_fixtures.py"
FILE_LIMIT = 1024 * 1024
TOTAL_BYTES = 128 * FILE_LIMIT
TOTAL_ENTRIES = 15000
QUERY_BYTES = 8 * FILE_LIMIT
QUERY_ENTRIES = 520
QUERY_LIMIT = 222
SECONDS = 900
SUCCESS = "private-followup-raw-collection-complete-unclassified-not-support"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(path, expected, *, pure=False):
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "Reviewed module SHA is not pinned")
    require(path.resolve() == path, "Reviewed module path is symlinked")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 65536,
            "Reviewed module path/type/size changed")
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(65537)
        after = os.fstat(stream.fileno())
    require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() == expected
            and signature(before) == signature(opened) == signature(after) == signature(path.lstat()),
            "Reviewed module bytes changed: " + str(path))
    tree = ast.parse(data, str(path))
    if pure:
        require(len(tree.body) == 2 and isinstance(tree.body[0], ast.Expr)
                and isinstance(tree.body[0].value, ast.Constant)
                and isinstance(tree.body[0].value.value, str)
                and isinstance(tree.body[1], ast.FunctionDef)
                and tree.body[1].name == "inventory"
                and not any(isinstance(n, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal))
                            for n in ast.walk(tree)), "Unexpected pure fixture module shape")
    module = types.ModuleType("fragma_followup_reviewed_" + path.stem)
    module.__file__ = str(path)
    exec(compile(tree, str(path), "exec"), module.__dict__)
    return module


def snapshot(d, rt, c, h, old, specifications, sources, pins):
    original, binary = d.snapshot(rt, c, h, old, CLASSIFIER_SHA, d.OLD_RUN / "sources")
    selected = {str(path): d.record(h, path)
                for path in (Path(__file__).resolve(), RECORDER, ARITHMETIC, VLA)}
    for path, pin in pins.items():
        require(selected[str(path)]["sha256"] == pin, "Followup module input changed")
    actual = h.inventory(sources)
    require(set(actual) == {case["fixture"] + ".c" for case in specifications},
            "Followup source inventory changed")
    for case in specifications:
        row = actual[case["fixture"] + ".c"]
        require(row["kind"] == "file"
                and row["sha256"] == hashlib.sha256(case["source"].encode("utf-8")).hexdigest(),
                "Followup source differs from reviewed inventory")
    return {"context_prerequisites": original, "selected_followups": selected,
            "sources": actual, "specifications": specifications}, binary


def command(d, binary, tool, phase, case, folder, source):
    if case is None:
        return [d.COMPILER, "--version"] if tool == "compiler" else [str(binary), "-version"]
    define = [] if case["alignment"] is None else ["-DFRAGMA_ALIGNMENT=" + str(case["alignment"])]
    if tool == "compiler":
        return [d.COMPILER, *d.ARCH_FLAGS, "-nostdinc", *define,
                "-S", "-emit-llvm", str(source), "-o", "-"]
    fold = ["-constfold"] if phase.endswith("-fold") else []
    return [str(binary), "-no-autoload-plugins", "-check", "-machdep", str(d.POLICY),
            "-cpp-command", shlex.join([d.COMPILER, "-E", "-C", *d.ARCH_FLAGS, *define]),
            "-cpp-frama-c-compliant",
            "-cpp-extra-args=" + shlex.join(["-nostdinc", "-I", str(d.LIBC)]),
            "-keep-temp-files", "-kernel-msg-key", "pp", *fold, "-print",
            "-ocode", str(folder / "printed.c"), str(source)]


def query_plan(d, rt, c, h, binary, cases, output, sources):
    plan = []

    def add(tool, phase, case=None, parent_index=None):
        index = len(plan) + 1
        folder = output / ("command-%03d" % index)
        source = (None if case is None else
                  output / ("command-%03d" % parent_index) / "printed.c"
                  if parent_index is not None else sources / (case["fixture"] + ".c"))
        temporary = folder / "private-temp"
        environment = (rt.runtime_environment(h, c, d.BUILD, temporary)[0]
                       if tool == "analyzer" else
                       {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TMPDIR": str(temporary)})
        plan.append({"index": index, "tool": tool, "phase": phase, "case": case,
                     "parent_index": parent_index, "source": None if source is None else str(source),
                     "argv": command(d, binary, tool, phase, case, folder, source),
                     "cwd": str(folder), "environment": environment, "stdin": "DEVNULL"})

    add("compiler", "version")
    add("analyzer", "version")
    for case in cases:
        first = len(plan) + 1
        add("compiler", "compiler-ir", case)
        add("analyzer", "analyzer-fold", case)
        add("analyzer", "analyzer-plain", case)
        add("analyzer", "reparse-fold", case, first + 1)
        add("analyzer", "reparse-plain", case, first + 2)
    require(len(plan) == QUERY_LIMIT, "Fixed followup plan must have 222 rows")
    return plan


def quota(h, folder, maximum, entries, *, query=False):
    items = h.inventory(folder, hash_files=False)
    require(len(items) <= entries and sum(v.get("size", 0) for v in items.values()) <= maximum,
            "Monitored followup output quota exceeded")
    if query:
        require(all(v.get("size", 0) <= FILE_LIMIT for v in items.values()),
                "Per-query file limit exceeded")
    return items


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def checked_source(c, h, path):
    data, row = c.checked_bytes(h, path, limit=FILE_LIMIT)
    require(data and b"\0" not in data, "Query source is empty or contains NUL")
    data.decode("utf-8")
    return {"path": str(path), **row}


def invoke(c, h, planned, deadline, commands, source_pin=None):
    """Local copy of reviewed d.invoke mechanics; explicit plan argv/environment.

    No recorder globals are modified. Never reap/signal the original leader
    before the reviewed finish_process_group helper can verify its identity.
    """
    require(1 <= planned["index"] <= QUERY_LIMIT
            and planned["index"] == len(commands) + 1, "Direct query index exceeded/repeated")
    folder = Path(planned["cwd"])
    folder.mkdir(mode=0o700)
    (folder / "private-temp").mkdir(mode=0o700)
    query_deadline = min(deadline, time.monotonic() + (10 if planned["tool"] == "compiler" else 30))
    row = {**planned, "execution": "planned", "started_at": h.stamp(),
           "child_started": False, "child_terminal": None, "returncode": None,
           "timeout_seconds": max(0, query_deadline - time.monotonic())}
    commands.append(row)
    proc = None
    try:
        if planned["source"] is not None:
            row["source_before"] = checked_source(c, h, Path(planned["source"]))
            require(source_pin is not None and row["source_before"] == source_pin,
                    "Explicit query source pin differs immediately before launch")
        h.save(folder / "intent.json", row)
        with (folder / "stdout").open("xb") as out, (folder / "stderr").open("xb") as err:
            require(not h.CANCELLED and time.monotonic() < query_deadline,
                    "Cancelled or followup query deadline exceeded")
            proc = subprocess.Popen(row["argv"], cwd=folder, env=row["environment"],
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    start_new_session=True, preexec_fn=child_limits)
            row.update(execution="executed", child_started=True, child_pid=proc.pid, child_terminal=False)
            h.save(folder / "process.json", {"pid": proc.pid, "argv": row["argv"]})
            next_quota = time.monotonic()
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                require(not h.CANCELLED and time.monotonic() < query_deadline,
                        "Cancelled or followup query deadline exceeded")
                if time.monotonic() >= next_quota:
                    quota(h, folder, QUERY_BYTES, QUERY_ENTRIES, query=True)
                    next_quota = time.monotonic() + 1
                time.sleep(0.05)
            require(not h.CANCELLED and time.monotonic() <= query_deadline,
                    "Followup query completed beyond deadline/cancellation")
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        row["transport_error"] = repr(exc)
    finally:
        if proc is not None:
            try:
                group = c.finish_process_group(proc)
                row.update(process_group=group, returncode=group["returncode"], child_terminal=group["leader_reaped"])
                if (not group["group_terminal"] or not group["leader_reaped"] or group["cleanup_error"]
                        or group["nonleader_members_observed"] or group["live_members_remaining"]
                        or group["returncode"] is None or group["returncode"] < 0):
                    row["transport_error"] = "Original process group/termination failed"
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
                row.update(transport_error="Group closure failed: " + repr(exc), child_terminal=False)
        row["finished_at"] = h.stamp()
        if planned["source"] is not None:
            try:
                row["source_after"] = checked_source(c, h, Path(planned["source"]))
                require(row["source_after"] == source_pin == row.get("source_before"),
                        "Query source changed during invocation")
            except (OSError, ValueError, KeyError, UnicodeError) as exc:
                row["transport_error"] = "Source retention failed: " + repr(exc)
        try:
            quota(h, folder, QUERY_BYTES, QUERY_ENTRIES, query=True)
            row["artifacts"] = h.inventory(folder)
            require(all(v["kind"] in ("file", "directory") for v in row["artifacts"].values()),
                    "Unexpected query artifact type/link")
            require(not any(Path(name).suffix in (".o", ".obj", ".s", ".bc", ".a", ".so")
                            for name in row["artifacts"]), "Unexpected nontext compilation artifact")
            h.save(folder / "result.json", row)
        except (OSError, ValueError, KeyError) as exc:
            row["transport_error"] = "Artifact retention failed: " + repr(exc)
    return row


def skip(h, planned, commands, reason, parent=None):
    require(planned["index"] == len(commands) + 1 and planned["index"] <= QUERY_LIMIT,
            "Skipped query index exceeded/repeated")
    folder = Path(planned["cwd"])
    folder.mkdir(mode=0o700)
    row = {**planned, "execution": "skipped", "skip_reason": reason,
           "child_started": False, "child_terminal": None, "returncode": None,
           "started_at": None, "finished_at": h.stamp()}
    if parent is not None:
        row["parent_outcome"] = {"index": parent["index"], "execution": parent["execution"],
                                 "returncode": parent["returncode"],
                                 "result_path": str(Path(parent["cwd"]) / "result.json")}
    commands.append(row)
    h.save(folder / "intent.json", row)
    row["artifacts"] = h.inventory(folder)
    h.save(folder / "result.json", row)
    return row


def preprocess_evidence(d, c, h, folder, source, case, libc_targets):
    """Exact supplied source only; no basename-based or old-fixture exceptions."""
    temporary = folder / "private-temp"
    files = h.inventory(temporary)
    require(all(v["kind"] in ("file", "directory") for v in files.values()),
            "Unexpected temporary link/type")
    suffix = lambda ending: [temporary / p for p, v in files.items()
                             if v["kind"] == "file" and p.endswith(ending)]
    inputs, headers, macros = suffix(".i"), suffix("/__fc_machdep.h"), suffix("/__fc_builtin_macros.h")
    require(len(inputs) == len(headers) == len(macros) == 1 and headers[0].parent == macros[0].parent,
            "Missing/ambiguous private preprocessing artifacts")
    text = lambda p: c.checked_bytes(h, p, limit=FILE_LIMIT)[0].decode("utf-8")
    require(re.findall(r"(?m)^#\s*define\s+__MAX_ALIGN_T\s+([^\n]+)$", text(headers[0])) == [d.DEFINITION],
            "Generated max_align_t changed")
    define = [] if case["alignment"] is None else ["-DFRAGMA_ALIGNMENT=" + str(case["alignment"])]
    expected = [d.COMPILER, "-E", "-C", *d.ARCH_FLAGS, *define, "-I" + str(headers[0].parent),
                "-I" + str(d.LIBC), "-U__STDC_IEC_559_COMPLEX__", "-U__STDC_IEC_60559_COMPLEX__",
                "-U__STDC_ISO_10646__", "-U__STDC_UTF16__", "-U__STDC_UTF32__", "-D__FRAMAC__", "-dD", "-nostdinc",
                "-undef", "-imacros", "__fc_builtin_macros.h", "-nostdinc", "-I", str(d.LIBC),
                str(source), "-o", str(inputs[0])]
    stdout = text(folder / "stdout")
    first = re.findall(r'(?m)^  preprocessing with "([^\n]*)"$', stdout)
    second = re.findall(r"(?m)^  Full preprocessing command: ([^\n]*)$", stdout)
    parsing = re.findall(r"(?m)^\[kernel\] Parsing ([^\n]+) \(with preprocessing\)$", stdout)
    require(len(first) == len(second) == 1 and parsing == [str(source)]
            and shlex.split(first[0]) == shlex.split(second[0]) == expected,
            "Actual preprocessing/Parsing command differs from exact supplied source")
    markers = []
    for name in re.findall(r'(?m)^#\s+(?:line\s+)?\d+\s+"([^"\n]+)"', text(inputs[0])):
        if name in ("<built-in>", "<command line>", "<command-line>"):
            continue
        path = Path(name)
        if not path.is_absolute():
            path = folder / path
        actual = path.resolve(strict=True)
        require(actual == source.resolve() or actual.is_relative_to(temporary.resolve())
                or str(actual) in libc_targets, "Unexpected preprocessing input: " + name)
        markers.append({"spelling": name, "resolved": str(actual), "file": d.record(h, actual)})
    require(any(m["resolved"] == str(source.resolve()) for m in markers), "Source missing from linemarkers")
    return {"status": "exact-private-preprocessing-closure-recorded", "actual_argv": expected,
            "source": d.record(h, source), "preprocessed": d.record(h, inputs[0]),
            "machdep_header": d.record(h, headers[0]), "builtin_header": d.record(h, macros[0]),
            "linemarkers": markers}


def observe(d, c, h, row, libc_targets):
    folder = Path(row["cwd"])
    read = lambda name: c.checked_bytes(h, folder / name, limit=FILE_LIMIT)
    stdout, stdout_row = read("stdout")
    stderr, stderr_row = read("stderr")
    observation = {"status": "raw-result-not-semantically-classified", "returncode": row["returncode"],
                   "stdout": stdout_row, "stderr": stderr_row, "printed_source": None}
    if row["case"] is None:
        expected = (c.checked_bytes(h, d.OLD_RUN / "command-001/stdout", limit=FILE_LIMIT)[0]
                    if row["tool"] == "compiler" else b"33.0 (Arsenic)\n")
        require(row["returncode"] == 0 and stdout == expected and not stderr, "Version gate failed")
        observation["status"] = "version-checked"
    elif row["tool"] == "analyzer":
        try:
            row["preprocessing"] = preprocess_evidence(
                d, c, h, folder, Path(row["source"]), row["case"], libc_targets)
        except (OSError, ValueError, KeyError, UnicodeError) as exc:
            row["preprocessing"] = {"status": "unverified-or-unavailable", "reason": repr(exc)}
        if os.path.lexists(folder / "printed.c"):
            try:
                observation["printed_source"] = checked_source(c, h, folder / "printed.c")
            except (OSError, ValueError, KeyError, UnicodeError) as exc:
                observation["printed_source_error"] = repr(exc)
    row["observation"] = observation
    h.save(folder / "observation.json", {"observation": observation,
                                         "preprocessing": row.get("preprocessing")})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--arithmetic-fixtures-sha256", required=True)
    parser.add_argument("--vla-fixtures-sha256", required=True)
    args = parser.parse_args()
    pins = {RECORDER: RECORDER_SHA, ARITHMETIC: args.arithmetic_fixtures_sha256,
            VLA: args.vla_fixtures_sha256}
    d = load(RECORDER, RECORDER_SHA)
    arithmetic = load(ARITHMETIC, pins[ARITHMETIC], pure=True).inventory()
    vla = load(VLA, pins[VLA], pure=True).inventory()
    require(len(arithmetic) == 20 and len(vla) == 24, "Need exactly 20 arithmetic and 24 VLA controls")
    specifications = arithmetic + vla
    require(len({case["fixture"] for case in specifications}) == 44, "Followup fixture names are not unique")
    for case in specifications:
        require(re.fullmatch(r"[a-z][a-z0-9-]*", case["fixture"])
                and 0 < len(case["source"].encode("utf-8")) <= 8192
                and not re.search(r"(?m)^\s*#\s*include\b", case["source"])
                and case["alignment"] is None
                and 1 <= len(case["fields"]) <= 8
                and len(set(case["fields"])) == len(case["fields"]), "Unexpected followup source/case shape")
    rt_path, c_path = BASE / "check_candidate_runtime_v4.py", BASE / "build_candidate_v4.py"
    require(d.BUILD == BASE / "candidate-build-4" and d.RUNTIME == BASE / "candidate-runtime-4",
            "Context reader is not the fixed fourth private candidate")
    rt = d.load(rt_path, d.PINS[rt_path])
    c = rt.load_builder(d.PINS[c_path])
    h = c.load_helper()
    old = d.load(d.OLD_BASE / "diagnose-v2.py", d.PINS[d.OLD_BASE / "diagnose-v2.py"])
    require(all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID"))
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "Need unreaped-leader process handling")
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)
    output = Path(os.path.abspath(args.output))
    require(output.parent == BASE and re.fullmatch(r"followup-run-[1-9][0-9]*", output.name)
            and output.resolve() == output and not os.path.lexists(output), "Need fresh private followup-run-N")
    cases = [{k: v for k, v in case.items() if k != "source"} for case in specifications]
    output.mkdir(mode=0o700)
    report = {"schema_version": 1, "scope": __doc__, "status": "failed", "started_at": h.stamp(),
              "integration_eligible": False, "alignment_resolution_established": False,
              "semantic_validation_complete": False, "query_limit": QUERY_LIMIT,
              "query_budget_seconds": SECONDS, "planned_case_count": 44,
              "deadline_scope": "monitored child queries; skips/cleanup/final hashes may finish later",
              "commands": [], "input_drift": None, "launch": vars(args)}
    before, plan = None, []
    try:
        h.save(output / "request.json", report)
        sources = output / "sources"
        sources.mkdir(mode=0o700)
        for case in specifications:
            with (sources / (case["fixture"] + ".c")).open("xb") as stream:
                stream.write(case["source"].encode("utf-8"))
        before, binary = snapshot(d, rt, c, h, old, specifications, sources, pins)
        h.save(output / "inputs-before.json", before)
        h.save(output / "case-inventory.json", cases)
        plan = query_plan(d, rt, c, h, binary, cases, output, sources)
        h.save(output / "query-plan.json", plan)
        report["query_plan"] = d.record(h, output / "query-plan.json")
        libc_targets = {v["absolute_path"] for v in before["context_prerequisites"]["libc_targets"].values()}
        deadline = time.monotonic() + SECONDS
        for planned in plan:
            require(not h.CANCELLED and time.monotonic() < deadline, "Cancelled or followup deadline exceeded")
            source_pin = None
            if planned["parent_index"] is not None:
                parent = report["commands"][planned["parent_index"] - 1]
                require(parent["phase"] == planned["phase"].replace("reparse", "analyzer")
                        and parent["case"] == planned["case"], "Reparse parent differs from fixed plan")
                if parent["execution"] != "executed" or parent["returncode"] != 0:
                    skip(h, planned, report["commands"], "parent-not-successful", parent)
                    continue
                source_pin = parent.get("observation", {}).get("printed_source")
                if source_pin is None:
                    skip(h, planned, report["commands"], "parent-has-no-bounded-regular-printed-source", parent)
                    continue
            elif planned["source"] is not None:
                path = Path(planned["source"])
                source_pin = {"path": str(path), **before["sources"][path.name]}
            row = invoke(c, h, planned, deadline, report["commands"], source_pin)
            require(not row.get("transport_error"), "Transport failed; no retry")
            observe(d, c, h, row, libc_targets)
            quota(h, output, TOTAL_BYTES, TOTAL_ENTRIES)
        require(len(report["commands"]) == QUERY_LIMIT, "Incomplete fixed followup plan")
        report["preprocessing_closure_complete"] = all(
            row.get("preprocessing", {}).get("status") == "exact-private-preprocessing-closure-recorded"
            for row in report["commands"]
            if row["execution"] == "executed" and row["tool"] == "analyzer" and row["case"] is not None)
        report["printed_source_checks_complete"] = not any(
            row.get("observation", {}).get("printed_source_error") for row in report["commands"])
        report["status"] = SUCCESS
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = repr(exc)
    finally:
        errors = []
        if plan:
            try:
                for planned in plan[len(report["commands"]):]:
                    skip(h, planned, report["commands"], "batch-stopped-before-launch: "
                         + report.get("error", "incomplete batch"))
            except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
                errors.append("unlaunched-plan-retention: " + repr(exc))
        if before is not None:
            try:
                after, _ = snapshot(d, rt, c, h, old, specifications, sources, pins)
                h.save(output / "inputs-after.json", after)
                report["input_drift"] = before != after
                require(before == after, "Followup selected inputs changed")
                require(d.record(h, output / "query-plan.json") == report["query_plan"], "Fixed query plan drift")
            except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
                errors.append("inputs: " + repr(exc))
        report["executed_query_count"] = sum(row["child_started"] is True for row in report["commands"])
        report["skipped_query_count"] = sum(row["execution"] == "skipped" for row in report["commands"])
        report["raw_returncode_counts"] = dict(Counter(
            row["phase"] + ":" + str(row["returncode"]) for row in report["commands"]
            if row["execution"] == "executed"))
        try:
            quota(h, output, TOTAL_BYTES, TOTAL_ENTRIES)
            report["artifacts"] = h.inventory(output)
        except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
            errors.append("artifacts: " + repr(exc))
        report["cancelled"] = h.CANCELLED
        report["cancellation_sampling_boundary"] = "after inventories, before receipt serialization"
        report["late_cancellation_policy"] = "later observed cancellation forces nonzero exit"
        if errors or h.CANCELLED:
            report.update(status="failed", finalization_errors=errors)
        report["finished_at"] = h.stamp()
        try:
            h.save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({k: report.get(k) for k in ("status", "error", "executed_query_count",
        "skipped_query_count", "raw_returncode_counts", "input_drift", "preprocessing_closure_complete",
        "printed_source_checks_complete", "finalization_errors", "receipt_write_error")}
        | {"cancelled_at_exit_sample": h.CANCELLED}))
    return 0 if (report["status"] == SUCCESS and report["input_drift"] is False
                 and report.get("preprocessing_closure_complete") is True
                 and report.get("printed_source_checks_complete") is True and not h.CANCELLED) else 1


if __name__ == "__main__":
    raise SystemExit(main())
