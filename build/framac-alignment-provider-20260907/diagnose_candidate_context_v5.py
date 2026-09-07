#!/usr/bin/env python3
"""Repeat all 55 unchanged pairs against the fresh VLA-bound local-init candidate.

The executed V1/V2/V3/V4 recorders, classifiers and receipts remain unchanged. The
V4 retained artifact tree is checked before and after this fresh execution.

Exactly 112 direct queries: two versions, 55 textual LLVM IR emissions, 55
core-only Frama-C parses with an explicit pinned Clang preprocessor. No objects,
linking, target execution, WP/Eva, kernel build, installation or promotion.
Unknown diagnostics, unsupported semantics and disagreements remain visible.
Historical receipts are retained, not reclassified into current approval.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import time
import types

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
OLD_BASE = ROOT / "build/hexagon-alignment-context-20260906"
OLD_RUN = OLD_BASE / "run-1"
BUILD = BASE / "candidate-build-5"
RUNTIME = BASE / "candidate-runtime-5"
POLICY = BASE / "candidate-policy.yaml"
ORIGINAL_POLICY = ROOT / "build/hexagon-max-align-20260906/generator-2/candidate.yaml"
COMPILER = "/usr/bin/clang-21"
RESOURCE = Path("/usr/lib/llvm-21/lib/clang/21/include")
LIBC = BUILD / "dune-build/install/default/share/frama-c/share/libc"
ARCH_FLAGS = ["--target=hexagon-linux-musl", "-mv68", "-G0", "-fno-short-enums",
              "-mlong-calls", "-ffixed-r19", "-DTHREADINFO_REG=r19", "-D__linux__",
              "-std=gnu11", "-funsigned-char", "-fshort-wchar", "-fno-strict-overflow",
              "-fno-strict-aliasing", "-ffreestanding"]
PINS = {
    BASE / "diagnose_candidate_context.py": "c51f15b50e9c6c7f404b91bdd80eaf312013080c6382ed61efa904113e7d06b6",
    BASE / "context_classifiers.py": "37419daca86065f5586eca22ee917ae7fea430976092331e8528b92501427050",
    BASE / "context-run-4/receipt.json": "7e0602c7da3fc42de389f04f8511fca2a7085e630668a6d60753fbc4fa2a7824",
    OLD_BASE / "diagnose-v2.py": "7ce09c8784d9d2c16dd29d98b024ad688d8653923200f43411c283be17ac6cf0",
    OLD_RUN / "receipt.json": "4bedf09d1c43627ca717408227e4e0513f53707dd192180349fc05e0bd7541cc",
    BASE / "check_candidate_runtime_v5.py": "4b1e1a2bb9d37813f61396dd5f1997d0c0419ccfcd41916bd3814c84d41d1b25",
    BASE / "build_candidate_v5.py": "51c54c5ff723121f51b8797bcf3509cb5add010a529444808b5e3852e0bb7c10",
    BUILD / "receipt.json": "3269ff1226f9fd31228c190eb03fd763578369f11edd34f1b84fe0f25fc2a13d",
    RUNTIME / "receipt.json": "a000aeb47acec904cfba8ade8a77946cb835b55f938be1242544dfefa032da59",
    POLICY: "b02ad2c10ae51b4bb7dee7169fedb33e3f38a2f69f5b6eddf1527595a6cea44e",
    ORIGINAL_POLICY: "f731bc881c56b1129ce557352ae1394eb3df118f56a1c78a5ace1a54da8d9103",
    Path("/usr/lib/llvm-21/bin/clang"): "412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932",
}
BINARY_SHA = "db71214d82eab3789aa0c15194e6b6c85dc58d76317eb8d2e289cd325b812e3b"
FILE_LIMIT = 1024 * 1024
JSON_LIMIT = 32 * FILE_LIMIT
TOTAL_BYTES = 128 * FILE_LIMIT
TOTAL_SECONDS = 600
QUERY_LIMIT = 112
DEFINITION = "struct { long long __ll; long double __ld; }"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load(path, expected):
    require(path.resolve() == path and path.stat().st_size <= 64 * 1024,
            "Helper path/size changed")
    data = path.read_bytes()
    require(len(data) <= 64 * 1024 and hashlib.sha256(data).hexdigest() == expected,
            "Reviewed helper pin changed: " + str(path))
    module = types.ModuleType("private_context_" + path.stem)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def record(h, path):
    path = Path(path)
    value = h.record(path)
    require(value["kind"] == "file", "Expected regular file: " + str(path))
    return {"absolute_path": str(path), **{k: v for k, v in value.items() if k != "kind"}}


def read_json(c, h, path, pin=None):
    return json.loads(c.checked_bytes(h, path, pin, JSON_LIMIT)[0])


def retained_tree(c, h, directory, pin, *, legacy=False):
    receipt = read_json(c, h, directory / "receipt.json", pin)
    actual = h.inventory(directory)
    if legacy:
        expected = {}
        for row in receipt["artifacts"]:
            path = Path(row["absolute_path"])
            require(path.is_relative_to(directory) and path.resolve() == path,
                    "Historical artifact path escapes its run")
            relative = str(path.relative_to(directory))
            require(relative not in expected, "Duplicate historical artifact")
            expected[relative] = {"kind": "file", **{k: row[k] for k in ("mode", "size", "sha256")}}
        expected["receipt.json"] = h.record(directory / "receipt.json")
        require({k: v for k, v in actual.items() if v["kind"] != "directory"} == expected,
                "Historical retained file inventory drift")
    else:
        require(actual == {**receipt["artifacts"], "receipt.json": h.record(directory / "receipt.json")},
                "Completed retained artifact inventory drift")
    return receipt, actual


def snapshot(rt, c, h, old, classifiers_pin, sources):
    extra = {**PINS, BASE / "context_classifiers_v2.py": classifiers_pin}
    selected = {str(path): record(h, path) for path in extra}
    require(all(selected[str(path)]["sha256"] == pin for path, pin in extra.items()),
            "Selected source/helper/tool pin changed")
    selected[str(Path(__file__).resolve())] = record(h, Path(__file__).resolve())
    require(Path(COMPILER).resolve() == Path("/usr/lib/llvm-21/bin/clang"), "Clang executable resolution changed")
    require(POLICY.read_bytes() == ORIGINAL_POLICY.read_bytes()
            + b"alignment_attribute_policy: clang-21-u32-bits\n", "Policy is not the exact one-field derivation")
    args = types.SimpleNamespace(receipt_sha256=PINS[BUILD / "receipt.json"], binary_sha256=BINARY_SHA,
                                 build_recorder_sha256=PINS[BASE / "build_candidate_v5.py"])
    private, binary = rt.snapshot(c, h, BUILD, args, RUNTIME / "command-06/core.i")
    runtime, runtime_tree = retained_tree(c, h, RUNTIME, PINS[RUNTIME / "receipt.json"])
    require(runtime["status"] == rt.SUCCESS and runtime["input_drift"] is False
            and runtime["cancelled"] is False and len(runtime["commands"]) == 6,
            "Private runtime prerequisite changed")
    require(read_json(c, h, RUNTIME / "inputs-before.json")
            == read_json(c, h, RUNTIME / "inputs-after.json") == private,
            "Private runtime inputs no longer match current source/dependencies")
    previous, previous_tree = retained_tree(c, h, BASE / "context-run-4", PINS[BASE / "context-run-4/receipt.json"])
    require(previous["status"] == "private-context-observations-complete-not-support"
            and previous["input_drift"] is False and not previous["cancelled"]
            and len(previous["commands"]) == 112 and len(previous["comparisons"]) == 55,
            "Previous private context inventory changed")
    historical, historical_tree = retained_tree(c, h, OLD_RUN, PINS[OLD_RUN / "receipt.json"], legacy=True)
    require(historical["input_drift"] is False and len(historical["commands"]) == 112
            and len(historical["comparisons"]) == 55, "Historical matrix inventory changed")
    adapter = types.SimpleNamespace(record=lambda path: record(h, path))
    fixtures, cases = old.inventory(adapter)
    old_inputs = read_json(c, h, OLD_RUN / "inputs-before.json")
    require(old_inputs == read_json(c, h, OLD_RUN / "inputs-after.json"), "Historical input metadata drift")
    require(fixtures == old_inputs["fixture_inventory"]
            and cases == read_json(c, h, OLD_RUN / "case-inventory.json"), "Original fixtures/cases changed")
    copied = h.inventory(sources)
    require(set(copied) == {name + ".c" for name in fixtures}, "Copied fixture inventory differs")
    for name, row in fixtures.items():
        require(copied[name + ".c"]["sha256"] == row["source"]["sha256"], "Copied fixture bytes changed")
    require(LIBC.resolve().is_relative_to(BUILD), "Private libc resolves outside candidate build")
    libc = h.inventory(LIBC.resolve())
    libc_targets = {}
    for name, entry in libc.items():
        if entry["kind"] == "directory":
            continue
        require(entry["kind"] in ("file", "symlink"), "Unexpected private libc entry")
        target = (LIBC / name).resolve(strict=True)
        require(target.is_relative_to(BUILD), "Private libc file escapes candidate build")
        libc_targets[name] = record(h, target)
    require(len(libc_targets) == 194, "Private libc file inventory changed")
    resources = h.inventory(RESOURCE)
    require(sum(v["kind"] == "file" for v in resources.values()) == 297, "Clang resource inventory changed")
    return {"selected": selected, "compiler_link": h.record(Path(COMPILER)),
            "private": private, "runtime_artifacts": runtime_tree, "previous_context_artifacts": previous_tree,
            "historical_artifacts": historical_tree,
            "historical_scope": "retained bytes and original case identity only; old nested inputs are not current approval",
            "fixtures": fixtures, "cases": cases, "sources": copied, "libc": libc,
            "libc_targets": libc_targets, "libc_resolved": str(LIBC.resolve()), "compiler_resources": resources}, binary


def command(binary, tool, case, folder, sources):
    if case is None:
        return [COMPILER, "--version"] if tool == "compiler" else [str(binary), "-version"]
    source = sources / (case["fixture"] + ".c")
    define = [] if case["alignment"] is None else ["-DFRAGMA_ALIGNMENT=" + str(case["alignment"])]
    if tool == "compiler":
        return [COMPILER, *ARCH_FLAGS, "-nostdinc", *define, "-S", "-emit-llvm", str(source), "-o", "-"]
    return [str(binary), "-no-autoload-plugins", "-machdep", str(POLICY),
            "-cpp-command", shlex.join([COMPILER, "-E", "-C", *ARCH_FLAGS, *define]),
            "-cpp-frama-c-compliant", "-cpp-extra-args=" + shlex.join(["-nostdinc", "-I", str(LIBC)]),
            "-keep-temp-files", "-kernel-msg-key", "pp", "-constfold", "-print",
            "-ocode", str(folder / "printed.c"), str(source)]


def quota(h, folder, maximum, entries):
    items = h.inventory(folder, hash_files=False)
    require(len(items) <= entries and sum(v.get("size", 0) for v in items.values()) <= maximum,
            "Monitored output quota exceeded")
    return items


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def preprocess_evidence(c, h, row, case, folder, sources, libc_targets):
    temporary = folder / "private-temp"
    files = h.inventory(temporary)
    require(all(v["kind"] in ("file", "directory") for v in files.values()), "Unexpected temporary link/type")
    suffix = lambda ending: [temporary / p for p, v in files.items() if v["kind"] == "file" and p.endswith(ending)]
    inputs, headers, macros = suffix(".i"), suffix("/__fc_machdep.h"), suffix("/__fc_builtin_macros.h")
    require(len(inputs) == len(headers) == len(macros) == 1
            and headers[0].parent == macros[0].parent, "Missing/ambiguous private preprocessing artifacts")
    text = lambda p: c.checked_bytes(h, p, limit=FILE_LIMIT)[0].decode("utf-8")
    require(re.findall(r"(?m)^#\s*define\s+__MAX_ALIGN_T\s+([^\n]+)$", text(headers[0])) == [DEFINITION],
            "Generated max_align_t changed")
    source = sources / (case["fixture"] + ".c")
    define = [] if case["alignment"] is None else ["-DFRAGMA_ALIGNMENT=" + str(case["alignment"])]
    expected = [COMPILER, "-E", "-C", *ARCH_FLAGS, *define, "-I" + str(headers[0].parent),
                "-I" + str(LIBC), "-U__STDC_IEC_559_COMPLEX__", "-U__STDC_IEC_60559_COMPLEX__",
                "-U__STDC_ISO_10646__", "-U__STDC_UTF16__", "-U__STDC_UTF32__", "-D__FRAMAC__",
                "-dD", "-nostdinc", "-undef", "-imacros", "__fc_builtin_macros.h", "-nostdinc",
                "-I", str(LIBC), str(source), "-o", str(inputs[0])]
    stdout = text(folder / "stdout")
    first = re.findall(r'(?m)^  preprocessing with "([^\n]*)"$', stdout)
    second = re.findall(r"(?m)^  Full preprocessing command: ([^\n]*)$", stdout)
    require(len(first) == len(second) == 1 and shlex.split(first[0]) == shlex.split(second[0]) == expected,
            "Actual preprocessing command differs from fixed private command")
    markers = []
    for name in re.findall(r'(?m)^#\s+(?:line\s+)?\d+\s+"([^"\n]+)"', text(inputs[0])):
        if name in ("<built-in>", "<command line>", "<command-line>"):
            continue
        path = Path(name)
        if not path.is_absolute():
            path = folder / path
        actual = path.resolve(strict=True)
        require(actual == source.resolve() or actual.is_relative_to(temporary.resolve())
                or str(actual) in libc_targets, "Preprocessing consumed an unexpected path: " + name)
        markers.append({"spelling": name, "resolved": str(actual), "file": record(h, actual)})
    require(any(m["resolved"] == str(source.resolve()) for m in markers), "Source missing from linemarkers")
    return {"actual_argv": expected, "preprocessed": record(h, inputs[0]),
            "machdep_header": record(h, headers[0]), "builtin_header": record(h, macros[0]),
            "linemarkers": markers}


def invoke(rt, c, h, binary, tool, case, index, output, sources, deadline, commands):
    require(index <= QUERY_LIMIT, "Direct query count exceeded")
    folder = output / ("command-%03d" % index)
    folder.mkdir(mode=0o700)
    temporary = folder / "private-temp"
    temporary.mkdir(mode=0o700)
    environment = (rt.runtime_environment(h, c, BUILD, temporary)[0] if tool == "analyzer" else
                   {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TMPDIR": str(temporary)})
    query_deadline = min(deadline, time.monotonic() + (10 if tool == "compiler" else 30))
    row = {"tool": tool, "case": case, "argv": command(binary, tool, case, folder, sources),
           "cwd": str(folder), "environment": environment, "stdin": "DEVNULL", "started_at": h.stamp(),
           "child_started": False, "child_terminal": None, "returncode": None,
           "timeout_seconds": max(0, query_deadline - time.monotonic())}
    commands.append(row)
    proc = None
    try:
        h.save(folder / "intent.json", row)
        with (folder / "stdout").open("xb") as out, (folder / "stderr").open("xb") as err:
            require(not h.CANCELLED and time.monotonic() < query_deadline, "Cancelled or query deadline exceeded")
            proc = subprocess.Popen(row["argv"], cwd=folder, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=True, preexec_fn=child_limits)
            row.update(child_started=True, child_pid=proc.pid, child_terminal=False)
            h.save(folder / "process.json", {"pid": proc.pid, "argv": row["argv"]})
            next_quota = time.monotonic()
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                require(not h.CANCELLED and time.monotonic() < query_deadline, "Cancelled or query deadline exceeded")
                if time.monotonic() >= next_quota:
                    quota(h, folder, 8 * FILE_LIMIT, 520)
                    next_quota = time.monotonic() + 1
                time.sleep(0.05)
            require(not h.CANCELLED and time.monotonic() <= query_deadline, "Query completed beyond deadline/cancellation")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        row["transport_error"] = repr(exc)
    finally:
        if proc is not None:
            group = c.finish_process_group(proc)
            row.update(process_group=group, returncode=group["returncode"], child_terminal=group["leader_reaped"])
            if (not group["group_terminal"] or not group["leader_reaped"] or group["cleanup_error"]
                    or group["nonleader_members_observed"] or group["returncode"] < 0):
                row["transport_error"] = "Original process group/termination failed"
        row["finished_at"] = h.stamp()
        try:
            quota(h, folder, 8 * FILE_LIMIT, 520)
            row["artifacts"] = h.inventory(folder)
            require(all(v.get("size", 0) <= FILE_LIMIT for v in row["artifacts"].values()), "Per-file query limit exceeded")
            require(not any(Path(name).suffix in (".o", ".obj", ".s", ".bc", ".a", ".so")
                            for name in row["artifacts"]), "Unexpected nontext compilation artifact")
            h.save(folder / "result.json", row)
        except (OSError, ValueError, KeyError) as exc:
            row["transport_error"] = "Artifact retention failed: " + repr(exc)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--classifiers-sha256", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.classifiers_sha256), "Need explicit classifier SHA")
    rt = load(BASE / "check_candidate_runtime_v5.py", PINS[BASE / "check_candidate_runtime_v5.py"])
    c = rt.load_builder(PINS[BASE / "build_candidate_v5.py"])
    h = c.load_helper()
    old = load(OLD_BASE / "diagnose-v2.py", PINS[OLD_BASE / "diagnose-v2.py"])
    classify = load(BASE / "context_classifiers_v2.py", args.classifiers_sha256)
    require(all(hasattr(os, n) for n in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID"))
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "Need Linux unreaped-leader process handling")
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)
    output = Path(os.path.abspath(args.output))
    require(output.parent == BASE and re.fullmatch(r"context-run-[1-9][0-9]*", output.name)
            and not os.path.lexists(output), "Need a fresh private context-run-N")
    output.mkdir(mode=0o700)
    report = {"schema_version": 1, "status": "failed", "scope": __doc__, "started_at": h.stamp(),
              "integration_eligible": False, "alignment_resolution_established": False,
              "commands": [], "comparisons": [], "input_drift": None, "query_limit": QUERY_LIMIT,
              "query_budget_seconds": TOTAL_SECONDS,
              "deadline_scope": "monitored query budget; cleanup and final hashes may finish later"}
    before = None
    try:
        h.save(output / "request.json", report)
        sources = output / "sources"
        sources.mkdir(mode=0o700)
        fixtures, cases = old.inventory(types.SimpleNamespace(record=lambda p: record(h, p)))
        for name, row in fixtures.items():
            data = c.checked_bytes(h, Path(row["source"]["absolute_path"]), row["source"]["sha256"], 8192)[0]
            with (sources / (name + ".c")).open("xb") as stream:
                stream.write(data)
        before, binary = snapshot(rt, c, h, old, args.classifiers_sha256, sources)
        h.save(output / "inputs-before.json", before)
        h.save(output / "case-inventory.json", cases)
        historical = read_json(c, h, OLD_RUN / "receipt.json", PINS[OLD_RUN / "receipt.json"])
        for i, case in enumerate([None, *cases]):
            require(command(binary, "compiler", case, output, OLD_RUN / "sources")
                    == historical["commands"][2 * i]["argv"], "Original compiler command differs")
        deadline = time.monotonic() + TOTAL_SECONDS
        for case in [None, *cases]:
            pair = []
            for tool in ("compiler", "analyzer"):
                row = invoke(rt, c, h, binary, tool, case, len(report["commands"]) + 1,
                             output, sources, deadline, report["commands"])
                require(not row.get("transport_error"), "Transport failed; no automatic retry")
                folder = Path(row["cwd"])
                text = lambda name: c.checked_bytes(h, folder / name, limit=FILE_LIMIT)[0].decode("utf-8")
                stdout, stderr = text("stdout"), text("stderr")
                try:
                    if case is None:
                        expected = ((OLD_RUN / "command-001/stdout").read_text() if tool == "compiler"
                                    else "33.0 (Arsenic)\n")
                        require(row["returncode"] == 0 and stdout == expected and not stderr, "Tool version mismatch")
                        observation = {"status": "version-checked", "version_output": stdout}
                    elif tool == "compiler":
                        observation = classify.compiler_observation(old, row["returncode"], stdout, stderr, case)
                    else:
                        row["preprocessing"] = preprocess_evidence(c, h, row, case, folder, sources,
                            {v["absolute_path"] for v in before["libc_targets"].values()})
                        printed = text("printed.c") if (folder / "printed.c").is_file() else None
                        observation = classify.analyzer_observation(old, row["returncode"], stdout, stderr, printed, case)
                    row["classification"] = observation
                except (OSError, ValueError, KeyError, UnicodeError) as exc:
                    row["classification"] = {"status": "unclassified", "reason": repr(exc)}
                h.save(folder / "observation.json", {"classification": row["classification"],
                                                     "preprocessing": row.get("preprocessing")})
                pair.append(row)
                quota(h, output, TOTAL_BYTES, 10000)
                if case is None:
                    require(row["classification"]["status"] == "version-checked", "Version gate failed")
            if case is not None:
                report["comparisons"].append(classify.compare(case, *pair))
        require(len(report["commands"]) == QUERY_LIMIT and len(report["comparisons"]) == 55,
                "Incomplete fixed matrix")
        report["summary"] = dict(Counter(row["status"] for row in report["comparisons"]))
        report["negative_control_unexpected_acceptance_count"] = sum(
            bool(row.get("negative_control_unexpected_acceptance_by")) for row in report["comparisons"])
        report["status"] = "private-context-observations-complete-not-support"
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = repr(exc)
    finally:
        errors = []
        if before is not None:
            try:
                after, _ = snapshot(rt, c, h, old, args.classifiers_sha256, sources)
                h.save(output / "inputs-after.json", after)
                report["input_drift"] = before != after
                require(before == after, "Context inputs changed")
            except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
                errors.append("inputs: " + repr(exc))
        try:
            quota(h, output, TOTAL_BYTES, 10000)
            report["artifacts"] = h.inventory(output)
        except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
            errors.append("artifacts: " + repr(exc))
        report["cancelled"] = h.CANCELLED
        report["cancellation_sampling_boundary"] = "after final inventories, before receipt serialization"
        report["late_cancellation_policy"] = "later observed cancellation forces nonzero exit"
        if errors or h.CANCELLED:
            report.update(status="failed", finalization_errors=errors)
        report["finished_at"] = h.stamp()
        try:
            h.save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({k: report.get(k) for k in ("status", "error", "summary", "input_drift",
        "negative_control_unexpected_acceptance_count", "finalization_errors", "receipt_write_error")}
        | {"cancelled_at_exit_sample": h.CANCELLED}))
    clean = {"constants-agree-not-support", "named-rejections-correspond-not-support"}
    return 0 if (report["status"] == "private-context-observations-complete-not-support"
                 and set(report.get("summary", {})) <= clean and not h.CANCELLED
                 and not report.get("negative_control_unexpected_acceptance_count")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
