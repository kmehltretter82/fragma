#!/usr/bin/env python3
"""Check five private early outputs and one inert, core-only preprocessed C parse.

Exactly six private executable queries are permitted. The final query disables
plugin autoloading and uses the private legacy x86_64 model, one global integer
initializer, no preprocessing, and no target execution. This does not validate
alignment semantics, plugin loading, proofs, Hexagon support, or integration.
Completed build artifacts, selected dependencies and source are rechecked;
these are not a hermetic host or descendant-process attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import time
import types

BASE = Path(__file__).resolve().parent
BUILDER = BASE / "build_candidate_v3.py"
FLAGS = ("-version", "-print-config", "-print-share-path", "-print-lib-path", "-print-plugin-path")
FIXTURE = b"int fragma_private_core_constant = 7;\n"
FILE_LIMIT = 1024 * 1024
JSON_LIMIT = 16 * 1024 * 1024
TOTAL_SECONDS = 300
QUERY_SECONDS = 30
SUCCESS = "private-early-paths-and-legacy-core-parse-checked-not-alignment-validated"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load_builder(expected):
    require(BUILDER.resolve() == BUILDER, "Build recorder path is symlinked")
    before = BUILDER.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 64 * 1024,
            "Build recorder is not a bounded regular file")
    with BUILDER.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    signature = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                               value.st_mtime_ns, value.st_ctime_ns)
    require(len(data) <= 64 * 1024 and hashlib.sha256(data).hexdigest() == expected
            and signature(BUILDER.stat()) == signature(before), "Explicit reviewed build recorder pin differs")
    builder = types.ModuleType("fragma_runtime_reviewed_candidate_builder")
    builder.__file__ = str(BUILDER)
    exec(compile(data, str(BUILDER), "exec"), builder.__dict__)
    return builder


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def query_quota(h, folder, temporary):
    entries = list(h.inventory(folder, hash_files=False).values())
    entries += list(h.inventory(temporary, hash_files=False).values())
    require(len(entries) <= 512 and sum(row.get("size", 0) for row in entries) <= 8 * FILE_LIMIT
            and all(row.get("size", 0) <= FILE_LIMIT for row in entries), "Private query output quota exceeded")


def runtime_environment(h, c, build, temporary):
    installed = build / "dune-build/install/default"
    paths = {"-print-share-path": str(installed / "share/frama-c/share"),
             "-print-lib-path": str(installed / "lib/frama-c/lib"),
             "-print-plugin-path": str(installed / "lib/frama-c/plugins")}
    for value in paths.values():
        path = Path(value)
        require(path.is_dir() and path.resolve().is_relative_to(build), "Private site escapes build")
    environment = {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
        "LD_LIBRARY_PATH": str(h.PREFIX / "lib"),
        "CAML_LD_LIBRARY_PATH": ":".join(str(h.SWITCH / p) for p in
            ("lib/stublibs", "lib/ocaml/stublibs", "lib/ocaml")),
        "OCAMLPATH": str(installed / "lib"),
        "DUNE_OCAML_HARDCODED": str(h.SWITCH / "lib/ocaml") + ":" + str(h.SWITCH / "lib"),
        "DUNE_OCAML_STDLIB": str(h.SWITCH / "lib/ocaml"),
        "DUNE_SOURCEROOT": str(c.SOURCE),
        "DUNE_DIR_LOCATIONS": ":".join(("frama-c", "libexec", str(installed / "lib/frama-c"),
            "frama-c", "lib", str(installed / "lib/frama-c"),
            "frama-c", "share", str(installed / "share/frama-c"))),
        "TMPDIR": str(temporary)}
    return environment, paths


def snapshot(c, h, build, args, fixture):
    def read_json(path, expected=None):
        return json.loads(c.checked_bytes(h, path, expected, JSON_LIMIT)[0])
    receipt = read_json(build / "receipt.json", args.receipt_sha256)
    group = receipt.get("process_group", {})
    require(receipt.get("status") == c.SUCCESS and receipt.get("returncode") == 0
            and receipt.get("child_terminal") is True
            and receipt.get("dependency_drift") is False and receipt.get("source_drift") is False
            and receipt.get("artifact_inventory_complete") is True
            and receipt.get("cancelled") is False and receipt.get("integration_eligible") is False
            and not receipt.get("cleanup_error") and not receipt.get("finalization_errors")
            and group.get("group_terminal") is True and group.get("leader_reaped") is True
            and group.get("returncode") == 0 and not group.get("cleanup_error")
            and not group.get("nonleader_members_observed") and not group.get("live_members_remaining"),
            "Completed candidate build prerequisite failed")
    binary = build / "dune-build/default/src/init/boot/empty_file.exe"
    require(binary.resolve() == binary, "Private executable is symlinked")
    binary_row = h.record(binary)
    require(binary_row.get("sha256") == args.binary_sha256
            and receipt.get("binary") == {"path": str(binary), **binary_row}, "Private binary pin differs")
    artifacts = h.inventory(build)
    expected = {**receipt["artifacts"], "receipt.json": h.record(build / "receipt.json")}
    require(artifacts == expected, "Completed candidate build artifact drift")
    pins = receipt["patch_sha256"]
    require(set(pins) == set(c.PATCH_FILES)
            and all(re.fullmatch(r"[0-9a-f]{64}", value) for value in pins.values()), "Patch pins differ")
    selected = c.selected_inputs(h, pins)
    require(selected[str(BUILDER)]["sha256"] == args.build_recorder_sha256, "Build recorder pin differs")
    dependencies = h.dependencies()
    inputs = {"selected": selected, "dependencies": dependencies}
    require(inputs == read_json(build / "inputs-before.json") == read_json(build / "inputs-after.json"),
            "Completed candidate selected inputs/dependencies changed")
    source = h.inventory(c.SOURCE)
    require(source == read_json(build / "source-before.json") == read_json(build / "source-after.json"),
            "Completed candidate patched source changed")
    fixture_bytes, fixture_row = c.checked_bytes(h, fixture, limit=FILE_LIMIT)
    require(fixture_bytes == FIXTURE, "Core-only fixture changed")
    return {"build_receipt": h.record(build / "receipt.json"), "build_artifacts": artifacts,
            "inputs": inputs, "source": source, "runtime_reader": h.record(Path(__file__).resolve()),
            "fixture": {"path": str(fixture), **fixture_row}}, binary


def classify(c, h, row, folder, index, paths):
    stdout, out_row = c.checked_bytes(h, folder / "stdout", limit=FILE_LIMIT)
    stderr, err_row = c.checked_bytes(h, folder / "stderr", limit=FILE_LIMIT)
    row["streams"] = {"stdout": out_row, "stderr": err_row}
    group = row.get("process_group", {})
    require(row.get("returncode") == 0 and row.get("child_terminal") is True
            and group.get("group_terminal") is True and not group.get("cleanup_error")
            and not group.get("nonleader_members_observed") and not group.get("live_members_remaining")
            and not row.get("cleanup_error") and not stderr, "Private query/group failed or emitted stderr")
    actual = stdout.decode("utf-8")
    if index <= len(FLAGS):
        flag = FLAGS[index - 1]
        if flag == "-version":
            expected = "33.0 (Arsenic)\n"
        elif flag in paths:
            expected = paths[flag]
        else:
            expected = ("Frama-C 33.0 (Arsenic)\nEnvironment:\n"
                + "  FRAMAC_SHARE  = " + json.dumps(paths["-print-share-path"]) + "\n"
                + "  FRAMAC_PLUGIN = " + json.dumps(paths["-print-plugin-path"]) + "\n"
                + "  FRAMAC_LIB    = " + json.dumps(paths["-print-lib-path"]) + "\n")
        require(actual == expected, "Private early output mismatch")
        row["classification"] = "exact-early-output-checked"
    else:
        require(actual == "[kernel] Parsing core.i (no preprocessing)\n", "Unexpected core parse diagnostics")
        printed, printed_row = c.checked_bytes(h, folder / "printed.c", limit=FILE_LIMIT)
        row["printed"] = printed_row
        require(re.fullmatch(r"\s*/\* Generated by Frama-C \*/\s*int\s+fragma_private_core_constant\s*=\s*7\s*;\s*",
                             printed.decode("utf-8")) is not None, "Printed core declaration differs")
        row["classification"] = "legacy-core-only-declaration-parsed-and-printed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "output", "build-recorder-sha256", "receipt-sha256", "binary-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(all(re.fullmatch(r"[0-9a-f]{64}", getattr(args, name)) for name in
                ("build_recorder_sha256", "receipt_sha256", "binary_sha256")), "Need three explicit SHA-256 pins")
    c = load_builder(args.build_recorder_sha256)
    h = c.load_helper()
    require(all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID"))
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "Linux waitid/WNOWAIT and default SIGCHLD handling are required")
    build, output = (Path(os.path.abspath(value)) for value in (args.build, args.output))
    require(build.parent == BASE and re.fullmatch(r"candidate-build-[1-9][0-9]*", build.name)
            and build.resolve() == build, "Need an exact private candidate-build-N")
    require(output.parent == BASE and re.fullmatch(r"candidate-runtime-[1-9][0-9]*", output.name)
            and not os.path.lexists(output), "Need fresh candidate-runtime-N output")
    output.mkdir(mode=0o700)
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)
    report = {"schema_version": 1, "status": "failed", "scope": __doc__, "started_at": h.stamp(),
              "integration_eligible": False, "alignment_validated": False, "plugins_validated": False,
              "legacy_core_parse_validated": False, "commands": [], "launch": vars(args),
              "query_limit": 6, "query_timeout_seconds": QUERY_SECONDS, "total_seconds": TOTAL_SECONDS,
              "deadline_scope": "No query launches/waits after deadline; cleanup and retained input hashing may finish later"}
    before = None
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        h.save(output / "request.json", report)
        for index in range(1, 7):
            (output / ("command-%02d" % index)).mkdir(mode=0o700)
        fixture = output / "command-06/core.i"
        with fixture.open("xb") as stream:
            stream.write(FIXTURE)
        temporary = output / "private-temp"
        temporary.mkdir(mode=0o700)
        before, binary = snapshot(c, h, build, args, fixture)
        h.save(output / "inputs-before.json", before)
        environment, paths = runtime_environment(h, c, build, temporary)
        queries = [[flag] for flag in FLAGS] + [["-no-autoload-plugins", "-machdep", "x86_64",
                   "-print", "-ocode", "printed.c", "core.i"]]
        for index, arguments in enumerate(queries, 1):
            require(not h.CANCELLED and time.monotonic() < deadline, "Cancelled or overall deadline exceeded")
            folder = output / ("command-%02d" % index)
            row = {"argv": [str(binary), *arguments], "cwd": str(folder), "environment": environment,
                   "stdin": "DEVNULL", "started_at": h.stamp(), "child_started": False,
                   "child_terminal": None, "timeout_seconds": min(QUERY_SECONDS, deadline - time.monotonic())}
            report["commands"].append(row)
            proc = None
            try:
                h.save(folder / "intent.json", row)
                query_deadline = min(deadline, time.monotonic() + QUERY_SECONDS)
                with (folder / "stdout").open("xb") as out, (folder / "stderr").open("xb") as err:
                    require(not h.CANCELLED and time.monotonic() < query_deadline,
                            "Cancelled or private query deadline exceeded before launch")
                    proc = subprocess.Popen(row["argv"], cwd=folder, env=environment,
                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                        start_new_session=True, preexec_fn=child_limits)
                    row.update(child_started=True, child_pid=proc.pid, child_terminal=False)
                    h.save(folder / "process.json", {"pid": proc.pid, "argv": row["argv"]})
                    next_quota = time.monotonic()
                    while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                        require(not h.CANCELLED and time.monotonic() < query_deadline,
                                "Cancelled or private query deadline exceeded")
                        if time.monotonic() >= next_quota:
                            query_quota(h, folder, temporary)
                            next_quota = time.monotonic() + 1
                        time.sleep(0.05)
                    require(not h.CANCELLED and time.monotonic() <= query_deadline,
                            "Cancelled or private query completed after deadline")
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
                row["error"] = repr(exc)
            finally:
                if proc is not None:
                    try:
                        # Never wait/poll/send_signal before this helper: its
                        # PID/group verification depends on the unreaped leader.
                        row["process_group"] = c.finish_process_group(proc)
                        row["returncode"] = row["process_group"].get("returncode")
                        row["child_terminal"] = row["process_group"].get("leader_reaped") is True
                    except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
                        row.update(cleanup_error=repr(exc), child_terminal=False)
                row["finished_at"] = h.stamp()
                try:
                    require(not row.get("error"), "Private query invocation failed")
                    classify(c, h, row, folder, index, paths)
                except (OSError, ValueError, KeyError) as exc:
                    row["classification_error"] = repr(exc)
                try:
                    query_quota(h, folder, temporary)
                    row["artifacts"] = h.inventory(folder)
                    h.save(folder / "result.json", row)
                except (OSError, ValueError, KeyError) as exc:
                    row["retention_error"] = repr(exc)
            require(not any(row.get(key) for key in ("error", "classification_error", "cleanup_error", "retention_error")),
                    "Private query failed; no retry")
        require(not h.CANCELLED and time.monotonic() < deadline, "Cancelled or overall deadline exceeded")
        report.update(status=SUCCESS, legacy_core_parse_validated=True)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = repr(exc)
    finally:
        final_errors = []
        if before is not None:
            try:
                after, _ = snapshot(c, h, build, args, fixture)
                h.save(output / "inputs-after.json", after)
                report["input_drift"] = before != after
                require(before == after, "Candidate runtime input drift")
            except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
                final_errors.append("inputs: " + repr(exc))
        try:
            report["artifacts"] = h.inventory(output)
        except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
            final_errors.append("artifacts: " + repr(exc))
        report["cancellation_sampling_boundary"] = "after final inventories, before receipt serialization"
        report["late_cancellation_policy"] = "a later cancellation forces nonzero process exit; receipt records the stated sample only"
        report["cancelled"] = h.CANCELLED
        if final_errors or h.CANCELLED:
            report.update(status="failed", legacy_core_parse_validated=False, finalization_errors=final_errors)
        report["finished_at"] = h.stamp()
        try:
            h.save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc), legacy_core_parse_validated=False)
    print(json.dumps({key: report.get(key) for key in ("status", "error", "input_drift", "finalization_errors", "receipt_write_error")}
                    | {"cancelled_at_exit_sample": h.CANCELLED}))
    return 0 if report["status"] == SUCCESS and not h.CANCELLED else 1


if __name__ == "__main__":
    raise SystemExit(main())
