#!/usr/bin/env python3
"""Build one exact already-patched private Frama-C source tree; never install.

Validate the original archive plus seven ordered explicit reviewed patch hashes against
the entire prepared worktree before one ordinary Dune build. No source edit,
patch application, package operation, analyzer/proof/kernel invocation, native
target execution, or verified-prefix write is requested. Normal Dune compiler
and configuration descendants run only after review of this recorder and the
patches. Selected-input hashes are not a hermetic or descendant attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import tarfile
import time
import types

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
HELPER = BASE / "build_baseline.py"
HELPER_SHA = "3181b7c935cc03b31ba9c4232176b5e7e4fda794c0f013f31692cfe1f4e3e7c7"
SOURCE = BASE / "worktree-5/source/frama-c-33.0-Arsenic"
PREPARATION = BASE / "worktree-5/preparation.json"
PREPARATION_SHA = "4567f327c2ff7f5943cbf650c5ff46d92b12b8c0ac643268a6e909ed99702c61"
BASELINE = BASE / "baseline-1"
BASELINE_PINS = {
    "receipt.json": "deb25b14d6add7d7f01bf0a10e52bbe53ff6864e69a051ad68eb0d07ba111836",
    "source-before.json": "a48ae1f98f0af67e43b8ec6b8929db8db98ea1cfed1eeb8a2802725085d173a5",
    "source-after.json": "a48ae1f98f0af67e43b8ec6b8929db8db98ea1cfed1eeb8a2802725085d173a5",
    "dependencies-before.json": "1872dd290aa35b7ebf228a09a06c21dab1f8df38433cc461705ba214f224fd25",
    "dependencies-after.json": "1872dd290aa35b7ebf228a09a06c21dab1f8df38433cc461705ba214f224fd25",
    "dune-build/default/src/init/boot/empty_file.exe":
        "e14caa0a3b5938a70ade4d85942444bbf73532a2a0a2c323b6d181246dd122ef",
}
PATCH_FILES = {
    "0002-alignment-attribute-policy-v2.patch": {
        "src/kernel_internals/runtime/machdep.ml",
        "src/kernel_internals/runtime/machdep.mli",
        "src/kernel_services/ast_data/machine.ml",
        "src/kernel_services/ast_data/machine.mli",
        "share/machdeps/machdep-schema.yaml",
        "share/machdeps/make_machdep/make_machdep.py",
    },
    "0003-clang-alignment-consumers.patch": {
        "src/kernel_services/ast_queries/cil.ml",
        "src/kernel_services/ast_queries/cil.mli",
    },
    "0004-clang-alignment-typing.patch": {
        "src/kernel_internals/typing/cabs2cil.ml",
    },
    "0005-c11-missing-definition.patch": {
        "src/kernel_internals/typing/cabs2cil.ml",
    },
    "0006-vla-typed-provenance-v2.patch": {
        "src/kernel_internals/typing/cabs2cil.ml",
    },
    "0007-clang-typed-gnu-alignment-v2.patch": {
        "src/kernel_internals/typing/cabs2cil.ml",
        "src/kernel_services/ast_queries/cil.ml",
        "src/kernel_services/ast_queries/cil.mli",
        "src/kernel_services/ast_printing/cil_printer.ml",
    },
    "0008-vla-bound-local-init.patch": {
        "src/kernel_internals/typing/cabs2cil.ml",
    },
}
PATCH_LIMIT = 256 * 1024
SUCCESS = "patched-private-build-complete-not-runtime-validated"
GROUP_CLOSE_SECONDS = 10


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load_helper():
    require(HELPER.resolve() == HELPER and not HELPER.is_symlink(), "Helper path changed")
    require(HELPER.stat().st_size < 64 * 1024, "Helper size bound exceeded")
    data = HELPER.read_bytes()
    require(hashlib.sha256(data).hexdigest() == HELPER_SHA, "Frozen helper changed")
    helper = types.ModuleType("fragma_candidate_frozen_build_helper")
    helper.__file__ = str(HELPER)
    exec(compile(data, str(HELPER), "exec"), helper.__dict__)
    return helper


def checked_bytes(h, path, expected=None, limit=4 * 1024 * 1024):
    require(path.resolve() == path, "Input path is symlinked: " + str(path))
    before = h.record(path)
    require(before["kind"] == "file" and before["size"] <= limit, "Input is not a bounded regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit and hashlib.sha256(data).hexdigest() == before["sha256"]
            and h.record(path) == before, "Input changed while reading: " + str(path))
    require(expected is None or before["sha256"] == expected, "Input pin differs: " + str(path))
    return data, before


def read_process_stat(pid):
    """Read Linux identity/state only, never process arguments or environment."""
    with Path(f"/proc/{pid}/stat").open("rb") as stream:
        raw = stream.read(8193)
    require(len(raw) <= 8192, "Process stat exceeds bound")
    fields = raw.rsplit(b")", 1)[1].split()
    require(len(fields) >= 20 and int(raw.split(b" ", 1)[0]) == pid,
            "Malformed process stat")
    return {"pid": pid, "state": fields[0].decode("ascii"),
            "pgrp": int(fields[2]), "session": int(fields[3]),
            "start_ticks": int(fields[19])}


def process_group_members(pgid):
    members = []
    with os.scandir("/proc") as entries:
        for count, entry in enumerate(entries):
            require(count < 100000, "Process inventory bound exceeded")
            if not entry.name.isdecimal():
                continue
            try:
                row = read_process_stat(int(entry.name))
            except FileNotFoundError:
                continue
            if row["pgrp"] == pgid:
                require(row["session"] == pgid, "Original process-group session differs")
                members.append(row)
    return sorted(members, key=lambda row: row["pid"])


def finish_process_group(proc):
    """Close only the original Linux session/group, keeping its leader unreaped.

    Caller must use waitid(WNOWAIT), never wait/poll/send_signal before this.
    Holding the unreaped leader prevents reuse of its numeric session/group.
    Zombies are terminal/nonwriting, retained separately, not called live.
    This does not attest descendants that escape the original process group.
    """
    result = {"leader_reaped": False, "returncode": None,
              "group_terminal": False, "nonleader_members_observed": [],
              "terminal_zombies": [], "live_members_remaining": [],
              "cleanup_error": None, "signal_sent": False,
              "timeout_seconds": GROUP_CLOSE_SECONDS}
    require(proc.returncode is None, "Leader was reaped before group closure")
    verified_group = False
    try:
        leader = read_process_stat(proc.pid)
        require(leader["pgrp"] == leader["session"] == proc.pid,
                "Child is not the original session/group leader")
        verified_group = True
        result["leader_identity"] = leader
        observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        result["leader_exit_observed_before_cleanup"] = observed is not None
        members = process_group_members(proc.pid)
        others = [row for row in members if row["pid"] != proc.pid]
        result["nonleader_members_observed"] = others
        if observed is None or any(row["state"] not in ("Z", "X") for row in others):
            os.killpg(proc.pid, signal.SIGKILL)
            result["signal_sent"] = True
        deadline = time.monotonic() + GROUP_CLOSE_SECONDS
        while True:
            observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            members = process_group_members(proc.pid)
            for row in members:
                if row["pid"] != proc.pid and not any(
                    old["pid"] == row["pid"] and old["start_ticks"] == row["start_ticks"]
                    for old in result["nonleader_members_observed"]):
                    result["nonleader_members_observed"].append(row)
            live = [row for row in members if row["state"] not in ("Z", "X")]
            result["live_members_remaining"] = live
            result["terminal_zombies"] = [row for row in members
                if row["pid"] != proc.pid and row["state"] in ("Z", "X")]
            if observed is not None and not live:
                result["group_terminal"] = True
                break
            if observed is not None and live and not result["signal_sent"]:
                os.killpg(proc.pid, signal.SIGKILL)
                result["signal_sent"] = True
            require(time.monotonic() < deadline, "Original process group did not become terminal")
            time.sleep(0.05)
    except (OSError, ValueError, IndexError) as exc:
        result["cleanup_error"] = type(exc).__name__ + ": " + str(exc)
        try:
            # The unreaped child PID is still owned. Signal its verified group
            # only when session identity was checked; otherwise only the child.
            if verified_group:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                os.kill(proc.pid, signal.SIGKILL)
            result["signal_sent"] = True
        except ProcessLookupError:
            pass
        except OSError as kill_error:
            result["cleanup_error"] += "; signal: " + repr(kill_error)
    try:
        result["returncode"] = proc.wait(timeout=GROUP_CLOSE_SECONDS)
        result["leader_reaped"] = True
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["cleanup_error"] = (result["cleanup_error"] or "") + "; reap: " + repr(exc)
    return result


def selected_inputs(h, patch_pins):
    pins = {HELPER: HELPER_SHA, PREPARATION: PREPARATION_SHA,
            **{BASELINE / name: value for name, value in BASELINE_PINS.items()},
            **{BASE / "patches" / name: value for name, value in patch_pins.items()}}
    result = {str(Path(__file__).resolve()): h.record(Path(__file__).resolve())}
    for path, expected in pins.items():
        require(path.resolve() == path, "Selected input path changed: " + str(path))
        row = h.record(path)
        require(row.get("kind") == "file" and row.get("sha256") == expected,
                "Selected input pin differs: " + str(path))
        result[str(path)] = row
    return result


def original_archive(h):
    """Read only; reconstruct the exact regular-file/directory inventory."""
    records, patch_sources, seen = {}, {}, set()
    allowed = set().union(*PATCH_FILES.values())
    with tarfile.open(h.ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == 11512 and sum(m.isfile() for m in members) == 10893
                and sum(m.isdir() for m in members) == 619
                and sum(m.size for m in members) == 49657870, "Archive inventory differs")
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and name.parts
                    and name.parts[0] == h.ARCHIVE_ROOT and str(name) not in seen
                    and (member.isfile() or member.isdir()) and member.size <= h.FILE_LIMIT,
                    "Unexpected original archive member")
            seen.add(str(name))
            if len(name.parts) == 1:
                require(member.isdir(), "Archive root is not a directory")
                continue
            relative = str(PurePosixPath(*name.parts[1:]))
            if member.isdir():
                records[relative] = {"kind": "directory"}
            else:
                with archive.extractfile(member) as stream:
                    data = stream.read(member.size + 1)
                require(len(data) == member.size, "Short/oversized archive member")
                records[relative] = {"kind": "file", "size": member.size,
                    "mode": 0o755 if member.mode & 0o111 else 0o644,
                    "sha256": hashlib.sha256(data).hexdigest()}
                if relative in allowed:
                    patch_sources[relative] = data
    require(len(records) == 11511 and set(patch_sources) == allowed, "Original source inventory incomplete")
    return dict(sorted(records.items())), patch_sources


def patched_bytes(text, originals, allowed):
    """Closed unified diff: existing named files, exact coordinates, no fuzz."""
    require(text.endswith("\n") and "\r" not in text, "Noncanonical patch text")
    lines, index, outputs, details = text.splitlines(keepends=True), 0, {}, []
    while index < len(lines):
        require(lines[index].startswith("--- a/"), "Expected exact old-file header")
        name = lines[index][6:-1]
        require(name in allowed and name not in outputs, "Unexpected/duplicate patched file: " + name)
        index += 1
        require(index < len(lines) and lines[index] == "+++ b/" + name + "\n", "New-file header differs")
        index += 1
        original = originals[name].decode("utf-8").splitlines(keepends=True)
        result, at, hunks = [], 0, []
        while index < len(lines) and not lines[index].startswith("--- a/"):
            match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: [^\n]*)?\n", lines[index])
            require(match is not None, "Malformed hunk header")
            start, old_count, new_start, new_count = [int(x) if x is not None else 1 for x in match.groups()]
            require(start >= 1 and new_start >= 1, "Zero-origin hunks are outside the fixed source-edit scope")
            index += 1
            before, after, edits = [], [], 0
            while index < len(lines) and not lines[index].startswith(("@@ ", "--- a/")):
                line = lines[index]
                require(line[:1] in (" ", "+", "-"), "Unsupported diff marker")
                if line[0] != "+":
                    before.append(line[1:])
                if line[0] != "-":
                    after.append(line[1:])
                edits += line[0] != " "
                index += 1
            require(len(before) == old_count and len(after) == new_count and edits > 0,
                    "Hunk counts differ or hunk has no edit")
            require(start - 1 >= at and original[start - 1:start - 1 + old_count] == before,
                    "Hunk context/old coordinate differs: " + name)
            result.extend(original[at:start - 1])
            require(len(result) == new_start - 1, "Hunk new coordinate differs: " + name)
            result.extend(after)
            at = start - 1 + old_count
            hunks.append({"old_start": start, "old_count": old_count,
                          "new_start": new_start, "new_count": new_count})
        require(hunks, "Patched file has no hunks")
        result.extend(original[at:])
        outputs[name] = "".join(result).encode("utf-8")
        require(outputs[name] != originals[name], "Patch has no net file change")
        details.append({"path": name, "hunks": hunks,
            "before_sha256": hashlib.sha256(originals[name]).hexdigest(),
            "after_sha256": hashlib.sha256(outputs[name]).hexdigest()})
    require(set(outputs) == allowed, "Patch does not touch its exact approved file set")
    return outputs, details


def validate_source(h, patch_pins):
    preparation_data, _ = checked_bytes(h, PREPARATION, PREPARATION_SHA, 16 * 1024 * 1024)
    preparation = json.loads(preparation_data)
    require(preparation.get("schema_version") == 1
            and preparation.get("status") == "editable-source-worktree-prepared-not-built"
            and preparation.get("source") == str(SOURCE)
            and preparation.get("archive_sha256") == h.ARCHIVE_SHA
            and preparation.get("helper_sha256") == HELPER_SHA
            and preparation.get("integration_eligible") is False
            and preparation.get("input_drift") is False
            and preparation.get("cancelled") is False
            and preparation.get("patch_sha256") == patch_pins, "Preparation identity differs")
    expected, originals = original_archive(h)
    require(preparation.get("original_source_entries") == expected, "Preparation differs from original archive")
    baseline_data, _ = checked_bytes(h, BASELINE / "source-before.json", BASELINE_PINS["source-before.json"])
    require(json.loads(baseline_data) == expected, "Frozen baseline original source differs")
    retained, diffs = {}, []
    current = dict(originals)
    for name, allowed in PATCH_FILES.items():
        data, row = checked_bytes(h, BASE / "patches" / name, patch_pins[name], PATCH_LIMIT)
        patched, changes = patched_bytes(data.decode("utf-8"), current, allowed)
        retained[name] = {**row, "content": data.decode("utf-8")}
        diffs.append({"patch": name, "sha256": row["sha256"], "files": changes})
        # Later patches consume the exact output of earlier patches, notably
        # 0004 through 0008 share cabs2cil.ml; coordinates/context remain strict.
        current.update(patched)
        for filename, value in patched.items():
            expected[filename] = {**expected[filename], "size": len(value),
                                  "sha256": hashlib.sha256(value).hexdigest()}
    require(preparation.get("prepared_source_entries") == expected,
            "Preparation final inventory differs from ordered seven-patch reconstruction")
    require(SOURCE.resolve() == SOURCE, "Prepared source path is symlinked")
    actual = h.inventory(SOURCE)
    differences = [name for name in sorted(set(expected) | set(actual)) if expected.get(name) != actual.get(name)]
    require(not differences, "Unapproved source differences: " + ", ".join(differences[:20]))
    return actual, retained, diffs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    for number in (2, 3, 4, 5, 6, 7, 8):
        parser.add_argument(f"--patch-{number}-sha256", required=True)
    args = parser.parse_args()
    patch_pins = dict(zip(PATCH_FILES, (getattr(args, f"patch_{n}_sha256") for n in (2, 3, 4, 5, 6, 7, 8))))
    require(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in patch_pins.values()), "Need seven explicit SHA-256 pins")
    require(re.fullmatch(r"[0-9a-f]{64}", PREPARATION_SHA),
            "Preparation has not been executed, reviewed and SHA-pinned")
    h = load_helper()
    require(all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WEXITED", "WNOHANG", "P_PID"))
            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "Linux waitid/WNOWAIT and default SIGCHLD handling are required")
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)
    output = Path(os.path.abspath(args.output))
    require(BASE == ROOT / "build/framac-alignment-provider-20260907" and output.parent == BASE
            and output.name == "candidate-build-5"
            and not os.path.lexists(output), "Need fresh fixed-scope candidate-build-5 output")
    output.mkdir(mode=0o700)
    report = {"schema_version": 1, "status": "failed", "started_at": h.stamp(),
        "integration_eligible": False, "semantic_changes": True, "runtime_validated": False,
        "child_started": False, "child_terminal": None, "returncode": None, "scope": __doc__,
        "source": str(SOURCE), "patch_sha256": patch_pins, "helper_sha256": HELPER_SHA,
        "archive_sha256": h.ARCHIVE_SHA, "source_edits_performed": False}
    proc, before, source_before = None, None, None
    try:
        h.save(output / "request.json", report)
        before = {"selected": selected_inputs(h, patch_pins), "dependencies": h.dependencies()}
        baseline_dependencies = []
        for name in ("dependencies-before.json", "dependencies-after.json"):
            data, _ = checked_bytes(h, BASELINE / name, BASELINE_PINS[name])
            baseline_dependencies.append(json.loads(data))
        require(baseline_dependencies[0] == baseline_dependencies[1] == before["dependencies"],
                "Current dependency closure differs from the authenticated baseline")
        h.save(output / "inputs-before.json", before)
        require(not h.CANCELLED, "Cancelled before source validation")
        source_before, patches, diffs = validate_source(h, patch_pins)
        h.save(output / "source-before.json", source_before)
        h.save(output / "patches.json", patches)
        h.save(output / "source-validation.json", {"status": "exact-original-plus-seven-ordered-patches",
            "changed_file_count": len(set().union(*PATCH_FILES.values())),
            "patch_count": len(diffs),
            "hunk_count": sum(len(f["hunks"]) for p in diffs for f in p["files"]),
            "source_entry_count": len(source_before), "patches": diffs})
        temporary, cache = output / "private-temp", output / "private-cache"
        temporary.mkdir(mode=0o700)
        cache.mkdir(mode=0o700)
        environment = {
            "PATH": str(h.SWITCH / "bin") + ":/usr/bin:/bin",
            "OPAM_SWITCH_PREFIX": str(h.SWITCH), "OCAMLPATH": str(h.SWITCH / "lib"),
            "CAML_LD_LIBRARY_PATH": ":".join(str(h.SWITCH / p) for p in
                ("lib/stublibs", "lib/ocaml/stublibs", "lib/ocaml")),
            "LD_LIBRARY_PATH": str(h.PREFIX / "lib"), "LIBRARY_PATH": str(h.PREFIX / "lib"),
            "CPATH": str(h.PREFIX / "include"), "PKG_CONFIG_PATH": str(h.PREFIX / "lib/pkgconfig"),
            "LC_ALL": "C", "LANG": "C", "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(cache), "DUNE_CACHE": "disabled", "DUNE_CACHE_ROOT": str(cache),
            "PYTHONDONTWRITEBYTECODE": "1"}
        argv = [str(h.SWITCH / "bin/dune"), "build", "--release", "--build-dir",
            str(output / "dune-build"), "-j2", "--promote-install-files=false",
            "--disable-promotion", "--cache=disabled", "--display=short", "@install"]
        report.update(argv=argv, cwd=str(SOURCE), environment=environment,
                      timeout_seconds=h.BUILD_SECONDS, stdin="DEVNULL",
                      timeout_semantics="monitored bound with inventory/scheduling latency; not instantaneous termination")
        h.save(output / "intent.json", report)
        require(not h.CANCELLED, "Cancelled before Dune launch")
        started = time.monotonic()
        with (output / "stdout").open("xb") as out, (output / "stderr").open("xb") as err:
            proc = subprocess.Popen(argv, cwd=SOURCE, env=environment, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, start_new_session=True, preexec_fn=h.child_limits)
            report.update(child_started=True, child_pid=proc.pid, child_terminal=False)
            identity = read_process_stat(proc.pid)
            require(identity["pgrp"] == identity["session"] == proc.pid,
                    "Dune did not start in its own session/group")
            h.save(output / "process.json", {**identity, "argv": argv, "cwd": str(SOURCE)})
            last_scan = started
            while True:
                require(not h.CANCELLED, "Cancellation requested")
                remaining = h.BUILD_SECONDS - (time.monotonic() - started)
                require(remaining > 0, "Build wall-clock bound exceeded")
                observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    report["build_elapsed_seconds"] = time.monotonic() - started
                    require(report["build_elapsed_seconds"] <= h.BUILD_SECONDS,
                            "Build completed beyond monitored deadline")
                    break
                if time.monotonic() - last_scan >= 10:
                    h.inventory(output, hash_files=False)
                    last_scan = time.monotonic()
                time.sleep(min(0.25, remaining))
            group = finish_process_group(proc)
            report.update(process_group=group, returncode=group["returncode"],
                          child_terminal=group["leader_reaped"])
            require(group["group_terminal"] and group["leader_reaped"]
                    and not group["cleanup_error"] and not group["nonleader_members_observed"],
                    "Original Dune group had leftovers or closure failed")
            require(not h.CANCELLED, "Cancelled after build completion")
        require(report["returncode"] == 0, "Dune build returned nonzero; no retry")
        binary = output / "dune-build/default/src/init/boot/empty_file.exe"
        require(binary.is_file() and not binary.is_symlink(), "Expected private native executable missing")
        with binary.open("rb") as stream:
            require(stream.read(4) == b"\x7fELF", "Private executable is not ELF")
        report["binary"] = {"path": str(binary), **h.record(binary)}
        report["status"] = SUCCESS
    except (OSError, ValueError, KeyError, IndexError, tarfile.TarError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if proc is not None and "process_group" not in report:
            group = finish_process_group(proc)
            report.update(process_group=group, returncode=group["returncode"],
                          child_terminal=group["leader_reaped"])
        group = report.get("process_group")
        if group and (not group["group_terminal"] or not group["leader_reaped"]
                      or group["cleanup_error"] or group["nonleader_members_observed"]):
            report["cleanup_error"] = group["cleanup_error"] or "Original group leftovers/closure failure"
        final_errors = []
        if before is not None:
            try:
                after = {"selected": selected_inputs(h, patch_pins), "dependencies": h.dependencies()}
                h.save(output / "inputs-after.json", after)
                report["dependency_drift"] = before != after
                require(before == after, "Selected input/dependency drift")
            except (OSError, ValueError, KeyboardInterrupt) as exc:
                final_errors.append("inputs: " + repr(exc))
        if source_before is not None:
            try:
                source_after = h.inventory(SOURCE)
                h.save(output / "source-after.json", source_after)
                report["source_drift"] = source_before != source_after
                require(source_before == source_after, "Patched source tree changed during build")
            except (OSError, ValueError, KeyboardInterrupt) as exc:
                final_errors.append("source: " + repr(exc))
        try:
            report["artifacts"] = h.inventory(output)
            report["artifact_inventory_complete"] = True
        except (OSError, ValueError, KeyboardInterrupt) as exc:
            final_errors.append("artifacts: " + repr(exc))
            report["artifact_inventory_complete"] = False
        report["cancellation_sampling_boundary"] = "after final inventories, before receipt serialization"
        report["late_cancellation_policy"] = "a later cancellation forces nonzero process exit; receipt records the stated sample only"
        report["cancelled"] = h.CANCELLED
        if final_errors:
            report["finalization_errors"] = final_errors
        if final_errors or report.get("cleanup_error") or report["child_terminal"] is False or h.CANCELLED:
            report["status"] = "failed"
        report["finished_at"] = h.stamp()
        try:
            h.save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({key: report.get(key) for key in ("status", "error", "returncode",
        "child_terminal", "dependency_drift", "source_drift", "finalization_errors", "receipt_write_error")}
        | {"cancelled_at_exit_sample": h.CANCELLED}))
    return 0 if report["status"] == SUCCESS and not h.CANCELLED else 1


if __name__ == "__main__":
    raise SystemExit(main())
