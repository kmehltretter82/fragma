#!/usr/bin/env python3
"""Prepare only fresh worktree-4 from the pinned archive and six ordered patches.

No subprocess, build, compiler, analyzer, package or installation is invoked.
The frozen V3 builder supplies only authenticated read/hash/archive/diff helpers.
All patches are checked in memory before extraction. Only ten files in the
newly created source tree are rewritten, once each, with their final bytes.
Existing worktrees/builds and executed evidence are never modified or removed.
Failed or cancelled partial output is retained and cannot be reused.
The original 0006/0007 proposals remain pinned; only their hunk coordinates
change in the rebased patches, and both base and sequential contexts are checked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import tarfile
import types

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
BUILDER = BASE / "build_candidate_v3.py"
BUILDER_SHA = "e1f9c310040ecf2588da7648de9a490e277926b9116096e39c714bbe53a98668"
OUTPUT = BASE / "worktree-4"
SOURCE = OUTPUT / "source/frama-c-33.0-Arsenic"
PATCH_PINS = {
    "0002-alignment-attribute-policy-v2.patch": "b7c995ec09d85356865f6ab799f4f2002140fe496a2b25e146ac34479fa730c9",
    "0003-clang-alignment-consumers.patch": "3dcd00320b8a07ac01879376bec8b4ee02ded8cd4b0646103fa926d30b2c8f49",
    "0004-clang-alignment-typing.patch": "970278b7dfd73a2206649583b2743b93f6bde6a349364c16c145b7370b0edc37",
    "0005-c11-missing-definition.patch": "1a7ab19aaff5d3d8785bc73d838e54bbd0273c60844bf5f9336f44eb357aaa29",
    "0006-vla-typed-provenance-v2.patch": "5f48f8485c99e74f574b570a5bf7ac78f8456a453858ed6047b8a6258eae37cd",
    "0007-clang-typed-gnu-alignment-v2.patch": "edfb032e3ecbf1de3c52b73062742df42d83ae74a484addcd2c1516185d8913d",
}
ORIGINAL_PROPOSALS = {
    "0006-vla-typed-provenance-v2.patch": (
        "0006-vla-typed-provenance.patch",
        "eb782d053c1ea3f4a25b80ac5a3dfee25e89954f3c3226b26d9f4bfa1aa9c7f4"),
    "0007-clang-typed-gnu-alignment-v2.patch": (
        "0007-clang-typed-gnu-alignment.patch",
        "b6323eff7cf792aa2bd0956349d49d0ad9cf48e7c14288473046bd384f352bd6"),
}
SUCCESS = "editable-source-worktree-prepared-not-built"


def load_builder():
    if BUILDER.resolve() != BUILDER or BUILDER.stat().st_size > 65536:
        raise ValueError("Frozen builder path/size changed")
    data = BUILDER.read_bytes()
    if len(data) > 65536 or hashlib.sha256(data).hexdigest() != BUILDER_SHA:
        raise ValueError("Frozen builder pin changed")
    module = types.ModuleType("fragma_v4_preparation_frozen_builder")
    module.__file__ = str(BUILDER)
    exec(compile(data, str(BUILDER), "exec"), module.__dict__)
    return module


def inputs(b, h):
    pins = {BUILDER: BUILDER_SHA, b.HELPER: b.HELPER_SHA, h.ARCHIVE: h.ARCHIVE_SHA,
            **{b.BASELINE / name: b.BASELINE_PINS[name]
               for name in ("source-before.json", "source-after.json")},
            **{BASE / "patches" / name: pin for name, pin in PATCH_PINS.items()},
            **{BASE / "patches" / name: pin for name, pin in ORIGINAL_PROPOSALS.values()}}
    result = {str(Path(__file__).resolve()): h.record(Path(__file__).resolve())}
    for path, pin in pins.items():
        b.require(path.resolve() == path, "Preparation input path is symlinked")
        row = h.record(path)
        b.require(row.get("kind") == "file" and row.get("sha256") == pin,
                  "Preparation input pin changed: " + str(path))
        result[str(path)] = row
    return result


def reconstruct(b, h):
    original, current = b.original_archive(h)
    # The frozen V3 helper materializes nine edited files; the new printer is
    # read separately from the same already-validated original archive.
    printer = "src/kernel_services/ast_printing/cil_printer.ml"
    with tarfile.open(h.ARCHIVE, "r:gz") as archive:
        with archive.extractfile(h.ARCHIVE_ROOT + "/" + printer) as stream:
            data = stream.read(original[printer]["size"] + 1)
    b.require(len(data) == original[printer]["size"]
              and hashlib.sha256(data).hexdigest() == original[printer]["sha256"],
              "Original printer bytes differ from authenticated archive inventory")
    current[printer] = data
    for name in ("source-before.json", "source-after.json"):
        data, _ = b.checked_bytes(h, b.BASELINE / name, b.BASELINE_PINS[name])
        b.require(json.loads(data) == original, "Original archive differs from frozen baseline")
    expected = {name: dict(row) for name, row in original.items()}
    patch_files = {
        **b.PATCH_FILES,
        "0006-vla-typed-provenance-v2.patch": {"src/kernel_internals/typing/cabs2cil.ml"},
        "0007-clang-typed-gnu-alignment-v2.patch": {
            "src/kernel_internals/typing/cabs2cil.ml",
            "src/kernel_services/ast_queries/cil.ml",
            "src/kernel_services/ast_queries/cil.mli", printer},
    }
    b.require(list(patch_files) == list(PATCH_PINS), "Ordered patch inventory differs")
    changes, proposal_base = [], None
    hunk_coordinates = re.compile(r"(?m)^@@ -[0-9]+(?:,[0-9]+)? \+[0-9]+(?:,[0-9]+)? @@")
    for name, allowed in patch_files.items():
        b.require(not h.CANCELLED, "Cancelled during in-memory patch validation")
        data, row = b.checked_bytes(h, BASE / "patches" / name, PATCH_PINS[name], b.PATCH_LIMIT)
        if name in ORIGINAL_PROPOSALS:
            original_name, original_pin = ORIGINAL_PROPOSALS[name]
            proposal, _ = b.checked_bytes(h, BASE / "patches" / original_name,
                                           original_pin, b.PATCH_LIMIT)
            b.require(proposal_base is not None, "Missing exact pre-0005 proposal base")
            b.patched_bytes(proposal.decode("utf-8"), proposal_base, allowed)
            b.require(hunk_coordinates.sub("@@ COORDINATES @@", proposal.decode("utf-8"))
                      == hunk_coordinates.sub("@@ COORDINATES @@", data.decode("utf-8")),
                      "Rebased proposal changed more than hunk coordinates")
        patched, details = b.patched_bytes(data.decode("utf-8"), current, allowed)
        current.update(patched)
        if name == "0004-clang-alignment-typing.patch":
            proposal_base = dict(current)
        for filename, value in patched.items():
            expected[filename] = {**expected[filename], "size": len(value),
                                  "sha256": hashlib.sha256(value).hexdigest()}
        changes.append({"patch": name, "sha256": row["sha256"], "files": details})
    b.require(len(current) == 10 and len(changes) == 6
              and sum(len(f["hunks"]) for p in changes for f in p["files"]) == 62,
              "Expected ten source files and six patches/62 hunks")
    return original, expected, current, changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    b = load_builder()
    h = b.load_helper()
    output = Path(os.path.abspath(args.output))
    b.require(BASE == ROOT / "build/framac-alignment-provider-20260907"
              and output == OUTPUT and output.parent.resolve() == BASE
              and not os.path.lexists(output), "Need unused, exact worktree-4 output")
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)
    output.mkdir(mode=0o700)
    report = {"schema_version": 1, "status": "failed", "scope": __doc__,
              "started_at": h.stamp(), "source": str(SOURCE), "launch": vars(args),
              "archive_sha256": h.ARCHIVE_SHA, "helper_sha256": b.HELPER_SHA,
              "builder_sha256": BUILDER_SHA, "patch_sha256": PATCH_PINS,
              "patch_order": list(PATCH_PINS), "original_proposals": ORIGINAL_PROPOSALS,
              "integration_eligible": False,
              "subprocesses_started": 0, "existing_source_edits_performed": False,
              "input_drift": None}
    before, expected = None, None
    try:
        h.save(output / "request.json", report)
        before = inputs(b, h)
        report["inputs_before"] = before
        original, expected, final_bytes, changes = reconstruct(b, h)
        report.update(original_source_entries=original, patch_changes=changes,
                      changed_file_count=len(final_bytes), hunk_count=62)
        b.require(not h.CANCELLED, "Cancelled before fresh extraction")
        h.extract(output / "source")
        b.require(SOURCE.resolve() == SOURCE and h.inventory(SOURCE) == original,
                  "Extracted original source differs from complete archive inventory")
        for name, data in sorted(final_bytes.items()):
            b.require(not h.CANCELLED, "Cancelled before writing new-tree patch output")
            path = SOURCE / name
            b.require(path.resolve() == path and h.record(path) == original[name],
                      "New-tree source changed before its one controlled write")
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW), "wb") as stream:
                stream.write(data)
            b.require(h.record(path) == expected[name], "Written patch bytes/mode differ")
        report["status"] = SUCCESS
    except (OSError, ValueError, KeyError, IndexError, UnicodeError, tarfile.TarError, KeyboardInterrupt) as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        errors = []
        if before is not None:
            try:
                after = inputs(b, h)
                report["inputs_after"] = after
                report["input_drift"] = before != after
                b.require(before == after, "Preparation inputs changed")
            except (OSError, ValueError, KeyboardInterrupt) as exc:
                errors.append("inputs: " + repr(exc))
        if expected is not None:
            try:
                actual = h.inventory(SOURCE)
                report["prepared_source_entries"] = actual
                b.require(actual == expected, "Prepared source differs from six ordered patches")
            except (OSError, ValueError, KeyboardInterrupt) as exc:
                errors.append("source: " + repr(exc))
        try:
            report["artifacts"] = h.inventory(output)
        except (OSError, ValueError, KeyboardInterrupt) as exc:
            errors.append("artifacts: " + repr(exc))
        report["cancellation_sampling_boundary"] = "after inventories, before preparation serialization"
        report["late_cancellation_policy"] = "later observed cancellation forces nonzero exit"
        report["cancelled"] = h.CANCELLED
        if errors or h.CANCELLED:
            report.update(status="failed", finalization_errors=errors)
        report["prepared_at"] = h.stamp()
        try:
            h.save(output / "preparation.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({k: report.get(k) for k in ("status", "error", "input_drift", "prepared_at",
                                                "finalization_errors", "receipt_write_error")}
                     | {"cancelled_at_exit_sample": h.CANCELLED}))
    return 0 if report["status"] == SUCCESS and report["input_drift"] is False and not h.CANCELLED else 1


if __name__ == "__main__":
    raise SystemExit(main())
