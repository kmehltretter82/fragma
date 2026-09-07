#!/usr/bin/env python3
"""Five early version/site queries only; no parsing, plugin loading or proof.

Use explicit private Dune sites with the existing read-only OCaml dependencies.
An early path result does not establish later plugin/dependency isolation or
analysis correctness, and does not change the completed build receipt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import types

BASE = Path(__file__).resolve().parent
HELPER = BASE / "build_baseline.py"
HELPER_SHA = "3181b7c935cc03b31ba9c4232176b5e7e4fda794c0f013f31692cfe1f4e3e7c7"
BUILD = BASE / "baseline-1"
RECEIPT_SHA = "deb25b14d6add7d7f01bf0a10e52bbe53ff6864e69a051ad68eb0d07ba111836"
FLAGS = ("-version", "-print-config", "-print-share-path", "-print-lib-path", "-print-plugin-path")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    data = HELPER.read_bytes()
    if hashlib.sha256(data).hexdigest() != HELPER_SHA:
        raise ValueError("Reviewed build helper changed")
    h = types.ModuleType("fragma_private_build_readers")
    h.__file__ = str(HELPER)
    exec(compile(data, str(HELPER), "exec"), h.__dict__)
    output = Path(os.path.abspath(args.output))
    h.require(output.parent == BASE and re.fullmatch(r"runtime-[1-9][0-9]*", output.name)
              and not os.path.lexists(output), "Need fresh runtime-N output")
    h.require(h.record(BUILD / "receipt.json").get("sha256") == RECEIPT_SHA,
              "Completed build receipt changed")
    receipt = json.loads((BUILD / "receipt.json").read_text())
    h.require(receipt["status"] == "unmodified-private-build-complete-not-runtime-validated"
              and receipt["child_terminal"] is True and receipt["source_drift"] is False
              and receipt["dependency_drift"] is False, "Build prerequisite did not pass")
    binary = Path(receipt["binary"]["path"])
    installed = BUILD / "dune-build/install/default"
    expected_paths = {"-print-share-path": str(installed / "share/frama-c/share"),
                      "-print-lib-path": str(installed / "lib/frama-c/lib"),
                      "-print-plugin-path": str(installed / "lib/frama-c/plugins")}
    for value in expected_paths.values():
        h.require(Path(value).is_dir(), "Expected private site missing")

    def snapshot():
        artifacts = h.inventory(BUILD)
        expected = dict(receipt["artifacts"])
        expected["receipt.json"] = h.record(BUILD / "receipt.json")
        h.require(artifacts == expected, "Completed build artifacts changed")
        dependencies = h.dependencies()
        h.require(dependencies == json.loads((BUILD / "dependencies-after.json").read_text()),
                  "Completed build dependencies changed")
        return {"build_receipt": h.record(BUILD / "receipt.json"),
                "runtime_reader": h.record(Path(__file__).resolve()),
                "dependencies": dependencies, "build_artifacts": artifacts}

    before = snapshot()
    output.mkdir(mode=0o700)
    temporary = output / "private-temp"
    temporary.mkdir(mode=0o700)
    h.save(output / "inputs-before.json", before)
    environment = {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
        "LD_LIBRARY_PATH": str(h.PREFIX / "lib"),
        "CAML_LD_LIBRARY_PATH": ":".join(str(h.SWITCH / p) for p in
            ("lib/stublibs", "lib/ocaml/stublibs", "lib/ocaml")),
        "OCAMLPATH": str(installed / "lib"),
        "DUNE_OCAML_HARDCODED": str(h.SWITCH / "lib/ocaml") + ":" + str(h.SWITCH / "lib"),
        "DUNE_OCAML_STDLIB": str(h.SWITCH / "lib/ocaml"),
        "DUNE_SOURCEROOT": str(BUILD / "source/frama-c-33.0-Arsenic"),
        "DUNE_DIR_LOCATIONS": ":".join(("frama-c", "libexec", str(installed / "lib/frama-c"),
            "frama-c", "lib", str(installed / "lib/frama-c"),
            "frama-c", "share", str(installed / "share/frama-c"))),
        "TMPDIR": str(temporary)}
    report = {"status": "failed", "scope": __doc__, "started_at": h.stamp(), "commands": [],
              "integration_eligible": False, "analysis_validated": False}
    signal.signal(signal.SIGINT, h.request_cancel)
    signal.signal(signal.SIGTERM, h.request_cancel)

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    try:
        for index, flag in enumerate(FLAGS, 1):
            h.require(not h.CANCELLED, "Cancellation requested")
            folder = output / ("command-%02d" % index)
            folder.mkdir(mode=0o700)
            row = {"argv": [str(binary), flag], "cwd": str(folder), "environment": environment,
                   "stdin": "DEVNULL", "started_at": h.stamp(), "timeout_seconds": 10,
                   "child_started": False, "child_terminal": None}
            h.save(folder / "intent.json", row)
            report["commands"].append(row)
            proc = None
            try:
                with (folder / "stdout").open("xb") as out, (folder / "stderr").open("xb") as err:
                    proc = subprocess.Popen(row["argv"], cwd=folder, env=environment,
                        stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                        start_new_session=True, preexec_fn=limits)
                    row.update(child_started=True, child_pid=proc.pid, child_terminal=False)
                    row["returncode"] = proc.wait(timeout=10)
                    row["child_terminal"] = True
            finally:
                if proc is not None and proc.returncode is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError as exc:
                        row["cleanup_error"] = repr(exc)
                    try:
                        row["returncode"] = proc.wait(timeout=5)
                        row["child_terminal"] = True
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        row.update(cleanup_error=repr(exc), child_terminal=False)
                row["finished_at"] = h.stamp()
                h.save(folder / "result.json", row)
            stdout = (folder / "stdout").read_text()
            stderr = (folder / "stderr").read_text()
            h.require(row.get("returncode") == 0 and row["child_terminal"] is True
                      and not row.get("cleanup_error") and not stderr, "Early runtime query failed")
            if flag == "-version":
                h.require(stdout == "33.0 (Arsenic)\n", "Unexpected private version")
            elif flag in expected_paths:
                h.require(stdout.rstrip("\n") == expected_paths[flag], "Private site path mismatch")
            else:
                expected = ("Frama-C 33.0 (Arsenic)\nEnvironment:\n"
                    + "  FRAMAC_SHARE  = " + json.dumps(expected_paths["-print-share-path"]) + "\n"
                    + "  FRAMAC_PLUGIN = " + json.dumps(expected_paths["-print-plugin-path"]) + "\n"
                    + "  FRAMAC_LIB    = " + json.dumps(expected_paths["-print-lib-path"]) + "\n")
                h.require(stdout == expected, "Unexpected private configuration output")
            row["classification"] = "early-output-checked"
        h.require(not h.CANCELLED, "Cancellation requested")
        report["status"] = "private-early-runtime-paths-checked-not-analysis-validated"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = repr(exc)
    finally:
        try:
            after = snapshot()
            h.save(output / "inputs-after.json", after)
            report["input_drift"] = before != after
            h.require(before == after, "Runtime query input drift")
            report["artifacts"] = h.inventory(output)
        except (OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
            report.update(status="failed", finalization_error=repr(exc))
        report["finished_at"] = h.stamp()
        try:
            h.save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({key: report.get(key) for key in ("status", "error", "input_drift",
                                                    "finalization_error", "receipt_write_error")}))
    return 0 if report["status"] == "private-early-runtime-paths-checked-not-analysis-validated" else 1


if __name__ == "__main__":
    raise SystemExit(main())
