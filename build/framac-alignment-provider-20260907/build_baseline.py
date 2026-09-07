#!/usr/bin/env python3
"""Build the unmodified pinned Frama-C archive privately; never install or test it.

One direct Dune build invokes its ordinary compiler/configuration descendants.
No package operation, network command, analyzer invocation, proof, kernel build,
target-program execution or verified-prefix edit is requested by this recorder.
Selected dependency trees and source bytes are compared before/after. This is
not a hermetic host/dependency or descendant-command attestation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import stat
import subprocess
import tarfile
import time

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
PREFIX = ROOT / "toolchain/verified-prefix"
SWITCH = PREFIX / "opam/fragma"
ARCHIVE_SHA = "9c1cbffd28bb33c17a668107e39c96e4ae7378a3d8249f69b47afc7ee964e9b8"
ARCHIVE = PREFIX / "opam/download-cache/sha256/9c" / ARCHIVE_SHA
ARCHIVE_ROOT = "frama-c-33.0-Arsenic"
DUNE_SHA = "dd980538897c189a25ead7debdf52affaa1c340cba3879c9062725e20163ea08"
BUILD_SECONDS = 1800
FILE_LIMIT = 512 * 1024 * 1024
TREE_LIMIT = 8 * 1024 * 1024 * 1024
ENTRY_LIMIT = 100000
CANCELLED = False


def request_cancel(_signum, _frame):
    # Defer cancellation across Popen/identity recording; do not pass a blocked
    # signal mask to Dune or risk losing a just-started child on KeyboardInterrupt.
    global CANCELLED
    CANCELLED = True


def require(ok, message):
    if not ok:
        raise ValueError(message)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def record(path):
    path = Path(path)
    before = path.lstat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if stat.S_ISLNK(before.st_mode):
        target = os.readlink(path)
        require(signature(path.lstat()) == signature(before), "Symlink changed: " + str(path))
        return {"kind": "symlink", "target": target}
    require(stat.S_ISREG(before.st_mode), "Not a regular file: " + str(path))
    require(before.st_size <= FILE_LIMIT, "File size bound exceeded: " + str(path))
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        opened = os.fstat(stream.fileno())
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(data)
            require(total <= FILE_LIMIT, "File grew beyond read bound")
            digest.update(data)
        after = os.fstat(stream.fileno())
    require(signature(before) == signature(opened) == signature(after)
            == signature(path.lstat()), "File changed during hashing: " + str(path))
    return {"kind": "file", "size": before.st_size,
            "mode": stat.S_IMODE(before.st_mode), "sha256": digest.hexdigest()}


def inventory(directory, *, hash_files=True):
    require(directory.is_dir() and not directory.is_symlink(), "Missing/symlinked tree root")
    result, total = {}, 0
    def walk_error(error):
        if hash_files or not isinstance(error, FileNotFoundError):
            raise error
    for parent, folders, files in os.walk(directory, followlinks=False, onerror=walk_error):
        for name in sorted(folders + files):
            path = Path(parent) / name
            try:
                st = path.lstat()
            except FileNotFoundError:
                if hash_files:
                    raise
                continue  # Dune may remove/rename a temporary during a live quota scan.
            require(len(result) < ENTRY_LIMIT, "Tree entry bound exceeded")
            if stat.S_ISDIR(st.st_mode):
                result[str(path.relative_to(directory))] = {"kind": "directory"}
            elif not hash_files and stat.S_ISSOCK(st.st_mode):
                # Dune's ordinary RPC server owns a filesystem socket while
                # building. Never open it; strict post-terminal hashing below
                # requires that normal shutdown has removed it.
                result[str(path.relative_to(directory))] = {"kind": "live-socket"}
            else:
                require(stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode),
                        "Special file in tree: " + str(path))
                require(st.st_size <= FILE_LIMIT, "Per-file output bound exceeded")
                total += st.st_size
                require(total <= TREE_LIMIT, "Tree byte bound exceeded")
                result[str(path.relative_to(directory))] = (record(path) if hash_files
                    else {"kind": "entry", "size": st.st_size})
    return dict(sorted(result.items()))


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def dependencies():
    trees = [SWITCH / "bin", SWITCH / "lib", PREFIX / "lib", PREFIX / "include"]
    paths = [Path(__file__).resolve(), ARCHIVE, ROOT / "toolchain/lock.json",
             ROOT / "toolchain/opam-switch.complete.export",
             SWITCH / ".opam-switch/switch-state",
             SWITCH / ".opam-switch/packages/frama-c.33.0/opam"]
    # Bind the real host build tools, including GCC's ordinary subprocesses.
    paths += [Path(p).resolve(strict=True) for p in (
        "/usr/bin/gcc", "/usr/bin/as", "/usr/bin/ld", "/usr/bin/ar",
        "/usr/bin/pkg-config", "/usr/libexec/gcc/x86_64-linux-gnu/15/cc1",
        "/usr/libexec/gcc/x86_64-linux-gnu/15/collect2")]
    require(record(ARCHIVE).get("sha256") == ARCHIVE_SHA, "Pinned archive changed")
    require(record(SWITCH / "bin/dune").get("sha256") == DUNE_SHA, "Dune pin changed")
    require("sha256=" + ARCHIVE_SHA in (ROOT / "toolchain/lock.json").read_text(),
            "Archive is not in the current source lock")
    return {"files": {str(p): record(p) for p in sorted(set(paths))},
            "trees": {str(p): inventory(p) for p in trees}}


def extract(destination):
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == 11512 and sum(m.isfile() for m in members) == 10893
                and sum(m.isdir() for m in members) == 619
                and sum(m.size for m in members) == 49657870,
                "Pinned archive inventory differs")
        seen = set()
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts
                    and name.parts[0] == ARCHIVE_ROOT and str(name) not in seen
                    and (member.isfile() or member.isdir()) and member.size <= FILE_LIMIT,
                    "Unexpected archive member")
            seen.add(str(name))
        destination.mkdir(mode=0o700)
        for member in members:
            path = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
            else:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with archive.extractfile(member) as incoming, path.open("xb") as outgoing:
                    copied = 0
                    for data in iter(lambda: incoming.read(1024 * 1024), b""):
                        copied += len(data)
                        require(copied <= member.size, "Archive member grew")
                        outgoing.write(data)
                require(copied == member.size, "Short archive member")
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
    require(record(ARCHIVE).get("sha256") == ARCHIVE_SHA, "Archive drift after extraction")


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT, FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGINT, request_cancel)
    signal.signal(signal.SIGTERM, request_cancel)
    output = Path(os.path.abspath(args.output))
    require(BASE == ROOT / "build/framac-alignment-provider-20260907"
            and output.parent == BASE and re.fullmatch(r"baseline-[1-9][0-9]*", output.name)
            and not os.path.lexists(output), "Need a fresh fixed-scope baseline-N output")
    output.mkdir(mode=0o700)
    report = {"status": "failed", "started_at": stamp(), "integration_eligible": False,
              "semantic_changes": False, "child_started": False, "child_terminal": None,
              "scope": __doc__, "archive_sha256": ARCHIVE_SHA, "returncode": None}
    proc, before, source_before = None, None, None
    try:
        before = dependencies()
        save(output / "dependencies-before.json", before)
        require(not CANCELLED, "Cancelled before extraction")
        extract(output / "source")
        source = output / "source" / ARCHIVE_ROOT
        source_before = inventory(source)
        save(output / "source-before.json", source_before)
        temporary, cache = output / "private-temp", output / "private-cache"
        temporary.mkdir(mode=0o700)
        cache.mkdir(mode=0o700)
        environment = {
            "PATH": str(SWITCH / "bin") + ":/usr/bin:/bin",
            "OPAM_SWITCH_PREFIX": str(SWITCH), "OCAMLPATH": str(SWITCH / "lib"),
            "CAML_LD_LIBRARY_PATH": ":".join(str(SWITCH / p) for p in
                ("lib/stublibs", "lib/ocaml/stublibs", "lib/ocaml")),
            "LD_LIBRARY_PATH": str(PREFIX / "lib"), "LIBRARY_PATH": str(PREFIX / "lib"),
            "CPATH": str(PREFIX / "include"), "PKG_CONFIG_PATH": str(PREFIX / "lib/pkgconfig"),
            "LC_ALL": "C", "LANG": "C", "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(cache), "DUNE_CACHE": "disabled", "DUNE_CACHE_ROOT": str(cache),
            "PYTHONDONTWRITEBYTECODE": "1"}
        argv = [str(SWITCH / "bin/dune"), "build", "--release", "--build-dir",
                str(output / "dune-build"), "-j2", "--promote-install-files=false",
                "--disable-promotion", "--cache=disabled", "--display=short", "@install"]
        report.update(argv=argv, cwd=str(source), environment=environment,
                      timeout_seconds=BUILD_SECONDS, stdin="DEVNULL")
        save(output / "intent.json", report)
        require(not CANCELLED, "Cancelled before Dune launch")
        started = time.monotonic()
        with (output / "stdout").open("xb") as out, (output / "stderr").open("xb") as err:
            proc = subprocess.Popen(argv, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=True, preexec_fn=child_limits)
            report.update(child_started=True, child_pid=proc.pid, child_terminal=False)
            save(output / "process.json", {"pid": proc.pid, "argv": argv, "cwd": str(source)})
            while True:
                require(not CANCELLED, "Cancellation requested")
                remaining = BUILD_SECONDS - (time.monotonic() - started)
                require(remaining > 0, "Build wall-clock bound exceeded")
                try:
                    report["returncode"] = proc.wait(timeout=min(10, remaining))
                    report["child_terminal"] = True
                    break
                except subprocess.TimeoutExpired:
                    inventory(output, hash_files=False)
        require(report["returncode"] == 0, "Dune build returned nonzero; no retry")
        binary = output / "dune-build/default/src/init/boot/empty_file.exe"
        require(binary.is_file() and not binary.is_symlink(), "Expected private native executable missing")
        with binary.open("rb") as stream:
            require(stream.read(4) == b"\x7fELF", "Private executable is not ELF")
        report["binary"] = {"path": str(binary), **record(binary)}
        report["status"] = "unmodified-private-build-complete-not-runtime-validated"
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        report["cancelled"] = CANCELLED
        if proc is not None and proc.returncode is not None:
            report.update(returncode=proc.returncode, child_terminal=True)
        if proc is not None and report["child_terminal"] is not True:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                report["cleanup_error"] = repr(exc)
            try:
                report["returncode"] = proc.wait(timeout=10)
                report["child_terminal"] = True
            except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                report["cleanup_error"] = repr(exc)
                report["child_terminal"] = False
        try:
            if before is not None:
                after = dependencies()
                save(output / "dependencies-after.json", after)
                report["dependency_drift"] = before != after
                require(before == after, "Selected build dependency drift")
            if source_before is not None:
                source_after = inventory(output / "source" / ARCHIVE_ROOT)
                save(output / "source-after.json", source_after)
                report["source_drift"] = source_before != source_after
                require(source_before == source_after, "Unmodified source tree changed")
            report["artifacts"] = inventory(output)
            report["artifact_inventory_complete"] = True
        except (OSError, ValueError, KeyboardInterrupt) as exc:
            report.update(status="failed", finalization_error=repr(exc), artifact_inventory_complete=False)
        if report.get("cleanup_error") or report["child_terminal"] is False:
            report["status"] = "failed"
        report["finished_at"] = stamp()
        try:
            save(output / "receipt.json", report)
        except (OSError, ValueError) as exc:
            report.update(status="failed", receipt_write_error=repr(exc))
    print(json.dumps({key: report.get(key) for key in ("status", "error", "returncode",
          "child_terminal", "dependency_drift", "source_drift", "finalization_error",
          "receipt_write_error")}))
    return 0 if report["status"] == "unmodified-private-build-complete-not-runtime-validated" else 1


if __name__ == "__main__":
    raise SystemExit(main())
