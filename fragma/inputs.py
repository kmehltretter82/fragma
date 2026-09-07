"""Prepare proof inputs with actual kernel compiler flags and consumed-file hashes."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time

from .sources import SourceError, check_snapshot_files, sha256
from . import frontend_policy


SHIMS = ["-D__builtin_memcpy=memcpy", "-D__typeof_unqual__=__typeof__",
         "-D__restrict__=restrict", "-D__SIZEOF_INT128__=16", "-D__signed__=",
         "-D__builtin_unreachable=fragma_unreachable", "-std=gnu11"]


def load_build(root: Path, profile_id: str, revision: str) -> dict:
    build = root / "build" / "kernel" / profile_id
    path = build / "fragma-build.json"
    if not path.is_file():
        raise SourceError(f"missing prepared kernel build: {build}")
    record = json.loads(path.read_text())
    if record.get("schema_version") != 1 or record.get("status") != "prepared":
        raise SourceError("kernel preparation did not complete")
    if record.get("revision") != revision or record.get("profile_id") != profile_id:
        raise SourceError("kernel build revision/profile mismatch")
    for name, expected in record.get("files", {}).items():
        if not (build / name).is_file() or sha256(build / name) != expected:
            raise SourceError(f"prepared kernel input changed: {build / name}")
    if sha256(Path(record["compiler"])) != record["compiler_sha256"]:
        raise SourceError("kernel build compiler binary changed")
    return {**record, "path": str(build), "receipt_sha256": sha256(path)}


def compile_entry(build: dict, relative_source: str) -> dict:
    db = json.loads((Path(build["path"]) / "compile_commands.json").read_text())
    source = Path(build["source"]) / relative_source
    entries = [entry for entry in db if Path(entry["file"]).resolve() == source.resolve()]
    if len(entries) != 1:
        raise SourceError(f"need exactly one build command for {relative_source}; got {len(entries)}")
    return entries[0]


def command_without_outputs(entry: dict) -> list[str]:
    """Keep real compiler flags, stripping only source and build output options."""
    args = entry.get("arguments") or shlex.split(entry["command"])
    result = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-o", "-MF", "-MT", "-MQ"):
            i += 2
            continue
        if arg in ("-c", "-MD", "-MMD", "-MP") or arg == entry["file"] or arg.startswith("-Wp,-MMD,"):
            i += 1
            continue
        if arg in ("&&", ";", "|", ">", "<"):
            raise SourceError("shell operators are not accepted in compilation database commands")
        result.append(arg)
        i += 1
    if not result:
        raise SourceError("empty compilation command")
    return result


def dependency_paths(path: Path, cwd: Path) -> list[Path]:
    if not path.is_file():
        raise SourceError(f"preprocessor did not emit dependencies: {path}")
    text = path.read_text().replace("\\\n", "")
    if not text.startswith("fragma:"):
        raise SourceError("unexpected dependency-file target")
    # GCC make escaping for spaces/backslashes/# is compatible with POSIX lexer
    # for the paths used here. Double dollars need make's literal-dollar decoding.
    words = shlex.split(text.split(":", 1)[1].replace("$$", "$"), comments=False)
    paths = []
    for word in words:
        item = Path(word)
        item = item if item.is_absolute() else cwd / item
        if not item.is_file():
            raise SourceError(f"missing consumed input: {item}")
        paths.append(item.resolve())
    if not paths:
        raise SourceError("preprocessor emitted an empty dependency list")
    return sorted(set(paths))


def input_receipts(root: Path, kernel: Path, revision: str, build: dict,
                   paths: list[Path]) -> list[dict]:
    source = Path(build["source"]).resolve()
    build_path = Path(build["path"]).resolve()
    kernel_paths = [path for path in paths if path.is_relative_to(source)]
    records = check_snapshot_files(kernel, revision, source, kernel_paths)
    if any(not record["passed"] for record in records):
        raise SourceError("consumed kernel source/header differs from pinned git revision")
    result = [{**record, "origin": "kernel", "absolute_path": str(source / record["path"])}
              for record in records]
    for path in paths:
        if path.is_relative_to(source):
            continue
        if path.is_relative_to(build_path):
            origin, relative = "kernel-build", path.relative_to(build_path)
        elif path.is_relative_to(root):
            origin, relative = "project", path.relative_to(root)
        else:
            raise SourceError(f"unclassified host header in proof inputs: {path}")
        result.append({"origin": origin, "path": str(relative),
                       "absolute_path": str(path), "sha256": sha256(path)})
    return result


def run_recorded(argv: list[str], *, cwd: Path, env: dict, log: Path,
                 timeout: int, stdout_file: Path | None = None) -> dict:
    started = time.monotonic()
    with log.open("w") as errors:
        output = stdout_file.open("w") if stdout_file else errors
        try:
            # Why3 launches solver children. A timeout must stop the whole
            # process group, not leave proof workers running after the report.
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=output,
                                       stderr=errors, start_new_session=True)
            try:
                code, timed_out = process.wait(timeout=timeout), False
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                # The parent can exit before a child which ignored SIGTERM.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                code, timed_out = None, True
            except BaseException:
                # Cancellation is not a successful timeout report, but still
                # must not leave analyzer or solver workers behind.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
        finally:
            if stdout_file:
                output.close()
    return {"argv": argv, "cwd": str(cwd), "returncode": code,
            "timed_out": timed_out, "seconds": time.monotonic() - started,
            "log": str(log), "log_sha256": sha256(log)}


def prepare_input(root: Path, target: dict, profile: dict, build: dict,
                  kernel: Path, revision: str, output: Path, env: dict) -> dict:
    """Capture compiler input/dependencies and configure Frama-C preprocessing.

    The compiler-only .i is an audit artifact, not the proof input: Frama-C must
    perform its own ACSL preprocessing so named macros inside comments expand.
    """
    frontend_policy.identity(target, root=root)
    harness = (root / target["harness"]).resolve()
    if not harness.is_file():
        raise SourceError(f"missing harness: {harness}")
    depfile, preprocessed = output / "headers.d", output / "input.i"
    cwd = Path(build["path"])
    if target["input_mode"] == "kernel-tu":
        if target["profile"] != "x86_64-gcc":
            raise SourceError("whole-TU header substitutions currently scoped to x86-64")
        entry = compile_entry(build, target["source"])
        args = command_without_outputs(entry)
        args[1:1] = ["-I", str(root / "annotated/override")]
        args.extend(["-include", str(root / target.get("specs", "annotated/specs.h")),
                     "-include", str(root / "annotated/compat.h"), *SHIMS])
    elif target["input_mode"] == "standalone":
        entry = None
        args = [profile["compiler"]["path"], *profile["analysis"]["compiler_flags"],
                "-nostdinc", "-D__KERNEL__"]
    else:
        raise SourceError(f"unsupported input mode: {target['input_mode']}")
    args = frontend_policy.add_cpp_arguments(args, target)
    frama_cpp_command = shlex.join([*args, "-E", "-C"])
    args += ["-D__FRAMAC__", "-E", "-C", "-MD", "-MF", str(depfile),
             "-MT", "fragma", str(harness)]
    receipt = run_recorded(args, cwd=cwd, env=env, log=output / "preprocess.log",
                           timeout=120, stdout_file=preprocessed)
    if receipt["returncode"] != 0 or not preprocessed.is_file() or not preprocessed.stat().st_size:
        raise SourceError(f"preprocessing failed; see {receipt['log']}")
    paths = dependency_paths(depfile, cwd)
    inputs = input_receipts(root, kernel, revision, build, paths)
    # Catch concurrent edits between preprocessing and use. The final suite also
    # rechecks these hashes after all analyses before accepting a run.
    return {"path": str(preprocessed), "sha256": sha256(preprocessed),
            "frama_input": str(harness), "frama_cpp_command": frama_cpp_command,
            "cwd": str(cwd),
            "preprocess": receipt, "original_compile_command": entry,
            "inputs": inputs, "annotations": "Frama-C native -pp-annot with target compiler"}


def audit_inputs(root: Path, kernel: Path, revision: str, build: dict,
                 output: Path, prepared: dict, target: dict) -> dict:
    """Check Frama-C's own consumed-source audit, retaining its actual CPP files.

    The analyzer's MD5 is used only to compare its observation with the current
    file. SHA-256 and pinned git-blob checks remain the source-identity gates.
    Forced includes can be absent from this audit, so it supplements rather
    than replaces the compiler dependency receipt.
    """
    audit_path = output / "audit.json"
    audit = json.loads(audit_path.read_text())
    if not isinstance(audit, dict):
        raise SourceError("Frama-C audit must be a JSON object")
    declared = audit.get("sources")
    if not isinstance(declared, dict) or not declared:
        raise SourceError("missing or empty Frama-C consumed-source audit")
    cwd = Path(prepared["cwd"])
    paths = set()
    for filename, expected in declared.items():
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{32}", expected):
            raise SourceError(f"unsupported Frama-C source digest for {filename}")
        path = Path(filename)
        path = (path if path.is_absolute() else cwd / path).resolve()
        if not path.is_file() or hashlib.md5(path.read_bytes(), usedforsecurity=False).hexdigest() != expected:
            raise SourceError(f"Frama-C consumed source changed: {path}")
        paths.add(path)
    for field in ("harness", "driver"):
        if target.get(field) and (root / target[field]).resolve() not in paths:
            raise SourceError(f"Frama-C audit does not include declared {field}")
    records = input_receipts(root, kernel, revision, build, sorted(paths))
    retained = []
    temporary = output / "tmp"
    for path in sorted(temporary.rglob("*")):
        if path.is_symlink():
            raise SourceError(f"unexpected symlink in retained preprocessing artifacts: {path}")
        if path.is_file():
            retained.append({"path": str(path.relative_to(output)),
                             "absolute_path": str(path), "sha256": sha256(path)})
    streams = []
    for field in ("harness", "driver"):
        if not target.get(field):
            continue
        name = Path(target[field]).name
        matches = [item for item in retained if Path(item["path"]).name.startswith(name)
                   and item["path"].endswith(".pp")]
        if len(matches) != 1:
            # A dependency makefile also has an .i suffix in Frama-C 33. It
            # cannot stand in for the ACSL-preprocessed stream actually parsed.
            raise SourceError(f"missing or ambiguous actual Frama-C .pp input for {name}")
        streams.append({"source": target[field], **matches[0]})
    return {"path": str(audit_path), "sha256": sha256(audit_path),
            "source_digest_algorithm": "md5 (analyzer observation only)",
            "inputs": records, "retained_preprocessing": retained, "parsed_streams": streams,
            "parameters": {name: value for name, value in audit.items() if name != "sources"}}


def kernel_model_check(root: Path, target: dict, build: dict, kernel: Path,
                       revision: str, output: Path, env: dict) -> dict | None:
    frontend_policy.identity(target, root=root)
    if not target.get("kernel_model_check"):
        return None
    fixture = (root / target["kernel_model_check"]).resolve()
    if not fixture.is_file():
        raise SourceError(f"missing kernel model check: {fixture}")
    entry = compile_entry(build, "lib/string.c")
    args = frontend_policy.add_cpp_arguments(command_without_outputs(entry), target)
    depfile = output / "model-headers.d"
    args += ["-Werror", "-MD", "-MF", str(depfile), "-MT", "fragma",
             "-c", str(fixture), "-o", str(output / "kernel-model.o")]
    receipt = run_recorded(args, cwd=Path(build["path"]), env=env,
                           log=output / "kernel-model.log", timeout=120)
    if receipt["returncode"] != 0:
        raise SourceError(f"kernel model check failed; see {receipt['log']}")
    receipt["inputs"] = input_receipts(root, kernel, revision, build,
        dependency_paths(depfile, Path(build["path"])))
    receipt["fixture_sha256"] = sha256(fixture)
    policy = frontend_policy.identity(target)
    if policy is not None:
        # Opt-in metadata does not backfill old fixture receipts or alter their
        # command shape. A new frontend policy binds the real command and output.
        obj = output / "kernel-model.o"
        if receipt["timed_out"] or not obj.is_file() or not obj.stat().st_size:
            raise SourceError("common24 kernel model check did not produce an object")
        receipt.update(frontend_policy=policy, original_compile_command=entry,
            object={"absolute_path": str(obj), "sha256": sha256(obj)},
            dependencies={"absolute_path": str(depfile), "sha256": sha256(depfile)},
            diagnostics={"absolute_path": receipt["log"], "sha256": receipt["log_sha256"]})
    return receipt
