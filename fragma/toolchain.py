"""Read-only, version-checked toolchain discovery for fragma.

No function in this module installs packages or evaluates shell output. Commands
are argument lists; the environment returned by prepare_environment is a copy.
The separate toolchain/install.sh entry point performs explicit setup.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any


class ToolchainError(ValueError):
    """A selected installation or lock is unavailable or malformed."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _prepend(env: dict[str, str], key: str, paths: list[Path]) -> None:
    entries = [str(path) for path in paths if path.is_dir()]
    entries.extend(item for item in env.get(key, "").split(os.pathsep) if item)
    # Empty PATH/library entries mean the working directory, so drop them.
    env[key] = os.pathsep.join(dict.fromkeys(entries))


def discover(root: Path, switch_prefix: Path | None = None,
             environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Find installation prefixes without using opam or modifying the machine.

    Explicit selections fail closed. Otherwise prefer the workspace installation
    and then the historical named switch. The caller's active opam switch is not
    implicitly used for a different verification baseline.
    """
    root = Path(root).resolve()
    env = os.environ if environ is None else environ
    user_dir = Path(env.get("HOME", str(Path.home())))
    configured_prefix = env.get("FRAGMA_TOOLCHAIN_PREFIX")
    local_prefix = root / "toolchain" / "prefix"
    prefix = Path(configured_prefix).expanduser().resolve() if configured_prefix else (
        local_prefix if local_prefix.is_dir() else user_dir / ".local")
    selected = switch_prefix or env.get("FRAGMA_SWITCH_PREFIX")
    if selected:
        switch = Path(selected).expanduser().resolve()
        if not (switch / ".opam-switch" / "switch-state").is_file():
            raise ToolchainError(f"Selected opam switch is missing its state: {switch}")
    else:
        candidates = [prefix / "opam" / "fragma"]
        if not configured_prefix:
            candidates.append(user_dir / ".opam" / "fragma")
        switch = next((path.resolve() for path in candidates
                       if (path / ".opam-switch" / "switch-state").is_file()), None)
    # An explicit prefix must not silently use the historical prover install.
    bins = [prefix / "bin", prefix / "graphviz" / "usr" / "bin"]
    if not configured_prefix:
        bins += [root / "toolchain" / "cvc5-Linux-x86_64-static" / "bin",
                 root / "toolchain" / "z3-4.13.4-x64-glibc-2.35" / "bin"]
    if switch is not None:
        bins.insert(0, switch / "bin")
    return {"root": str(root), "prefix": str(prefix),
            "switch_prefix": str(switch) if switch else None,
            "bin_directories": [str(path) for path in bins if path.is_dir()]}


def prepare_environment(root: Path, switch_prefix: Path | None = None,
                        environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a subprocess environment; do not mutate os.environ or run setup."""
    env = dict(os.environ if environ is None else environ)
    found = discover(root, switch_prefix, env)
    prefix = Path(found["prefix"])
    _prepend(env, "PATH", [Path(item) for item in found["bin_directories"]])
    _prepend(env, "LD_LIBRARY_PATH", [prefix / "lib",
             prefix / "graphviz" / "usr" / "lib" / "x86_64-linux-gnu"])
    _prepend(env, "LIBRARY_PATH", [prefix / "lib"])
    _prepend(env, "CPATH", [prefix / "include"])
    _prepend(env, "PKG_CONFIG_PATH", [prefix / "lib" / "pkgconfig"])
    env["FRAGMA_TOOLCHAIN_PREFIX"] = str(prefix)
    if found["switch_prefix"]:
        switch = Path(found["switch_prefix"])
        env["FRAGMA_SWITCH_PREFIX"] = str(switch)
        env["OPAM_SWITCH_PREFIX"] = str(switch)
        _prepend(env, "CAML_LD_LIBRARY_PATH", [switch / "lib" / "stublibs",
                 switch / "lib" / "ocaml" / "stublibs", switch / "lib" / "ocaml"])
        env["OCAML_TOPLEVEL_PATH"] = str(switch / "lib" / "toplevel")
    env["LC_ALL"] = "C"
    return env


def load_lock(root: Path) -> dict[str, Any]:
    path = Path(root) / "toolchain" / "lock.json"
    try:
        lock = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ToolchainError(f"Cannot read toolchain lock {path}: {exc}") from exc
    if lock.get("schema_version") != 1 or not isinstance(lock.get("tools"), dict):
        raise ToolchainError(f"Unsupported or malformed toolchain lock: {path}")
    return lock


CLANG_TARGET_ARGS = ["--target=hexagon-linux-musl", "-mv68"]
CLANG_TARGET = "hexagon-unknown-linux-musl"
CLANG_VERSION = "21.1.8"
CLANG_VERSION_PATTERN = r"clang version\s+(\d+\.\d+\.\d+)(?![\w.+-])"


def _compiler_specification_error(specification: Mapping[str, Any]) -> str | None:
    family = specification.get("compiler_family", "gcc")
    if family not in ("gcc", "clang"):
        return "Unsupported explicit compiler family"
    if family != "clang":
        if "target_args" in specification or "resource_include_tree_sha256" in specification:
            return "Target arguments and resource pins require the explicit Clang route"
        return None
    if (type(specification.get("target_args")) is not list or
            specification["target_args"] != CLANG_TARGET_ARGS or
            specification.get("target") != CLANG_TARGET or
            specification.get("version") != CLANG_VERSION or
            type(specification.get("version_args")) is not list or
            specification["version_args"] != ["--version"]):
        return "Clang requires the exact Hexagon v68 target, version and query arguments"
    for field in ("reference_sha256", "resource_include_tree_sha256"):
        value = specification.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            return "Clang requires an exact " + field
    if specification.get("require_binary_hash") is not True:
        return "Clang requires its pinned executable hash"
    return None


def _clang_binary_identity(path: Path) -> dict[str, str]:
    """Hash a regular executable through its invocation alias without executing it."""
    resolved = path.resolve(strict=True)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ToolchainError("Clang executable is not a regular file")
    digest = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ToolchainError("Clang executable is no longer a regular file")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        final = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)
    if (any(identity(value) != identity(before) for value in (opened, final, path.stat())) or
            path.resolve(strict=True) != resolved):
        raise ToolchainError("Clang executable changed during hashing")
    return {"sha256": digest.hexdigest(), "resolved_path": str(resolved)}


def clang_resource_tree(resource_root: Path) -> dict[str, Any]:
    """Read a bounded builtin-header tree; never invoke a compiler.

    The digest is SHA-256 of UTF-8 JSON for the relative ``entries`` map,
    using sort_keys=True and separators=(',', ':'). Entries include empty
    directories, file bytes, and confined symlink text/resolved-relative paths.
    Entry names are relative; literal absolute symlink targets remain part of
    their identity. Symlinked directories are traversed, but escapes, cycles
    and special files fail.
    This authenticates builtin resources, not target libc headers or a model.
    """
    root = Path(resource_root)
    if not root.is_absolute():
        raise ToolchainError("Clang resource directory must be absolute")
    resolved_root = root.resolve(strict=True)
    include = root / "include"
    resolved_include = include.resolve(strict=True)
    if (not resolved_root.is_dir() or not resolved_include.is_dir() or
            not resolved_include.is_relative_to(resolved_root)):
        raise ToolchainError("Clang builtin include directory is missing or outside its resource root")
    entries, files = {}, []
    total_bytes = 0

    def visit(path: Path, relative: str, ancestors: frozenset[Path], depth: int):
        nonlocal total_bytes
        if len(entries) >= 20000 or depth > 64:
            raise ToolchainError("Clang resource tree exceeds bounded entry/depth limits")
        observed = path.lstat()
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(resolved_include):
            raise ToolchainError("Clang resource symlink escapes its builtin include tree")
        link = stat.S_ISLNK(observed.st_mode)
        actual = path.stat() if link else observed
        kind = "directory" if stat.S_ISDIR(actual.st_mode) else "file" if stat.S_ISREG(actual.st_mode) else None
        if kind is None:
            raise ToolchainError("Clang resource tree contains a non-regular entry")
        row = {"kind": "symlink" if link else kind}
        if link:
            row.update(target=os.readlink(path), target_kind=kind,
                       resolved_relative_path=resolved.relative_to(resolved_include).as_posix())
        entries[relative] = row
        if kind == "directory":
            if resolved in ancestors:
                raise ToolchainError("Clang resource tree contains a symlink cycle")
            for child in sorted(path.iterdir()):
                visit(child, (relative + "/" if relative else "") + child.name,
                      ancestors | {resolved}, depth + 1)
        else:
            if actual.st_size > 16 * 1024 * 1024:
                raise ToolchainError("Clang resource header exceeds the bounded file-size limit")
            total_bytes += actual.st_size
            if total_bytes > 256 * 1024 * 1024:
                raise ToolchainError("Clang resource tree exceeds the bounded byte limit")
            # A replaced special file must not block a preflight read. Bound
            # the read itself as well as the earlier size observation.
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise ToolchainError("Clang resource file is no longer regular")
                content = stream.read(16 * 1024 * 1024 + 1)
                final = os.fstat(stream.fileno())
            if len(content) > 16 * 1024 * 1024:
                raise ToolchainError("Clang resource file grew beyond the bounded size limit")
            observed_identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                                value.st_mtime_ns, value.st_ctime_ns)
            if observed_identity(opened) != observed_identity(actual) or observed_identity(final) != observed_identity(actual):
                raise ToolchainError("Clang resource file changed during reading")
            digest = hashlib.sha256(content).hexdigest()
            after = path.stat()
            if ((actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns, actual.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                    path.resolve(strict=True) != resolved):
                raise ToolchainError("Clang resource file changed during hashing")
            row["sha256"] = digest
            files.append({"relative_path": relative, "absolute_path": str(path),
                          "resolved_path": str(resolved), "sha256": digest})

    visit(include, "", frozenset(), 0)
    if not files:
        raise ToolchainError("Clang builtin include tree is empty")
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"root": str(root), "resolved_root": str(resolved_root),
            "include_directory": str(include), "resolved_include_directory": str(resolved_include),
            "include_tree_sha256": digest, "entries": entries, "files": files}


def _clang_resource_query(record: Mapping[str, Any], env: Mapping[str, str],
                          expected: str, timeout: float) -> dict[str, Any]:
    command = [record["path"], *record["target_args"], "-print-resource-dir"]
    resources: dict[str, Any] = {"status": "resource-error", "expected_include_tree_sha256": expected,
                                "query": {"command": command}}
    try:
        run = subprocess.run(command, env=dict(env), capture_output=True, text=True,
                             timeout=timeout, check=False)
        resources["query"].update(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)
        value = run.stdout.strip()
        if run.returncode or run.stderr.strip() or not value or len(value.splitlines()) != 1:
            raise ToolchainError("Clang resource directory query failed")
        resources.update(clang_resource_tree(Path(value)))
        if resources["include_tree_sha256"] != expected:
            raise ToolchainError("Clang builtin resource tree differs from its locked hash")
        again = clang_resource_tree(Path(value))
        if any(resources[key] != again[key] for key in again):
            raise ToolchainError("Clang builtin resources changed during inventory")
        resources["status"] = "ok"
    except (OSError, RuntimeError, ToolchainError, subprocess.TimeoutExpired) as exc:
        resources["reason"] = str(exc)
    return resources


def probe(name: str, specification: Mapping[str, Any],
          env: Mapping[str, str], timeout: float = 15.0) -> dict[str, Any]:
    """Probe one tool and enforce its exact version (and hash when required)."""
    requested = env.get("FRAGMA_TOOL_" + re.sub(r"[^A-Z0-9]", "_", name.upper()),
                        specification.get("executable", name))
    path = shutil.which(requested, path=env.get("PATH", ""))
    record: dict[str, Any] = {"name": name, "requested_executable": requested,
        "required": specification.get("required", True), "path": path,
        "expected_version": specification.get("version"), "status": "missing"}
    invalid = _compiler_specification_error(specification)
    if invalid:
        record.update(status="invalid-specification", reason=invalid)
        return record
    clang = specification.get("compiler_family") == "clang"
    if clang:
        record.update(compiler_family="clang", target_args=list(specification["target_args"]))
    if not path:
        record["reason"] = f"Executable unavailable: {requested}"
        return record
    if clang:
        try:
            before = _clang_binary_identity(Path(path))
        except (OSError, RuntimeError, ToolchainError) as exc:
            record.update(status="tool-error", reason=str(exc))
            return record
        record.update(before)
        record["binary_before"] = before
        record["reference_hash_matches"] = before["sha256"] == specification["reference_sha256"]
        if not record["reference_hash_matches"]:
            record.update(status="hash-mismatch", reason="Prebuilt executable differs from locked artifact before querying")
            return record
    command = [path, *specification.get("version_args", ["--version"])]
    record["command"] = command
    try:
        result = subprocess.run(command, env=dict(env), capture_output=True,
                                text=True, timeout=timeout, check=False)
        record.update(returncode=result.returncode, output=(result.stdout + result.stderr).strip())
        if clang:
            try:
                current = _clang_binary_identity(Path(path))
            except (OSError, RuntimeError, ToolchainError) as exc:
                record.update(status="tool-error", reason=str(exc))
                return record
            record["binary_after_version"] = current
            if current != before:
                record.update(status="hash-mismatch", reason="Clang executable identity changed during version query")
                return record
        else:
            record.update(sha256=sha256(Path(path)), resolved_path=str(Path(path).resolve()))
    except (OSError, subprocess.TimeoutExpired) as exc:
        record.update(status="tool-error", reason=str(exc))
        return record
    if result.returncode:
        record.update(status="tool-error", reason=f"Version command exited {result.returncode}")
        return record
    if clang:
        versions = re.findall(CLANG_VERSION_PATTERN, record["output"])
        record["version"] = versions[0] if len(versions) == 1 else None
    else:
        match = re.search(specification.get("version_pattern", r"(?m)^v?(\d+(?:\.\d+)+)"),
                          record["output"])
        record["version"] = match.group(1) if match else None
    if record["version"] != specification["version"]:
        record.update(status="version-mismatch", reason=(
            f"Expected {specification['version']}, found {record['version']!r}"))
        return record
    reference_hash = specification.get("reference_sha256")
    record["reference_hash_matches"] = reference_hash == record["sha256"] if reference_hash else None
    if specification.get("require_binary_hash") and not record["reference_hash_matches"]:
        record.update(status="hash-mismatch", reason="Prebuilt executable differs from locked artifact")
        return record
    if specification.get("target"):
        target_command = [path, *(record["target_args"] if clang else []), "-dumpmachine"]
        if clang:
            record["target_query"] = {"command": target_command}
        try:
            result = subprocess.run(target_command, env=dict(env), capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if clang:
                record["target_query"]["reason"] = str(exc)
            record.update(status="tool-error", reason=str(exc))
            return record
        record["target_command"] = target_command
        record["target"] = result.stdout.strip()
        if clang:
            record["target_query"].update(returncode=result.returncode,
                                          stdout=result.stdout, stderr=result.stderr)
        if result.returncode or record["target"] != specification["target"] or (clang and result.stderr.strip()):
            record.update(status="target-mismatch", reason=(
                f"Expected compiler target {specification['target']}, found {record['target']!r}"))
            return record
    if clang:
        resources = _clang_resource_query(record, env, specification["resource_include_tree_sha256"], timeout)
        record["compiler_resources"] = resources
        if resources["status"] != "ok":
            record.update(status="resource-error", reason=resources["reason"])
            return record
        try:
            final = _clang_binary_identity(Path(path))
        except (OSError, RuntimeError, ToolchainError) as exc:
            record.update(status="tool-error", reason=str(exc))
            return record
        record["binary_final"] = final
        if final != before:
            record.update(status="hash-mismatch", reason="Clang executable identity changed during target/resource queries")
            return record
    record["status"] = "ok"
    return record


def installed_packages(switch_prefix: Path) -> list[str]:
    """Parse the installed atom list, rejecting absent/ambiguous/empty state."""
    path = Path(switch_prefix) / ".opam-switch" / "switch-state"
    try:
        source = path.read_text()
    except OSError as exc:
        raise ToolchainError(f"Cannot read installed opam state {path}: {exc}") from exc
    blocks = re.findall(r"(?m)^installed:\s*\[([^\]]*)\]", source)
    if len(blocks) != 1:
        raise ToolchainError(f"Missing or ambiguous installed package set in {path}")
    block = blocks[0]
    packages = re.findall(r'"([A-Za-z0-9_+.-]+)"', block)
    remainder = re.sub(r'"[A-Za-z0-9_+.-]+"', "", block)
    if remainder.strip() or not packages or len(set(packages)) != len(packages):
        raise ToolchainError(f"Malformed or empty installed package set in {path}")
    return sorted(packages)


def _opam_inventory(root: Path, env: Mapping[str, str],
                    locked: Mapping[str, Any]) -> dict[str, Any]:
    prefix = env.get("FRAGMA_SWITCH_PREFIX")
    record: dict[str, Any] = {"switch_prefix": prefix, "status": "missing"}
    if not prefix:
        record["reason"] = "No fragma opam switch found; run explicit setup or select FRAGMA_SWITCH_PREFIX"
        return record
    try:
        packages = installed_packages(Path(prefix))
    except ToolchainError as exc:
        record.update(status="tool-error", reason=str(exc))
        return record
    historical = set(locked.get("installed", []))
    complete = set(locked.get("complete_installed", historical))
    observed = set(packages)
    selected_profile = "complete" if observed == complete else "historical-analysis"
    expected = complete if selected_profile == "complete" else historical
    record["package_profile"] = selected_profile
    record["missing_post_dependencies"] = sorted(complete - observed)
    record["dependency_closure_complete"] = observed == complete
    record.update(installed=packages, missing=sorted(expected - set(packages)),
                  unexpected=sorted(set(packages) - expected), metadata=[])
    for atom in packages:
        path = Path(prefix) / ".opam-switch" / "packages" / atom / "opam"
        entry = {"package": atom, "path": str(path), "sha256": sha256(path) if path.is_file() else None}
        record["metadata"].append(entry)
    # Definitions are hashed into run identity. Full exported definitions are
    # pinned for installation; raw installed formatting can change on import.
    missing_metadata = [entry["package"] for entry in record["metadata"] if not entry["sha256"]]
    record["missing_metadata"] = missing_metadata
    record["status"] = "ok" if not (record["missing"] or record["unexpected"] or missing_metadata) else "package-mismatch"
    if record["status"] != "ok":
        record["reason"] = "Installed package set or metadata does not match the complete lock"
    export = root / locked.get("export", "toolchain/opam-switch.export")
    record["export_sha256"] = sha256(export) if export.is_file() else None
    if record["export_sha256"] != locked.get("export_sha256"):
        record.update(status="hash-mismatch", reason="Locked full opam export is missing or modified")
    if locked.get("complete_export"):
        complete_export = root / locked["complete_export"]
        record["complete_export_sha256"] = sha256(complete_export) if complete_export.is_file() else None
        if record["complete_export_sha256"] != locked["complete_export_sha256"]:
            record.update(status="hash-mismatch", reason="Locked complete opam export is missing or modified")
    return record


def _runtime_receipt(tools: Mapping[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    """Hash loaded native libraries and shipped analysis/driver support files."""
    linker = shutil.which("ldd", path=env.get("PATH", ""))
    libraries: dict[str, Any] = {}
    commands = []
    compiler_components = {}
    binaries = {tools[name]["path"] for name in ("frama-c", "why3", "alt-ergo", "gcc")
                if tools.get(name, {}).get("path")}
    known_hashes = {}
    for name, tool in tools.items():
        if tool.get("status") != "ok" or not tool.get("target"):
            continue
        if tool.get("compiler_family") == "clang":
            resources = tool.get("compiler_resources", {})
            checked = {"status": "resource-error"}
            try:
                current = clang_resource_tree(Path(resources["root"]))
                if (resources.get("status") != "ok" or
                        current["include_tree_sha256"] != resources.get("expected_include_tree_sha256") or
                        any(current[key] != resources.get(key) for key in current)):
                    raise ToolchainError("Clang builtin resources changed after compiler probing")
                checked = {**resources, **current}
                binaries.add(tool["path"])
            except (OSError, RuntimeError, KeyError, TypeError, ToolchainError) as exc:
                checked.update(reason=str(exc))
            compiler_components[name] = {"compiler_resources": checked}
            continue
        resources = {}
        for component in ("cc1", "as", "ld"):
            command = [tool["path"], f"-print-prog-name={component}"]
            try:
                result = subprocess.run(command, env=dict(env), capture_output=True,
                                        text=True, timeout=15, check=False)
                requested = result.stdout.strip()
                executable = shutil.which(requested, path=env.get("PATH", "")) if requested else None
                if executable:
                    resolved = str(Path(executable).resolve())
                    if resolved not in known_hashes:
                        known_hashes[resolved] = sha256(Path(executable))
                    resources[component] = {"command": command, "path": executable,
                        "resolved_path": resolved, "sha256": known_hashes[resolved]}
                    binaries.add(executable)
                else:
                    resources[component] = {"command": command, "status": "missing", "output": requested}
            except (OSError, subprocess.TimeoutExpired) as exc:
                resources[component] = {"command": command, "status": "tool-error", "reason": str(exc)}
        compiler_components[name] = resources
    for executable in sorted(binaries):
        if not executable or not linker:
            continue
        command = [linker, executable]
        try:
            result = subprocess.run(command, env=dict(env), capture_output=True,
                                    text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            commands.append({"command": command, "status": "tool-error", "reason": str(exc)})
            continue
        output = result.stdout + result.stderr
        commands.append({"command": command, "returncode": result.returncode, "output": output.strip()})
        for line in output.splitlines():
            match = re.search(r"(?:=>\s+|^\s*)(/.*?)\s+\(0x[0-9a-fA-F]+\)", line)
            if not match:
                continue
            path = Path(match.group(1))
            if path.is_file():
                libraries[str(path)] = {"sha256": sha256(path), "resolved_path": str(path.resolve())}
    support = {}
    switch = env.get("FRAGMA_SWITCH_PREFIX")
    if switch:
        for component in ("frama-c", "why3"):
            directory = Path(switch) / "share" / component
            entries = {str(path.relative_to(directory)): sha256(path)
                       for path in sorted(directory.rglob("*")) if path.is_file()} if directory.is_dir() else {}
            digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            support[component] = {"directory": str(directory), "files": entries,
                                  "tree_sha256": digest, "status": "ok" if entries else "missing"}
    return {"linker_commands": commands, "libraries": libraries,
            "compiler_components": compiler_components, "support_data": support}


def inventory(root: Path, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Inspect locked tools, Frama-C components and all installed opam packages.

    Optional target compilers appear in capabilities without making an unrelated
    profile unavailable. A profile must require its own compiler explicitly.
    """
    root = Path(root).resolve()
    selected_env = dict(env) if env is not None else prepare_environment(root)
    lock = load_lock(root)
    tools = {name: probe(name, spec, selected_env) for name, spec in lock["tools"].items()}
    issues = [f"{name}: {record.get('reason', record['status'])}" for name, record in tools.items()
              if record["required"] and record["status"] != "ok"]
    components: dict[str, Any] = {"status": "unavailable", "required": lock.get("required_plugins", [])}
    analyzer = tools.get("frama-c", {})
    if analyzer.get("status") == "ok":
        command = [analyzer["path"], "-plugins"]
        try:
            result = subprocess.run(command, env=selected_env, capture_output=True,
                                    text=True, timeout=30, check=False)
            present = [name for name in components["required"]
                       if re.search(r"(?m)^" + re.escape(name) + r"\s", result.stdout)]
            components.update(command=command, returncode=result.returncode,
                available=present, output=(result.stdout + result.stderr).strip(),
                status="ok" if result.returncode == 0 and present == components["required"] else "missing")
        except (OSError, subprocess.TimeoutExpired) as exc:
            components.update(status="tool-error", reason=str(exc))
    if components["status"] != "ok":
        issues.append("Frama-C: required analysis components unavailable")
    why3: dict[str, Any] = {"status": "not-configured"}
    if lock.get("why3"):
        settings = lock["why3"]
        config = root / settings["config"]
        why3.update(path=str(config), sha256=sha256(config) if config.is_file() else None)
        if why3["sha256"] != settings["sha256"]:
            why3.update(status="hash-mismatch", reason="Why3 configuration is missing or modified")
        elif analyzer.get("status") == "ok":
            command = [analyzer["path"], "-wp-why3-config", str(config),
                       "-wp-no-why3-detect", "-wp-list-provers"]
            try:
                result = subprocess.run(command, env=selected_env, capture_output=True,
                                        text=True, timeout=30, check=False)
                missing = [name for name in settings["required_provers"]
                           if not re.search(r"\(" + re.escape(name) + r"\)", result.stdout)]
                why3.update(command=command, returncode=result.returncode,
                    output=(result.stdout + result.stderr).strip(), missing=missing,
                    status="ok" if result.returncode == 0 and not missing else "missing")
                # The portable config names commands on PATH. An overridden
                # binary must not be recorded while a different binary runs.
                mismatched_commands = []
                for name in settings["required_provers"]:
                    actual = shutil.which(name, path=selected_env.get("PATH", ""))
                    selected = tools.get(name, {}).get("path")
                    if actual != selected:
                        mismatched_commands.append(name)
                if mismatched_commands:
                    why3.update(status="tool-mismatch", reason=(
                        "Why3 config does not use selected binary overrides: " + ", ".join(mismatched_commands)))
            except (OSError, subprocess.TimeoutExpired) as exc:
                why3.update(status="tool-error", reason=str(exc))
        else:
            why3["status"] = "unavailable"
        if why3["status"] != "ok":
            issues.append("Why3: " + why3.get("reason", why3["status"]))
    opam = _opam_inventory(root, selected_env, lock["opam"])
    if opam["status"] != "ok":
        issues.append("opam: " + opam.get("reason", opam["status"]))
    native_post_dependencies = {}
    graphviz = next((item for item in lock.get("artifacts", {}).values()
                     if item.get("package") == "graphviz"), None)
    if graphviz:
        dot = probe("dot", {"version": graphviz["version"].split("-")[0],
            "version_args": ["-V"], "version_pattern": r"graphviz version (\d+(?:\.\d+)+)",
            "required": opam.get("dependency_closure_complete", False)}, selected_env)
        native_post_dependencies["dot"] = dot
        if dot["required"] and dot["status"] != "ok":
            issues.append("Complete opam profile: " + dot.get("reason", dot["status"]))
    scripts = {}
    for name in lock.get("required_scripts", []):
        path = shutil.which(name, path=selected_env.get("PATH", ""))
        scripts[name] = {"path": path, "status": "ok" if path else "missing",
                         "sha256": sha256(Path(path)) if path else None}
        if not path:
            issues.append(f"Required analysis script unavailable: {name}")
    runtime = _runtime_receipt(tools, selected_env)
    for name, record in tools.items():
        if record.get("compiler_family") != "clang" or record["status"] != "ok":
            continue
        checked = runtime["compiler_components"].get(name, {}).get("compiler_resources", {})
        if checked.get("status") != "ok":
            record.update(status="resource-error", reason=checked.get("reason", "Clang resource recheck missing"))
            if record["required"]:
                issues.append(name + ": " + record["reason"])
    return {"schema_version": 1, "ok": not issues, "issues": issues,
            "lock_sha256": sha256(root / "toolchain" / "lock.json"),
            "tools": tools, "plugins": components, "why3": why3, "opam": opam, "scripts": scripts,
            "native_post_dependencies": native_post_dependencies,
            "runtime_receipt": runtime,
            "environment": {key: selected_env.get(key) for key in (
                "FRAGMA_SWITCH_PREFIX", "FRAGMA_TOOLCHAIN_PREFIX", "PATH",
                "LD_LIBRARY_PATH", "CAML_LD_LIBRARY_PATH", "CPATH", "LIBRARY_PATH")},
            "limitations": lock.get("limitations", [])}


def verify_artifact(root: Path, artifact: str, path: Path) -> str:
    """Verify an explicit download against its locked SHA-256; return digest."""
    lock = load_lock(root)
    if artifact not in lock.get("artifacts", {}):
        raise ToolchainError(f"Unknown locked artifact: {artifact}")
    if not Path(path).is_file():
        raise ToolchainError(f"Artifact is missing: {path}")
    actual = sha256(Path(path))
    if actual != lock["artifacts"][artifact]["sha256"]:
        raise ToolchainError(f"Checksum mismatch for {artifact}: {path}")
    return actual


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--switch-prefix", type=Path)
    parser.add_argument("--verify-artifact", metavar="ID")
    parser.add_argument("--artifact-path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify_artifact:
            if args.artifact_path is None:
                parser.error("--verify-artifact requires --artifact-path")
            print(verify_artifact(args.root, args.verify_artifact, args.artifact_path))
            return 0
        result = inventory(args.root, prepare_environment(args.root, args.switch_prefix))
    except ToolchainError as exc:
        print(json.dumps({"schema_version": 1, "ok": False, "issues": [str(exc)]}, indent=2))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
