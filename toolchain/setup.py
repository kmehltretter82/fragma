#!/usr/bin/env python3
"""Plan or explicitly install the locked Linux x86_64 verification tools.

The default only prints the plan. --apply builds in a new, isolated prefix;
it will not reuse or upgrade an existing opam root or change shell startup files.
System compilers and native build prerequisites must already be installed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fragma.toolchain import (ToolchainError, inventory, load_lock,
                             prepare_environment, probe, sha256, verify_artifact)


def make_plan(args: argparse.Namespace) -> dict:
    lock = load_lock(ROOT)
    prefix = args.prefix.expanduser().resolve()
    build = args.build_dir.expanduser().resolve()
    cache = args.download_cache.expanduser().resolve()
    return {"schema_version": 1, "mode": "apply" if args.apply else "plan",
        "prefix": str(prefix), "build_directory": str(build), "download_cache": str(cache),
        "kernel": str(args.kernel.expanduser().resolve()) if args.kernel else None,
        "host": lock["host"], "jobs": args.jobs,
        "artifacts": lock["artifacts"], "opam_package_count": len(lock["opam"].get("complete_installed", lock["opam"]["installed"])),
        "switch_prefix": str(prefix / "opam" / "fragma"),
        "steps": [
            "Require the pinned host GCC and native build prerequisites",
            "Verify existing archives or download and verify each locked SHA-256",
            "Install pinned opam, cvc5 and z3 inside the new prefix",
            "Extract pinned Graphviz binary/libraries locally for the conf-graphviz version check",
            "Build GMP 6.3.0 with the pinned GCC using GNU C17",
            "Initialize an isolated opam root without changing the shell environment",
            "Import the complete package export with checksums required and no system package installation",
            "Run the same version/package/component inventory used by analysis"],
        "limitations": lock["limitations"]}


def _fetch(artifact: str, cache: Path, lock: dict) -> Path:
    record = lock["artifacts"][artifact]
    destination = cache / record["file"]
    if destination.exists():
        verify_artifact(ROOT, artifact, destination)
        return destination
    local = ROOT / "toolchain" / record["file"]
    candidates = [local, ROOT / "toolchain" / f"{artifact}.zip"]
    if artifact == "opam":
        existing = shutil.which("opam", path=prepare_environment(ROOT).get("PATH", ""))
        if existing:
            candidates.append(Path(existing))
    cached = next((path for path in candidates if path.is_file()), None)
    with tempfile.NamedTemporaryFile(prefix=f"{artifact}-", suffix=".part", dir=cache,
                                     delete=False) as stream:
        temporary = Path(stream.name)
        if cached:
            verify_artifact(ROOT, artifact, cached)
            with cached.open("rb") as source:
                shutil.copyfileobj(source, stream)
        else:
            request = urllib.request.Request(record["url"], headers={"User-Agent": "fragma-locked-setup/1"})
            with urllib.request.urlopen(request, timeout=120) as response:
                shutil.copyfileobj(response, stream)
    verify_artifact(ROOT, artifact, temporary)
    temporary.rename(destination)
    return destination


def _extract(archive: Path, destination: Path) -> None:
    """Extract verified archives; reject members outside the build directory."""
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            for member in source.infolist():
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise ToolchainError(f"Unsafe archive member: {member.filename}")
            source.extractall(destination)
    else:
        with tarfile.open(archive) as source:
            source.extractall(destination, filter="data")


def apply_plan(args: argparse.Namespace, plan: dict) -> dict:
    lock = load_lock(ROOT)
    prefix = Path(plan["prefix"])
    build = Path(plan["build_directory"])
    cache = Path(plan["download_cache"])
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ToolchainError("This bootstrap lock supplies binaries only for Linux x86_64 hosts")
    if prefix == ROOT or prefix == Path.home() or prefix == Path("/"):
        raise ToolchainError(f"An isolated installation prefix is required: {prefix}")
    marker_path = prefix / ".fragma-setup.json"
    marker = None
    if args.resume:
        if not marker_path.is_file():
            raise ToolchainError(f"Cannot resume a prefix without a fragma setup marker: {prefix}")
        marker = json.loads(marker_path.read_text())
        if marker.get("lock_sha256") != sha256(ROOT / "toolchain" / "lock.json"):
            raise ToolchainError("Toolchain lock changed since the failed setup; use a new prefix")
        if marker.get("prefix") != str(prefix):
            raise ToolchainError("Setup marker does not identify the selected prefix")
    elif prefix.exists() and (not prefix.is_dir() or any(prefix.iterdir())):
        raise ToolchainError(f"Refusing to change an existing nonempty installation: {prefix}")
    if build == prefix or build in prefix.parents or prefix in build.parents:
        raise ToolchainError("Build directory and installation prefix must not overlap")
    if cache == prefix or prefix in cache.parents:
        raise ToolchainError("Download cache must be outside the installation prefix")
    if args.kernel and not (Path(plan["kernel"]) / "Makefile").is_file():
        raise ToolchainError(f"Selected kernel source lacks a Makefile: {plan['kernel']}")
    if args.jobs < 1:
        raise ToolchainError("--jobs must be positive")
    if sys.version_info < (3, 12):
        raise ToolchainError("Setup needs Python 3.12+ for safe tar extraction")
    compiler = probe("gcc", lock["tools"]["gcc"], os.environ)
    if compiler["status"] != "ok":
        raise ToolchainError(f"Pinned host GCC unavailable: {compiler.get('reason')}")
    missing = [name for name in ("make", "pkg-config", "patch", "tar", "bzip2", "unzip", "git", "dpkg-deb")
               if not shutil.which(name)]
    if missing:
        raise ToolchainError(f"Install native build prerequisites explicitly: {', '.join(missing)}")
    cache.mkdir(parents=True, exist_ok=True)
    downloads = {name: _fetch(name, cache, lock) for name in lock["artifacts"]}
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / "bin").mkdir(exist_ok=bool(marker))
    build.mkdir(parents=True, exist_ok=True)
    work = Path(marker["work_directory"]) if marker else Path(tempfile.mkdtemp(prefix="fragma-setup-", dir=build))
    if not work.resolve().is_relative_to(build.resolve()) or not work.is_dir():
        raise ToolchainError("Setup work directory is missing or outside the selected build directory")
    if marker is None:
        marker = {"schema_version": 1, "prefix": str(prefix), "work_directory": str(work),
                  "lock_sha256": sha256(ROOT / "toolchain" / "lock.json"), "stage": "allocated"}
        marker_path.write_text(json.dumps(marker, indent=2) + "\n")
    def run(command, *, cwd=None, env=None):
        print("Running: " + " ".join(command), flush=True)
        with (work / "setup.log").open("a") as log:
            log.write("\nCOMMAND " + json.dumps(command) + "\n")
            log.flush()
            subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    def checkpoint(stage):
        marker["stage"] = stage
        marker_path.write_text(json.dumps(marker, indent=2) + "\n")
    shutil.copy2(downloads["opam"], prefix / "bin" / "opam")
    (prefix / "bin" / "opam").chmod(0o755)
    for name, folder in (("cvc5", "cvc5-Linux-x86_64-static"),
                         ("z3", "z3-4.13.4-x64-glibc-2.35")):
        _extract(downloads[name], work)
        shutil.copy2(work / folder / "bin" / name, prefix / "bin" / name)
        (prefix / "bin" / name).chmod(0o755)
    for name, artifact in lock["artifacts"].items():
        if artifact.get("component") == "graphviz-version-check":
            run(["dpkg-deb", "--extract", str(downloads[name]), str(prefix / "graphviz")])
    if marker["stage"] == "allocated":
        _extract(downloads["gmp"], work)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("OPAM") or key.startswith("FRAGMA_"):
            env.pop(key)
    env["PATH"] = str(prefix / "bin") + os.pathsep + env.get("PATH", os.defpath)
    env["CC"] = str(compiler["path"]) + " -std=gnu17"
    env["LC_ALL"] = "C"
    gmp = work / "gmp-6.3.0"
    if marker["stage"] == "allocated":
        for command in (["./configure", f"--prefix={prefix}"], ["make", f"-j{args.jobs}"],
                        ["make", f"-j{args.jobs}", "check"], ["make", "install"]):
            run(command, cwd=gmp, env=env)
        checkpoint("gmp-installed")
    env["FRAGMA_TOOLCHAIN_PREFIX"] = str(prefix)
    env = prepare_environment(ROOT, environ=env)
    opam = str(prefix / "bin" / "opam")
    opam_root = prefix / "opam"
    common = ["--cli=2.5", "--no-self-upgrade", f"--root={opam_root}"]
    if marker["stage"] == "gmp-installed":
        run([opam, "init", *common, "--bare", "--no-setup", "--disable-shell-hook", "--yes",
             "--kind=local", "default", str(ROOT / lock["opam"]["repository"])], env=env)
        checkpoint("opam-initialized")
    if args.opam_download_cache and marker["stage"] != "complete":
        source_cache = args.opam_download_cache.expanduser().resolve()
        if not source_cache.is_dir():
            raise ToolchainError(f"Selected opam source cache is missing: {source_cache}")
        shutil.copytree(source_cache, opam_root / "download-cache", dirs_exist_ok=True)
    if marker["stage"] != "complete":
        run([opam, "switch", "import", str(ROOT / lock["opam"]["complete_export"]), *common,
             "--switch=fragma", "--no-switch", "--yes", f"--jobs={args.jobs}",
             "--require-checksums", "--no-depexts"], env=env)
    env = prepare_environment(ROOT, opam_root / "fragma", environ=env)
    report = inventory(ROOT, env)
    report["setup_work_directory"] = str(work)
    if not report["ok"]:
        raise ToolchainError("Installed toolchain did not match lock: " + "; ".join(report["issues"]))
    checkpoint("complete")
    (prefix / "setup-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=ROOT / "toolchain" / "prefix")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "toolchain" / "build")
    parser.add_argument("--download-cache", type=Path, default=ROOT / "toolchain" / "downloads")
    parser.add_argument("--kernel", type=Path, help="Optional kernel path availability check; never modifies it")
    parser.add_argument("--opam-download-cache", type=Path,
                        help="Copy an existing source download cache read-only; opam still checks every archive")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--resume", action="store_true", help="Resume only a failed prefix carrying a matching setup marker")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Download and install in the selected new prefix")
    mode.add_argument("--dry-run", action="store_true", help="Print the setup plan (the default)")
    args = parser.parse_args(argv)
    try:
        plan = make_plan(args)
        report = apply_plan(args, plan) if args.apply else plan
    except (ToolchainError, OSError, subprocess.CalledProcessError) as exc:
        print(f"fragma setup: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
