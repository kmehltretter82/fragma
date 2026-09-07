#!/usr/bin/env python3
"""Explicit offline setup of pinned optional emulators; default is read-only."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "toolchain/runtime-lock.json"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_archive(path, record):
    if (not Path(path).is_file() or type(record.get("size")) is not int or
            Path(path).stat().st_size != record["size"] or sha256(path) != record["sha256"]):
        raise ValueError("runtime archive size/SHA256 mismatch")


def plan(prefix, archive=None):
    lock = json.loads(LOCK.read_text())
    if type(lock.get("schema_version")) is not int or lock["schema_version"] != 1:
        raise ValueError("unsupported optional runtime lock")
    prefix = Path(prefix).absolute()
    if prefix in (ROOT, Path.home(), Path("/")) or prefix.is_symlink():
        raise ValueError("a new isolated runtime prefix is required")
    return {"schema_version": 1, "mode": "plan", "prefix": str(prefix.resolve()),
            "archive": str(Path(archive).resolve()) if archive else None,
            "lock_sha256": sha256(LOCK), "lock": lock}


def extract_data(archive, destination):
    # dpkg-deb only reads the verified archive. Its data stream is checked by
    # tarfile's safe data filter; no control scripts or host registrations run.
    with tempfile.TemporaryFile() as stream:
        command = ["dpkg-deb", "--fsys-tarfile", str(archive)]
        result = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, timeout=120)
        if result.returncode:
            raise ValueError("cannot read package data: " + result.stderr.decode(errors="replace"))
        stream.seek(0)
        with tarfile.open(fileobj=stream) as data:
            members = data.getmembers()
            if not members:
                raise ValueError("empty runtime package")
            for member in members:
                name = Path(member.name)
                if (name.is_absolute() or ".." in name.parts or
                        not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                    raise ValueError("unsupported runtime archive member: " + member.name)
            data.extractall(destination, members=members, filter="data")
    return command


def apply(plan_record):
    prefix = Path(plan_record["prefix"])
    lock = plan_record["lock"]
    if plan_record["lock_sha256"] != sha256(LOCK):
        raise ValueError("optional runtime lock changed after planning")
    if {"system": platform.system(), "machine": platform.machine()} != lock["host"]:
        raise ValueError("runtime package requires its pinned Linux x86-64 host")
    if prefix.exists() or prefix.is_symlink():
        raise ValueError("runtime prefix already exists; choose a new directory")
    if not plan_record["archive"]:
        raise ValueError("--apply requires the explicitly downloaded --archive")
    archive = Path(plan_record["archive"])
    check_archive(archive, lock["artifact"])
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fragma-runtime-setup-", dir=prefix.parent) as temporary:
        staged = Path(temporary) / "data"
        staged.mkdir()
        command = extract_data(archive, staged)
        probe_path = staged / lock["probe"]["binary"]
        if not probe_path.is_file() or not probe_path.resolve().is_relative_to(staged):
            raise ValueError("pinned s390 emulator missing from package")
        version = subprocess.run([str(probe_path), "--version"], capture_output=True, text=True, timeout=15)
        if (version.returncode or version.stderr or
                not version.stdout.startswith(lock["probe"]["version_prefix"])):
            raise ValueError("extracted emulator failed its pinned version check")
        elf = subprocess.run(["readelf", "--wide", "--program-headers", str(probe_path)],
                             capture_output=True, text=True, timeout=15)
        if elf.returncode or "INTERP" in elf.stdout:
            raise ValueError("pinned emulator must have no dynamic ELF interpreter")
        files = {}
        for path in sorted(staged.rglob("*")):
            if path.is_symlink() and not path.resolve().is_relative_to(staged):
                raise ValueError("extracted runtime link escapes prefix")
            if path.is_file():
                files[str(path.relative_to(staged))] = {"sha256": sha256(path)}
                if path.is_symlink():
                    files[str(path.relative_to(staged))]["link_target"] = str(path.readlink())
        receipt = {**plan_record, "mode": "apply", "status": "installed", "files": files,
                   "setup_sha256": sha256(Path(__file__)), "python": sys.version,
                   "extract_command": command, "version": version.stdout,
                   "static_probe": {"returncode": elf.returncode, "program_headers": elf.stdout},
                   "verification_level": "not-established"}
        (staged / "fragma-runtime.json").write_text(json.dumps(receipt, indent=2) + "\n")
        staged.rename(prefix)
    return {"status": "installed", "prefix": str(prefix), "files": len(files),
            "receipt": str(prefix / "fragma-runtime.json"), "lock_sha256": plan_record["lock_sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=ROOT / "toolchain/runtime-prefix")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        planned = plan(args.prefix, args.archive)
        print(json.dumps(apply(planned) if args.apply else planned, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as exc:
        parser.exit(2, f"runtime setup: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
