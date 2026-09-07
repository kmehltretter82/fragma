#!/usr/bin/env python3
"""Prepare pinned musl RISC-V LP64 headers offline, without building a libc.

The caller downloads the official source archive explicitly. Verification never
runs this setup step or accesses the network.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


SHA256 = "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"
URL = "https://musl.libc.org/releases/musl-1.2.5.tar.gz"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def setup(archive, output):
    archive, output = Path(archive).resolve(), Path(output).resolve()
    if digest(archive) != SHA256:
        raise ValueError("musl source archive SHA256 mismatch")
    if output.exists():
        raise ValueError("Output already exists; choose a new sysroot path")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fragma-musl-setup-", dir=output.parent) as temporary:
        work = Path(temporary)
        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            for member in members:
                path = Path(member.name)
                if path.is_absolute() or ".." in path.parts or path.parts[0] != "musl-1.2.5" or not (member.isdir() or member.isfile()):
                    raise ValueError("Unexpected source archive member: " + member.name)
            # Members were checked above; links and devices are never extracted.
            source.extractall(work, members=members, filter="data")
        source = work / "musl-1.2.5"
        staged = work / "headers"
        command = ["make", "-C", str(source), "ARCH=riscv64", "prefix=" + str(staged), "install-headers"]
        run = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if run.returncode:
            raise ValueError("Upstream header installation failed: " + run.stderr)
        (staged / "setup.log").write_text(run.stdout + run.stderr)
        shutil.copy2(source / "COPYRIGHT", staged / "COPYRIGHT")
        shutil.copy2(archive, staged / "musl-1.2.5.tar.gz")
        hashes = {path.relative_to(staged).as_posix(): digest(path)
                  for path in sorted((staged / "include").rglob("*")) if path.is_file()}
        receipt = {"schema_version": 1, "libc": "musl", "version": "1.2.5", "architecture": "riscv64",
                   "source_url": URL, "archive_sha256": SHA256,
                   "scope": "Generator-only standard/POSIX headers; no libc objects, runtime, or kernel ABI substitutions.",
                   "command": command, "returncode": run.returncode, "header_hashes": hashes}
        (staged / "fragma-sysroot.json").write_text(json.dumps(receipt, indent=2) + "\n")
        shutil.move(str(staged), str(output))
    return {"sysroot": str(output), "headers": len(hashes), "archive_sha256": SHA256}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(setup(args.archive, args.output), indent=2))
