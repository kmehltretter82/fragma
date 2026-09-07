#!/usr/bin/env python3
"""Provision pinned musl MIPS headers and a generator-only limits overlay.

This is an offline preparation step.  It installs headers from the exact musl
1.2.5 archive, never builds a libc, never activates a Fragma profile, and never
uses host libc headers as MIPS evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import tempfile


class SetupError(ValueError):
    """The archive, output path, or retained sysroot is not the pinned input."""


VERSION = "1.2.5"
ARCHIVE_ROOT = f"musl-{VERSION}"
ARCHIVE_SHA256 = "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4"
SOURCE_URL = f"https://musl.libc.org/releases/musl-{VERSION}.tar.gz"
HEADER_COUNT = 218
LIMIT_VALUES = {"PATH_MAX": 4096, "TTY_NAME_MAX": 32, "HOST_NAME_MAX": 255}
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 10000
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SetupError(message)


def sha256_file(path: Path, *, limit: int = MAX_ARCHIVE_BYTES) -> str:
    path = Path(path)
    require(not path.is_symlink(), f"symlink input is unsupported: {path}")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            f"input is not a bounded regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def archive_inventory(data: bytes) -> list[dict[str, object]]:
    """Validate a tar archive before extraction and return its bounded inventory."""
    require(len(data) <= MAX_ARCHIVE_BYTES, "archive exceeds the size limit")
    rows: list[dict[str, object]] = []
    names: set[str] = set()
    total = 0
    try:
        source = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise SetupError(f"cannot parse source archive: {exc}") from exc
    with source:
        for member in source:
            require(len(rows) < MAX_MEMBERS, "archive member limit exceeded")
            name = member.name.removesuffix("/")
            pure = PurePosixPath(name)
            require(name and not pure.is_absolute() and all(
                part not in ("", ".", "..") for part in pure.parts
            ), f"invalid archive path: {member.name}")
            require(pure.parts[0] == ARCHIVE_ROOT,
                    f"unexpected archive root: {member.name}")
            require(name not in names, f"duplicate archive member: {name}")
            names.add(name)
            require(member.isfile() or member.isdir(),
                    f"links and special archive members are unsupported: {name}")
            require(not member.linkname and not member.issparse(),
                    f"linked or sparse archive member is unsupported: {name}")
            require(0 <= member.size <= MAX_MEMBER_BYTES,
                    f"oversized archive member: {name}")
            total += member.size
            require(total <= MAX_TOTAL_BYTES, "archive expanded size limit exceeded")
            rows.append({"path": name, "kind": "file" if member.isfile() else "directory",
                         "size": member.size})
    require(any(row["path"] == ARCHIVE_ROOT and row["kind"] == "directory"
                for row in rows), "archive root directory is missing")
    return rows


def limits_values(text: str) -> dict[str, int]:
    """Extract only the three exact, simple musl definitions used by the overlay."""
    found: dict[str, list[str]] = {name: [] for name in LIMIT_VALUES}
    for line in text.splitlines():
        for name in found:
            prefix = f"#define {name} "
            if line.startswith(prefix):
                found[name].append(line[len(prefix):])
    values: dict[str, int] = {}
    for name, expected in LIMIT_VALUES.items():
        require(len(found[name]) == 1, f"expected one source definition of {name}")
        require(found[name][0].isdigit(), f"non-literal source definition of {name}")
        value = int(found[name][0])
        require(value == expected, f"unexpected source value for {name}: {value}")
        values[name] = value
    return values


def overlay_bytes(values: dict[str, int]) -> bytes:
    require(values == LIMIT_VALUES, "limits overlay values are not the reviewed set")
    lines = [
        "#ifndef FRAGMA_MIPS_GENERATOR_LIMITS_H",
        "#define FRAGMA_MIPS_GENERATOR_LIMITS_H",
        "#include_next <limits.h>",
        "",
        "/* Generator-only POSIX values copied from the pinned musl limits.h. */",
    ]
    lines.extend(f"#define {name} {values[name]}" for name in LIMIT_VALUES)
    lines.extend(["#endif", ""])
    return "\n".join(lines).encode()


def header_hashes(include: Path) -> dict[str, str]:
    require(include.is_dir() and not include.is_symlink(), "installed include tree is missing")
    result: dict[str, str] = {}
    for path in sorted(include.rglob("*")):
        require(not path.is_symlink(), f"installed header symlink is unsupported: {path}")
        if path.is_dir():
            continue
        require(path.is_file(), f"special installed header entry: {path}")
        relative = path.relative_to(include).as_posix()
        result[relative] = sha256_file(path, limit=MAX_MEMBER_BYTES)
    require(len(result) == HEADER_COUNT,
            f"expected {HEADER_COUNT} installed headers, found {len(result)}")
    return result


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def setup(archive: Path, output: Path) -> dict[str, object]:
    archive = Path(archive).resolve()
    output = Path(output).absolute()
    require(archive.is_file(), f"missing musl archive: {archive}")
    require(sha256_file(archive) == ARCHIVE_SHA256, "musl source archive SHA-256 mismatch")
    archive_data = archive.read_bytes()
    inventory = archive_inventory(archive_data)
    require(not os.path.lexists(output), "output already exists; choose a new sysroot path")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fragma-mips-musl-", dir=output.parent) as temporary:
        temporary_path = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as source:
            source.extractall(temporary_path, filter="data")
        source_tree = temporary_path / ARCHIVE_ROOT
        staged = temporary_path / "sysroot"
        command = ["/usr/bin/make", "-C", str(source_tree), "ARCH=mips",
                   f"prefix={staged}", "install-headers"]
        run = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                             text=True, timeout=180, env=ENVIRONMENT, check=False)
        require(run.returncode == 0, "upstream musl header installation failed: " + run.stderr)
        require(staged.is_dir(), "musl did not create the staged sysroot")
        hashes = header_hashes(staged / "include")
        values = limits_values((staged / "include/limits.h").read_text())
        overlay = staged / "generator-overlay"
        overlay.mkdir(mode=0o755)
        (overlay / "limits.h").write_bytes(overlay_bytes(values))
        shutil.copy2(source_tree / "COPYRIGHT", staged / "COPYRIGHT")
        shutil.copy2(archive, staged / f"musl-{VERSION}.tar.gz")
        (staged / "setup.log").write_text(run.stdout + run.stderr)
        receipt = {
            "schema_version": 1,
            "kind": "mips32el-generator-header-sysroot",
            "status": "provisioned",
            "libc": "musl",
            "version": VERSION,
            "architecture": "mips",
            "source_url": SOURCE_URL,
            "archive_sha256": ARCHIVE_SHA256,
            "archive_members": len(inventory),
            "header_count": len(hashes),
            "header_hashes": hashes,
            "limits_source_sha256": hashes["limits.h"],
            "limits_values": values,
            "overlay_sha256": sha256_file(overlay / "limits.h"),
            "copyright_sha256": sha256_file(staged / "COPYRIGHT"),
            "setup_log_sha256": sha256_file(staged / "setup.log"),
            "provider_sha256": sha256_file(Path(__file__).resolve()),
            "command": {"argv": ["/usr/bin/make", "-C", "PINNED_SOURCE",
                                  "ARCH=mips", "prefix=STAGED_OUTPUT", "install-headers"],
                        "returncode": run.returncode},
            "include_order": ["generator-overlay", "clang-resource", "musl"],
            "scope": "Generator-only MIPS musl headers and three source-derived POSIX limits; no libc objects/runtime, kernel ABI substitution, profile activation, L1 or L2.",
            "network": False,
            "sudo": False,
        }
        _write_json(staged / "fragma-mips-sysroot.json", receipt)
        shutil.move(str(staged), str(output))
    return verify(output)


def verify(output: Path) -> dict[str, object]:
    output = Path(output).resolve()
    require(output.is_dir() and not output.is_symlink(), "retained sysroot is missing")
    expected = {"include", "generator-overlay", "COPYRIGHT", f"musl-{VERSION}.tar.gz",
                "setup.log", "fragma-mips-sysroot.json"}
    require({path.name for path in output.iterdir()} == expected,
            "unexpected retained sysroot entries")
    try:
        receipt = json.loads((output / "fragma-mips-sysroot.json").read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SetupError(f"malformed retained receipt: {exc}") from exc
    require(receipt.get("schema_version") == 1 and receipt.get("status") == "provisioned"
            and receipt.get("architecture") == "mips", "retained receipt identity mismatch")
    require(receipt.get("archive_sha256") == ARCHIVE_SHA256
            and sha256_file(output / f"musl-{VERSION}.tar.gz") == ARCHIVE_SHA256,
            "retained archive identity mismatch")
    hashes = header_hashes(output / "include")
    require(receipt.get("header_hashes") == hashes, "retained header set/content changed")
    values = limits_values((output / "include/limits.h").read_text())
    require(receipt.get("limits_values") == values, "retained source limit values changed")
    overlay = output / "generator-overlay/limits.h"
    require(overlay.read_bytes() == overlay_bytes(values)
            and receipt.get("overlay_sha256") == sha256_file(overlay),
            "retained generator overlay changed")
    require(receipt.get("provider_sha256") == sha256_file(Path(__file__).resolve()),
            "sysroot provider implementation changed")
    for name, key in (("COPYRIGHT", "copyright_sha256"), ("setup.log", "setup_log_sha256")):
        require(receipt.get(key) == sha256_file(output / name), f"retained {name} changed")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = verify(args.output) if args.verify else setup(args.archive, args.output)
        print(json.dumps({"status": result["status"], "headers": result["header_count"],
                          "archive_sha256": result["archive_sha256"],
                          "overlay_sha256": result["overlay_sha256"]}, indent=2))
        return 0
    except (OSError, SetupError, subprocess.SubprocessError) as exc:
        print(str(exc), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
