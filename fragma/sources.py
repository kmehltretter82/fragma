"""Materialize an immutable git revision without modifying the source checkout."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile


class SourceError(ValueError):
    """An input cannot be associated with the requested source revision."""


def git_output(tree: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(tree), *args], capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        raise SourceError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def resolve_revision(tree: Path, revision: str) -> str:
    if not revision or revision.startswith("-") or any(c in revision for c in "\n\r\x00"):
        raise SourceError("invalid source revision")
    return git_output(tree, "rev-parse", "--verify", f"{revision}^{{commit}}")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(tree: Path, revision: str, destination: Path) -> dict:
    """Extract a git archive into a new directory; never reuse an unverified tree.

    The snapshot's marker identifies its origin, not its current contents. Proof
    runs must independently hash and check every source/header they actually use.
    """
    tree = tree.resolve()
    commit = resolve_revision(tree, revision)
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise SourceError(f"snapshot destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".fragma-source-", dir=destination.parent))
    try:
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(
                ["git", "-C", str(tree), "archive", "--format=tar", commit],
                stdout=subprocess.PIPE, stderr=errors,
            )
            assert process.stdout is not None
            try:
                with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                    for member in archive:
                        name = PurePosixPath(member.name)
                        if name.is_absolute() or ".." in name.parts:
                            raise SourceError(f"unsafe source archive path: {member.name}")
                        archive.extract(member, temporary, filter="data")
            except BaseException:
                process.terminate()
                process.wait()
                raise
            finally:
                process.stdout.close()
            if process.wait():
                errors.seek(0)
                raise SourceError(errors.read().decode(errors="replace"))
        record = {
            "schema_version": 1,
            "revision": commit,
            "git_tree": git_output(tree, "rev-parse", f"{commit}^{{tree}}"),
            "repository": str(tree),
            "contents_must_be_rechecked": True,
        }
        (temporary / ".fragma-source.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
        os.rename(temporary, destination)
        return {**record, "path": str(destination)}
    finally:
        # Only our private, newly allocated temporary directory is disposable.
        if temporary.exists():
            shutil.rmtree(temporary)


def check_snapshot_files(tree: Path, revision: str, source: Path,
                         paths: list[Path]) -> list[dict]:
    """Compare consumed snapshot files with git blobs, including local edits."""
    commit = resolve_revision(tree, revision)
    source = source.resolve()
    records = []
    for path in sorted(set(p.resolve() for p in paths)):
        try:
            relative = path.relative_to(source).as_posix()
        except ValueError:
            raise SourceError(f"input is outside source snapshot: {path}") from None
        result = subprocess.run(
            ["git", "-C", str(tree), "show", f"{commit}:{relative}"],
            capture_output=True, check=False,
        )
        if result.returncode:
            raise SourceError(f"input is not tracked at {commit}: {relative}")
        expected = hashlib.sha256(result.stdout).hexdigest()
        actual = sha256(path)
        records.append({"path": relative, "sha256": actual,
                        "expected_sha256": expected, "passed": actual == expected})
    return records
