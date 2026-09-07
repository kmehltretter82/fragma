"""Pinned Linux Kernel Memory Model/herd7 C3 semantic calibrations.

This module deliberately stops at capability calibration.  The selected files
are kernel-owned litmus tests, not abstractions of a production function.  A
passing run therefore demonstrates that the exact provider/model pair detects
the expected weak and ordered outcomes; it accepts zero kernel properties.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any


class ConcurrencyC3LkmmError(ValueError):
    """The C3 LKMM declaration, provider, model, or result is unusable."""


_CASE_IDS = {
    "mp_once_once",
    "mp_release_acquire",
    "sb_once_once",
    "sb_full_barrier",
}
_ROLES = {"weakened_control", "ordered_calibration"}
_OBSERVATIONS = {"Sometimes", "Never"}
_OPERATIONS = {
    "READ_ONCE",
    "WRITE_ONCE",
    "smp_store_release",
    "smp_load_acquire",
    "smp_mb",
}
_OUTPUT = re.compile(
    r"\ATest (?P<test>\S+) (?P<disposition>\S+)\n"
    r"States (?P<states>[0-9]+)\n"
    r"(?P<state_lines>(?:[^\n]+\n)+?)"
    r"(?P<marker>Ok|No)\n"
    r"Witnesses\n"
    r"Positive: (?P<positive>[0-9]+) Negative: (?P<negative>[0-9]+)\n"
    r"(?P<flags>(?:Flag [^\n]+\n)*)"
    r"Condition (?P<condition>[^\n]+)\n"
    r"Observation (?P<observation_test>\S+) "
    r"(?P<observation>\S+) (?P<observation_positive>[0-9]+) "
    r"(?P<observation_negative>[0-9]+)\n"
    r"Time (?P<time_test>\S+) (?P<seconds>[0-9]+(?:\.[0-9]+)?)\n"
    r"Hash=(?P<hash>[0-9a-f]{32})\n{1,2}\Z"
)


def _strict_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ConcurrencyC3LkmmError(
                    f"duplicate JSON key {key!r} in {path}"
                )
            result[key] = value
        return result

    def finite(value: str) -> None:
        raise ConcurrencyC3LkmmError(
            f"non-finite JSON number {value!r} in {path}"
        )

    try:
        return json.loads(
            path.read_text(), object_pairs_hook=unique, parse_constant=finite
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ConcurrencyC3LkmmError(f"cannot load {path}: {exc}") from exc


def _json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(root: Path, path: Path, role: str) -> Path:
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ConcurrencyC3LkmmError(f"{role} escapes the project root") from exc
    return path


def _relative(root: Path, value: Any, role: str, *, directory: bool) -> Path:
    if not isinstance(value, str):
        raise ConcurrencyC3LkmmError(f"{role} must be a project-relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC3LkmmError(
            f"{role} must be a project-relative path: {value!r}"
        )
    path = _inside(root, root.joinpath(*pure.parts), role)
    exists = path.is_dir() if directory else path.is_file()
    if not exists or path.is_symlink():
        kind = "directory" if directory else "regular file"
        raise ConcurrencyC3LkmmError(f"{role} is missing or not a {kind}: {value}")
    return path


def _nonempty(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyC3LkmmError(f"{role} must be a nonempty string")
    return value


def _strings(value: Any, role: str, *, allowed: set[str] | None = None) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise ConcurrencyC3LkmmError(
            f"{role} must be a nonempty unique string list"
        )
    if allowed is not None and not set(value) <= allowed:
        raise ConcurrencyC3LkmmError(f"{role} contains an unsupported value")
    return value


def _digest(value: Any, role: str, length: int = 64) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        rf"[0-9a-f]{{{length}}}", value
    ):
        raise ConcurrencyC3LkmmError(f"{role} is not a {length}-digit hex digest")
    return value


def _version(value: str) -> tuple[int, ...]:
    match = re.match(r"([0-9]+(?:\.[0-9]+)+)", value)
    if not match:
        raise ConcurrencyC3LkmmError(f"cannot parse herdtools version: {value!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def _case_path(model_directory: Path, value: Any, role: str) -> Path:
    if not isinstance(value, str):
        raise ConcurrencyC3LkmmError(f"{role} must be model-relative")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ConcurrencyC3LkmmError(f"{role} must be model-relative: {value!r}")
    path = model_directory.joinpath(*pure.parts)
    try:
        path.resolve().relative_to(model_directory.resolve())
    except ValueError as exc:
        raise ConcurrencyC3LkmmError(f"{role} escapes the model directory") from exc
    if not path.is_file() or path.is_symlink():
        raise ConcurrencyC3LkmmError(f"{role} is missing: {value}")
    return path


def load_manifest(root: Path) -> dict[str, Any]:
    """Load and strictly validate the single C3 calibration declaration."""
    root = root.resolve()
    manifest = _strict_json(root / "config/concurrency-c3-lkmm.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {
            "schema_version", "id", "kernel", "provider", "scope", "pairs",
            "cases",
        }
        or manifest["schema_version"] != 1
        or manifest["id"] != "linux-lkmm-herd7-c3-calibration"
    ):
        raise ConcurrencyC3LkmmError("unsupported concurrency C3 LKMM schema")

    kernel = manifest["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
        "revision", "git_tree", "source_root", "source_receipt",
        "model_directory", "minimum_herdtools_version", "source_identities",
    }:
        raise ConcurrencyC3LkmmError("C3 kernel/model record is not exact")
    _digest(kernel["revision"], "kernel revision", 40)
    _digest(kernel["git_tree"], "kernel tree", 40)
    source_root = _relative(root, kernel["source_root"], "kernel source", directory=True)
    receipt = _relative(root, kernel["source_receipt"], "source receipt", directory=False)
    model_directory = _relative(
        root, kernel["model_directory"], "LKMM directory", directory=True
    )
    try:
        model_directory.resolve().relative_to(source_root.resolve())
        receipt.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ConcurrencyC3LkmmError(
            "LKMM directory and receipt must belong to the pinned source"
        ) from exc
    if kernel["minimum_herdtools_version"] != "7.58":
        raise ConcurrencyC3LkmmError("this kernel snapshot requires herdtools7 7.58")
    source_identities = kernel["source_identities"]
    if not isinstance(source_identities, dict) or len(source_identities) != 8:
        raise ConcurrencyC3LkmmError("C3 source identity set is not exact")
    required_suffixes = {
        ".fragma-source.json", "README", "Documentation/litmus-tests.txt",
        "linux-kernel.cat", "linux-kernel.bell", "linux-kernel.cfg",
        "linux-kernel.def", "lock.cat",
    }
    observed_suffixes: set[str] = set()
    for name, digest in source_identities.items():
        _relative(root, name, "C3 source identity", directory=False)
        _digest(digest, f"source identity for {name}")
        for suffix in required_suffixes:
            if name.endswith(suffix):
                observed_suffixes.add(suffix)
    if observed_suffixes != required_suffixes:
        raise ConcurrencyC3LkmmError("C3 source identity roles are incomplete")

    provider = manifest["provider"]
    if not isinstance(provider, dict) or set(provider) != {
        "binary", "binary_realpath", "binary_sha256", "expected_version",
        "library_directory", "library_upstream", "library_identities",
        "fixed_arguments",
    }:
        raise ConcurrencyC3LkmmError("C3 provider record is not exact")
    binary = Path(_nonempty(provider["binary"], "herd7 binary"))
    if not binary.is_absolute() or not binary.is_file():
        raise ConcurrencyC3LkmmError("herd7 binary must be an existing absolute file")
    realpath = Path(_nonempty(provider["binary_realpath"], "herd7 realpath"))
    if not realpath.is_absolute():
        raise ConcurrencyC3LkmmError("herd7 realpath must be absolute")
    _digest(provider["binary_sha256"], "herd7 identity")
    expected_version = _nonempty(provider["expected_version"], "herd7 version")
    if _version(expected_version) < _version(kernel["minimum_herdtools_version"]):
        raise ConcurrencyC3LkmmError("configured herd7 is older than LKMM requires")
    library_directory = _relative(
        root, provider["library_directory"], "herd CAT library", directory=True
    )
    upstream = provider["library_upstream"]
    if not isinstance(upstream, dict) or set(upstream) != {
        "repository", "tag", "commit", "git_tree", "license",
    }:
        raise ConcurrencyC3LkmmError("herd library provenance is not exact")
    if (
        upstream["repository"] != "https://github.com/herd/herdtools7"
        or upstream["tag"] != "7.58"
        or upstream["license"] != "CeCILL-B"
    ):
        raise ConcurrencyC3LkmmError("unexpected herd library provenance")
    _digest(upstream["commit"], "herd upstream commit", 40)
    _digest(upstream["git_tree"], "herd upstream tree", 40)
    library_identities = provider["library_identities"]
    if not isinstance(library_identities, dict) or len(library_identities) != 5:
        raise ConcurrencyC3LkmmError("herd library identity set is not exact")
    required_library_names = {
        "LICENSE.txt", "README.md", "libdir/stdlib.cat", "libdir/cross.cat",
        "libdir/cos-opt.cat",
    }
    library_names: set[str] = set()
    library_root = library_directory.parent
    for name, digest in library_identities.items():
        path = _relative(root, name, "herd library identity", directory=False)
        _digest(digest, f"library identity for {name}")
        try:
            library_names.add(path.relative_to(library_root).as_posix())
        except ValueError as exc:
            raise ConcurrencyC3LkmmError(
                "herd library identity is outside its vendored root"
            ) from exc
    if library_names != required_library_names:
        raise ConcurrencyC3LkmmError("herd library files are not the exact subset")
    if provider["fixed_arguments"] != [
        "-set-libdir", "{library_directory}", "-conf", "linux-kernel.cfg",
    ]:
        raise ConcurrencyC3LkmmError("herd7 invocation is not explicitly bound")

    scope = manifest["scope"]
    if (
        not isinstance(scope, dict)
        or set(scope) != {"evidence_kind", "accepted_capabilities", "exclusions"}
        or scope["evidence_kind"] != "semantic_calibration"
    ):
        raise ConcurrencyC3LkmmError("C3 scope is not a semantic calibration")
    _strings(scope["accepted_capabilities"], "accepted C3 capabilities")
    exclusions = _strings(scope["exclusions"], "C3 exclusions")
    joined_exclusions = " ".join(exclusions).lower()
    for boundary in ("production", "lifetime", "architecture", "whole-kernel", "klitmus7"):
        if boundary not in joined_exclusions:
            raise ConcurrencyC3LkmmError(f"C3 scope omits the {boundary} boundary")

    cases = manifest["cases"]
    if not isinstance(cases, list) or len(cases) != 4:
        raise ConcurrencyC3LkmmError("C3 requires exactly four calibrations")
    by_id: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "id", "path", "sha256", "role", "required_operations",
            "forbidden_operations", "expected",
        }:
            raise ConcurrencyC3LkmmError("C3 case record is not exact")
        case_id = case["id"]
        if case_id not in _CASE_IDS or case_id in by_id:
            raise ConcurrencyC3LkmmError(f"invalid or duplicate C3 case: {case_id!r}")
        by_id[case_id] = case
        _case_path(model_directory, case["path"], f"litmus test for {case_id}")
        _digest(case["sha256"], f"litmus identity for {case_id}")
        if case["role"] not in _ROLES:
            raise ConcurrencyC3LkmmError(f"invalid C3 role for {case_id}")
        required = _strings(
            case["required_operations"], f"required operations for {case_id}",
            allowed=_OPERATIONS,
        )
        forbidden = _strings(
            case["forbidden_operations"], f"forbidden operations for {case_id}",
            allowed=_OPERATIONS,
        )
        if set(required) & set(forbidden):
            raise ConcurrencyC3LkmmError(f"contradictory operations for {case_id}")
        expected = case["expected"]
        if not isinstance(expected, dict) or set(expected) != {
            "test", "disposition", "states", "marker", "positive", "negative",
            "flags", "condition", "observation", "hash",
        }:
            raise ConcurrencyC3LkmmError(f"expected output for {case_id} is not exact")
        for key in ("test", "disposition", "marker", "condition", "observation"):
            _nonempty(expected[key], f"{case_id} expected {key}")
        if (
            not isinstance(expected["flags"], list)
            or any(not isinstance(flag, str) or not flag for flag in expected["flags"])
            or len(expected["flags"]) != len(set(expected["flags"]))
        ):
            raise ConcurrencyC3LkmmError(f"{case_id} expected flags are invalid")
        for key in ("states", "positive", "negative"):
            if type(expected[key]) is not int or expected[key] < 0:
                raise ConcurrencyC3LkmmError(f"{case_id} expected {key} is invalid")
        _digest(expected["hash"], f"herd hash for {case_id}", 32)
        if expected["disposition"] != "Allowed":
            raise ConcurrencyC3LkmmError(f"{case_id} disposition must be Allowed")
        if expected["observation"] not in _OBSERVATIONS:
            raise ConcurrencyC3LkmmError(f"{case_id} observation is unsupported")
        if case["role"] == "weakened_control":
            if expected["observation"] != "Sometimes" or expected["positive"] < 1 or expected["marker"] != "Ok":
                raise ConcurrencyC3LkmmError(f"{case_id} is not a detecting weak control")
        elif expected["observation"] != "Never" or expected["positive"] != 0 or expected["marker"] != "No":
            raise ConcurrencyC3LkmmError(f"{case_id} is not an ordered Never calibration")
    if set(by_id) != _CASE_IDS:
        raise ConcurrencyC3LkmmError("C3 calibration inventory is incomplete")

    pairs = manifest["pairs"]
    if not isinstance(pairs, list) or len(pairs) != 2:
        raise ConcurrencyC3LkmmError("C3 requires exactly two A/B pairs")
    pair_ids: set[str] = set()
    referenced: set[str] = set()
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {
            "id", "weakened_control", "ordered_calibration",
            "ordering_primitives", "expected_transition",
        }:
            raise ConcurrencyC3LkmmError("C3 pair record is not exact")
        pair_id = _nonempty(pair["id"], "C3 pair id")
        if pair_id in pair_ids:
            raise ConcurrencyC3LkmmError(f"duplicate C3 pair id: {pair_id}")
        pair_ids.add(pair_id)
        weak = pair["weakened_control"]
        ordered = pair["ordered_calibration"]
        if weak not in by_id or ordered not in by_id or weak == ordered:
            raise ConcurrencyC3LkmmError(f"invalid C3 pair members for {pair_id}")
        if by_id[weak]["role"] != "weakened_control" or by_id[ordered]["role"] != "ordered_calibration":
            raise ConcurrencyC3LkmmError(f"reversed C3 pair roles for {pair_id}")
        primitives = _strings(
            pair["ordering_primitives"], f"ordering primitives for {pair_id}",
            allowed=_OPERATIONS,
        )
        if not set(primitives) <= set(by_id[ordered]["required_operations"]):
            raise ConcurrencyC3LkmmError(f"ordered case omits pair primitive for {pair_id}")
        if not set(primitives) <= set(by_id[weak]["forbidden_operations"]):
            raise ConcurrencyC3LkmmError(f"weak control does not remove pair primitive for {pair_id}")
        if by_id[weak]["expected"]["condition"] != by_id[ordered]["expected"]["condition"]:
            raise ConcurrencyC3LkmmError(f"C3 pair conditions differ for {pair_id}")
        if pair["expected_transition"] != "Sometimes->Never":
            raise ConcurrencyC3LkmmError(f"invalid C3 transition for {pair_id}")
        referenced.update((weak, ordered))
    if referenced != _CASE_IDS:
        raise ConcurrencyC3LkmmError("each C3 case must belong to exactly one pair")
    return manifest


def parse_herd_output(value: str) -> dict[str, Any]:
    """Parse one complete, intentionally narrow herd7 textual result."""
    match = _OUTPUT.fullmatch(value)
    if not match:
        raise ConcurrencyC3LkmmError("herd7 output does not match the pinned format")
    groups = match.groupdict()
    state_values = groups["state_lines"].rstrip("\n").splitlines()
    result = {
        "test": groups["test"],
        "disposition": groups["disposition"],
        "states": int(groups["states"]),
        "state_values": state_values,
        "marker": groups["marker"],
        "positive": int(groups["positive"]),
        "negative": int(groups["negative"]),
        "flags": [
            line.removeprefix("Flag ")
            for line in groups["flags"].splitlines()
        ],
        "condition": groups["condition"],
        "observation": groups["observation"],
        "hash": groups["hash"],
        "seconds": float(groups["seconds"]),
    }
    if (
        result["states"] != len(state_values)
        or len(state_values) != len(set(state_values))
        or groups["observation_test"] != result["test"]
        or groups["time_test"] != result["test"]
        or int(groups["observation_positive"]) != result["positive"]
        or int(groups["observation_negative"]) != result["negative"]
        or not math.isfinite(result["seconds"])
    ):
        raise ConcurrencyC3LkmmError("herd7 output is internally inconsistent")
    return result


def _run(argv: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        process = subprocess.run(
            argv, cwd=cwd, env=environment, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
        return {
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "returncode": 124,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
        }


def _write_process(
    directory: Path, argv: list[str], cwd: Path, process: dict[str, Any]
) -> None:
    (directory / "stdout.txt").write_text(process["stdout"])
    (directory / "stderr.txt").write_text(process["stderr"])
    _json(directory / "command.json", {
        "argv": argv,
        "cwd": str(cwd),
        "environment_overrides": {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        "returncode": process["returncode"],
        "timed_out": process["timed_out"],
    })


def _check(name: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {
        "name": name,
        "expected": expected,
        "actual": actual,
        "passed": expected == actual,
    }


def _core_result(parsed: dict[str, Any] | None) -> dict[str, Any] | None:
    if parsed is None:
        return None
    return {
        key: parsed[key]
        for key in (
            "test", "disposition", "states", "marker", "positive", "negative",
            "flags", "condition", "observation", "hash",
        )
    }


def _code_without_comments(source: str) -> str:
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)


def _operation_present(source: str, operation: str) -> bool:
    return re.search(rf"\b{re.escape(operation)}\s*\(", source) is not None


def _artifact_hashes(output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name not in {"summary.json", "SUMMARY.md"}:
            result[path.relative_to(output).as_posix()] = {
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
    return result


def render_summary(result: dict[str, Any]) -> str:
    checks = result["checks"]
    passed = sum(item["passed"] for item in checks)
    lines = [
        "# Linux LKMM/herd7 C3 capability calibration",
        "",
        f"Overall calibration: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        f"Semantic calibrations accepted: **{result['calibration_count']}**",
        f"Production kernel properties accepted: **{result['kernel_verification_count']}**",
        "",
        "| Case | Role | Condition outcome | Witnesses +/− | States | Gate |",
        "|---|---|---|---:|---:|---|",
    ]
    for case in result["cases"]:
        parsed = case["parsed"] or {}
        lines.append(
            f"| `{case['id']}` | {case['role']} | "
            f"{parsed.get('observation', 'unparsed')} | "
            f"{parsed.get('positive', '?')}/{parsed.get('negative', '?')} | "
            f"{parsed.get('states', '?')} | {'PASS' if case['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        f"Evidence checks: **{passed}/{len(checks)} passed**.",
        "",
        "The two weakened READ_ONCE/WRITE_ONCE controls permit their bad outcome;",
        "the matching release/acquire and full-barrier tests forbid it. This pins",
        "a working architecture-independent LKMM route and proves the runner can",
        "distinguish weak-memory outcomes from ordinary interleavings.",
        "",
        "This is not yet a production-code proof or a kernel bug result. Source-to-",
        "litmus correspondence, compiler/architecture lowering, lifetime, functional",
        "lock-free behavior, and progress remain separate C3 gates. No klitmus7",
        "module, running-kernel action, installation, or privileged command was used.",
        "",
        "Raw stdout/stderr, exact argv and working directories, manifest snapshot,",
        "input identities, parsed decisions, and artifact hashes are retained beside",
        "this summary.",
        "",
    ])
    return "\n".join(lines)


def run_c3_lkmm(root: Path, output: Path, timeout: int = 120) -> dict[str, Any]:
    """Run the provider inventory and four pinned LKMM semantic controls."""
    root = root.resolve()
    manifest = load_manifest(root)
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise ConcurrencyC3LkmmError(f"C3 LKMM output already exists: {output}")
    if type(timeout) is not int or timeout < 1:
        raise ConcurrencyC3LkmmError("C3 LKMM timeout must be a positive integer")
    output.mkdir(parents=True, exist_ok=False)
    inventory_directory = output / "inventory"
    cases_directory = output / "cases"
    inventory_directory.mkdir()
    cases_directory.mkdir()

    kernel = manifest["kernel"]
    provider = manifest["provider"]
    model_directory = _relative(
        root, kernel["model_directory"], "LKMM directory", directory=True
    )
    library_directory = _relative(
        root, provider["library_directory"], "herd CAT library", directory=True
    )
    binary = Path(provider["binary"])
    checks: list[dict[str, Any]] = []

    for name, expected in kernel["source_identities"].items():
        path = _relative(root, name, "C3 source identity", directory=False)
        checks.append(_check(f"source identity: {name}", expected, _sha256(path)))
    for name, expected in provider["library_identities"].items():
        path = _relative(root, name, "herd library identity", directory=False)
        checks.append(_check(f"library identity: {name}", expected, _sha256(path)))

    receipt = _strict_json(
        _relative(root, kernel["source_receipt"], "source receipt", directory=False)
    )
    checks.extend([
        _check("source receipt revision", kernel["revision"], receipt.get("revision")),
        _check("source receipt tree", kernel["git_tree"], receipt.get("git_tree")),
        _check(
            "source receipt requires content rechecks", True,
            receipt.get("contents_must_be_rechecked"),
        ),
    ])
    kernel_readme = (model_directory / "README").read_text()
    model_config = (model_directory / "linux-kernel.cfg").read_text()
    model_cat = (model_directory / "linux-kernel.cat").read_text()
    checks.extend([
        _check(
            "kernel documents compatible herdtools minimum", True,
            "Version 7.58 or higher" in kernel_readme,
        ),
        _check(
            "kernel documents small-state exhaustive exploration", True,
            "exhaustively explores\n"
            "the state space of small litmus tests" in kernel_readme,
        ),
        _check("config selects exact CAT model", True, "model linux-kernel.cat" in model_config),
        _check("config selects exact Bell model", True, "bell linux-kernel.bell" in model_config),
        _check("config selects exact macro definitions", True, "macros linux-kernel.def" in model_config),
        _check("CAT model imports lock model", True, 'include "lock.cat"' in model_cat),
        _check("CAT model defines release/acquire order", True, "let acq-po" in model_cat and "let po-rel" in model_cat),
        _check("CAT model defines full-barrier order", True, "let mb =" in model_cat),
    ])

    inventory: dict[str, dict[str, Any]] = {}
    inventory_commands = {
        "version": [str(binary), "-version"],
        "compiled_default_libdir": [str(binary), "-libdir"],
    }
    for name, argv in inventory_commands.items():
        directory = inventory_directory / name
        directory.mkdir()
        process = _run(argv, root, timeout)
        _write_process(directory, argv, root, process)
        inventory[name] = process
        checks.extend([
            _check(f"inventory {name} timed out", False, process["timed_out"]),
            _check(f"inventory {name} exit", 0, process["returncode"]),
        ])
    version = inventory["version"]["stdout"].strip()
    default_libdir = inventory["compiled_default_libdir"]["stdout"].strip()
    checks.extend([
        _check("herd7 realpath", provider["binary_realpath"], str(binary.resolve())),
        _check("herd7 binary identity", provider["binary_sha256"], _sha256(binary)),
        _check("herd7 exact version", provider["expected_version"], version),
        _check(
            "herd7 satisfies kernel minimum", True,
            _version(version) >= _version(kernel["minimum_herdtools_version"]),
        ),
        _check("explicit CAT library differs from compiled default", False,
               Path(default_libdir).resolve() == library_directory.resolve()),
    ])

    fixed_arguments = [
        str(library_directory) if value == "{library_directory}" else value
        for value in provider["fixed_arguments"]
    ]
    checks.extend([
        _check("invocation starts with explicit library option", "-set-libdir", fixed_arguments[0]),
        _check("invocation uses authenticated library", str(library_directory), fixed_arguments[1]),
        _check("invocation uses pinned kernel config", ["-conf", "linux-kernel.cfg"], fixed_arguments[2:]),
    ])

    case_results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        directory = cases_directory / case["id"]
        directory.mkdir()
        source_path = _case_path(
            model_directory, case["path"], f"litmus test for {case['id']}"
        )
        source = _code_without_comments(source_path.read_text())
        argv = [str(binary), *fixed_arguments, case["path"]]
        process = _run(argv, model_directory, timeout)
        _write_process(directory, argv, model_directory, process)
        parse_error: str | None = None
        try:
            parsed = parse_herd_output(process["stdout"])
        except ConcurrencyC3LkmmError as exc:
            parsed = None
            parse_error = str(exc)
        case_checks = [
            _check("litmus identity", case["sha256"], _sha256(source_path)),
            _check("timed out", False, process["timed_out"]),
            _check("exit code", 0, process["returncode"]),
            _check("stderr empty", "", process["stderr"]),
            _check("parse error", None, parse_error),
            _check("semantic result", case["expected"], _core_result(parsed)),
        ]
        for operation in case["required_operations"]:
            case_checks.append(_check(
                f"required operation: {operation}", True,
                _operation_present(source, operation),
            ))
        for operation in case["forbidden_operations"]:
            case_checks.append(_check(
                f"forbidden operation: {operation}", False,
                _operation_present(source, operation),
            ))
        result = {
            "id": case["id"],
            "role": case["role"],
            "path": case["path"],
            "verification_candidate": False,
            "returncode": process["returncode"],
            "timed_out": process["timed_out"],
            "parsed": parsed,
            "parse_error": parse_error,
            "checks": case_checks,
            "passed": all(item["passed"] for item in case_checks),
        }
        _json(directory / "result.json", result)
        case_results.append(result)

    by_id = {case["id"]: case for case in case_results}
    pair_results: list[dict[str, Any]] = []
    for pair in manifest["pairs"]:
        weak = by_id[pair["weakened_control"]]
        ordered = by_id[pair["ordered_calibration"]]
        weak_parsed = weak["parsed"] or {}
        ordered_parsed = ordered["parsed"] or {}
        transition = (
            f"{weak_parsed.get('observation', 'unparsed')}->"
            f"{ordered_parsed.get('observation', 'unparsed')}"
        )
        pair_checks = [
            _check("both pair members passed", True, weak["passed"] and ordered["passed"]),
            _check("observation transition", pair["expected_transition"], transition),
            _check("condition preserved", weak_parsed.get("condition"), ordered_parsed.get("condition")),
            _check("ordered variant removes bad witnesses", 0, ordered_parsed.get("positive")),
            _check("weakened control exposes bad witness", True, weak_parsed.get("positive", 0) > 0),
            _check("pair hashes differ", True, weak_parsed.get("hash") != ordered_parsed.get("hash")),
        ]
        pair_result = {
            **pair,
            "checks": pair_checks,
            "passed": all(item["passed"] for item in pair_checks),
        }
        pair_results.append(pair_result)

    checks.extend(item for case in case_results for item in case["checks"])
    checks.extend(item for pair in pair_results for item in pair["checks"])
    accepted = all(item["passed"] for item in checks)

    identity_names = sorted(set([
        *kernel["source_identities"],
        *provider["library_identities"],
        "config/concurrency-c3-lkmm.json",
        "fragma/__main__.py",
        "fragma/concurrency_c3_lkmm.py",
        "tests/test_concurrency_c3_lkmm.py",
        *[
            f"{kernel['model_directory']}/{case['path']}"
            for case in manifest["cases"]
        ],
    ]))
    identities = {
        name: {
            "sha256": _sha256(_relative(root, name, "C3 input identity", directory=False)),
            "size": _relative(root, name, "C3 input identity", directory=False).stat().st_size,
        }
        for name in identity_names
    }
    identities[str(binary)] = {
        "sha256": _sha256(binary),
        "size": binary.stat().st_size,
        "realpath": str(binary.resolve()),
    }
    _json(output / "manifest.json", manifest)
    _json(output / "input-identities.json", identities)
    summary = {
        "schema_version": 1,
        "kind": "linux-lkmm-herd7-c3-semantic-calibration",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": manifest["id"],
        "kernel_revision": kernel["revision"],
        "kernel_tree": kernel["git_tree"],
        "model_directory": str(model_directory),
        "provider": {
            "binary": str(binary),
            "realpath": str(binary.resolve()),
            "sha256": _sha256(binary),
            "version": version,
            "compiled_default_libdir": default_libdir,
            "explicit_library_directory": str(library_directory),
            "library_upstream": provider["library_upstream"],
        },
        "scope": manifest["scope"],
        "input_identities": identities,
        "cases": case_results,
        "pairs": pair_results,
        "checks": checks,
        "accepted": accepted,
        "calibration_count": len(case_results) if accepted else 0,
        "kernel_verification_count": 0,
        "c3_capability_baseline_complete": accepted,
        "c3_stage_complete": False,
        "remaining_c3": [
            "Production source-to-litmus correspondence and property acceptance",
            "Compiler and architecture lowering evidence for selected primitives",
            "Lock-free functional and lifetime properties",
            "Any separately claimed progress guarantee",
        ],
        "klitmus_or_runtime_used": False,
        "sudo_or_install_used": False,
        "output": str(output),
    }
    summary["raw_artifacts"] = _artifact_hashes(output)
    _json(output / "summary.json", summary)
    _json(output / "pilot-audit.json", summary)
    (output / "SUMMARY.md").write_text(render_summary(summary))
    return summary


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"concurrency-c3-lkmm-{stamp}"
