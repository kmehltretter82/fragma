"""Audit the retained RV32 load_unaligned_zeropad() A/B experiment."""

from __future__ import annotations

from datetime import datetime, timezone
from email.parser import Parser
from email.utils import getaddresses
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
from typing import Any


class RV32ZeropadError(ValueError):
    """The RV32 evidence, manifest, or requested output is unusable."""


_FAILURE = re.compile(
    r"EXPECTATION FAILED(?:(?!EXPECTATION FAILED).)*?"
    r"got == (\d+) \((0x[0-9a-f]+)\)(?:(?!EXPECTATION FAILED).)*?"
    r"expected == (\d+) \((0x[0-9a-f]+)\)(?:(?!EXPECTATION FAILED).)*?"
    r"remaining bytes: ([123])",
    re.DOTALL | re.IGNORECASE,
)


def _strict_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RV32ZeropadError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as exc:
        raise RV32ZeropadError(f"cannot load {path}: {exc}") from exc


def _relative(root: Path, value: str, role: str, *, directory: bool = False) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise RV32ZeropadError(f"{role} must be a project-relative path: {value!r}")
    path = root.joinpath(*pure.parts)
    present = path.is_dir() if directory else path.is_file()
    if not present or path.is_symlink():
        kind = "directory" if directory else "regular file"
        raise RV32ZeropadError(f"{role} is missing or not a {kind}: {value}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_config(text: str) -> dict[str, str]:
    """Parse assigned and explicitly disabled Kconfig symbols."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        assigned = re.fullmatch(r"(CONFIG_[A-Za-z0-9_]+)=(.*)", line)
        disabled = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_]+) is not set", line)
        if assigned:
            key, value = assigned.groups()
        elif disabled:
            key, value = disabled.group(1), "n"
        else:
            continue
        if key in result:
            raise RV32ZeropadError(f"duplicate configuration symbol: {key}")
        result[key] = value
    return result


def _one_status(text: str, pattern: str, role: str) -> str:
    statuses = re.findall(pattern, text, flags=re.MULTILINE)
    if len(statuses) != 1:
        raise RV32ZeropadError(
            f"expected exactly one {role} status, found {len(statuses)}"
        )
    return statuses[0]


def parse_kunit_log(text: str) -> dict[str, Any]:
    """Extract the architecture, exact failures, and terminal KUnit statuses."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    failures: dict[str, dict[str, Any]] = {}
    for got, got_hex, expected, expected_hex, remaining in _FAILURE.findall(text):
        if remaining in failures:
            raise RV32ZeropadError(f"duplicate failure for {remaining} remaining bytes")
        got_value = int(got)
        expected_value = int(expected)
        if got_value != int(got_hex, 16) or expected_value != int(expected_hex, 16):
            raise RV32ZeropadError("decimal and hexadecimal KUnit values disagree")
        failures[remaining] = {
            "got": got_value,
            "got_hex": got_hex.lower(),
            "expected": expected_value,
            "expected_hex": expected_hex.lower(),
        }

    isa = re.findall(r"^Boot HART Base ISA\s+:\s+(\S+)\s*$", text, re.MULTILINE)
    versions = re.findall(r"^\[[^\]]+\] Linux version (.+)$", text, re.MULTILINE)
    command_lines = re.findall(
        r"^\[[^\]]+\] Kernel command line: (.+)$", text, re.MULTILINE
    )
    if len(isa) != 1 or len(versions) != 1 or len(command_lines) != 1:
        raise RV32ZeropadError("log lacks a unique ISA, Linux version, or command line")
    commit = re.search(r"-g([0-9a-f]{12})(?:\s|\))", versions[0])
    if commit is None:
        raise RV32ZeropadError("Linux version does not expose a 12-digit git identity")

    timestamp = r"^\[[^\]]+\]"
    suite = _one_status(
        text,
        timestamp + r" (not ok|ok) 1 riscv-load-unaligned-zeropad\s*$",
        "KUnit suite",
    )
    case = _one_status(
        text,
        timestamp + r"\s{5}(not ok|ok) 1 riscv_load_unaligned_zeropad_guard_test\s*$",
        "KUnit case",
    )
    suite_matches = list(re.finditer(
        timestamp + r" (?:not ok|ok) 1 riscv-load-unaligned-zeropad\s*$",
        text, flags=re.MULTILINE,
    ))
    panic_at = text.find("Kernel panic - not syncing: VFS: Unable to mount root fs")
    return {
        "isa": isa[0],
        "linux_version": versions[0],
        "kernel_commit_abbrev": commit.group(1),
        "kernel_command_line": command_lines[0],
        "failures": failures,
        "failure_count": text.count("EXPECTATION FAILED"),
        "case_status": case,
        "suite_status": suite,
        "rootfs_panic_after_test": (
            len(suite_matches) == 1 and panic_at > suite_matches[0].end()
        ),
    }


def parse_elf(path: Path) -> dict[str, Any]:
    header = path.read_bytes()[:20]
    if len(header) != 20 or header[:4] != b"\x7fELF":
        raise RV32ZeropadError(f"not an ELF file: {path}")
    if header[5] not in (1, 2):
        raise RV32ZeropadError(f"unsupported ELF byte order in {path}")
    byteorder = "little" if header[5] == 1 else "big"
    return {
        "class_bits": {1: 32, 2: 64}.get(header[4]),
        "byte_order": byteorder,
        "machine": int.from_bytes(header[18:20], byteorder),
    }


def parse_mail_recipients(patch_text: str) -> dict[str, list[tuple[str, str]]]:
    """Return normalized To/Cc recipients from a format-patch mail header."""
    header_text = patch_text.split("\n\n", 1)[0]
    lines = header_text.splitlines()
    if not lines or not re.fullmatch(
        r"From [0-9a-f]{40} Mon Sep 17 00:00:00 2001", lines[0]
    ):
        raise RV32ZeropadError("submission lacks a format-patch envelope line")
    headers = Parser().parsestr("\n".join(lines[1:]) + "\n\n", headersonly=True)
    if headers.defects:
        raise RV32ZeropadError(f"malformed submission mail headers: {headers.defects}")
    return {
        "to": getaddresses(headers.get_all("To", [])),
        "cc": getaddresses(headers.get_all("Cc", [])),
    }


def _run(argv: list[str], cwd: Path, *, input_text: str | None = None,
         environment: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    if environment:
        env.update(environment)
    try:
        process = subprocess.run(
            argv, cwd=cwd, env=env, input=input_text, text=True,
            capture_output=True, timeout=30, check=False,
        )
        return {
            "argv": argv,
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "returncode": 127, "stdout": "", "stderr": str(exc)}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _render(result: dict[str, Any]) -> str:
    before = result["logs"]["before"]
    after = result["logs"]["after"]
    passed_checks = sum(check["passed"] for check in result["checks"])
    lines = [
        "# RV32 `load_unaligned_zeropad()` A/B audit",
        "",
        f"Overall audit: **{'PASS' if result['accepted'] else 'FAIL'}**",
        "",
        "The unpatched kernel returned bytes from the preceding word in all three",
        "guard-page cases. The patched kernel passed the same KUnit case under a",
        "byte-identical configuration.",
        f"{passed_checks}/{len(result['checks'])} recorded checks passed.",
        "",
        "| Remaining mapped bytes | Expected | Before | Before status | After status |",
        "|---:|---:|---:|---|---|",
    ]
    for remaining in (1, 2, 3):
        failure = before["failures"][str(remaining)]
        lines.append(
            f"| {remaining} | `{failure['expected_hex']}` | `{failure['got_hex']}` | "
            f"fail | pass |"
        )
    lines.extend([
        "",
        f"A-side suite: **{before['suite_status']}**; B-side suite: "
        f"**{after['suite_status']}**.",
        "",
        f"Base: `{result['source']['mainline_base']}` ({result['source']['mainline_name']})",
        f"Submission commit: `{result['source']['submission_commit']}`",
        f"Stable patch-id: `{result['source']['stable_patch_id']}`",
        "",
        "The submission patch passes strict `checkpatch.pl`, applies cleanly to the",
        "recorded mainline and linux-next commits, and has an RV64 compile control.",
        "The later no-rootfs panic in each log occurs after KUnit and is not a test",
        "failure. Raw images, configurations, logs, objects, and the source clone",
        "remain local; their pinned SHA-256 identities are in `pilot-audit.json`.",
        "The patch is send-ready but has not been emailed or maintainer-acknowledged.",
        "",
    ])
    return "\n".join(lines)


def audit(root: Path, output: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = root / "config/rv32-zeropad.json"
    manifest = _strict_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise RV32ZeropadError("unsupported RV32 zeropad manifest")
    output = output if output.is_absolute() else root / output
    if output.exists() or output.is_symlink():
        raise RV32ZeropadError(f"audit output already exists: {output}")

    evidence = _relative(
        root, manifest["evidence_directory"], "evidence directory", directory=True
    )
    repository = _relative(
        root, manifest["source_repository"], "source repository", directory=True
    )
    if not (repository / ".git").exists():
        raise RV32ZeropadError("source repository has no Git metadata")

    checks: list[dict[str, Any]] = []

    def add(name: str, expected: Any, actual: Any) -> None:
        checks.append({
            "name": name,
            "expected": expected,
            "actual": actual,
            "passed": expected == actual,
        })

    identities = {"config/rv32-zeropad.json": sha256(manifest_path)}
    for value in (
        "fragma/rv32_zeropad.py",
        "tests/test_rv32_zeropad.py",
        "riscv/rv32-zeropad/run-ab.sh",
    ):
        path = _relative(root, value, "audit implementation input")
        identities[value] = sha256(path)
    project_paths: dict[str, Path] = {}
    for name, record in manifest["patches"].items():
        path = _relative(root, record["path"], name)
        project_paths[name] = path
        actual = sha256(path)
        identities[record["path"]] = actual
        add(f"{name} SHA-256", record["sha256"], actual)

    artifact_paths: dict[str, Path] = {}
    for name, record in manifest["artifacts"].items():
        path = _relative(evidence, record["path"], name)
        artifact_paths[name] = path
        actual = sha256(path)
        identities[f"{manifest['evidence_directory']}/{record['path']}"] = actual
        add(f"{name} SHA-256", record["sha256"], actual)

    config_before_bytes = artifact_paths["config_before"].read_bytes()
    config_after_bytes = artifact_paths["config_after"].read_bytes()
    add("A/B configurations byte-identical", True,
        config_before_bytes == config_after_bytes)
    config = parse_config(config_before_bytes.decode())
    for symbol, expected in manifest["required_config"].items():
        add(f"configuration {symbol}", expected, config.get(symbol))
    add("CONFIG_64BIT is not enabled", False, config.get("CONFIG_64BIT") == "y")

    before = parse_kunit_log(artifact_paths["log_before"].read_text(errors="strict"))
    after = parse_kunit_log(artifact_paths["log_after"].read_text(errors="strict"))
    expected_failures = manifest["expected_before_failures"]
    compact_failures = {
        key: {"got": value["got"], "expected": value["expected"]}
        for key, value in before["failures"].items()
    }
    add("A-side exact wrong values", expected_failures, compact_failures)
    add("A-side failure count", 3, before["failure_count"])
    add("A-side case status", "not ok", before["case_status"])
    add("A-side suite status", "not ok", before["suite_status"])
    add("B-side failures", {}, after["failures"])
    add("B-side failure count", 0, after["failure_count"])
    add("B-side case status", "ok", after["case_status"])
    add("B-side suite status", "ok", after["suite_status"])
    for side, parsed in (("A", before), ("B", after)):
        add(f"{side}-side RV32 ISA", True, parsed["isa"].startswith("rv32"))
        add(f"{side}-side kernel command line", manifest["kernel_command_line"],
            parsed["kernel_command_line"])
        add(f"{side}-side KUnit precedes intentional rootfs panic", True,
            parsed["rootfs_panic_after_test"])
    source = manifest["source"]
    add("A-side diagnostic commit", source["diagnostic_commit"][:12],
        before["kernel_commit_abbrev"])
    add("B-side tested fix commit", source["tested_fix_commit"][:12],
        after["kernel_commit_abbrev"])

    rv32_elf = parse_elf(artifact_paths["rv32_fixed_vmlinux"])
    rv32_object = parse_elf(artifact_paths["rv32_fixed_extable_object"])
    rv64_object = parse_elf(artifact_paths["rv64_fixed_extable_object"])
    rv64_baseline_object = parse_elf(
        artifact_paths["rv64_baseline_extable_object"]
    )
    for name, value, bits in (
        ("RV32 fixed vmlinux", rv32_elf, 32),
        ("RV32 fixed extable.o", rv32_object, 32),
        ("RV64 fixed extable.o", rv64_object, 64),
        ("RV64 baseline extable.o", rv64_baseline_object, 64),
    ):
        add(f"{name} ELF class", bits, value["class_bits"])
        add(f"{name} RISC-V machine", 243, value["machine"])
    add(
        "RV64 extable.o unchanged byte-for-byte",
        True,
        artifact_paths["rv64_baseline_extable_object"].read_bytes()
        == artifact_paths["rv64_fixed_extable_object"].read_bytes(),
    )
    rv32_command = artifact_paths["rv32_fixed_extable_command"].read_text()
    rv64_command = artifact_paths["rv64_fixed_extable_command"].read_text()
    add("RV32 compile command uses ILP32", True, "-mabi=ilp32" in rv32_command)
    add("RV32 compile command uses rv32 ISA", True, "-march=rv32" in rv32_command)
    add("RV64 compile command uses LP64", True, "-mabi=lp64" in rv64_command)
    add("RV64 compile command uses rv64 ISA", True, "-march=rv64" in rv64_command)
    rv64_config = parse_config(artifact_paths["rv64_fixed_config"].read_text())
    add("RV64 compile configuration", "y", rv64_config.get("CONFIG_64BIT"))
    add("RV64 compile MMU configuration", "y", rv64_config.get("CONFIG_MMU"))

    commands: dict[str, Any] = {}
    for name, tool in manifest["tools"].items():
        process = _run(tool["argv"], root)
        commands[f"tool_{name}"] = process
        first = process["stdout"].splitlines()[0] if process["stdout"].splitlines() else ""
        add(f"{name} inventory exit", 0, process["returncode"])
        add(f"{name} inventory", tool["expected_first_line"], first)

    def git(name: str, argv: list[str], *, input_text: str | None = None) -> dict[str, Any]:
        process = _run(["git", *argv], repository, input_text=input_text)
        commands[name] = process
        return process

    for name, commit in source.items():
        if name.endswith("_commit") or name.endswith("_base"):
            process = git(f"commit_{name}", ["cat-file", "-e", f"{commit}^{{commit}}"])
            add(f"Git object {name}", 0, process["returncode"])
    ancestry = git("introducing_commit_ancestry", [
        "merge-base", "--is-ancestor", source["introducing_commit"],
        source["mainline_base"],
    ])
    add("introducing commit is in mainline history", 0, ancestry["returncode"])
    for name, child, parent in (
        ("submission parent", source["submission_commit"], source["mainline_base"]),
        ("diagnostic parent", source["diagnostic_commit"], source["mainline_base"]),
        ("tested fix parent", source["tested_fix_commit"], source["diagnostic_commit"]),
    ):
        process = git(name.replace(" ", "_"), ["rev-parse", f"{child}^"])
        add(name, parent, process["stdout"].strip())

    patch_text = project_paths["submission"].read_text()
    add("submission mail patch commit", True,
        patch_text.startswith(f"From {source['submission_commit']} "))
    recipients = parse_mail_recipients(patch_text)
    for kind in ("to", "cc"):
        add(
            f"embedded {kind.upper()} recipients",
            getaddresses(manifest["email"][kind]),
            recipients[kind],
        )
    review_notes = patch_text.split("\n---\n", 1)[1].split("\ndiff --git ", 1)[0]
    for phrase in (
        "RV32 QEMU virt/TCG",
        "fill bytes from the previous word",
        "0xa5, 0xa5a5, and\n0xa5a5a5",
        "string tail (0x44, 0x4433, and 0x443322)",
        "all three cases and the suite passed",
        "full RV32 Images",
        "RV64\nextable.o is byte-for-byte identical",
    ):
        add(f"review note {phrase.replace(chr(10), ' ')}", True,
            phrase in review_notes)
    patch_id = git("submission_patch_id", ["patch-id", "--stable"], input_text=patch_text)
    patch_id_value = patch_id["stdout"].split()[0] if patch_id["stdout"].split() else ""
    add("submission stable patch-id", source["stable_patch_id"], patch_id_value)
    tested_diff = git("tested_fix_diff", [
        "diff", "--binary", f"{source['diagnostic_commit']}..{source['tested_fix_commit']}"
    ])
    tested_patch_id = git(
        "tested_fix_patch_id", ["patch-id", "--stable"],
        input_text=tested_diff["stdout"],
    )
    tested_patch_id_value = (
        tested_patch_id["stdout"].split()[0]
        if tested_patch_id["stdout"].split() else ""
    )
    add("tested and submission patch-id", source["stable_patch_id"],
        tested_patch_id_value)
    content = git("tested_submission_content", [
        "diff", "--exit-code",
        f"{source['submission_commit']}:arch/riscv/mm/extable.c",
        f"{source['tested_fix_commit']}:arch/riscv/mm/extable.c",
    ])
    add("tested and submission extable content", 0, content["returncode"])

    diagnostic_text = project_paths["diagnostic"].read_text()
    add("diagnostic mail patch commit", True,
        diagnostic_text.startswith(f"From {source['diagnostic_commit']} "))
    diagnostic_patch_id = git(
        "diagnostic_patch_id", ["patch-id", "--stable"],
        input_text=diagnostic_text,
    )
    diagnostic_diff = git("diagnostic_commit_diff", [
        "diff", "--binary", f"{source['mainline_base']}..{source['diagnostic_commit']}"
    ])
    diagnostic_commit_patch_id = git(
        "diagnostic_commit_patch_id", ["patch-id", "--stable"],
        input_text=diagnostic_diff["stdout"],
    )
    diagnostic_patch_id_value = (
        diagnostic_patch_id["stdout"].split()[0]
        if diagnostic_patch_id["stdout"].split() else ""
    )
    diagnostic_commit_patch_id_value = (
        diagnostic_commit_patch_id["stdout"].split()[0]
        if diagnostic_commit_patch_id["stdout"].split() else ""
    )
    add("diagnostic file and tested commit patch-id",
        diagnostic_commit_patch_id_value, diagnostic_patch_id_value)

    old_fragment = "offset = addr & 0x7UL;\n\taddr &= ~0x7UL;"
    fixed_fragment = (
        "offset = addr & (sizeof(data) - 1);\n"
        "\taddr &= ~(sizeof(data) - 1);"
    )
    for label, commit in (("mainline", source["mainline_base"]),
                          ("linux-next", source["linux_next_base"])):
        shown = git(f"{label}_extable", [
            "show", f"{commit}:arch/riscv/mm/extable.c"
        ])
        add(f"bug present on {label}", True, old_fragment in shown["stdout"])
    shown_fixed = git("fixed_extable", [
        "show", f"{source['submission_commit']}:arch/riscv/mm/extable.c"
    ])
    add("width-derived fix present", True, fixed_fragment in shown_fixed["stdout"])

    for label, commit in (("mainline", source["mainline_base"]),
                          ("linux-next", source["linux_next_base"])):
        with tempfile.TemporaryDirectory(prefix="fragma-rv32-index-") as temporary:
            index = str(Path(temporary) / "index")
            environment = {"GIT_INDEX_FILE": index}
            read_tree = _run(["git", "read-tree", commit], repository,
                             environment=environment)
            apply = _run(
                ["git", "apply", "--cached", "--check", "--whitespace=error-all",
                 str(project_paths["submission"])],
                repository, environment=environment,
            )
            commands[f"apply_{label}_read_tree"] = read_tree
            commands[f"apply_{label}"] = apply
            add(f"prepare {label} apply index", 0, read_tree["returncode"])
            add(f"submission applies to {label}", 0, apply["returncode"])

    checkpatch = _run(
        [str(repository / "scripts/checkpatch.pl"), "--strict", "--no-tree",
         str(project_paths["submission"])], repository,
    )
    commands["checkpatch"] = checkpatch
    checkpatch_text = checkpatch["stdout"] + checkpatch["stderr"]
    add("strict checkpatch exit", 0, checkpatch["returncode"])
    add("strict checkpatch clean", True,
        "0 errors, 0 warnings, 0 checks" in checkpatch_text)

    maintainers = _run(
        [str(repository / "scripts/get_maintainer.pl"), "--no-rolestats",
         str(project_paths["submission"])], repository,
    )
    commands["get_maintainer"] = maintainers
    actual_maintainers = [line for line in maintainers["stdout"].splitlines() if line]
    add("get_maintainer exit", 0, maintainers["returncode"])
    add("maintainer routing", manifest["maintainers"], actual_maintainers)

    email_argv = [
        "git", "send-email", "--dry-run", "--confirm=never",
        str(project_paths["submission"]),
    ]
    email = _run(email_argv, root)
    commands["send_email_dry_run"] = email
    email_text = email["stdout"] + email["stderr"]
    add("git send-email dry-run exit", 0, email["returncode"])
    add("git send-email dry-run mode", True, "Dry-OK." in email_text)
    add("git send-email dry-run result", True, "Result: OK" in email_text)
    for _, address in recipients["to"] + recipients["cc"]:
        add(f"git send-email envelope recipient {address}", True,
            f"RCPT TO:<{address}>" in email_text)

    commit_message = git("submission_commit_message", [
        "show", "-s", "--format=%B", source["submission_commit"]
    ])["stdout"]
    for trailer in (
        f"Fixes: {source['introducing_commit'][:12]}",
        "Cc: stable@vger.kernel.org",
        "Signed-off-by: Karl Mehltretter <kmehltretter@gmail.com>",
    ):
        add(f"submission trailer {trailer.split(':', 1)[0]}", True,
            trailer in commit_message)
    add("submission Assisted-by trailer", True,
        "Assisted-by: LLM" in patch_text)

    objdump = _run(
        ["riscv64-linux-gnu-objdump", "-dr",
         str(artifact_paths["rv32_fixed_extable_object"])], root,
    )
    commands["rv32_objdump"] = objdump
    add("RV32 disassembly exit", 0, objdump["returncode"])
    for instruction in ("andi\ta3,a5,3", "andi\ta5,a5,-4", "srl\ta5,a5,a3"):
        add(f"RV32 fix instruction {instruction}", True,
            instruction in objdump["stdout"])

    result = {
        "schema_version": 1,
        "kind": "rv32-load-unaligned-zeropad-ab-audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "accepted": all(check["passed"] for check in checks),
        "source": source,
        "logs": {"before": before, "after": after},
        "config_sha256": sha256(artifact_paths["config_before"]),
        "elf": {
            "rv32_fixed_vmlinux": rv32_elf,
            "rv32_fixed_extable_object": rv32_object,
            "rv64_fixed_extable_object": rv64_object,
            "rv64_baseline_extable_object": rv64_baseline_object,
        },
        "identities": identities,
        "checks": checks,
        "commands": commands,
        "maintainers": actual_maintainers,
        "email_dry_run": True,
        "raw_evidence_published": False,
        "email_sent": False,
        "maintainer_acknowledged": False,
    }
    output.mkdir(parents=True, exist_ok=False)
    _write_json(output / "pilot-audit.json", result)
    (output / "SUMMARY.md").write_text(_render(result))
    return result


def default_output(root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "results" / f"rv32-zeropad-{stamp}"
