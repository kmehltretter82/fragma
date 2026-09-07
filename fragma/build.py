"""Reproducible out-of-tree kernel preparation for registered profiles."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import time

from .sources import SourceError, sha256


def prepare_build(root: Path, source: Path, profile: dict, env: dict,
                  *, seed_config: Path | None = None, jobs: int = 4) -> dict:
    root, source = root.resolve(), source.resolve()
    if jobs < 1:
        raise SourceError("jobs must be positive")
    marker = source / ".fragma-source.json"
    if not marker.is_file():
        raise SourceError("kernel source must be a fragma pinned snapshot")
    identity = json.loads(marker.read_text())
    profile_id = profile["id"]
    if not profile_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in profile_id):
        raise SourceError("invalid profile ID")
    output = root / "build" / "kernel" / profile_id
    if output.exists():
        raise SourceError(f"build directory already exists; retain or explicitly choose a fresh workspace: {output}")
    compiler = shutil.which(profile["compiler"], path=env.get("PATH"))
    if not compiler:
        raise SourceError(f"compiler unavailable: {profile['compiler']}")
    command = ["make", "-C", str(source), f"O={output}",
               f"ARCH={profile['kernel']['arch']}", f"CC={compiler}"]
    if profile["kernel"].get("subarch"):
        command.append(f"SUBARCH={profile['kernel']['subarch']}")
    llvm_receipt = None
    if profile.get("compiler_family", "gcc") == "clang":
        from .llvm_build import prepare_llvm
        assignments, llvm_receipt, env = prepare_llvm(profile, compiler, env)
        command = [arg for arg in command if not arg.startswith("CC=")] + assignments
    elif profile.get("compiler_family", "gcc") != "gcc":
        raise SourceError("unsupported compiler family")
    elif profile["compiler"] != "gcc":
        if not compiler.endswith("gcc"):
            raise SourceError("cross compiler prefix must be declared for non-GCC builds")
        command.append(f"CROSS_COMPILE={compiler[:-3]}")
    output.mkdir(parents=True)
    record = {"schema_version": 1, "profile_id": profile_id,
              "source": str(source), "revision": identity["revision"],
              "source_tree": identity["git_tree"], "compiler": compiler,
              "compiler_sha256": sha256(Path(compiler)), "commands": [],
              "status": "running", "output": str(output)}
    if llvm_receipt is not None:
        record["llvm"] = llvm_receipt
    config = output / ".config"
    if seed_config:
        seed_config = seed_config.resolve()
        record["seed_config"] = {"path": str(seed_config), "sha256": sha256(seed_config)}
        shutil.copyfile(seed_config, config)
        recipe = ["olddefconfig"]
    else:
        recipe = profile["kernel"]["config_recipe"]
    commands = [command + recipe, command + [f"-j{jobs}", "prepare", "lib/string.o"],
                ["python3", str(source / "scripts/clang-tools/gen_compile_commands.py"),
                 "-d", str(output), "-o", str(output / "compile_commands.json")]]
    with (output / "prepare.log").open("w") as log:
        for argv in commands:
            started = time.monotonic()
            print("+ " + repr(argv), file=log, flush=True)
            result = subprocess.run(argv, env=env, stdout=log, stderr=subprocess.STDOUT,
                                    check=False)
            record["commands"].append({"argv": argv, "returncode": result.returncode,
                                       "seconds": time.monotonic() - started})
            if result.returncode:
                record["status"] = "failed"
                break
        else:
            record["status"] = "prepared"
        if record["status"] == "prepared" and llvm_receipt is not None:
            from .llvm_build import verify_llvm_build
            try:
                record["llvm_validation"] = verify_llvm_build(profile, output, llvm_receipt, source=source)
            except (OSError, ValueError) as exc:
                record["status"] = "failed"
                record["validation_error"] = str(exc)
                print("LLVM validation failed: " + str(exc), file=log)
    record["files"] = {name: sha256(output / name) for name in (
        ".config", "include/generated/autoconf.h", "include/config/auto.conf",
        "compile_commands.json") if (output / name).is_file()}
    if llvm_receipt is not None:
        record["files"].update({name: sha256(output / name) for name in (
            "lib/string.o", "lib/.string.o.cmd", "prepare.log") if (output / name).is_file()})
    (output / "fragma-build.json").write_text(json.dumps(record, indent=2) + "\n")
    return record
