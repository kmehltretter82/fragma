#!/usr/bin/env python3
"""Print a review candidate for lock.json from a selected, existing switch.

First refresh opam-switch.export with `opam switch export --full --readonly`.
This command never installs packages and never updates the accepted lock.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fragma.toolchain import installed_packages, prepare_environment, sha256


ROOT = Path(__file__).resolve().parents[1]
SPECS = {
    "frama-c": (["-version"], r"^(\d+\.\d+)"),
    "why3": (["--version"], r"version (\d+(?:\.\d+)+)"),
    "alt-ergo": (["--version"], r"^v(\d+(?:\.\d+)+)"),
    "cvc5": (["--version"], r"^cvc5 (\d+(?:\.\d+)+)"),
    "z3": (["--version"], r"^Z3 version (\d+(?:\.\d+)+)"),
    "opam": (["--version"], r"^(\d+(?:\.\d+)+)"),
    "ocamlc": (["-version"], r"^(\d+(?:\.\d+)+)"),
    "gcc": (["-dumpfullversion", "-dumpversion"], r"^(\d+(?:\.\d+)+)"),
}
COMPILERS = ["aarch64-linux-gnu-gcc", "alpha-linux-gnu-gcc", "arm-linux-gnueabi-gcc",
    "i686-linux-gnu-gcc", "m68k-linux-gnu-gcc", "powerpc-linux-gnu-gcc",
    "riscv64-linux-gnu-gcc", "s390x-linux-gnu-gcc", "sh4-linux-gnu-gcc",
    "x86_64-linux-gnu-gcc"]


def capture(switch: Path | None) -> dict:
    env = prepare_environment(ROOT, switch)
    switch = Path(env["FRAGMA_SWITCH_PREFIX"])
    tools = {}
    for name, (args, pattern) in {**SPECS, **{name: SPECS["gcc"] for name in COMPILERS}}.items():
        executable = shutil.which(name, path=env["PATH"])
        if not executable:
            if name in COMPILERS:
                continue
            raise RuntimeError(f"Required capture tool is missing: {name}")
        result = subprocess.run([executable, *args], env=env, capture_output=True,
                                text=True, check=True, timeout=15)
        match = re.search(pattern, result.stdout + result.stderr)
        if not match:
            raise RuntimeError(f"Cannot identify version of {name}")
        record = {"version": match.group(1), "version_args": args,
            "version_pattern": pattern, "required": name not in COMPILERS and name != "z3",
            "reference_sha256": sha256(Path(executable)),
            "require_binary_hash": name in ("opam", "cvc5", "z3")}
        if name == "gcc" or name in COMPILERS:
            record["target"] = subprocess.check_output([executable, "-dumpmachine"], env=env, text=True).strip()
        tools[name] = record
    installed = installed_packages(switch)
    metadata = {}
    for atom in installed:
        path = switch / ".opam-switch" / "packages" / atom / "opam"
        source = path.read_text()
        metadata[atom] = {"reference_metadata_sha256": sha256(path),
            "source_checksums": sorted(set(re.findall(r'"((?:sha256|sha512|md5)=[a-f0-9]+)"', source))),
            "source_urls": re.findall(r'\bsrc:\s*"([^"\n]+)"', source)}
    export = ROOT / "toolchain" / "opam-switch.export"
    export_atoms = re.findall(r'"([A-Za-z0-9_+.-]+)"', re.search(
        r"(?m)^installed:\s*\[([^\]]*)\]", export.read_text()).group(1))
    if sorted(export_atoms) != installed:
        raise RuntimeError("Full export does not match installed package set")
    artifact_inputs = {
        "opam": (Path(shutil.which("opam", path=env["PATH"])),
            "https://github.com/ocaml/opam/releases/download/2.5.0/opam-2.5.0-x86_64-linux"),
        "gmp": (ROOT / "toolchain" / "gmp-6.3.0.tar.xz",
            "https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz"),
        "cvc5": (ROOT / "toolchain" / "cvc5.zip",
            "https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.4/cvc5-Linux-x86_64-static.zip"),
        "z3": (ROOT / "toolchain" / "z3.zip",
            "https://github.com/Z3Prover/z3/releases/download/z3-4.13.4/z3-4.13.4-x64-glibc-2.35.zip"),
    }
    artifacts = {name: {"url": url, "sha256": sha256(path), "size": path.stat().st_size,
        "file": path.name if name != "opam" else "opam-2.5.0-x86_64-linux",
        "checksum_origin": "observed local artifact; upstream signature not independently authenticated"}
        for name, (path, url) in artifact_inputs.items()}
    runtime = {}
    for library in [Path(env["FRAGMA_TOOLCHAIN_PREFIX"]) / "lib" / "libgmp.so.10.5.0",
                    Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
                    Path("/usr/lib/x86_64-linux-gnu/libz.so.1")]:
        if library.is_file():
            runtime[library.name] = {"reference_sha256": sha256(library),
                                    "reference_path": str(library.resolve())}
    try:
        output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}=${Version}\n",
            "gcc-15", "binutils", "libc6", "zlib1g", "libgmp10", "make", "pkg-config"], text=True)
        distro_packages = output.splitlines()
    except (FileNotFoundError, subprocess.CalledProcessError):
        distro_packages = []
    graphviz_lock = ROOT / "toolchain" / "graphviz-artifacts.json"
    if graphviz_lock.is_file():
        artifacts.update(json.loads(graphviz_lock.read_text())["artifacts"])
    return {"schema_version": 1, "captured_at": "2026-09-05",
        "host": {"system": "Linux", "machine": "x86_64"},
        "tools": tools, "required_plugins": ["WP", "Eva", "RteGen", "E-ACSL", "Report"],
        "required_scripts": ["e-acsl-gcc"],
        "why3": {"config": "toolchain/why3.conf", "sha256": sha256(ROOT / "toolchain" / "why3.conf"),
            "required_provers": ["alt-ergo", "cvc5"],
            "driver_compatibility": "CVC5 1.3.4 uses Why3 1.8.2 cvc5 driver; bounded true/false arithmetic calibration passed, general compatibility remains assumed"},
        "opam": {"export": "toolchain/opam-switch.export", "export_sha256": sha256(export),
            "installed": installed, "packages": metadata,
            "complete_installed": sorted([*installed, "conf-graphviz.0.1"]),
            "complete_export": "toolchain/opam-switch.complete.export",
            "complete_export_sha256": sha256(ROOT / "toolchain" / "opam-switch.complete.export"),
            "historical_missing_post_dependency": "conf-graphviz.0.1 (dot absent; original post-install failed)",
            "repository": "toolchain/opam-repository",
            "repository_sha256": sha256(ROOT / "toolchain" / "opam-repository" / "repo"),
            "historical_repository": "git+https://github.com/ocaml/opam-repository.git#3e2ef3aff96fed8cfa47af6ea93970d3ff8c1c10"},
        "artifacts": artifacts, "runtime_libraries": runtime,
        "reference_distribution_packages": distro_packages,
        "limitations": [
            "The bootstrap binaries target Linux x86_64; kernel analysis targets can use cross-compilers.",
            "Downloaded artifact hashes pin observed bytes; upstream signatures have not been independently authenticated.",
            "The complete opam export includes source URLs and checksums, including transitive packages. It does not vendor all source archives.",
            "The historical 90-package switch lacks the conf-graphviz post dependency. Clean setup uses a separately locked 91-package complete export.",
            "Compiler executables and system-library hashes are recorded. Distribution build dependencies are observed, not supplied as a hermetic operating-system image.",
            "Rebuilt OCaml tool binaries can differ due to build paths. Their versions are enforced and their actual hashes remain part of run identity.",
            "CVC5 1.3.4 requires explicit Why3 configuration because Why3 1.8.2 detection expects an older version banner. Standard cvc5 driver compatibility beyond the recorded calibration remains an assumption.",
            "A clean installation and proof replay at another location have not yet been established by this lock alone."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--switch-prefix", type=Path)
    args = parser.parse_args()
    print(json.dumps(capture(args.switch_prefix), indent=2, sort_keys=True))
