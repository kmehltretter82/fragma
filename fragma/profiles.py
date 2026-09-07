"""Target profiles and fail-closed compiler/Frama-C model calibration.

Only generated evidence can raise a registered profile's level. No target
compiler, semantic flag, or missing machine-description value falls back to the
host. The upstream generator needs PyYAML; this module is otherwise stdlib-only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from . import analysis_policy


class ProfileError(ValueError):
    """Invalid registration, input identity, or unavailable profile."""


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _normalize_machdep_compiler_dialect(profile, machine):
    """Make Frama-C's compiler field describe syntax, not an executable.

    make_machdep uses the --compiler argument both to run ABI probes and as the
    generated YAML value.  For cross compilers those are distinct identities:
    Frama-C accepts the literal dialects ``gcc`` and ``clang`` for GNU syntax,
    while the executable, target, flags and hash are recorded separately.
    """
    family = profile.get("compiler_family", "gcc")
    if family not in ("gcc", "clang"):
        raise ProfileError("Unsupported machine-description compiler dialect")
    path = Path(machine)
    text = path.read_text()
    matches = list(re.finditer(r"(?m)^compiler:[ \t]*([^\r\n]+?)[ \t]*$", text))
    if len(matches) != 1:
        raise ProfileError("Generated machine description has no unique compiler field")
    observed = matches[0].group(1).strip()
    if observed != profile["compiler"]:
        raise ProfileError("Generated machine-description compiler identity changed")
    rewritten = text[:matches[0].start()] + "compiler: " + family + text[matches[0].end():]
    path.write_text(rewritten)
    return {"schema_version": 1, "status": "checked", "generated_value": observed,
            "dialect": family, "changed_fields": ["compiler"],
            "executable_identity_source": "profile compiler receipt"}


def load_architectures(root):
    data = json.loads((Path(root) / "config/architectures.json").read_text())
    if data.get("schema_version") != 1:
        raise ProfileError("Unsupported architecture schema")
    rows = data["architectures"]
    if len({a["id"] for a in rows}) != len(rows):
        raise ProfileError("Duplicate architecture")
    return data


UML_HEADER_REVIEW_PATHS = frozenset({
    "arch/um/Makefile", "arch/um/include/uapi/asm/Kbuild",
    "scripts/Makefile.asm-headers", "arch/x86/um/Kconfig",
})

CLANG_PROFILE_ROUTES = {
    "hexagon": {
        "target": "hexagon-unknown-linux-musl",
        "target_args": ["--target=hexagon-linux-musl", "-mv68"],
        "required_config": {"CONFIG_HEXAGON_ARCH_VERSION": "68"},
    },
    "mips": {
        "target": "mipsel-unknown-linux-gnu",
        "target_args": ["--target=mipsel-linux-gnu", "-mabi=32", "-EL",
                        "-march=mips32r2", "-msoft-float"],
        "required_config": {
            "CONFIG_MIPS": "y", "CONFIG_32BIT": "y", "CONFIG_RALINK": "y",
            "CONFIG_SOC_MT7621": "y",
            "CONFIG_CPU_LITTLE_ENDIAN": "y", "CONFIG_CPU_MIPS32_R2": "y",
            "CONFIG_SMP": "y", "CONFIG_MIPS_MT_SMP": "y",
            "CONFIG_MIPS_CPS": "y", "CONFIG_NR_CPUS": "4",
        },
        "config_recipe": ["olddefconfig"],
        "seed_config": "profiles/configs/mips32el-mt7621.config",
        "seed_config_sha256": "dd8a59933e4ab6d02a40a319953326871669f9d075f510ff28b80e5053cfeb2b",
        "abi": {
            "bits": 32, "byte_order": "little", "char_unsigned": True,
            "wchar_bytes": 2, "short_bytes": 2, "int_bytes": 4, "long_bytes": 4,
            "long_long_bytes": 8, "pointer_bytes": 4, "long_alignment": 4,
            "pointer_alignment": 4, "long_long_alignment": 8,
        },
    },
}


def _header_architecture(profile):
    """Resolve only the explicitly reviewed UML kernel-header delegation.

    This does not select a compiler or machine model. Other architectures keep
    their own pinned header trees; missing headers never trigger a fallback.
    """
    arch = profile["architecture"]
    if arch != "um":
        if "header_arch" in profile or "header_arch_review" in profile:
            raise ProfileError("Header architecture override has no reviewed port route")
        return arch
    kernel, abi = profile.get("kernel", {}), profile.get("abi", {})
    if (profile.get("header_arch") != "x86" or kernel.get("arch") != "um" or
            kernel.get("subarch") != "x86_64" or abi.get("bits") != 64 or
            profile.get("header_type") != "asm/posix_types_64.h" or
            profile.get("generic_bitsperlong", False) is not False or
            profile.get("extra_uapi_headers")):
        raise ProfileError("UML headers require the reviewed x86_64 kernel route")
    review = profile.get("header_arch_review")
    if (not isinstance(review, dict) or review.get("status") != "reviewed" or
            not isinstance(review.get("reason"), str) or not review["reason"].strip()):
        raise ProfileError("UML header delegation requires an explicit review")
    hashes = review.get("file_hashes")
    if (not isinstance(hashes, dict) or set(hashes) != UML_HEADER_REVIEW_PATHS or
            not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in hashes.values())):
        raise ProfileError("UML header review must bind every pinned selection input")
    return "x86"


def _compiler_target_args(profile):
    """Select only reviewed Clang target routes; legacy GCC remains unchanged."""
    family = profile.get("compiler_family", "gcc")
    if family == "gcc":
        if profile.get("compiler_target_args") not in (None, []):
            raise ProfileError("GCC profiles do not accept separate compiler target arguments")
        return []
    if family != "clang":
        raise ProfileError("Unsupported compiler family")
    architecture = profile.get("architecture")
    route = CLANG_PROFILE_ROUTES.get(architecture)
    kernel = profile.get("kernel", {})
    if (not route or kernel.get("arch") != architecture or
            profile.get("compiler_version") != "21.1.8" or
            profile.get("compiler_target") != route["target"] or
            profile.get("compiler_target_args") != route["target_args"] or
            any(kernel.get("required_config", {}).get(key) != value
                for key, value in route["required_config"].items()) or
            ("config_recipe" in route and
             (kernel.get("config_recipe") != route["config_recipe"] or
              kernel.get("seed_config") != route["seed_config"] or
              kernel.get("seed_config_sha256") != route["seed_config_sha256"])) or
            ("abi" in route and any(profile.get("abi", {}).get(key) != value
                                    for key, value in route["abi"].items()))):
        raise ProfileError("Clang profile requires an exact reviewed target/version/configuration/ABI route")
    for key in ("flags", "common_flags"):
        flags = profile.get(key)
        if not isinstance(flags, list) or not all(isinstance(flag, str) and flag for flag in flags):
            raise ProfileError("Unknown Clang profile flags: " + key)
        for flag in flags:
            if (re.search(r"\s|\x00", flag) or flag.startswith((
                    "--target", "-target", "-mv", "-mcpu", "-march", "@", "-Xclang",
                    "-Xpreprocessor", "-Xarch_", "-Xassembler", "-Wa,", "-Wp,",
                    "--config", "--driver-mode", "-cc1", "-resource-dir", "--resource-dir",
                    "--sysroot", "-isysroot", "-I", "-isystem", "-include", "-imacros",
                    "-idirafter", "-iquote", "-iprefix", "-iwithprefix", "-B",
                    "--gcc-toolchain", "--gcc-install-dir", "-fplugin", "-fpass-plugin",
                    "-mabi", "-mips", "-D__HEXAGON", "-U__HEXAGON", "-D__hexagon",
                    "-U__hexagon", "-D__mips", "-U__mips")) or
                    flag in ("-D", "-U", "-EL", "-EB", "-msoft-float", "-mhard-float")):
                raise ProfileError("Conflicting or unreviewed Clang target/CPU/forwarded flags")
    return list(route["target_args"])


def compiler_flags(profile):
    """The complete target prefix travels with every model/preprocessor use."""
    return _compiler_target_args(profile) + profile["flags"] + profile["common_flags"]


def compiler_version_args(profile):
    _compiler_target_args(profile)
    return ["--version"] if profile.get("compiler_family") == "clang" else ["-dumpfullversion"]


def _compiler_version(profile, output):
    if profile.get("compiler_family") != "clang":
        return output.strip()
    versions = re.findall(r"clang version\s+(\d+\.\d+\.\d+)(?![\w.+-])", output)
    return versions[0] if len(versions) == 1 else None


def _clang_lock_matches(profile, specification, compiler):
    return (profile.get("compiler_family") == "clang" and isinstance(specification, dict) and
            specification.get("compiler_family") == "clang" and
            specification.get("version") == profile["compiler_version"] and
            specification.get("target") == profile["compiler_target"] and
            specification.get("target_args") == _compiler_target_args(profile) and
            specification.get("version_args") == ["--version"] and
            specification.get("require_binary_hash") is True and
            specification.get("reference_sha256") == _hash(compiler) and
            isinstance(specification.get("resource_include_tree_sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", specification["resource_include_tree_sha256"]) is not None)


def validate_registration(profile):
    """Reject unknown semantic settings before attempting any analysis."""
    if not isinstance(profile.get("id"), str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", profile["id"]):
        raise ProfileError("Invalid profile ID")
    if profile.get("status") == "planned":
        return
    if profile.get("status") != "experimental":
        raise ProfileError("Unsupported profile registration status")
    _header_architecture(profile)
    for key in ("compiler", "compiler_target", "compiler_version", "frama_c_version"):
        if not isinstance(profile.get(key), str) or not profile[key]:
            raise ProfileError("Unknown profile setting: " + key)
    for key in ("flags", "common_flags"):
        if not isinstance(profile.get(key), list) or not all(isinstance(x, str) and x for x in profile[key]):
            raise ProfileError("Unknown profile flags: " + key)
    _compiler_target_args(profile)
    abi = profile.get("abi")
    if not isinstance(abi, dict) or abi.get("bits") not in (32, 64):
        raise ProfileError("Unknown kernel ABI width")
    if abi.get("byte_order") not in ("little", "big") or type(abi.get("char_unsigned")) is not bool:
        raise ProfileError("Unknown byte order or plain-char signedness")
    for key in ("short_bytes", "int_bytes", "long_bytes", "long_long_bytes", "pointer_bytes",
                "wchar_bytes", "long_alignment", "pointer_alignment", "long_long_alignment"):
        if type(abi.get(key)) is not int or abi[key] <= 0:
            raise ProfileError("Unknown profile layout: " + key)
    if abi["pointer_bytes"] * 8 != abi["bits"]:
        raise ProfileError("Profile pointer and kernel ABI widths disagree")
    kernel = profile.get("kernel", {})
    if "seed_config_sha256" in kernel:
        seed = kernel.get("seed_config")
        if (not isinstance(seed, str) or not seed or Path(seed).is_absolute() or
                ".." in Path(seed).parts or
                not isinstance(kernel["seed_config_sha256"], str) or
                re.fullmatch(r"[0-9a-f]{64}", kernel["seed_config_sha256"]) is None):
            raise ProfileError("Invalid pinned kernel seed configuration")
    try:
        analysis_policy.model_identity(profile.get("analysis"))
    except analysis_policy.AnalysisPolicyError as exc:
        raise ProfileError("Unsupported analysis policy: " + str(exc)) from exc


def load_profiles(root):
    """Return profiles keyed by ID, including explicit planned registrations."""
    data = json.loads((Path(root) / "config/profiles.json").read_text())
    if data.get("schema_version") != 1:
        raise ProfileError("Unsupported profile schema")
    registry = load_architectures(root)
    if data["kernel_revision"] != registry["kernel_revision"]:
        raise ProfileError("Profile and architecture revisions disagree")
    by_arch = {row["id"]: row for row in registry["architectures"]}
    result = {}
    for item in data["profiles"]:
        profile = copy.deepcopy(data["defaults"])
        profile.update(copy.deepcopy(item))
        profile["kernel_revision"] = data["kernel_revision"]
        if profile["id"] in result:
            raise ProfileError("Duplicate profile: " + profile["id"])
        if profile["architecture"] not in by_arch:
            raise ProfileError("Unregistered architecture: " + profile["architecture"])
        if profile["kernel"]["arch"] != by_arch[profile["architecture"]]["kernel_arch"]:
            raise ProfileError("Kernel ARCH disagrees with architecture registry")
        validate_registration(profile)
        result[profile["id"]] = profile
    for arch in registry["architectures"]:
        if arch["baseline_profile"] not in result:
            candidate = "clang" if arch["id"] == "hexagon" else "gcc" if arch["id"] == "um" else arch["compiler_target"] + "-gcc"
            result[arch["baseline_profile"]] = {
                "id": arch["baseline_profile"], "architecture": arch["id"],
                "status": "planned", "kernel_revision": data["kernel_revision"],
                "compiler": None, "compiler_target": arch["compiler_target"],
                "compiler_candidate": candidate,
                "kernel": {"arch": arch["kernel_arch"], "subarch": arch["subarch"],
                           "config_recipe": None, "build_path": None},
                "abi": None, "variants": arch["variants"],
                "gaps": [f"Candidate compiler {candidate} must be provisioned and its target/version locked.",
                         "Kernel configuration and supported machine variants need explicit selection.",
                         "No compiler-derived machine description or calibration.",
                         "No source-gated proof baseline."],
            }
    return result


def _environment(env=None):
    """Copy a caller-selected environment, excluding ambient header injection."""
    values = os.environ if env is None else env
    return {**{key: value for key, value in values.items()
               if key not in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH")},
            "LC_ALL": "C"}


def _which(command, env):
    return shutil.which(str(command), path=env.get("PATH", ""))


def compiler_capabilities(root, *, env=None):
    """Discover candidate tools without turning their presence into port support."""
    root = Path(root).resolve()
    env = _environment(env)
    profiles = load_profiles(root)
    lock_path = root / "toolchain/lock.json"
    lock = json.loads(lock_path.read_text()) if lock_path.is_file() else {}
    tools = lock.get("tools", {})
    rows = []
    for profile in profiles.values():
        name = profile.get("compiler") or profile["compiler_candidate"]
        path = _which(name, env)
        expected = tools.get(name)
        row = {"profile_id": profile["id"], "architecture": profile["architecture"],
               "profile_status": profile["status"], "compiler_candidate": name,
               "required_target": profile["compiler_target"], "compiler_path": path,
               "locked_version": expected.get("version") if expected else None,
               "status": "missing-compiler" if not path else "unlocked-compiler" if not expected else "available",
               "gaps": []}
        if not path:
            row["gaps"].append("Missing executable: " + name)
        elif not expected:
            row["gaps"].append("No exact version/target requirement in toolchain/lock.json for " + name)
        elif expected.get("compiler_family") == "clang" or profile.get("compiler_family") == "clang":
            from . import toolchain
            try:
                target_args = _compiler_target_args(profile)
                if not _clang_lock_matches(profile, expected, path):
                    raise ProfileError("Clang capability requires matching explicit profile/toolchain settings")
                observation = toolchain.probe(name, expected, env)
                row.update(observed_version=observation.get("version"),
                           observed_target=observation.get("target"), compiler_sha256=observation.get("sha256"),
                           compiler_family="clang", compiler_target_args=target_args,
                           compiler_observation=observation)
                if (observation.get("status") != "ok" or observation.get("path") != path or
                        observation.get("sha256") != _hash(path)):
                    raise ProfileError("Clang compiler/resource identity does not satisfy the recorded requirements")
            except (ProfileError, OSError, ValueError) as exc:
                row["status"] = "compiler-mismatch"
                row["gaps"].append(str(exc))
        else:
            version = subprocess.run([path, *expected["version_args"]], capture_output=True, text=True, timeout=15, env=env)
            match = re.search(expected["version_pattern"], version.stdout + version.stderr, re.M)
            target = subprocess.run([path, "-dumpmachine"], capture_output=True, text=True, timeout=15, env=env)
            row["observed_version"] = match[1] if match else None
            row["observed_target"] = target.stdout.strip()
            row["compiler_sha256"] = _hash(path)
            if version.returncode or not match or match[1] != expected["version"] or target.returncode or row["observed_target"] != profile["compiler_target"]:
                row["status"] = "compiler-mismatch"
                row["gaps"].append("Observed compiler target/version does not satisfy recorded requirements")
        if profile["status"] == "planned":
            row["gaps"].extend(["No selected kernel configuration or checked machine description", "No source-gated proof baseline"])
        row["runtime_emulators"] = {method: _which(method, env) for method in profile.get("runtime_methods", []) if method.startswith("qemu-")}
        rows.append(row)
    return {"schema_version": 1, "kernel_revision": load_architectures(root)["kernel_revision"],
            "toolchain_lock_sha256": _hash(lock_path) if lock_path.is_file() else None,
            "profiles": rows, "note": "Compiler availability is prerequisite evidence only, never L1/L2 support."}


def validate_roster(root, kernel, *, env=None):
    registry = load_architectures(root)
    cmd = ["git", "-C", str(kernel), "ls-tree", "-d", "--name-only",
           registry["kernel_revision"] + ":arch"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=_environment(env))
    if proc.returncode:
        raise ProfileError(proc.stderr.strip())
    expected = sorted(row["id"] for row in registry["architectures"])
    observed = sorted(proc.stdout.splitlines())
    if observed != expected:
        raise ProfileError(f"Pinned architecture roster changed: {observed!r} != {expected!r}")
    return {"status": "passed", "revision": registry["kernel_revision"],
            "architectures": observed, "command": cmd}


def machdep_scalars(path):
    """Read only YAML top-level scalar fields; avoid a second YAML dependency."""
    result = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_]+):\s*(.*?)\s*", line)
        if not match or not match[2]:
            continue
        key, value = match.groups()
        if value in ("true", "false"):
            result[key] = value == "true"
        elif re.fullmatch(r"-?\d+", value):
            result[key] = int(value)
        else:
            result[key] = value.strip("'\"")
    return result


def check_machine_description(profile, path):
    """Independent expected model check; rejects wrong widths and endianness."""
    values = machdep_scalars(path)
    abi = profile["abi"]
    required = {"sizeof_short": abi["short_bytes"], "sizeof_int": abi["int_bytes"],
                "sizeof_long": abi["long_bytes"], "sizeof_longlong": abi["long_long_bytes"],
                "sizeof_ptr": abi["pointer_bytes"], "alignof_long": abi["long_alignment"],
                "alignof_ptr": abi["pointer_alignment"],
                "alignof_longlong": abi["long_long_alignment"],
                "little_endian": abi["byte_order"] == "little",
                "char_is_unsigned": abi["char_unsigned"],
                "wchar_t": "unsigned short" if abi["wchar_bytes"] == 2 else "int",
                "size_t": "unsigned long" if abi["bits"] == 64 else "unsigned int"}
    errors = [f"{key}: expected {value!r}, observed {values.get(key)!r}"
              for key, value in required.items() if values.get(key) != value]
    if errors:
        raise ProfileError("Machine description mismatch: " + "; ".join(errors))
    return {key: values[key] for key in required}


def _run(command, output, name, timeout=120, stdin=None, cwd=None, env=None):
    command = [str(arg) for arg in command]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, input=stdin,
                              timeout=timeout, cwd=cwd, env=_environment(env))
        result = {"command": command, "exit_code": proc.returncode,
                  "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired as exc:
        result = {"command": command, "exit_code": None, "stdout": "",
                  "stderr": f"Tool timeout after {exc.timeout}s"}
    log = output / (name + ".log")
    log.write_text("$ " + shlex.join(command) + "\n" + result["stdout"] + result["stderr"])
    result["log"] = str(log)
    return result


def _export_headers(profile, kernel, output, *, env=None):
    """Read pinned Linux headers, with no host include directories."""
    arch = _header_architecture(profile)
    source_paths = {
        "asm-generic/bitsperlong.h": "include/uapi/asm-generic/bitsperlong.h",
        "asm-generic/posix_types.h": "include/uapi/asm-generic/posix_types.h",
        "asm-generic/int-ll64.h": "include/uapi/asm-generic/int-ll64.h",
    }
    generic_bits = profile.get("generic_bitsperlong", False)
    if generic_bits:
        source_paths["source-evidence/asm-generic-Kbuild"] = "include/uapi/asm-generic/Kbuild"
    else:
        source_paths["asm/bitsperlong.h"] = f"arch/{arch}/include/uapi/asm/bitsperlong.h"
    if profile["header_type"] == "asm/posix_types.h":
        source_paths["asm/posix_types.h"] = f"arch/{arch}/include/uapi/asm/posix_types.h"
    elif arch == "x86":
        source_paths["asm/posix_types_64.h"] = "arch/x86/include/uapi/asm/posix_types_64.h"
        source_paths["asm/kernel-posix-selection.h"] = "arch/x86/include/asm/posix_types.h"
    for header in profile.get("extra_uapi_headers", []):
        source_paths["asm/" + header] = f"arch/{arch}/include/uapi/asm/{header}"
    reviewed_hashes = profile.get("header_arch_review", {}).get("file_hashes", {})
    source_paths.update({"source-evidence/" + path: path for path in reviewed_hashes})
    include = output / "kernel-headers"
    hashes = {}
    for dest, source in source_paths.items():
        command = ["git", "-C", str(kernel), "show", profile["kernel_revision"] + ":" + source]
        proc = subprocess.run(command, capture_output=True, timeout=30, env=_environment(env))
        if proc.returncode or not proc.stdout:
            raise ProfileError(f"Cannot export pinned header {source}: {proc.stderr.decode()}")
        if source in reviewed_hashes and hashlib.sha256(proc.stdout).hexdigest() != reviewed_hashes[source]:
            raise ProfileError("UML header selection changed since review: " + source)
        target = include / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(proc.stdout)
        hashes[source] = _hash(target)
    if generic_bits:
        source = (include / "source-evidence/asm-generic-Kbuild").read_text()
        if "mandatory-y += bitsperlong.h" not in source:
            raise ProfileError("Pinned Kbuild no longer selects generic bitsperlong.h")
        probe = subprocess.run(["git", "-C", str(kernel), "cat-file", "-e", profile["kernel_revision"] + f":arch/{arch}/include/uapi/asm/bitsperlong.h"], capture_output=True, timeout=30, env=_environment(env))
        if probe.returncode == 0:
            raise ProfileError("Profile requested generic bitsperlong.h but architecture supplies an override")
        wrapper = include / "asm/bitsperlong.h"
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text("#include <asm-generic/bitsperlong.h>\n")
        hashes["generated:asm/bitsperlong.h"] = _hash(wrapper)
    wrapper = include / "kernel-types.h"
    wrapper.write_text(f'#include <{profile["header_type"]}>\n'
                       '#include <asm-generic/int-ll64.h>\n')
    hashes["generated:kernel-types.h"] = _hash(wrapper)
    return include, hashes


def _defines(profile):
    abi = profile["abi"]
    result = ["-D__KERNEL__"]
    if abi["bits"] == 64:
        result.append("-DCONFIG_64BIT=1")
    for key in ("bits", "short_bytes", "int_bytes", "long_bytes", "long_long_bytes",
                "pointer_bytes", "wchar_bytes", "long_alignment", "pointer_alignment",
                "long_long_alignment"):
        result.append(f"-DFRAGMA_{key.upper()}={abi[key]}")
    result += [f'-DFRAGMA_CHAR_UNSIGNED={int(abi["char_unsigned"])}',
               f'-DFRAGMA_BYTE_ORDER={1234 if abi["byte_order"] == "little" else 4321}',
               f'-DFRAGMA_FIRST_BYTE={4 if abi["byte_order"] == "little" else 1}']
    pointer_offset = ((abi["long_alignment"] + abi["long_bytes"] + abi["pointer_alignment"] - 1)
                      // abi["pointer_alignment"] * abi["pointer_alignment"])
    struct_align = max(abi["long_alignment"], abi["pointer_alignment"])
    natural_size = (pointer_offset + abi["pointer_bytes"] + struct_align - 1) // struct_align * struct_align
    result.append(f"-DFRAGMA_NATURAL_SIZE={natural_size}")
    return result


def _generator_headers(profile, root, compiler, output, *, env=None):
    """Use an explicitly provisioned target header sysroot, never a host ABI."""
    settings = profile.get("generator_headers")
    if profile.get("compiler_family") == "clang":
        if profile.get("architecture") != "mips" or not isinstance(settings, dict):
            # Tool resources are not a complete target libc/POSIX header route.
            # Hexagon deliberately remains closed; unrelated sysroots cannot be
            # borrowed to activate it.
            raise ProfileError("Clang model generation requires its reviewed generator-header route; no host or cross-architecture fallback")
        expected_keys = {
            "sysroot", "environment", "provider", "receipt", "source_url",
            "archive_sha256", "feature_flags", "include_order", "scope",
        }
        if (set(settings) != expected_keys or
                settings.get("provider") != "profiles/setup_mips_musl.py" or
                settings.get("receipt") != "fragma-mips-sysroot.json" or
                settings.get("source_url") != "https://musl.libc.org/releases/musl-1.2.5.tar.gz" or
                settings.get("archive_sha256") != "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4" or
                settings.get("feature_flags") != ["-D_POSIX_C_SOURCE=200809L"] or
                settings.get("include_order") != ["generator-overlay", "clang-resource", "musl"]):
            raise ProfileError("MIPS generator-header specification is not the reviewed musl 1.2.5 route")
        env = _environment(env)
        sysroot = Path(env.get(settings["environment"], str(root / settings["sysroot"]))).resolve()
        provider_input = root / settings["provider"]
        if not provider_input.is_file():
            raise ProfileError("Missing pinned MIPS generator-header verifier")
        provider = provider_input.resolve()
        specification = importlib.util.spec_from_file_location("fragma_profile_mips_headers", provider)
        if specification is None or specification.loader is None:
            raise ProfileError("Cannot load the pinned MIPS generator-header verifier")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        receipt = module.verify(sysroot)
        receipt_path = sysroot / settings["receipt"]
        if (receipt.get("kind") != "mips32el-generator-header-sysroot" or
                receipt.get("status") != "provisioned" or
                receipt.get("architecture") != "mips" or
                receipt.get("source_url") != settings["source_url"] or
                receipt.get("archive_sha256") != settings["archive_sha256"] or
                receipt.get("include_order") != settings["include_order"]):
            raise ProfileError("MIPS generator-header receipt identity mismatch")
        resource = _run([compiler, *_compiler_target_args(profile), "-print-resource-dir"],
                        output, "compiler-builtin-headers", env=env)
        resource_root = Path(resource["stdout"].strip())
        if (resource["exit_code"] or resource["stderr"].strip() or
                len(resource["stdout"].splitlines()) != 1 or not resource_root.is_absolute()):
            raise ProfileError("Target compiler builtin resource directory unavailable")
        from . import toolchain
        resources = toolchain.clang_resource_tree(resource_root)
        lock = json.loads((root / "toolchain/lock.json").read_text())["tools"][profile["compiler"]]
        if resources["include_tree_sha256"] != lock.get("resource_include_tree_sha256"):
            raise ProfileError("MIPS generator Clang resource identity differs from the central lock")
        flags = ["-nostdinc", "-isystem", str(sysroot / "generator-overlay"),
                 "-isystem", resources["include_directory"],
                 "-isystem", str(sysroot / "include"), *settings["feature_flags"]]
        return flags, {
            "provider": str(provider), "provider_sha256": _hash(provider),
            "sysroot": str(sysroot), "archive_sha256": settings["archive_sha256"],
            "header_hashes": receipt["header_hashes"],
            "overlay_sha256": receipt["overlay_sha256"],
            "compiler_resources": resources,
            "receipt": str(receipt_path), "receipt_sha256": _hash(receipt_path),
            "include_order": settings["include_order"], "scope": settings["scope"],
        }
    if not settings:
        return [], None
    env = _environment(env)
    sysroot = Path(env.get(settings["environment"], str(root / settings["sysroot"]))).resolve()
    receipt_path = sysroot / "fragma-sysroot.json"
    if not receipt_path.is_file():
        raise ProfileError("Missing generator header sysroot; run profiles/setup_musl.py with the pinned archive: " + str(sysroot))
    receipt = json.loads(receipt_path.read_text())
    if receipt.get("architecture") != "riscv64" or receipt.get("archive_sha256") != settings["archive_sha256"] or receipt.get("returncode") != 0:
        raise ProfileError("Generator sysroot receipt identity mismatch")
    archive = sysroot / "musl-1.2.5.tar.gz"
    if not archive.is_file() or _hash(archive) != settings["archive_sha256"]:
        raise ProfileError("Generator sysroot pinned source archive missing/changed")
    actual = {path.relative_to(sysroot).as_posix(): _hash(path)
              for path in sorted((sysroot / "include").rglob("*")) if path.is_file()}
    if not actual or actual != receipt["header_hashes"]:
        raise ProfileError("Generator sysroot header set/content changed")
    builtin = _run([compiler, "-print-file-name=include"], output, "compiler-builtin-headers", env=env)
    include = Path(builtin["stdout"].strip())
    if builtin["exit_code"] or not include.is_dir():
        raise ProfileError("Target compiler builtin include directory unavailable")
    builtin_hashes = {path.relative_to(include).as_posix(): _hash(path)
                      for path in sorted(include.rglob("*.h")) if path.is_file()}
    return ["-nostdinc", "-isystem", str(include), "-isystem", str(sysroot / "include"), *settings["feature_flags"]], {
        "sysroot": str(sysroot), "archive_sha256": settings["archive_sha256"],
        "header_hashes": actual, "compiler_builtin_header_hashes": builtin_hashes,
        "receipt_sha256": _hash(receipt_path), "scope": settings["scope"]}


def _check_uml_prepare_commands(receipt):
    """Reject contradictory selectors or unsuccessful recorded preparation."""
    records = receipt.get("commands")
    if (not isinstance(records, list) or not records or
            not all(isinstance(row, dict) and isinstance(row.get("argv"), list) and
                    row["argv"] and all(isinstance(arg, str) for arg in row["argv"])
                    for row in records)):
        raise ProfileError("Malformed UML build command receipt")
    # bool is not an exit status even though Python treats it as an int.
    if any(type(row.get("returncode")) is not int or row["returncode"] != 0
           for row in records):
        raise ProfileError("UML preparation command did not record a successful exit")
    make_commands = [row["argv"] for row in records if row["argv"][0] == "make"]
    if len(make_commands) != 2:
        raise ProfileError("UML build receipt requires two recorded make commands")
    assignment = re.compile(r"^(?:ARCH|SUBARCH)\s*(?:::=|::=|:=|\+=|\?=|!=|=)")
    for args in make_commands:
        selectors = [arg for arg in args if assignment.match(arg)]
        if sorted(selectors) != ["ARCH=um", "SUBARCH=x86_64"]:
            raise ProfileError("UML build receipt lacks unique exact ARCH/SUBARCH selectors")


def _uml_compile_flags_match(profile, args):
    """Match this reviewed UML kernel context, including opposing options.

    This is deliberately not a general GCC option interpreter. Response files
    are unsupported; explicit CPP forwarding is inspected for the protected
    UML selector rather than silently allowing a later macro override.
    """
    if not all(flag in args for flag in profile["flags"]):
        return False
    conflicting = {"-mno-red-zone", "-fbuiltin", "-fPIE", "-fpie", "-fPIC", "-fpic",
                   "-msse", "-mmmx", "-msse2", "-m3dnow", "-mavx"}
    if (conflicting.intersection(args) or
            any(arg.startswith("-mcmodel=") and arg != "-mcmodel=large" for arg in args)):
        return False
    cpp_args, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("@"):
            return False
        if arg == "-Xpreprocessor":
            index += 1
            if index == len(args):
                return False
            cpp_args.append(args[index])
        elif arg.startswith("-Wp,"):
            cpp_args.extend(arg[4:].split(","))
        else:
            cpp_args.append(arg)
        index += 1
    if any(arg.startswith("@") for arg in cpp_args):
        return False
    selectors, index = [], 0
    while index < len(cpp_args):
        arg = cpp_args[index]
        if arg.startswith(("-D", "-U")):
            operation, value = arg[1], arg[2:]
            if not value:
                index += 1
                if index == len(cpp_args):
                    return False
                value = cpp_args[index]
            name = re.split(r"[=(]", value, maxsplit=1)[0]
            if name == "__arch_um__":
                selectors.append((operation, value))
            elif name == "__UM_HOST__" and operation == "D":
                return False
        index += 1
    return selectors == [("D", "__arch_um__")]


def _check_build(profile, kernel_build, kernel, compiler, *, env=None):
    env = _environment(env)
    build = Path(kernel_build).resolve()
    config = build / ".config"
    db_path = build / "compile_commands.json"
    if not config.is_file() or not db_path.is_file():
        raise ProfileError("L1 requires .config and compile_commands.json in kernel_build")
    receipt_file = build / "fragma-build.json"
    if not receipt_file.is_file():
        raise ProfileError("L1 requires a recorded fragma-build.json build receipt")
    receipt = json.loads(receipt_file.read_text())
    if receipt.get("status") != "prepared" or receipt.get("profile_id") != profile["id"] or receipt.get("revision") != profile["kernel_revision"]:
        raise ProfileError("Kernel build receipt profile/revision/status mismatch")
    if receipt.get("compiler_sha256") != _hash(compiler):
        raise ProfileError("Kernel build compiler changed")
    seed_sha256 = profile["kernel"].get("seed_config_sha256")
    if seed_sha256 is not None and receipt.get("seed_config", {}).get("sha256") != seed_sha256:
        raise ProfileError("Kernel build receipt seed configuration differs from the profile")
    if profile["architecture"] == "um":
        _check_uml_prepare_commands(receipt)
    llvm_validation = None
    if profile.get("compiler_family") == "clang":
        from .llvm_build import verify_llvm_build
        try:
            llvm_validation = verify_llvm_build(profile, build, receipt["llvm"], source=Path(receipt["source"]))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ProfileError("Clang genuine-build validation failed: " + str(exc)) from exc
        if llvm_validation != receipt.get("llvm_validation"):
            raise ProfileError("Clang genuine-build validation envelope changed")
    for relative in (".config", "compile_commands.json", "include/generated/autoconf.h", "include/config/auto.conf"):
        path = build / relative
        if not path.is_file() or _hash(path) != receipt.get("files", {}).get(relative):
            raise ProfileError("Kernel build receipt input changed: " + relative)
    expected_tree = subprocess.run(["git", "-C", str(kernel), "rev-parse", profile["kernel_revision"] + "^{tree}"], capture_output=True, text=True, timeout=30, env=env)
    if expected_tree.returncode or expected_tree.stdout.strip() != receipt.get("source_tree"):
        raise ProfileError("Kernel build source tree identity mismatch")
    values = {}
    for line in config.read_text().splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    for key, expected in profile["kernel"]["required_config"].items():
        if values.get(key, "n") != expected:
            raise ProfileError(f"Build configuration {key}: expected {expected}, got {values.get(key, 'n')}")
    db = json.loads(db_path.read_text())
    if not db:
        raise ProfileError("Empty kernel compilation database")
    commands = []
    for entry in db:
        args = entry.get("arguments") or shlex.split(entry["command"])
        if not entry["file"].endswith("/lib/string.c"):
            continue
        actual_compiler = _which(args[0], env)
        if not actual_compiler or Path(actual_compiler).resolve() != Path(compiler).resolve():
            continue
        if not all(flag in args for flag in profile["common_flags"] if flag != "-ffreestanding"):
            continue
        if profile.get("compiler_family") == "clang" and not all(flag in args for flag in compiler_flags(profile)):
            # A matched Clang binary/CPU is insufficient if model flags add a
            # different enum, packing or other semantic setting to the real TU.
            continue
        # A command's architecture-specific flags may be more detailed, but the
        # ABI-changing profile flags must be present before accepting it.
        abi_flags = [flag for flag in profile["flags"] if flag.startswith(("-mabi=", "-m64", "-m32", "-mfloat-abi=", "-mlittle-endian", "-mbig-endian"))]
        if not all(flag in args for flag in abi_flags):
            continue
        if profile["architecture"] == "um":
            # A matching host compiler/triple is insufficient: ordinary x86
            # kernel flags use a different code model and stack conventions.
            if not _uml_compile_flags_match(profile, args):
                continue
        prohibited = {"-fsigned-char", "-fno-short-wchar", "-fstrict-overflow", "-fstrict-aliasing", "-fno-wrapv"}
        prohibited.add("-m32" if profile["abi"]["bits"] == 64 else "-m64")
        if prohibited.intersection(args):
            continue
        if any(arg.startswith("-std=") and arg != "-std=gnu11" for arg in args):
            continue
        commands.append(entry)
    if not commands:
        raise ProfileError("No real kernel compile command matches the profile's semantic and ABI flags")
    generated = build / "include/generated/autoconf.h"
    if not generated.is_file():
        raise ProfileError("Missing generated kernel autoconf.h")
    result = {"config_sha256": _hash(config), "compilation_database_sha256": _hash(db_path),
            "autoconf_sha256": _hash(generated), "matched_commands": commands,
            "build_receipt_sha256": _hash(receipt_file), "source": receipt["source"],
            "build_path": str(build.resolve())}
    if llvm_validation is not None:
        result.update(llvm=receipt["llvm"], llvm_validation=llvm_validation)
    return result


def _configured_kernel_check(profile, receipt, root, output, kernel, *, env=None):
    """Compile the same fixtures using the genuine kernel TU include context."""
    entry = receipt["matched_commands"][0]
    args = entry.get("arguments") or shlex.split(entry["command"])
    source = root / "profiles/calibration.c"
    include = output / "configured-kernel-headers"
    include.mkdir()
    (include / "kernel-types.h").write_text("#include <linux/types.h>\n")
    command = [args[0]]
    skip = False
    for arg in args[1:]:
        if skip:
            skip = False
            continue
        if arg == "-o":
            skip = True
        elif arg == "-c" or arg.startswith("-Wp,-MMD,") or arg == entry["file"]:
            continue
        else:
            command.append(arg)
    definitions = [flag for flag in _defines(profile) if flag.startswith("-DFRAGMA_")]
    deps = output / "configured-kernel-calibration.d"
    run = _run([*command, "-I", str(include), *definitions, "-MD", "-MF", str(deps),
                "-c", str(source), "-o", str(output / "configured-kernel-calibration.o")],
               output, "configured-kernel-calibration", cwd=entry["directory"], env=env)
    if run["exit_code"] != 0:
        raise ProfileError("Configured kernel type/layout calibration failed: " + run["log"])
    dependency_paths = shlex.split(deps.read_text().replace("\\\n", "").split(":", 1)[1])
    hashes = {}
    snapshot = Path(receipt["source"]).resolve()
    for value in dependency_paths:
        path = Path(value)
        if not path.is_absolute():
            path = Path(entry["directory"]) / path
        path = path.resolve()
        hashes[str(path)] = _hash(path)
        if path.is_relative_to(snapshot):
            relative = path.relative_to(snapshot).as_posix()
            original = subprocess.run(["git", "-C", str(kernel), "show", profile["kernel_revision"] + ":" + relative], capture_output=True, timeout=30, env=_environment(env))
            if original.returncode or hashlib.sha256(original.stdout).hexdigest() != hashes[str(path)]:
                raise ProfileError("Configured calibration source/header drift: " + relative)
    return {"command": run["command"], "log": run["log"], "input_hashes": hashes}


def validate_profile(root, profile_or_id, *, kernel=None, frama_c=None, output=None,
                     run_calibration=True, kernel_build=None, env=None):
    """Generate fresh model evidence and return a structured, fail-closed result.

    status=passed concerns the declared model checks; level stays L0 without a
    genuine configured-build receipt. This API alone never awards L2 or L3.
    An explicit env controls all tool lookup, loader paths and subprocesses;
    ambient include-path injection is removed without mutating the caller.
    """
    root = Path(root).resolve()
    inherited_environment = env is None
    env = _environment(env)
    profiles = load_profiles(root)
    if isinstance(profile_or_id, str):
        if profile_or_id not in profiles:
            raise ProfileError("Unknown profile: " + profile_or_id)
        profile = profiles[profile_or_id]
    else:
        profile = copy.deepcopy(profile_or_id)
    validate_registration(profile)
    result = {"schema_version": 1, "profile_id": profile["id"],
              "architecture": profile["architecture"], "status": "blocked", "level": "L0",
              "checks": [], "gaps": list(profile.get("gaps", [])),
              "profile_sha256": _digest(profile), "kernel_revision": profile["kernel_revision"]}
    result["execution_environment"] = {"source": "inherited" if inherited_environment else "supplied",
        "settings": {key: env[key] for key in ("PATH", "LD_LIBRARY_PATH", "CAML_LD_LIBRARY_PATH", "OCAMLLIB",
                    "OCAMLPATH", "OPAM_SWITCH_PREFIX", "OPAMSWITCH", "FRAMAC_SHARE", "FRAMAC_PLUGIN",
                    "FRAMA_C", "FRAGMA_MACHDEP_PYTHON", "PYTHONPATH", "LIBRARY_PATH", "GCC_EXEC_PREFIX",
                    "COMPILER_PATH", "FRAGMA_MIPS32EL_MUSL_SYSROOT", "LC_ALL") if key in env},
        "excluded_include_variables": ["CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH"]}
    if profile.get("status") != "experimental":
        return result
    output = Path(output or tempfile.mkdtemp(prefix="fragma-profile-")).resolve()
    if output.exists() and any(output.iterdir()):
        raise ProfileError("Profile output directory is not empty; preserve it and select a fresh output: " + str(output))
    output.mkdir(parents=True, exist_ok=True)
    result["output"] = str(output)

    def check(name, passed, details=None):
        if isinstance(details, dict) and "log" in details:
            details = {key: value for key, value in details.items()
                       if key not in ("stdout", "stderr")}
        result["checks"].append({"name": name, "status": "passed" if passed else "failed",
                                 "details": details})
        if not passed:
            raise ProfileError(f"{name} failed: {details}")

    try:
        compiler = _which(profile["compiler"], env)
        if not compiler:
            raise ProfileError("Missing target compiler: " + profile["compiler"])
        version = _run([compiler, *compiler_version_args(profile)], output, "compiler-version", env=env)
        target_args = _compiler_target_args(profile)
        target = _run([compiler, *target_args, "-dumpmachine"], output, "compiler-target", env=env)
        full = _run([compiler, "--version"], output, "compiler-identification", env=env)
        observed_version = _compiler_version(profile, version["stdout"] +
                                            (version["stderr"] if profile.get("compiler_family") == "clang" else ""))
        result["compiler"] = {"path": compiler, "sha256": _hash(compiler),
                              "target": target["stdout"].strip(),
                              "version": observed_version,
                              "identification": full["stdout"].splitlines()[0] if full["stdout"] else ""}
        if profile.get("compiler_family") == "clang":
            result["compiler"].update(compiler_family="clang", target_args=target_args)
        check("compiler-version", version["exit_code"] == 0 and observed_version == profile["compiler_version"], result["compiler"])
        check("compiler-target", target["exit_code"] == 0 and target["stdout"].strip() == profile["compiler_target"]
              and (profile.get("compiler_family") != "clang" or not target["stderr"].strip()), result["compiler"])
        lock_path = root / "toolchain/lock.json"
        if not lock_path.is_file():
            raise ProfileError("Compiler capability requires toolchain/lock.json")
        tool_lock = json.loads(lock_path.read_text()).get("tools", {}).get(profile["compiler"])
        lock_matches = (_clang_lock_matches(profile, tool_lock, compiler) if profile.get("compiler_family") == "clang"
                        else bool(tool_lock) and tool_lock.get("version") == profile["compiler_version"]
                        and tool_lock.get("target") == profile["compiler_target"])
        check("compiler-toolchain-lock", lock_matches, tool_lock)
        result["compiler"]["toolchain_requirement"] = tool_lock
        if profile.get("compiler_family") == "clang":
            from . import toolchain
            observation = toolchain.probe(profile["compiler"], tool_lock, env)
            check("compiler-resource-identity", observation.get("status") == "ok" and
                  observation.get("path") == compiler and observation.get("sha256") == _hash(compiler), observation)
            result["compiler"]["resource_identity"] = observation
        candidate = frama_c or env.get("FRAMA_C") or _which("frama-c", env)
        if not candidate and inherited_environment:
            candidate = Path.home() / ".opam/fragma/bin/frama-c"
        if not candidate:
            raise ProfileError("Missing Frama-C executable in the supplied environment")
        fc = Path(_which(candidate, env) or candidate).resolve()
        if not fc.is_file():
            raise ProfileError("Missing Frama-C executable")
        version = _run([fc, "-version"], output, "frama-c-version", env=env)
        result["frama_c"] = {"path": str(fc), "version": version["stdout"].strip(), "sha256": _hash(fc)}
        check("frama-c-version", version["exit_code"] == 0 and version["stdout"].strip() == profile["frama_c_version"], result["frama_c"])
        if not kernel:
            raise ProfileError("Pinned kernel git repository is required for model calibration")
        check("architecture-roster", True, validate_roster(root, kernel, env=env))
        helper = fc.parent.parent / "lib/frama-c/lib/make_machdep/make_machdep.py"
        schema = fc.parent.parent / "share/frama-c/share/machdeps/machdep-schema.yaml"
        if not helper.is_file() or not schema.is_file():
            raise ProfileError("Pinned Frama-C compiler-based machdep generator/schema unavailable")
        check("machine-generator-identity", _hash(helper) == profile["machdep_generator_sha256"]
              and _hash(schema) == profile["machdep_schema_sha256"],
              {"helper_sha256": _hash(helper), "schema_sha256": _hash(schema)})
        flags = compiler_flags(profile)
        generator_flags, generator_header_evidence = _generator_headers(profile, root, compiler, output, env=env)
        if generator_header_evidence:
            result["generator_headers"] = generator_header_evidence
        machine = output / (profile["id"] + ".yaml")
        helper_python = env.get("FRAGMA_MACHDEP_PYTHON", "/usr/bin/python3")
        command = [helper_python, str(helper), "--compiler", profile["compiler"],
                   "--machdep-schema", str(schema), "--cpp-arch-flags=" + " ".join(flags),
                   "--compiler-flags=" + " ".join(["-c", *generator_flags]), "-o", str(machine)]
        generation = _run(command, output, "generate-machdep", timeout=180, env=env)
        result["generator"] = {"path": str(helper), "sha256": _hash(helper),
                               "schema_sha256": _hash(schema), "command": command,
                               "probe_input_hashes": {path.name: _hash(path) for path in sorted(helper.parent.iterdir())
                                                      if path.suffix in (".c", ".h")}}
        check("machine-generation", generation["exit_code"] == 0 and not generation["stderr"].strip(), generation)
        result["machdep_compiler_dialect"] = _normalize_machdep_compiler_dialect(profile, machine)
        check("machine-compiler-dialect", True, result["machdep_compiler_dialect"])
        values = check_machine_description(profile, machine)
        check("machine-fields", True, values)
        result["machdep"] = {"path": str(machine), "sha256": _hash(machine), "checked_fields": values}
        macro = _run([compiler, *flags, "-dM", "-E", "-x", "c", "-"], output, "compiler-macros", stdin="", env=env)
        check("compiler-predefined-macros", macro["exit_code"] == 0, {"log": macro["log"]})
        result["compiler"]["predefined_macros_sha256"] = hashlib.sha256(macro["stdout"].encode()).hexdigest()
        result["compiler"]["flags"] = flags
        includes, hashes = _export_headers(profile, kernel, output, env=env)
        result["header_hashes"] = hashes
        result["exported_header_inputs"] = [{"absolute_path": str(path.resolve()), "sha256": _hash(path)}
            for path in sorted(includes.rglob("*")) if path.is_file()]
        definitions = _defines(profile)
        source = root / "profiles/calibration.c"
        result["fixture_sha256"] = _hash(source)
        cflags = [*flags, "-nostdinc", "-I", str(includes), *definitions]
        compile_run = _run([compiler, *cflags, "-Werror", "-c", source, "-o", output / "calibration.o"], output, "compiler-calibration", env=env)
        check("compiler-kernel-types-layout", compile_run["exit_code"] == 0, compile_run)
        for name, flag in [("wrong-width", f'-DFRAGMA_POINTER_BYTES={4 if profile["abi"]["pointer_bytes"] != 4 else 8}'),
                           ("wrong-endian", f'-DFRAGMA_BYTE_ORDER={4321 if profile["abi"]["byte_order"] == "little" else 1234}')]:
            bad = _run([compiler, *cflags, flag, "-c", source, "-o", output / (name + ".o")], output, name, env=env)
            check("reject-" + name, bad["exit_code"] not in (0, None) and "static assertion failed" in bad["stderr"], {"log": bad["log"]})
        cpp = shlex.join([compiler, "-E", "-C", *flags])
        result["analysis"] = {**profile["analysis"], "machdep": str(machine),
                              "cpp_command": cpp, "cpp_extra_args": ["-nostdinc", "-D__KERNEL__"],
                              "calibration_cpp_extra_args": ["-nostdinc", "-I", str(includes), *definitions],
                              "compiler_flags": flags}
        fc_command = [str(fc), "-machdep", str(machine), "-cpp-command", cpp,
                      "-cpp-frama-c-compliant",
                      "-cpp-extra-args=" + shlex.join(result["analysis"]["calibration_cpp_extra_args"]),
                      *analysis_policy.analyzer_flags(profile["analysis"]), str(source)]
        parsing = _run(fc_command, output, "frama-c-parse", env=env)
        check("representative-parsing", parsing["exit_code"] == 0, parsing)
        if run_calibration:
            policy_audit = output / "analysis-policy-audit.json"
            eva = _run([*fc_command, "-audit-prepare", str(policy_audit),
                        "-eva", "-eva-slevel", "10"], output, "frama-c-eva", env=env)
            text = eva["stdout"] + eva["stderr"]
            assertions = re.search(r"(\d+) valid\s+(\d+) unknown\s+(\d+) invalid", text)
            passed = eva["exit_code"] == 0 and "0 alarms generated" in text and assertions is not None and assertions.groups() == ("7", "0", "0")
            check("eva-arithmetic-and-memory-byte-order", passed, eva)
            audited = json.loads(policy_audit.read_text())
            parameters = {key: value for key, value in audited.items() if key != "sources"}
            result["validated_model_policy"] = analysis_policy.validate_actual_model_policy(
                result["analysis"], eva["command"], parameters)
            result["analysis_policy_audit"] = {"path": str(policy_audit), "sha256": _hash(policy_audit),
                                               "parameters": parameters}
            check("analysis-runtime-policy", True, result["validated_model_policy"])
            # A correct preprocessor macro is not enough: alter only Frama-C's
            # memory byte order while keeping compiler macro definitions intact.
            # The memory observation must then contradict the expected byte.
            wrong_machine = output / (profile["id"] + "-wrong-endian.yaml")
            wrong_text, changes = re.subn(r"(?m)^little_endian: (true|false)$",
                                         "little_endian: " + ("false" if profile["abi"]["byte_order"] == "little" else "true"),
                                         machine.read_text())
            check("negative-model-construction", changes == 1, {"changes": changes})
            wrong_machine.write_text(wrong_text)
            wrong_command = list(fc_command)
            wrong_command[2] = str(wrong_machine)
            wrong_eva = _run([*wrong_command, "-eva", "-eva-slevel", "10"], output, "frama-c-wrong-endian", env=env)
            wrong_output = wrong_eva["stdout"] + wrong_eva["stderr"]
            check("reject-frama-c-wrong-memory-byte-order",
                  wrong_eva["exit_code"] == 0 and "byte_order_memory" in wrong_output and
                  re.search(r"Assertions\s+\d+ valid\s+\d+ unknown\s+1 invalid", wrong_output) is not None,
                  wrong_eva)
        else:
            raise ProfileError("Calibration was not executed; no passing model result can be issued")
        native = platform.machine() in ("x86_64", "amd64") and profile["architecture"] == "x86" and profile["abi"]["bits"] == 64
        result["runtime"] = {"status": "unavailable", "methods": profile["runtime_methods"],
                             "available_emulators": [m for m in profile["runtime_methods"] if m.startswith("qemu-") and _which(m, env)]}
        if native:
            executable = output / "calibration-native"
            build = _run([compiler, *cflags, "-O2", source, "-o", executable], output, "native-build", env=env)
            check("native-calibration-build", build["exit_code"] == 0, build)
            runtime = _run([executable], output, "native-run", env=env)
            check("native-calibration", runtime["exit_code"] == 0, runtime)
            result["runtime"] = {"status": "passed", "method": "native x86_64", "log": runtime["log"]}
        result["status"] = "passed"
        if kernel_build:
            receipt = _check_build(profile, kernel_build, kernel, compiler, env=env)
            receipt["calibration"] = _configured_kernel_check(profile, receipt, root, output, kernel, env=env)
            check("configured-kernel-build", True, receipt)
            result["build"] = receipt
            result["level"] = "L1"
            result["gaps"] = [g for g in result["gaps"] if not g.startswith("A generated kernel configuration")]
        else:
            result["gaps"].append("Model fixtures passed, but configured-kernel build evidence was not supplied: level remains L0.")
    except (ProfileError, OSError, subprocess.SubprocessError, KeyError, ValueError) as exc:
        result["status"] = "failed" if result["checks"] else "blocked"
        result["gaps"].append(str(exc))
    result["fingerprint"] = _digest({k: result.get(k) for k in ("profile_sha256", "compiler", "frama_c", "machdep", "machdep_compiler_dialect", "generator", "generator_headers", "header_hashes", "exported_header_inputs", "fixture_sha256", "build", "execution_environment", "analysis", "validated_model_policy", "analysis_policy_audit")})
    (output / "profile.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile")
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--capabilities", action="store_true")
    parser.add_argument("--kernel-build", type=Path)
    parser.add_argument("--frama-c")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.capabilities:
        result = compiler_capabilities(Path(__file__).resolve().parent.parent)
        if args.output:
            if args.output.exists():
                parser.error("Capabilities output already exists; choose a fresh file")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0
    if not args.profile or not args.kernel or not args.output:
        parser.error("Model calibration requires --profile, --kernel and --output")
    result = validate_profile(Path(__file__).resolve().parent.parent, args.profile,
                              kernel=args.kernel, kernel_build=args.kernel_build,
                              frama_c=args.frama_c, output=args.output)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
