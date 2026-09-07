"""Independent, bounded native witnesses for the frozen x86 string drivers.

This is deliberately not a general ACSL compiler or native kernel runner.
Only the reviewed driver hash and explicit local-object mappings are accepted.
No analyzer outcome is changed and no universal kernel proof is claimed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

from . import analysis_policy, inputs, provenance, sources
from .sources import sha256


class NativeError(ValueError):
    """A witness lacks the exact inputs or observations required by its scope."""


ASSERTION = re.compile(r"/\*@\s*assert\s+([A-Za-z_]\w*)\s*:\s*(.*?)\s*;\s*\*/", re.S)
INSERTION = re.compile(r"/\* FRAGMA_NATIVE_BEGIN_(\d+) \*/.*?/\* FRAGMA_NATIVE_END_\1 \*/", re.S)
IDENTIFIERS = {"result", "dest", "src", "input", "sizeof", "char", "const", "void"}
OPERATORS = {"(", ")", "[", "]", "*", "+", "-", "!", "==", "!=", "&&", "||", ">=", "<=", ">", "<"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def strict_json(text):
    def unique_object(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise NativeError("duplicate native JSON key")
            result[name] = value
        return result

    def invalid_constant(value):
        raise NativeError("non-JSON native numeric constant: " + value)

    return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def normalized(expression):
    return " ".join(expression.split())


def validate_expression(expression):
    """Allow only the reviewed side-effect-free scalar-expression subset."""
    tokens = provenance.tokenize(expression)
    for token in tokens:
        if token in IDENTIFIERS or token in OPERATORS:
            continue
        if re.fullmatch(r"[0-9]+", token) or re.fullmatch(r"'(?:[^'\\]|\\.)'", token):
            continue
        raise NativeError("unsupported native observation token: " + token)
    return expression


def render_driver(source, targets, mapping):
    """Insert observation calls; erasing them must restore original C tokens."""
    if hashlib.sha256(source.encode()).hexdigest() != mapping.get("driver_sha256"):
        raise NativeError("driver changed: native mappings require explicit re-review")
    if "FRAGMA_NATIVE_" in source:
        raise NativeError("original driver contains reserved instrumentation markers")
    cases = mapping.get("cases", [])
    if len(targets) != 8 or len(cases) != 8:
        raise NativeError("native scope is exactly the eight reviewed string entries")
    if [target["entry"] for target in targets] != [case["entry"] for case in cases]:
        raise NativeError("target order/entries disagree with native mapping")
    if len({target["id"] for target in targets}) != 8 or len({case["entry"] for case in cases}) != 8:
        raise NativeError("duplicate native target or entry")
    all_names = [name for target in targets for name in target["required_properties"]]
    matches = list(ASSERTION.finditer(source))
    if len(all_names) != len(set(all_names)) or [match[1] for match in matches] != all_names:
        raise NativeError("driver assertions do not exactly match required named properties")
    logical = {item["name"]: item for item in mapping.get("logical_mappings", [])}
    if len(logical) != len(mapping.get("logical_mappings", [])):
        raise NativeError("duplicate logical observation mapping")
    used_logical, insertions, properties, serial = set(), [], [], 0
    starts = [provenance.extract_function(source, target["entry"]).line for target in targets]
    if starts != sorted(starts):
        raise NativeError("driver entry ordering is ambiguous")
    by_name = {match[1]: match for match in matches}
    for index, (target, case) in enumerate(zip(targets, cases)):
        if target.get("role") != "calibration" or target.get("analysis") != "eva":
            raise NativeError("only EVA calibration targets have native corroboration")
        if target.get("functions") not in (["strlcat"], ["strnchr"]):
            raise NativeError("unreviewed native kernel function")
        negative = target.get("expected_invalid")
        names = target["required_properties"]
        if not isinstance(negative, list) or len(negative) != 1 or negative != names[-1:]:
            raise NativeError("exactly one terminal false-spec observation is required")
        allowed_state = ("fragma_native_append_state(result, dest, sizeof(dest), src, sizeof(src));"
                         if target["functions"] == ["strlcat"] else
                         "fragma_native_search_state(input, 0, result);" if case["entry"] == "fragma_string_zero_count" else
                         "fragma_native_search_state(input, sizeof(input), result);")
        if case.get("state_call") != allowed_state:
            raise NativeError("unreviewed native state observer")
        entry_properties = []
        for ordinal, name in enumerate(names):
            match = by_name[name]
            line = source.count("\n", 0, match.start()) + 1
            if line <= starts[index] or (index + 1 < len(starts) and line >= starts[index + 1]):
                raise NativeError("assertion is outside its declared entry")
            expression = normalized(match[2])
            kind, reason = "scalar-c-expression", "Same side-effect-free C predicate; ACSL null is converted to a C null pointer."
            if name in logical:
                rule = logical[name]
                if rule["required_entry"] != target["entry"] or normalized(rule["acsl"]) != expression:
                    raise NativeError("logical observation mapping changed scope or predicate")
                native = rule["c_expression"]
                kind, reason = rule["kind"], rule["justification"]
                used_logical.add(name)
            else:
                native = expression.replace("\\null", "((void *)0)")
            validate_expression(native)
            row = {"name": name, "file": target["driver"], "line": line,
                   "function": target["entry"], "acsl": expression,
                   "native_expression": native, "translation": kind, "justification": reason,
                   "expected": name not in negative}
            entry_properties.append(row)
            observation = f'fragma_native_expect("{name}", !!({native}), {int(row["expected"])});'
            if ordinal == 0:
                observation = allowed_state + "\n\t" + observation
            serial += 1
            snippet = f"/* FRAGMA_NATIVE_BEGIN_{serial} */\n\t{observation}\n\t/* FRAGMA_NATIVE_END_{serial} */"
            insertions.append((match.end(), snippet))
        properties.append(entry_properties)
    if used_logical != logical.keys():
        raise NativeError("stale or unused native logical mapping")
    instrumented = source
    for position, snippet in reversed(insertions):
        instrumented = instrumented[:position] + snippet + instrumented[position:]
    erased = INSERTION.sub("", instrumented)
    if erased != source or provenance.tokenize(erased) != provenance.tokenize(source):
        raise NativeError("native instrumentation changed original driver C")
    dispatch = ["int main(int argc, char **argv)", "{",
                "    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '7' || argv[1][1] != 0) return 64;",
                "    switch (argv[1][0] - '0') {"]
    for index, target in enumerate(targets):
        entry = target["entry"]
        dispatch += [f"    case {index}:", f'        fragma_native_begin("{entry}");',
                     f"        {entry}();", f'        fragma_native_end("{entry}");', "        break;"]
    dispatch += ["    }", "    return 0;", "}"]
    generated = '#include "native_sensitivity_support.h"\n' + instrumented + "\n" + "\n".join(dispatch) + "\n"
    return generated, properties


def validate_events(text, target, case, properties, returncode, stderr):
    """Require reached observations plus normal completion, not merely an exit."""
    if type(returncode) is not int or returncode != 0 or stderr:
        raise NativeError("native witness did not return cleanly")

    try:
        events = [strict_json(line) for line in text.splitlines()]
    except (json.JSONDecodeError, ValueError) as exc:
        raise NativeError("malformed native observation stream") from exc
    expected = [{"kind": "begin", "entry": target["entry"]}, case["state"]]
    expected += [{"kind": "property", "name": row["name"],
                  "observed": row["expected"], "expected": row["expected"]} for row in properties]
    expected += [{"kind": "normal-return", "entry": target["entry"]}]
    # Reject JSON integers impersonating Booleans (Python otherwise equates 0/False).
    for event in events:
        if not isinstance(event, dict):
            raise NativeError("native event is not an object")
        if event.get("kind") == "property" and any(type(event.get(key)) is not bool for key in ("observed", "expected")):
            raise NativeError("native property observations must be Booleans")
    # Canonical serialization preserves scalar types (6.0 != 6, true != 1)
    # while deliberately ignoring insignificant JSON object-key ordering.
    if json.dumps(events, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise NativeError("native states, named checks, order, or normal return did not match")
    return [{**row, "observed": event["observed"], "reached": True}
            for row, event in zip(properties, events[2:-1])]


def _file(path):
    return {"path": str(Path(path).resolve()), "sha256": sha256(Path(path))}


def _json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def model_identity(model):
    """Current configured identity, with no default for missing pointer policy."""
    return {"profile_id": model["profile_id"], "status": model["status"],
            "level": model["level"], "kernel_revision": model["kernel_revision"],
            "compiler": {key: model["compiler"][key] for key in ("sha256", "target", "version", "flags")},
            "machdep_sha256": model["machdep"]["sha256"],
            "checked_fields": model["machdep"]["checked_fields"],
            "analysis": analysis_policy.model_identity(model["analysis"]),
            "build": {key: model["build"][key] for key in ("config_sha256", "compilation_database_sha256",
                       "autoconf_sha256", "build_receipt_sha256")}}


def analysis_binding(model, targets):
    """Bind intended analyzer semantics; this is not an analyzer execution audit.

    The enclosing suite separately checks its actual command and correctness
    audit. Native observations never override any positive analyzer property.
    """
    if (not isinstance(targets, list) or not targets or
            any(not isinstance(target, dict) or not isinstance(target.get("id"), str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", target["id"]) for target in targets) or
            len({target["id"] for target in targets}) != len(targets)):
        raise NativeError("native analysis binding requires a distinct target inventory")
    return {"schema_version": 1, "model": analysis_policy.model_identity(model["analysis"]),
            "pipelines": [{"target_id": target["id"], "pipeline": analysis_policy.pipeline_identity(target)}
                          for target in targets]}


def command_plan(root, build, model, directory):
    """Independently reconstruct the exact bounded compiler/execute plan."""
    compiler = str(Path(build["compiler"]))
    flags = [flag for flag in model["compiler"]["flags"] if flag != "-ffreestanding"]
    flags += ["-O0", "-fno-builtin", "-fno-pie", "-fno-PIE", "-fno-stack-protector"]
    plan = {"locate-" + name: ([compiler, "-print-prog-name=" + name], directory)
            for name in ("cc1", "collect2", "as", "ld")}
    plan["compile-kernel"] = ([*inputs.command_without_outputs(inputs.compile_entry(build, "lib/string.c")),
        "-ffunction-sections", "-fdata-sections", "-MD", "-MF", str(directory / "kernel-headers.d"),
        "-MT", "fragma", "-c", str(root / "harness/string_calibration.c"), "-o", str(directory / "kernel-string.o")], Path(build["path"]))
    plan["compile-driver"] = ([compiler, *flags, "-I", str(root / "harness"), "-MD", "-MF",
        str(directory / "driver-headers.d"), "-MT", "fragma", "-c", str(directory / "driver.native.c"),
        "-o", str(directory / "driver.o")], directory)
    plan["link"] = ([compiler, "-m64", "-no-pie", "-Wl,--gc-sections", "-Wl,--wrap=memcpy",
        "-Wl,--version-script=" + str(root / "harness/native_sensitivity.symbols"),
        "-Wl,-Map=" + str(directory / "link.map"),
        *["-Wl,--trace-symbol=" + symbol for symbol in ("strlcat", "strnchr", "strlen")],
        str(directory / "driver.o"), str(directory / "kernel-string.o"), "-o", str(directory / "string-witness")], directory)
    for name, tool, options in (("defined-symbols", "nm", ["--defined-only", "--format=posix"]),
                               ("elf-header", "readelf", ["--file-header"]),
                               ("runtime-libraries", "ldd", [])):
        executable = shutil.which(tool, path=os.defpath)
        if not executable:
            raise NativeError("native inspection tool unavailable: " + tool)
        plan[name] = ([executable, *options, str(directory / "string-witness")], directory)
    for index in range(8):
        plan["case-" + str(index)] = ([str(directory / "string-witness"), str(index)], directory)
    return plan


def native_deviations(driver_flags):
    return {"kernel_added_flags": ["-ffunction-sections", "-fdata-sections"],
            "driver_hosted_flags": driver_flags,
            "memcpy_backend": "Genuine compiler inlines the builtin copy. --wrap=memcpy has no provided wrapper: unexpected external copy resolution must fail linking.",
            "symbol_visibility": "All executable definitions local; no kernel string interposition in the hosted observer's libc.",
            "trap": "Genuine configured kernel headers and trap retained; no out-of-domain inputs executed.",
            "observer": "Hosted observation code has userspace stack ABI; kernel object keeps configured kernel ABI.",
            "scope": "Eight concrete sequential normal-return executions; no universal theorem, caller coverage, or architecture-level promotion."}


def run_native(root, kernel, output, profile_path=None):
    root, kernel, output = Path(root).resolve(), Path(kernel).resolve(), Path(output).resolve()
    if platform.machine() != "x86_64" or sys.byteorder != "little":
        raise NativeError("native string corroboration requires a little-endian x86_64 host")
    if not output.is_relative_to(root / "build/string-sensitivity") or output == root / "build/string-sensitivity":
        raise NativeError("native output must be a new child of build/string-sensitivity")
    if output.exists():
        raise NativeError("native output already exists; evidence is never overwritten")
    output.mkdir(parents=True)
    evidence = {"schema_version": 1, "kind": "fragma-native-spec-sensitivity",
                "status": "running", "corroborated": False, "verified_kernel_functions": [],
                "cases": [], "commands": [], "issues": []}
    _json(output / "receipt.json", evidence)
    try:
        manifest_path = root / "config/string-sensitivity-targets.json"
        mapping_path = root / "config/string-native-observations.json"
        manifest, mapping = json.loads(manifest_path.read_text()), json.loads(mapping_path.read_text())
        revision = manifest["kernel_revision"]
        if type(mapping.get("schema_version")) is not int or mapping.get("schema_version") != 1 or mapping.get("profile") != "x86_64-gcc" or mapping.get("kernel_revision") != revision:
            raise NativeError("native mapping revision/profile/schema mismatch")
        targets = manifest["targets"]
        for target in targets:
            if (target.get("profile"), target.get("source"), target.get("harness"), target.get("specs"), target.get("driver")) != (
                    "x86_64-gcc", "lib/string.c", "harness/string_calibration.c", "harness/specs.sensitivity.h", mapping["driver"]):
                raise NativeError("native target inputs exceed reviewed scope")
        profile_path = Path(profile_path or root / "build/profile-checks/x86_64-gcc-configured/profile.json").resolve()
        model = json.loads(profile_path.read_text())
        build = inputs.load_build(root, "x86_64-gcc", revision)
        compiler = Path(build["compiler"])
        if (model.get("profile_id"), model.get("status"), model.get("level"), model.get("kernel_revision")) != (
                "x86_64-gcc", "passed", "L1", revision):
            raise NativeError("a validated configured x86 L1 model is required")
        if model["compiler"]["sha256"] != sha256(compiler) or model["build"]["build_receipt_sha256"] != build["receipt_sha256"]:
            raise NativeError("native compiler/build do not match configured model")
        if sha256(Path(model["machdep"]["path"])) != model["machdep"]["sha256"]:
            raise NativeError("configured machine description changed")
        policy_binding = analysis_binding(model, targets)
        original = (root / mapping["driver"]).read_text()
        generated, properties = render_driver(original, targets, mapping)
        gate = provenance.check_target({**targets[0], "functions": ["strlcat", "strnchr", "strlen"]},
                                       kernel, revision, root)
        if not gate["passed"]:
            raise NativeError("kernel source gate failed before native compilation")
        evidence["source_gate_before_compile"] = gate
        adapter = output / "driver.native.c"
        adapter.write_text(generated)
        bind_paths = [manifest_path, mapping_path, profile_path, Path(model["machdep"]["path"]),
                      root / mapping["driver"], root / targets[0]["harness"], root / targets[0]["specs"],
                      root / "harness/native_sensitivity_support.h", root / "harness/native_sensitivity.symbols",
                      Path(__file__), Path(analysis_policy.__file__), Path(inputs.__file__),
                      Path(provenance.__file__), Path(sources.__file__),
                      compiler, Path(build["path"]) / "fragma-build.json"]
        bindings = [_file(path) for path in bind_paths]
        evidence.update(kernel_revision=revision, profile_id="x86_64-gcc", model=model, build=build,
                        analysis_policy=policy_binding,
                        bindings=bindings, profile_receipt=_file(profile_path), mapping_sha256=sha256(mapping_path), adapter=_file(adapter),
                        driver_tokens_preserved=True, host={"machine": platform.machine(), "system": platform.system(),
                            "release": platform.release(), "byte_order": sys.byteorder})
        env = {"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(output)}

        def run(name, command, cwd=output, timeout=60):
            stdout, stderr = output / (name + ".stdout"), output / (name + ".stderr")
            record = inputs.run_recorded(command, cwd=cwd, env=env, log=stderr,
                                         stdout_file=stdout, timeout=timeout)
            record.update(stdout=_file(stdout), stderr=_file(stderr))
            evidence["commands"].append({"name": name, **record})
            return record, stdout.read_text(), stderr.read_text()

        def checked(name, command, cwd=output):
            record, stdout, stderr = run(name, command, cwd)
            if record["returncode"] != 0:
                raise NativeError(f"{name} failed; see {record['log']}")
            return stdout, stderr

        tool_inputs = [_file(Path(sys.executable))]
        for program in ("cc1", "collect2", "as", "ld"):
            value, _ = checked("locate-" + program, [str(compiler), "-print-prog-name=" + program])
            candidate = Path(value.strip())
            if not candidate.is_absolute():
                found = shutil.which(str(candidate), path=env["PATH"])
                if not found:
                    raise NativeError("cannot identify native compiler component: " + program)
                candidate = Path(found)
            tool_inputs.append(_file(candidate))

        original_entry = inputs.compile_entry(build, "lib/string.c")
        kernel_args = inputs.command_without_outputs(original_entry)
        section_flags = ["-ffunction-sections", "-fdata-sections"]
        kernel_object, driver_object = (output / name for name in ("kernel-string.o", "driver.o"))
        dep = output / "kernel-headers.d"
        checked("compile-kernel", [*kernel_args, *section_flags, "-MD", "-MF", str(dep), "-MT", "fragma",
                "-c", str(root / targets[0]["harness"]), "-o", str(kernel_object)], Path(build["path"]))
        kernel_inputs = inputs.input_receipts(root, kernel, revision, build,
                            inputs.dependency_paths(dep, Path(build["path"])))
        driver_flags = [flag for flag in model["compiler"]["flags"] if flag != "-ffreestanding"]
        driver_flags += ["-O0", "-fno-builtin", "-fno-pie", "-fno-PIE", "-fno-stack-protector"]
        checked("compile-driver", [str(compiler), *driver_flags, "-I", str(root / "harness"),
                "-MD", "-MF", str(output / "driver-headers.d"), "-MT", "fragma",
                "-c", str(adapter), "-o", str(driver_object)])
        hosted_inputs = [_file(path) for path in inputs.dependency_paths(output / "driver-headers.d", output)]
        binary = output / "string-witness"
        symbols = ["strlcat", "strnchr", "strlen"]
        _, link_trace = checked("link", [str(compiler), "-m64", "-no-pie", "-Wl,--gc-sections", "-Wl,--wrap=memcpy",
                "-Wl,--version-script=" + str(root / "harness/native_sensitivity.symbols"),
                "-Wl,-Map=" + str(output / "link.map"), *["-Wl,--trace-symbol=" + name for name in symbols],
                str(driver_object), str(kernel_object), "-o", str(binary)])
        nm = shutil.which("nm", path=env["PATH"])
        if not nm:
            raise NativeError("nm is required to check native symbol ownership")
        symbol_text, _ = checked("defined-symbols", [nm, "--defined-only", "--format=posix", str(binary)])
        tool_inputs.append(_file(Path(nm)))
        for name in symbols:
            if not re.search(r"^" + re.escape(name) + r" t ", symbol_text, re.M) or str(kernel_object) + ": definition of " + name not in link_trace:
                raise NativeError("native helper symbol not bound to expected object: " + name)
        readelf = shutil.which("readelf", path=env["PATH"])
        if not readelf:
            raise NativeError("readelf is required to record actual binary architecture")
        elf_header, _ = checked("elf-header", [readelf, "--file-header", str(binary)])
        if not all(fragment in elf_header for fragment in ("ELF64", "little endian", "Advanced Micro Devices X86-64", "EXEC (Executable file)")):
            raise NativeError("native executable does not match the x86-64 execution profile")
        tool_inputs.append(_file(Path(readelf)))
        ldd = shutil.which("ldd", path=env["PATH"])
        if not ldd:
            raise NativeError("ldd is required to record the hosted observation runtime")
        libraries, _ = checked("runtime-libraries", [ldd, str(binary)])
        tool_inputs.append(_file(Path(ldd)))
        shared_paths = sorted(set(re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)\s+\(", libraries, re.M)))
        if not shared_paths:
            raise NativeError("hosted runtime libraries were not identified")
        runtime_inputs = [_file(Path(path)) for path in shared_paths]
        link_paths = re.findall(r"^LOAD (/[^\n]+)$", (output / "link.map").read_text(), re.M)
        if not link_paths:
            raise NativeError("native link input inventory is empty")
        link_inputs = [_file(Path(path)) for path in sorted(set(link_paths))]
        evidence.update(original_compile_command=original_entry, kernel_inputs=kernel_inputs,
                        hosted_inputs=hosted_inputs, runtime_inputs=runtime_inputs,
                        tool_inputs=tool_inputs, link_inputs=link_inputs, python_version=sys.version,
                        binary=_file(binary), symbol_owners={name: str(kernel_object) for name in symbols},
                        native_deviations=native_deviations(driver_flags))
        for index, (target, case, rows) in enumerate(zip(targets, mapping["cases"], properties)):
            gate = provenance.check_target(target, kernel, revision, root)
            if not gate["passed"]:
                raise NativeError("kernel source gate failed")
            process, stdout, stderr = run("case-" + str(index), [str(binary), str(index)], timeout=5)
            observations = validate_events(stdout, target, case, rows, process["returncode"], stderr)
            evidence["cases"].append({"target_id": target["id"], "target_sha256": digest(target),
                "entry": target["entry"], "source_gate": gate, "process": process, "state": case["state"],
                "properties": observations, "normal_return": True, "status": "native-corroborated"})
        tracked = [*bindings, *hosted_inputs, *runtime_inputs, *tool_inputs, *link_inputs,
                   *[{"path": item["absolute_path"], "sha256": item["sha256"]} for item in kernel_inputs]]
        changed = [item for item in tracked if not Path(item["path"]).is_file() or sha256(Path(item["path"])) != item["sha256"]]
        if changed:
            evidence["changed_inputs"] = changed
            raise NativeError("native witness input changed during the run")
        evidence.update(status="native-corroborated", corroborated=True, changed_inputs=[])
    except (NativeError, OSError, ValueError, KeyError) as exc:
        evidence.update(status="incomplete", corroborated=False)
        evidence["issues"].append(str(exc))
    evidence["artifact_hashes"] = {str(path.relative_to(output)): sha256(path)
        for path in sorted(output.rglob("*")) if path.is_file() and path.name != "receipt.json"}
    _json(output / "receipt.json", evidence)
    return evidence


def validate_native_receipt(root, kernel, target, revision, freshmodel, build, receipt_path):
    """Revalidate one requested calibration case; no execution or status rewrite.

The receipt is inspectable local evidence, not a signed execution attestation.
The caller must still gate its fresh EVA source/model/assumptions and compare
the exact reported property identity. All returned files need a final drift
check before accepting the enclosing regression run.
"""
    root, kernel, path = Path(root).resolve(), Path(kernel).resolve(), Path(receipt_path).resolve()
    if not path.is_relative_to(root / "build/string-sensitivity") or path.name != "receipt.json":
        raise NativeError("native receipt is not an explicit local string-calibration receipt")
    if target.get("role") != "calibration" or target.get("analysis") != "eva":
        raise NativeError("native evidence is scoped only to EVA calibration")
    try:
        evidence = strict_json(path.read_text())
        if type(evidence.get("schema_version")) is not int or evidence.get("corroborated") is not True:
            raise NativeError("native receipt schema/corroboration flag is malformed")
        if (evidence.get("schema_version"), evidence.get("kind"), evidence.get("status"),
                evidence.get("corroborated"), evidence.get("kernel_revision"), evidence.get("profile_id")) != (
                1, "fragma-native-spec-sensitivity", "native-corroborated", True, revision, target["profile"]):
            raise NativeError("native receipt is incomplete or has the wrong identity")
        if evidence.get("issues") or evidence.get("changed_inputs") or evidence.get("verified_kernel_functions") != []:
            raise NativeError("native receipt has unresolved issues or exceeds its scope")
        if digest(model_identity(evidence["model"])) != digest(model_identity(freshmodel)):
            raise NativeError("native receipt does not match fresh configured model")
        if freshmodel.get("status") != "passed" or freshmodel.get("level") != "L1":
            raise NativeError("fresh configured L1 model required for native corroboration")
        if evidence["build"]["receipt_sha256"] != build["receipt_sha256"] or evidence["build"]["files"] != build["files"]:
            raise NativeError("native receipt does not match fresh build")
        expected_host = {"machine": platform.machine(), "system": platform.system(),
                         "release": platform.release(), "byte_order": sys.byteorder}
        if evidence.get("host") != expected_host or expected_host["machine"] != "x86_64" or expected_host["byte_order"] != "little":
            raise NativeError("native host execution profile differs")
        manifest_path, mapping_path = root / "config/string-sensitivity-targets.json", root / "config/string-native-observations.json"
        manifest, mapping = json.loads(manifest_path.read_text()), json.loads(mapping_path.read_text())
        targets = manifest["targets"]
        if type(mapping.get("schema_version")) is not int or mapping["schema_version"] != 1 or mapping.get("profile") != "x86_64-gcc" or manifest["kernel_revision"] != revision or mapping["kernel_revision"] != revision:
            raise NativeError("native mapping source revision differs")
        for item in targets:
            if (item.get("profile"), item.get("source"), item.get("harness"), item.get("specs"), item.get("driver")) != (
                    "x86_64-gcc", "lib/string.c", "harness/string_calibration.c", "harness/specs.sensitivity.h", mapping["driver"]):
                raise NativeError("native manifest target input scope differs")
        policy_binding = analysis_binding(freshmodel, targets)
        if digest(evidence.get("analysis_policy")) != digest(policy_binding):
            raise NativeError("native receipt has missing or changed semantic/pipeline binding")
        candidates = [index for index, item in enumerate(targets) if item["id"] == target["id"]]
        if len(candidates) != 1 or digest(targets[candidates[0]]) != digest(target):
            raise NativeError("native target differs from current target manifest")
        index = candidates[0]
        generated, all_properties = render_driver((root / mapping["driver"]).read_text(), targets, mapping)
        if evidence.get("driver_tokens_preserved") is not True:
            raise NativeError("native driver token-preservation evidence missing")
        directory = path.parent
        if (directory / "driver.native.c").read_text() != generated:
            raise NativeError("native adapter does not regenerate from current driver/mappings")
        if evidence["adapter"]["path"] != str(directory / "driver.native.c") or evidence["binary"]["path"] != str(directory / "string-witness"):
            raise NativeError("native adapter/binary paths are not bound to receipt")
        tracked = {}

        def track(filename, expected):
            filename = Path(filename)
            if not filename.is_absolute() or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise NativeError("malformed native input hash record")
            resolved = str(filename.resolve())
            if resolved in tracked and tracked[resolved] != expected:
                raise NativeError("conflicting native input hash records")
            if not filename.is_file() or sha256(filename) != expected:
                raise NativeError("native input/artifact changed: " + str(filename))
            tracked[resolved] = expected

        for field in ("bindings", "hosted_inputs", "runtime_inputs", "tool_inputs", "link_inputs"):
            records = evidence.get(field)
            if not isinstance(records, list) or not records:
                raise NativeError("missing native input inventory: " + field)
            for item in records:
                track(item["path"], item["sha256"])
        for item in evidence["kernel_inputs"]:
            track(item["absolute_path"], item["sha256"])
        artifacts = evidence.get("artifact_hashes")
        if not isinstance(artifacts, dict) or not artifacts:
            raise NativeError("native artifact inventory missing")
        actual_artifacts = {str(item.relative_to(directory)) for item in directory.rglob("*")
                            if item.is_file() and item.name != "receipt.json"}
        if set(artifacts) != actual_artifacts:
            raise NativeError("native artifact inventory is incomplete or changed")
        for filename, expected in artifacts.items():
            item = (directory / filename).resolve()
            if not item.is_relative_to(directory) or Path(filename).is_absolute():
                raise NativeError("native artifact escapes its receipt directory")
            track(item, expected)
        for field in ("adapter", "binary", "profile_receipt"):
            track(evidence[field]["path"], evidence[field]["sha256"])
        if digest(strict_json(Path(evidence["profile_receipt"]["path"]).read_text())) != digest(evidence["model"]):
            raise NativeError("native profile metadata differs from its bound source receipt")

        def exact_inventory(field, paths):
            wanted = {str(Path(filename).resolve()): sha256(Path(filename)) for filename in paths}
            records = evidence[field]
            actual = {item["path"]: item["sha256"] for item in records}
            if not wanted or actual != wanted or len(records) != len(actual):
                raise NativeError("native input inventory is incomplete or contradictory: " + field)

        mandatory_bindings = [manifest_path, mapping_path, Path(__file__).resolve(), Path(analysis_policy.__file__), Path(inputs.__file__),
                              Path(provenance.__file__), Path(sources.__file__), root / target["harness"],
                              root / target["driver"], root / target["specs"],
                              root / "harness/native_sensitivity_support.h", root / "harness/native_sensitivity.symbols",
                              Path(build["compiler"]), Path(build["path"]) / "fragma-build.json",
                              Path(evidence["profile_receipt"]["path"]), Path(evidence["model"]["machdep"]["path"])]
        exact_inventory("bindings", mandatory_bindings)
        if evidence.get("mapping_sha256") != sha256(mapping_path):
            raise NativeError("native mapping digest metadata differs")
        kernel_paths = inputs.dependency_paths(directory / "kernel-headers.d", Path(build["path"]))
        expected_kernel = inputs.input_receipts(root, kernel, revision, build, kernel_paths)
        if not expected_kernel or evidence["kernel_inputs"] != expected_kernel:
            raise NativeError("native kernel dependencies differ from retained compiler dependency file")
        exact_inventory("hosted_inputs", inputs.dependency_paths(directory / "driver-headers.d", directory))
        link_paths = re.findall(r"^LOAD (/[^\n]+)$", (directory / "link.map").read_text(), re.M)
        exact_inventory("link_inputs", link_paths)
        libraries = (directory / "runtime-libraries.stdout").read_text()
        runtime_paths = re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)\s+\(", libraries, re.M)
        exact_inventory("runtime_inputs", runtime_paths)
        tool_paths = [Path(sys.executable)]
        for name in ("cc1", "collect2", "as", "ld"):
            filename = Path((directory / ("locate-" + name + ".stdout")).read_text().strip())
            if not filename.is_absolute():
                found = shutil.which(str(filename), path=os.defpath)
                if not found:
                    raise NativeError("native compiler component no longer resolves")
                filename = Path(found)
            tool_paths.append(filename)
        tool_paths += [Path(shutil.which(name, path=os.defpath) or "") for name in ("nm", "readelf", "ldd")]
        exact_inventory("tool_inputs", tool_paths)
        if evidence.get("python_version") != sys.version:
            raise NativeError("native generator Python runtime differs")
        if evidence.get("original_compile_command") != inputs.compile_entry(build, "lib/string.c"):
            raise NativeError("native original compile-command receipt differs")
        plan = command_plan(root, build, evidence["model"], directory)
        commands = evidence.get("commands")
        if not isinstance(commands, list) or [item["name"] for item in commands] != list(plan):
            raise NativeError("native command inventory is missing, duplicate, or reordered")
        command_records = {item["name"]: item for item in commands}
        for name, (argv, cwd) in plan.items():
            record = command_records[name]
            if record["argv"] != argv or record["cwd"] != str(cwd) or type(record["returncode"]) is not int or record["returncode"] != 0 or record["timed_out"] is not False:
                raise NativeError("native command does not match reconstructed plan: " + name)
            for kind in ("stdout", "stderr"):
                expected_file = directory / (name + "." + kind)
                if record[kind] != _file(expected_file):
                    raise NativeError("native command output metadata differs")
            if record["log"] != str(directory / (name + ".stderr")) or record["log_sha256"] != sha256(Path(record["log"])):
                raise NativeError("native command stderr receipt differs")
        driver_flags = [flag for flag in evidence["model"]["compiler"]["flags"] if flag != "-ffreestanding"]
        driver_flags += ["-O0", "-fno-builtin", "-fno-pie", "-fno-PIE", "-fno-stack-protector"]
        if evidence.get("native_deviations") != native_deviations(driver_flags):
            raise NativeError("native deviation metadata does not match command policy")
        elf_header = (directory / "elf-header.stdout").read_text()
        if not all(value in elf_header for value in ("ELF64", "little endian", "Advanced Micro Devices X86-64", "EXEC (Executable file)")):
            raise NativeError("native ELF execution profile differs")
        gate = provenance.check_target(target, kernel, revision, root)
        if not gate["passed"]:
            raise NativeError("fresh native source gate failed")
        closure = provenance.check_target({**target, "functions": ["strlcat", "strnchr", "strlen"]}, kernel, revision, root)
        recorded_closure = evidence.get("source_gate_before_compile", {})
        if not closure["passed"] or recorded_closure.get("passed") is not True or digest(recorded_closure.get("functions")) != digest(closure["functions"]) or recorded_closure.get("harness") != closure["harness"] or recorded_closure.get("source", {}).get("sha256") != closure["source"]["sha256"]:
            raise NativeError("native precompile source/dependency closure gate differs")
        records = evidence.get("cases")
        if not isinstance(records, list) or len(records) != 8 or [item["target_id"] for item in records] != [item["id"] for item in targets]:
            raise NativeError("native case inventory is missing, duplicate, or reordered")
        case = records[index]
        if case["target_sha256"] != digest(target) or case["entry"] != target["entry"] or case.get("normal_return") is not True or case.get("status") != "native-corroborated":
            raise NativeError("native case target/entry/normal-return mismatch")
        if case["source_gate"].get("passed") is not True or case["source_gate"]["harness"]["sha256"] != gate["harness"]["sha256"] or case["source_gate"]["source"]["sha256"] != gate["source"]["sha256"]:
            raise NativeError("native source identity differs from fresh source gate")
        process = case["process"]
        if process != {key: value for key, value in command_records["case-" + str(index)].items() if key != "name"}:
            raise NativeError("native case process differs from command inventory")
        if process["argv"] != [str(directory / "string-witness"), str(index)] or process["cwd"] != str(directory) or process["timed_out"] is not False:
            raise NativeError("native execution command or timeout status differs")
        for key in ("stdout", "stderr"):
            item = process[key]
            if item["path"] != str(directory / f"case-{index}.{key}"):
                raise NativeError("native observation output path differs")
            track(item["path"], item["sha256"])
        observed = validate_events(Path(process["stdout"]["path"]).read_text(), target, mapping["cases"][index],
                                  all_properties[index], process["returncode"], Path(process["stderr"]["path"]).read_text())
        if digest(case["properties"]) != digest(observed) or digest(case["state"]) != digest(mapping["cases"][index]["state"]):
            raise NativeError("native observation metadata differs from actual output")
        kernel_object = directory / "kernel-string.o"
        symbol_text = (directory / "defined-symbols.stdout").read_text()
        link_trace = (directory / "link.stderr").read_text()
        for symbol in ("strlcat", "strnchr", "strlen"):
            if evidence["symbol_owners"].get(symbol) != str(kernel_object) or str(kernel_object) + ": definition of " + symbol not in link_trace or not re.search(r"^" + symbol + r" t ", symbol_text, re.M):
                raise NativeError("native helper symbol ownership evidence differs")
        track(path, sha256(path))
        return {"status": "passed", "kind": "native-specification-calibration", "target_id": target["id"],
                "profile": target["profile"], "source": target["source"], "entry": target["entry"],
                "kernel_revision": revision, "source_root": str(root), "target_sha256": digest(target),
                "receipt": _file(path), "properties": observed, "analysis_policy": policy_binding,
                "tracked_files": [{"absolute_path": filename, "sha256": expected} for filename, expected in sorted(tracked.items())]}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, NativeError):
            raise
        raise NativeError("cannot validate native receipt: " + str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--kernel-tree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_native(args.root, args.kernel_tree, args.output, args.profile)
    except (NativeError, OSError) as exc:
        parser.exit(2, str(exc) + "\n")
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "issues": result["issues"]}))
    return 0 if result["corroborated"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
