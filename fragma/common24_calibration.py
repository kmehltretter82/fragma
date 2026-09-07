"""Genuine-header, fixed-input common24 compiler sensitivity.

This module does not issue architecture levels, native evidence, runtime
reachability, or corroboration for ambiguous EVA outcomes. Compiler observations
do not approve the suite's proof assumptions or diagnostics. Every command
compiles or preprocesses fixed source; no emitted object or kernel program runs.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
import re

from fragma import analysis_policy, frontend_policy, inputs, integrity, profiles, provenance, replay


class CalibrationError(ValueError):
    pass


KIND = "fragma-common24-compiler-sensitivity"
STATUS = "compiler-calibration-passed"
SOURCE_SHA256 = "84a5ffce5e314761a57769837f13550323d4bfbaa7e9126cecf70a029fac157d"
SOURCE = "common/annotated/compiler-calibration.c"
ENVIRONMENT_POLICY = "common24-compiler-clean-v1"
CASES = (
    "decode_be", "decode_le", "store_be_0", "store_be_1", "store_be_2",
    "store_le_0", "store_le_1", "store_le_2", "roundtrip_be", "roundtrip_le",
    "maximum_be_0", "maximum_be_1", "maximum_be_2", "maximum_roundtrip",
    "discarded_le_0", "discarded_le_1", "discarded_le_2", "discarded_roundtrip",
    "memory_0", "memory_1", "memory_2", "memory_3",
)
CASE_LINES = dict(zip(CASES, (46, 47, *range(50, 58), *range(59, 63),
                              *range(64, 72)), strict=True))
CLANG_NOTE_MESSAGES = (
    "expanded from macro 'FRAGMA_CHECK'",
    "expanded from macro 'BUILD_BUG_ON_MSG'",
    "expanded from macro 'compiletime_assert'",
    "expanded from macro '_compiletime_assert'",
    "expanded from macro '__compiletime_assert'",
    "expanded from here",
)
HELPERS = ("__get_unaligned_be24", "__get_unaligned_le24",
           "__put_unaligned_be24", "__put_unaligned_le24")
BOUNDARY = {"observation": "compiler-eliminated-fixed-input-predicates",
            "native_executed": False, "analyzer_executed": False,
            "runtime_reachability": False, "full_domain_proof": False,
            "ambiguous_eva_corroboration": False, "architecture_level_awarded": None}


def require(value, message):
    if not value:
        raise CalibrationError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def same(left, right):
    return canonical(left) == canonical(right)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def sha(path):
    path = Path(path)
    # Compiler invocation paths may be symlinks, but their targets and every
    # other hashed input must be regular files before opening them.
    require(path.is_file(), "missing or non-regular input: " + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path):
    return {"absolute_path": str(Path(path).absolute()), "sha256": sha(path)}


def read_json(path):
    return replay.strict_json(Path(path).read_text())


def local(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
            "expected an explicit relative project path")
    require(".." not in Path(relative).parts, "parent path is not permitted")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), "missing or escaping project input")
    return path


def frontend_options(target):
    """Use the one frozen shared schema/mapping; never infer an architecture."""
    try:
        result = frontend_policy.cpp_arguments(target)
    except ValueError as exc:
        raise CalibrationError(str(exc)) from exc
    require(bool(result), "compiler calibration requires an explicit frontend policy")
    return result


def identity(target, *, root=None):
    """Closed setting: no arbitrary source, compiler flags or native provider."""
    require(isinstance(target, dict), "calibration target must be an object")
    if "compiler_calibration" not in target:
        return None
    setting = target["compiler_calibration"]
    require(isinstance(setting, dict) and set(setting) == {"kind", "source"}
            and setting["kind"] == "common24-fixed22" and setting["source"] == SOURCE,
            "missing or unknown compiler-calibration setting/source")
    require(frontend_policy.identity(target, root=root) is not None
            and target.get("role") == "proof" and target.get("analysis") == "wp"
            and target.get("functions") == list(HELPERS), "compiler calibration requires the common24 WP scope")
    if root is not None:
        source = Path(root).resolve() / SOURCE
        require(source.is_file() and not source.is_symlink() and source == source.resolve()
                and sha(source) == SOURCE_SHA256, "reviewed calibration source changed or is missing")
    return dict(setting)


def required_files(target):
    return [] if identity(target) is None else [SOURCE, "fragma/common24_calibration.py",
                                               "fragma/common24_controls.py", "fragma/elf.py"]


def compiler_environment(output):
    """Compiler-only environment, independent of parent search paths/hooks."""
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC", "TMPDIR": str(Path(output).resolve())}


def environment_identity(output):
    values = compiler_environment(output)
    return {"schema_version": 1, "policy": ENVIRONMENT_POLICY,
            "values": values, "sha256": digest(values)}


def review_identity(target):
    setting = identity(target)
    return None if setting is None else {"kind": KIND, "setting": setting,
        "environment_policy": ENVIRONMENT_POLICY, "cases": list(CASES),
        "fixture_controls": ["wrong-type", "wrong-inline"]}


def assertion_symbols(expanded):
    """Derive exact error identities from the positive calibration definition.

    Genuine headers may already consume __COUNTER__. No architecture offset or
    negative diagnostic supplies the expected identity. The caller authenticates
    this positive stream's command, bytes and source/dependency closure.
    """
    require(isinstance(expanded, str), "positive preprocessing must be decoded text")
    function = provenance.extract_function(expanded, "fragma_common24_compiler_calibration")
    tokens = function.tokens
    require(function.declaration_prefix == ("void",)
            and tokens[:5] == ("fragma_common24_compiler_calibration", "(", "void", ")", "{"),
            "calibration function declaration changed")
    declarations, uses = [], []
    prefix = "__compiletime_assert_"
    for index, token in enumerate(tokens):
        if not token.startswith(prefix):
            continue
        require(re.fullmatch(r"__compiletime_assert_(?:0|[1-9][0-9]*)", token) is not None,
                "noncanonical calibration assertion symbol")
        if tokens[index + 1:index + 4] == ("(", "void", ")"):
            require(index >= 8 and index + 10 < len(tokens), "incomplete assertion declaration")
            case = tokens[index + 10][1:-1]
            require(case in CASES, "unknown calibration assertion label")
            before = ("__attribute__", "(", "(", "__noreturn__", ")", ")", "extern", "void")
            after = ("(", "void", ")", "__attribute__", "(", "(", "__error__", "(",
                     '"fragma common24 "', '"' + case + '"', ")", ")", ")", ";")
            require(tokens[index - len(before):index] == before
                    and tokens[index + 1:index + 1 + len(after)] == after,
                    "calibration assertion declaration/error attribute changed")
            declarations.append((case, token))
            uses.append((token, "declaration"))
        else:
            require(tokens[index + 1:index + 4] == ("(", ")", ";"),
                    "calibration assertion symbol is not a direct call")
            uses.append((token, "call"))
    require([case for case, _ in declarations] == list(CASES)
            and tokens.count('"fragma common24 "') == len(CASES)
            and tokens.count("__error__") == len(CASES),
            "missing, extra or reordered calibration assertion declarations")
    numbers = [int(symbol[len(prefix):]) for _, symbol in declarations]
    require(numbers == list(range(numbers[0], numbers[0] + len(CASES))),
            "calibration assertion symbols are not unique and consecutive")
    expected_uses = [(symbol, kind) for _, symbol in declarations for kind in ("declaration", "call")]
    require(uses == expected_uses, "calibration assertion declaration/call correspondence differs")
    return dict(declarations)


def validate_wrong(case, command, stderr, stdout, object_exists, *, symbol,
                   compiler_family="gcc"):
    require(case in CASES, "unknown fixed-input observation")
    require(isinstance(symbol, str)
            and re.fullmatch(r"__compiletime_assert_(?:0|[1-9][0-9]*)", symbol) is not None,
            "explicit positive-preprocessing assertion symbol required")
    require(type(command.get("returncode")) is int and command["returncode"] == 1
            and command.get("timed_out") is False and object_exists is False and stdout == "",
            "negative control process/output mismatch")
    require(compiler_family in {"gcc", "clang"}, "unknown compiler diagnostic family")
    require(isinstance(stderr, str) and not any(char in stderr for char in ("\x1b", "\x00", "\r")),
            "unsupported diagnostic encoding")
    if compiler_family == "gcc":
        diagnostics = re.findall(r"^[^\r\n]*?\b(fatal error|error|warning):[ \t]*(.*)$",
                                 stderr, re.M | re.I)
        expected = ("call to '" + symbol
                    + "' declared with attribute error: fragma common24 " + case)
        require(diagnostics == [("error", expected)],
                "negative lacks its sole intended GCC diagnostic")
        return

    argv = command.get("argv")
    require(isinstance(argv, list) and argv.count("-c") == 1 and
            argv.index("-c") + 1 < len(argv), "Clang negative lacks its source command")
    source = argv[argv.index("-c") + 1]
    observed, summaries = [], []
    lines = stderr.splitlines()
    for index, line in enumerate(lines):
        diagnostic = re.fullmatch(
            r"(.+):(\d+):(\d+): (fatal error|error|warning|note): (.*)", line)
        if diagnostic:
            observed.append((diagnostic[1], int(diagnostic[2]), int(diagnostic[3]),
                             diagnostic[4], diagnostic[5]))
        elif summary := re.fullmatch(r"(\d+) errors? generated\.", line):
            summaries.append((index, int(summary[1])))
        else:
            require(line == "" or re.fullmatch(r"\s*\d+\s*\|.*", line) or
                    re.fullmatch(r"\s*\|[\s^~]*", line),
                    "unexpected Clang diagnostic continuation")
    errors = [row for row in observed if row[3] != "note"]
    notes = [row for row in observed if row[3] == "note"]
    expected = ("call to '" + symbol
                + "' declared with 'error' attribute: fragma common24 " + case)
    require(errors == [(source, CASE_LINES[case], 2, "error", expected)],
            "negative lacks its sole intended Clang diagnostic")
    require([row[4] for row in notes] == list(CLANG_NOTE_MESSAGES),
            "Clang macro-expansion diagnostic chain differs")
    require(summaries == [(len(lines) - 1, 1)],
            "Clang diagnostic summary count or position differs")


def optimization_mode(base_argv):
    """Recognize a sole genuine supported mode; never rewrite compiler flags."""
    require(isinstance(base_argv, list) and all(isinstance(arg, str) for arg in base_argv),
            "compiler argv must be an explicit string list")
    modes = [arg for arg in base_argv if arg.startswith("-O")]
    require(modes in (["-O2"], ["-Os"]), "fixed optimization context required")
    return modes[0]


def context(root, target, model, build, revision):
    """Reconstruct current identity, never import an old stage receipt as trust."""
    require(target.get("source") == "include/linux/unaligned.h"
            and target.get("input_mode") == "standalone"
            and same(target.get("functions"), list(HELPERS)), "not the exact four-helper scope")
    require(model.get("status") == "passed" and model.get("level") == "L1"
            and model.get("kernel_revision") == revision
            and model.get("profile_id") == target.get("profile") == build.get("profile_id"),
            "model/build/profile mismatch")
    analysis_policy.model_identity(model["analysis"])
    registered = profiles.load_profiles(root).get(target["profile"])
    require(registered is not None and profiles._digest(registered) == model.get("profile_sha256"),
            "model does not bind the current registered profile")
    def read_policy(path, expected):
        require(sha(path) == expected, "model policy audit changed")
        return Path(path).read_text()
    require(replay.model_policy_observation(model, read_policy).get("actual_pointer_formation") == "true",
            "current independently audited model policy required")
    setting = identity(target, root=root)
    require(setting is not None, "missing compiler-calibration setting")
    source = local(root, setting["source"])
    require(sha(source) == SOURCE_SHA256, "reviewed fixed-input calibration source changed")
    fixture = local(root, target.get("kernel_model_check"))
    current_build = inputs.load_build(root, target["profile"], revision)
    require(same(current_build, build), "supplied build is not the current genuine build")
    entry = inputs.compile_entry(build, "lib/string.c")
    require(entry in model["build"]["matched_commands"], "genuine command not bound by model")
    base = inputs.command_without_outputs(entry)
    require(base[0] == model["compiler"]["path"] and sha(base[0]) == model["compiler"]["sha256"],
            "compiler command/digest mismatch")
    optimization_mode(base)
    require(not any(arg.startswith(("-flto", "-fwhole-program", "-D__OPTIMIZE__", "-U__OPTIMIZE__",
                "-D__OPTIMIZE_SIZE__", "-U__OPTIMIZE_SIZE__",
                "-DFRAGMA_COMMON24", "-UFRAGMA_COMMON24", "-DBUILD_BUG", "-UBUILD_BUG",
                "-D__compiletime", "-U__compiletime", "-fplugin", "-specs", "-wrapper")) for arg in base),
            "unexpected control/override in genuine command")
    require(not any(arg in ("-D", "-U") and index + 1 < len(base)
                    and base[index + 1].startswith(("__OPTIMIZE__", "__OPTIMIZE_SIZE__"))
                    for index, arg in enumerate(base)),
            "unexpected optimization macro override in genuine command")
    yaml = Path(model["machdep"]["path"])
    require(sha(yaml) == model["machdep"]["sha256"], "changed machine description")
    little = re.findall(r"^little_endian:\s*(true|false)\s*$", yaml.read_text(), re.M)
    require(little in (["true"], ["false"]), "missing/ambiguous model byte order")
    tracked = integrity.profile_records(root, model)
    tracked += [record(path) for path in (source, fixture, Path(__file__).resolve())]
    tracked += [record(path) for path in sorted({*root.glob("fragma/*.py"), *root.glob("config/*.json")})]
    tracked += [record(local(root, name)) for name in frontend_policy.required_files(target)]
    tracked += [integrity.receipt(Path(build["path"]) / leaf, value) for leaf, value in build["files"].items()]
    tracked.append(integrity.receipt(Path(build["path"]) / "fragma-build.json", build["receipt_sha256"]))
    tracked = integrity.merge_records(tracked)
    require(not integrity.changed_files(tracked), "context input drift")
    return {"schema_version": 1, "profile": target["profile"], "revision": revision,
            "target_sha256": digest(target), "model_sha256": digest(model),
            "source": str(source), "fixture": str(fixture), "base_argv": base,
            "frontend_target": target,
            "cwd": str(Path(build["path"]).resolve()), "frontend_options": frontend_options(target),
            "big_endian": little == ["false"], "tracked_inputs": tracked}


def command_plan(binding, output):
    """The original 25-command calibration, without any executable launch."""
    require(type(binding.get("big_endian")) is bool, "explicit Boolean byte-order expectation required")
    output = Path(output).resolve()
    base, source = binding["base_argv"], binding["source"]
    define = "-DFRAGMA_COMMON24_EXPECT_BIG_ENDIAN=" + str(int(binding["big_endian"]))
    result = [("positive", [*base, define, "-Werror", "-MD", "-MF", str(output / "positive.d"),
               "-MT", "fragma", "-c", source, "-o", str(output / "positive.o")]),
              ("macros", [*base, define, "-dM", "-E", source]),
              ("preprocess", [*base, define, "-E", "-P", source])]
    result += [("wrong-" + case, [*base, define, "-Werror", "-DFRAGMA_COMMON24_WRONG_CASE=" + str(i),
                "-c", source, "-o", str(output / ("wrong-" + case + ".o"))])
               for i, case in enumerate(CASES, 1)]
    return result


def expected_gate_argv(binding, output):
    output = Path(output).resolve()
    return [*binding["base_argv"], *binding["frontend_options"], "-Werror", "-MD", "-MF",
            str(output / "model-headers.d"), "-MT", "fragma", "-c", binding["fixture"],
            "-o", str(output / "kernel-model.o")]


def validate_gate(root, kernel, binding, build, gate, output, *, target=None, model=None):
    """Read-only: compare actual shared input gate with its exact expected context."""
    output = Path(output).resolve()
    require(isinstance(gate, dict) and same(gate.get("argv"), expected_gate_argv(binding, output))
            and gate.get("cwd") == binding["cwd"], "genuine header gate command/selector mismatch")
    require(type(gate.get("returncode")) is int and gate["returncode"] == 0
            and gate.get("timed_out") is False, "genuine header gate did not complete normally")
    log, dep, obj = (output / name for name in ("kernel-model.log", "model-headers.d", "kernel-model.o"))
    require(all(path.is_file() and not path.is_symlink() for path in (log, dep, obj)),
            "missing or non-regular genuine-header artifacts")
    require(gate.get("log") == str(log) and gate.get("log_sha256") == sha(log)
            and log.read_bytes() == b"", "genuine header gate diagnostics/binding mismatch")
    require(isinstance(target, dict) and isinstance(model, dict), "explicit gate target/model required")
    object_identity = frontend_policy.fixture_object(obj.read_bytes(), target, model)
    for field, path in (("object", obj), ("dependencies", dep), ("diagnostics", log)):
        require(same(gate.get(field), record(path)), "genuine gate artifact inventory mismatch")
    require(same(gate.get("frontend_policy"), frontend_policy.identity(target)), "genuine gate policy mismatch")
    require(gate.get("original_compile_command") == inputs.compile_entry(build, "lib/string.c"),
            "genuine gate original compiler entry mismatch")
    paths = inputs.dependency_paths(dep, Path(binding["cwd"]))
    required = {Path(binding["fixture"]).resolve(), (root / frontend_policy.HEADER).resolve(),
                *(Path(build["source"]) / "include/linux" / name for name in
                  ("types.h", "unaligned.h", "compiler_types.h"))}
    require(required <= set(paths), "genuine gate omits required fixture/type/inline headers")
    consumed = inputs.input_receipts(root, kernel, binding["revision"], build, paths)
    require(same(gate.get("inputs"), consumed) and gate.get("fixture_sha256") == sha(binding["fixture"]),
            "genuine header gate source/dependency mismatch")
    return {"record_sha256": digest(gate), "artifacts": [record(path) for path in (log, dep, obj)],
            "inputs": consumed, "fixture": record(binding["fixture"]), "object_identity": object_identity}


def validate_commands(binding, output, commands, *, compiler_family="gcc"):
    """Exact raw command/stream inventory; a passed label is never sufficient."""
    output = Path(output).resolve()
    plan = command_plan(binding, output)
    require(isinstance(commands, list) and len(commands) == len(plan), "missing/extra compiler command")
    symbols = None
    for i, (command, (name, argv)) in enumerate(zip(commands, plan, strict=True)):
        require(command.get("name") == name and same(command.get("argv"), argv)
                and command.get("cwd") == binding["cwd"], "compiler command/order/context mismatch")
        streams = []
        for stream in ("stderr", "stdout"):
            path = output / (name + "." + stream)
            expected = {"path": str(path), "sha256": sha(path)}
            require(same(command.get(stream), expected) and path.resolve().parent == output,
                    "raw stream identity/path mismatch")
            streams.append(path.read_text())
        stderr, stdout = streams
        require(command.get("log") == str(output / (name + ".stderr"))
                and command.get("log_sha256") == command["stderr"]["sha256"], "raw stderr binding mismatch")
        if i < 3:
            require(type(command.get("returncode")) is int and command["returncode"] == 0
                    and command.get("timed_out") is False and stderr == "", "positive/preprocessing failed")
            if i == 0:
                require(stdout == "" and (output / "positive.o").is_file(), "positive object/output mismatch")
            elif i == 2:
                # Only the already command/hash-checked positive stream supplies
                # identities; no negative error text can choose its own match.
                symbols = assertion_symbols(stdout)
        else:
            obj = output / (name + ".o")
            validate_wrong(CASES[i - 3], command, stderr, stdout, obj.exists() or obj.is_symlink(),
                           symbol=symbols[CASES[i - 3]], compiler_family=compiler_family)
    return symbols


def validate_expansion(binding, expanded, macros, genuine_header):
    assertion_symbols(expanded)
    mode = optimization_mode(binding.get("base_argv"))
    # Match whole identifiers, including malformed/function-like definitions,
    # so a hidden duplicate cannot evade the raw positive macro inventory.
    for name, expected in (("__OPTIMIZE__", ["1"]),
                           ("__OPTIMIZE_SIZE__", ["1"] if mode == "-Os" else [])):
        values = re.findall(r"^#[ \t]*define[ \t]+" + name + r"(?![A-Za-z0-9_])([^\r\n]*)$",
                            macros, re.M)
        require(values == [" " + value for value in expected], "optimization macro mismatch: " + name)
    require(re.findall(r"^#define __compiletime_error\(msg\) (.*)$", macros, re.M)
            == ["__attribute__((__error__(msg)))"], "error attribute disabled/changed")
    require(re.findall(r"^#define FRAGMA_COMMON24_WRONG_CASE (.*)$", macros, re.M) == ["0"],
            "positive case overridden")
    require(re.findall(r'__error__\("fragma common24 " "([a-z_0-9]+)"\)', expanded) == list(CASES),
            "expanded observation inventory changed")
    target = binding.get("frontend_target")
    require(isinstance(target, dict) and same(binding.get("frontend_options"), frontend_options(target)),
            "missing or mismatched explicit frontend target")
    for helper in HELPERS:
        actual = provenance.extract_function(expanded, helper)
        original = provenance.extract_function(genuine_header, helper)
        require(actual.tokens == original.tokens
                and actual.declaration_prefix == frontend_policy.expected_prefix(target, helper),
                "genuine helper body/declarator/inline metadata changed")


RECORD_STATUS = "compiler-results-recorded"
VALIDATION_STATUS = STATUS
LIMITATIONS = ["Fixed compiler-eliminated predicates, not runtime reachability or a full-domain proof.",
               "Compiler/object checks do not approve proof assumptions, warnings or architecture levels."]


def _write(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    os.replace(temporary, path)


def required_artifacts(binding, output):
    """Reconstruct the fixed inventory independently of any receipt array."""
    return sorted([name + "." + stream for name, _ in command_plan(binding, output)
                   for stream in ("stdout", "stderr")] + ["positive.o", "positive.d"])


def _artifacts(output):
    result = []
    for path in sorted(output.rglob("*")):
        require(not path.is_symlink(), "symlink in compiler calibration output: " + str(path))
        if path.is_file() and path != output / "receipt.json":
            result.append(record(path))
        elif path.is_dir():
            raise CalibrationError("unexpected directory in flat compiler calibration output")
        elif not path.is_file():
            raise CalibrationError("unexpected non-regular compiler calibration artifact: " + str(path))
    return result


def _initial(binding, gate):
    return integrity.merge_records(binding["tracked_inputs"], integrity.metadata_records(gate))


def _consumed(root, kernel, binding, build, output):
    paths = inputs.dependency_paths(output / "positive.d", Path(binding["cwd"]))
    required = {Path(binding["source"]).resolve(),
                *(Path(build["source"]) / "include/linux" / name for name in
                  ("types.h", "unaligned.h", "build_bug.h"))}
    require(required <= set(paths), "calibration omits required source/type/helper/error-macro dependencies")
    return inputs.input_receipts(root, kernel, binding["revision"], build, paths)


def positive_object(data, model, gate_object):
    from fragma import elf
    return elf.calibration_object(data, model, gate_object)


def validate(root, target, model, build, kernel, revision, receipt_path,
             *, kernel_model_gate, kernel_model_output):
    """Read-only current-input validation of fixed compiler observations only."""
    root, receipt_path = Path(root).resolve(), Path(receipt_path).absolute()
    require(receipt_path.name == "receipt.json" and receipt_path.is_relative_to(root) and receipt_path.is_file()
            and not receipt_path.is_symlink() and receipt_path == receipt_path.resolve(),
            "receipt must be a non-symlinked local calibration receipt")
    output = receipt_path.parent
    saved = read_json(receipt_path)
    require(isinstance(saved, dict) and set(saved) == {"schema_version", "kind", "status", "boundary", "limitations", "target", "model", "build",
        "revision", "kernel", "gate_sha256", "gate_output", "output", "timeout", "environment", "started_at", "completed_at",
        "binding", "gate", "plan", "intents", "commands", "initial_inputs", "consumed_inputs", "final_inputs",
        "input_drift", "finalization_errors", "artifacts", "error", "positive_object", "fixture_controls"}, "unknown or missing receipt fields")
    require(type(saved["schema_version"]) is int and saved["schema_version"] == 1
            and saved["kind"] == KIND and saved["status"] == RECORD_STATUS
            and same(saved["boundary"], BOUNDARY) and same(saved["limitations"], LIMITATIONS),
            "receipt is not a completed compiler-only observation")
    require(type(saved["timeout"]) is int and 1 <= saved["timeout"] <= 600, "invalid compiler timeout")
    require(same([saved["target"], saved["model"], saved["build"], saved["revision"]], [target, model, build, revision])
            and saved["kernel"] == str(Path(kernel).resolve())
            and saved["output"] == str(output) and saved["gate_output"] == str(Path(kernel_model_output).resolve())
            and saved["gate_sha256"] == digest(kernel_model_gate), "receipt context mismatch")
    started, completed = (datetime.fromisoformat(saved[key]) for key in ("started_at", "completed_at"))
    require(started.tzinfo is not None and completed.tzinfo is not None and completed >= started,
            "invalid execution timestamps")
    require(same(saved["environment"], environment_identity(output)), "compiler environment policy mismatch")
    binding = context(root, target, model, build, revision)
    gate = validate_gate(root, kernel, binding, build, kernel_model_gate, kernel_model_output,
                         target=target, model=model)
    require(same(saved["binding"], binding) and same(saved["gate"], gate), "current context/gate differs")
    from fragma import common24_controls
    controls = common24_controls.validate(root, kernel, target, model, build, binding, gate,
        output.parent / "compiler-controls" / "receipt.json", timeout=saved["timeout"])
    require(same(saved["fixture_controls"], controls), "genuine fixture controls differ")
    expected_plan = [{"name": name, "argv": argv} for name, argv in command_plan(binding, output)]
    require(same(saved["plan"], expected_plan), "recorded command plan differs")
    expected_intents = [{**item, "cwd": binding["cwd"], "timeout": saved["timeout"]} for item in expected_plan]
    require(same(saved["intents"], expected_intents), "missing or changed compiler invocation intent")
    require(isinstance(saved["commands"], list), "compiler command inventory must be an array")
    for command in saved["commands"]:
        require(isinstance(command, dict) and set(command) == {"name", "argv", "cwd", "returncode", "timed_out",
                "seconds", "log", "log_sha256", "stderr", "stdout"}
                and type(command.get("seconds")) in (int, float)
                and math.isfinite(command["seconds"]) and command["seconds"] >= 0,
                "unknown/missing compiler receipt field or invalid duration")
    actual_artifacts = _artifacts(output)
    require([str(Path(item["absolute_path"]).relative_to(output)) for item in actual_artifacts]
            == required_artifacts(binding, output), "required compiler artifacts missing or unexpected")
    require(same(saved["artifacts"], actual_artifacts), "saved artifact inventory differs")
    family = model.get("compiler", {}).get("compiler_family", "gcc")
    symbols = validate_commands(binding, output, saved["commands"], compiler_family=family)
    initial = integrity.merge_records(_initial(binding, gate), controls["tracked_files"])
    consumed = _consumed(root, kernel, binding, build, output)
    final = integrity.merge_records(initial, integrity.metadata_records(consumed))
    require(same(saved["initial_inputs"], initial) and same(saved["consumed_inputs"], consumed)
            and same(saved["final_inputs"], final), "required input inventory missing or altered")
    require(not integrity.changed_files(final) and saved["input_drift"] == []
            and saved["finalization_errors"] == [] and saved["error"] is None, "input drift or failed finalization")
    header = Path(build["source"]) / "include/linux/unaligned.h"
    require(str(header.resolve()) in {str(Path(row["absolute_path"]).resolve()) for row in consumed},
            "genuine helper header is missing from calibration dependencies")
    validate_expansion(binding, (output / "preprocess.stdout").read_text(),
                       (output / "macros.stdout").read_text(), header.read_text())
    object_identity = positive_object((output / "positive.o").read_bytes(), model, gate["object_identity"])
    require(same(saved["positive_object"], object_identity), "positive object identity differs")
    return {"schema_version": 1, "kind": KIND, "status": VALIDATION_STATUS,
            "receipt": record(receipt_path), "target_id": target["id"], "profile": target["profile"],
            "revision": revision, "setting": identity(target), "source_sha256": SOURCE_SHA256,
            "environment_policy": ENVIRONMENT_POLICY, "positive_object": object_identity,
            "fixture_controls": controls,
            "commands_checked": 25, "cases_checked": list(CASES),
            "assertion_symbols": symbols,
            "artifact_count": len(actual_artifacts), "input_count": len(final),
            "tracked_files": integrity.merge_records(final, actual_artifacts, [record(receipt_path)]),
            "boundary": dict(BOUNDARY), "limitations": list(LIMITATIONS)}


def run(root, target, model, build, kernel, revision, output, env,
        *, kernel_model_gate, kernel_model_output, timeout=60):
    """Compile-only runner; no source rewriting or generated-program execution.

    Failure receipts retain invocation intents and every available artifact.
    Successful compiler observations do not approve a proof or architecture.
    """
    root, output = Path(root).resolve(), Path(output).absolute()
    require(output != root and output.is_relative_to(root) and output == output.resolve()
            and output.parent.is_dir() and not output.exists() and not output.is_symlink(),
            "output must be a new non-symlinked child directory")
    require(type(timeout) is int and 1 <= timeout <= 600, "invalid compiler timeout")
    require(isinstance(env, dict) and same(env, compiler_environment(output)),
            "compiler environment must match the reconstructed clean policy")
    output.mkdir()
    saved = {"schema_version": 1, "kind": KIND, "status": "running", "boundary": dict(BOUNDARY),
        "limitations": list(LIMITATIONS), "target": target, "model": model, "build": build, "revision": revision,
        "kernel": str(Path(kernel).resolve()), "fixture_controls": None,
        "gate_sha256": digest(kernel_model_gate), "gate_output": str(Path(kernel_model_output).resolve()),
        "output": str(output), "timeout": timeout,
        "environment": environment_identity(output),
        "started_at": datetime.now(timezone.utc).isoformat(), "completed_at": None,
        "binding": None, "gate": None, "plan": [], "intents": [], "commands": [],
        "initial_inputs": [], "consumed_inputs": [], "final_inputs": None, "input_drift": [],
        "finalization_errors": [], "artifacts": [], "error": None, "positive_object": None}
    receipt_path = output / "receipt.json"
    _write(receipt_path, saved)
    interruption = None
    try:
        binding = context(root, target, model, build, revision)
        saved["binding"] = binding
        gate = validate_gate(root, kernel, binding, build, kernel_model_gate, kernel_model_output,
                             target=target, model=model)
        saved["gate"] = gate
        saved["initial_inputs"] = _initial(binding, gate)
        require(not integrity.changed_files(saved["initial_inputs"]), "initial input drift")
        from fragma import common24_controls
        controls = common24_controls.run(root, kernel, target, model, build, binding, gate,
            output.parent / "compiler-controls", timeout=timeout)
        saved["fixture_controls"] = controls
        _write(receipt_path, saved)
        require(controls.get("status") == common24_controls.CHECKED, "genuine fixture controls failed")
        saved["initial_inputs"] = integrity.merge_records(saved["initial_inputs"], controls["tracked_files"])
        saved["plan"] = [{"name": name, "argv": argv} for name, argv in command_plan(binding, output)]
        symbols = None
        for index, item in enumerate(saved["plan"]):
            name, argv = item["name"], item["argv"]
            saved["intents"].append({**item, "cwd": binding["cwd"], "timeout": timeout})
            _write(receipt_path, saved)
            stderr, stdout = output / (name + ".stderr"), output / (name + ".stdout")
            command = inputs.run_recorded(argv, cwd=Path(binding["cwd"]), env=env,
                log=stderr, stdout_file=stdout, timeout=timeout)
            command.update(name=name, stderr={"path": str(stderr), "sha256": sha(stderr)},
                           stdout={"path": str(stdout), "sha256": sha(stdout)})
            saved["commands"].append(command)
            _write(receipt_path, saved)
            if index < 3:
                require(type(command["returncode"]) is int and command["returncode"] == 0
                        and command["timed_out"] is False and stderr.read_text() == "",
                        "positive/preprocessing command failed")
                if index == 2:
                    symbols = assertion_symbols(stdout.read_text())
            else:
                obj = output / (name + ".o")
                family = model.get("compiler", {}).get("compiler_family", "gcc")
                validate_wrong(CASES[index - 3], command, stderr.read_text(), stdout.read_text(),
                               obj.exists() or obj.is_symlink(), symbol=symbols[CASES[index - 3]],
                               compiler_family=family)
        family = model.get("compiler", {}).get("compiler_family", "gcc")
        validate_commands(binding, output, saved["commands"], compiler_family=family)
        saved["consumed_inputs"] = _consumed(root, kernel, binding, build, output)
        saved["positive_object"] = positive_object((output / "positive.o").read_bytes(), model, gate["object_identity"])
        saved["status"] = RECORD_STATUS
    except BaseException as exc:
        interruption = exc if not isinstance(exc, Exception) else None
        saved.update(status="interrupted" if interruption is not None else "error",
                     error={"type": type(exc).__name__, "message": str(exc)})
    for name, action in (("final_inputs", lambda: integrity.merge_records(saved["initial_inputs"],
                         integrity.metadata_records(saved["consumed_inputs"]))),
                         ("artifacts", lambda: _artifacts(output))):
        try:
            saved[name] = action()
        except Exception as exc:
            saved["finalization_errors"].append(name + ": " + str(exc))
    for observed in [*saved["initial_inputs"], *integrity.metadata_records(saved["consumed_inputs"])]:
        try:
            saved["input_drift"] += integrity.changed_files([observed])
        except Exception as exc:
            saved["finalization_errors"].append("input drift: " + str(exc))
    if saved["input_drift"] or saved["finalization_errors"]:
        if interruption is None:
            saved["status"] = "error"
    saved["completed_at"] = datetime.now(timezone.utc).isoformat()
    _write(receipt_path, saved)
    if interruption is not None:
        raise interruption
    if saved["status"] == RECORD_STATUS:
        try:
            return validate(root, target, model, build, kernel, revision, receipt_path,
                            kernel_model_gate=kernel_model_gate, kernel_model_output=kernel_model_output)
        except Exception as exc:
            saved.update(status="error", error={"type": type(exc).__name__, "message": str(exc)})
            _write(receipt_path, saved)
    return {"schema_version": 1, "kind": KIND, "status": saved["status"], "receipt": record(receipt_path),
            "boundary": dict(BOUNDARY), "limitations": list(LIMITATIONS)}


def _bound_json(row):
    require(isinstance(row, dict) and set(row) == {"absolute_path", "sha256"}, "invalid compiler receipt binding")
    path = Path(row["absolute_path"])
    require(path.is_absolute() and path.is_file() and not path.is_symlink()
            and path == path.resolve(), "missing or non-regular compiler receipt")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == row["sha256"], "compiler receipt bytes changed")
    return replay.strict_json(data.decode())


def observation(root, target, model, evidence, shared, *, read=None):
    """Reconstruct a saved compiler envelope; absent old evidence is not filled in."""
    root = Path(root).resolve()
    setting = identity(target, root=root)
    saved = evidence.get("validated_compiler_calibration")
    if setting is None:
        require(saved is None, "compiler envelope has no declared setting")
        return None
    require(isinstance(saved, dict) and saved.get("status") == STATUS, "required compiler envelope is missing or failed")
    combined = dict(shared)
    for name, expected in replay.hash_records(evidence["integrity_inputs"]).items():
        require(name not in combined or combined[name] == expected, "conflicting compiler input hashes")
        combined[name] = expected
    directory = Path(evidence["kernel_model_check"]["log"]).parent
    expected_path = directory / "compiler-calibration" / "receipt.json"
    receipt = saved.get("receipt")
    require(isinstance(receipt, dict) and receipt.get("absolute_path") == str(expected_path)
            and combined.get(str(expected_path)) == receipt.get("sha256"), "compiler receipt path/hash not bound to target")
    raw = _bound_json(receipt)
    require(isinstance(raw.get("kernel"), str) and Path(raw["kernel"]).is_absolute(), "missing compiler Git-source path")
    build = inputs.load_build(root, target["profile"], model["kernel_revision"])
    actual = validate(root, target, model, build, Path(raw["kernel"]), model["kernel_revision"], expected_path,
        kernel_model_gate=evidence["kernel_model_check"], kernel_model_output=directory)
    require(same(actual, saved), "saved compiler envelope differs from current raw evidence")
    for row in actual["tracked_files"]:
        require(combined.get(row["absolute_path"]) == row["sha256"], "compiler input/artifact omitted from target integrity")
        if read is not None and Path(row["absolute_path"]).is_relative_to(directory):
            read(row["absolute_path"], row["sha256"], binary=True)
    review = evidence.get("validated_review")
    if review is not None:
        context_record = review["review_context"]
        require(same(context_record.get("compiler_calibration"), review_identity(target)), "review compiler policy mismatch")
        require(all(context_record.get("file_hashes", {}).get(name) == combined.get(str(root / name))
                    == sha(root / name) for name in required_files(target)), "review compiler implementation/source mismatch")
    return actual


def logical_observation(observed, mapper):
    """Normalize verified commands, never use transient receipt/model digests as keys."""
    if observed is None:
        return None
    raw = _bound_json(observed["receipt"])
    controls = _bound_json(observed["fixture_controls"]["receipt"])
    def commands(rows):
        return [{"name": row["name"], "argv": mapper.argv(row["argv"]), "cwd": mapper.path(row["cwd"]),
                 "returncode": row["returncode"], "timed_out": row["timed_out"]} for row in rows]
    def environment(values):
        return {**mapper.metadata(values), "TMPDIR": mapper.path(values["TMPDIR"])}
    return {key: observed[key] for key in ("kind", "status", "setting", "source_sha256", "environment_policy",
            "positive_object", "commands_checked", "cases_checked", "assertion_symbols", "boundary", "limitations")} | {
        "commands": commands(raw["commands"]), "timeout": raw["timeout"],
        "environment": environment(raw["environment"]["values"]),
        "fixture_controls": {key: observed["fixture_controls"][key] for key in
                             ("kind", "status", "commands_checked", "controls", "boundary")},
        "control_commands": commands(controls["commands"]), "control_environment": environment(controls["environment"])}
