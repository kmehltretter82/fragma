"""Read-only, conservative comparison of completed Fragma run evidence.

No cache reuse, proof acceptance, receipt relocation, or review authorization is
implemented here. Historical inputs are compared by recorded identity; retained
run artifacts and assertion source files must still be available and unchanged.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex

from fragma import report


class ReplayError(ValueError):
    pass


POLICY = "fragma-replay-v1"
SHA = re.compile(r"[0-9a-f]{64}")
PATH_FIELDS = {"path", "file", "absolute_path", "resolved_path", "cwd", "output",
               "directory", "source_root", "source", "build_path", "switch_prefix",
               "machdep", "frama_input"}
COMMAND_FIELDS = {"argv", "command", "target_command", "cpp_command", "frama_cpp_command"}
ARGV_FIELDS = {"cpp_extra_args", "calibration_cpp_extra_args", "compiler_flags", "flags"}
PATH_LIST_FIELDS = {"PATH", "LD_LIBRARY_PATH", "CAML_LD_LIBRARY_PATH", "OCAMLPATH", "LIBRARY_PATH", "COMPILER_PATH", "CPATH"}
RESOURCE_OPTIONS = {"-wp-timeout", "-wp-par", "-wp-smoke-timeout"}
LINE_MARKER = re.compile(r'^(#\s+(?:line\s+)?\d+\s+)"([^"\\\n]+)"(.*)$')
# The two inspected pre-wall-limit string receipts bind this historical runner.
# Do not infer a default for arbitrary legacy runner hashes or legacy EVA runs,
# which do not expose the caller's per-prover timeout in their command line.
LEGACY_WALL_RUNNERS = {"8656fc0bf8096fcca6486561e93615b3f7f454961b1a7f94946e50fa6d42b4d4"}
# Inspected retained string/core receipts used declaration-line-only assertion
# labels. Reconstruct that naming policy only for these exact parser hashes;
# do not silently strip newly derived labels from arbitrary historical reports.
LEGACY_ASSERTION_MAPPERS = {
    "e7cef08abd54e8b5084b009b505f63f3af9d8423d1721e841aefe015e1bda0b3",
    "d42ed22ffbd7000cced42c0340b6266c92d1e235da95e6f434190a3818ad23cf",
    "dbeab855f2156d89f584d2f4c51b1fb1709e3023aa5cf51b077d4a31394f5f0a",
}
# Exact pairs inspected in retained string, core and relocated receipts. These
# identify the old runner/profile policy; their missing pointer guard is never
# upgraded to the current policy merely because the historical proof passed.
LEGACY_ANALYSIS_POLICIES = {
    ("8656fc0bf8096fcca6486561e93615b3f7f454961b1a7f94946e50fa6d42b4d4",
     "491dc6ac997ff582cb1de9c97f6c106a1e118cb5c9fbe5b7d39bce0c66d80601"),
    ("1555c9389fc6d44ba0b75a02372ba357b741840ff512b3e2051a94d75783d74a",
     "da00f7b91215cf2fa0e76ebd1496a9c8025bcec33bd1ca6bde6bf8d83de255b4"),
    ("3160058b24448c2d7f2ee8506e9985be1c3270d2828f625065bf204ca2f03a49",
     "da00f7b91215cf2fa0e76ebd1496a9c8025bcec33bd1ca6bde6bf8d83de255b4"),
}
LEGACY_ARITHMETIC_FLAGS = ["-no-warn-signed-overflow", "-no-warn-unsigned-overflow",
    "-no-warn-signed-downcast", "-no-warn-unsigned-downcast", "-no-warn-right-shift-negative"]


def assertion_predicate_starts(input_hashes, project):
    """Retained parser identity selects its exact assertion-label convention."""
    return input_hashes.get(str(Path(project) / "fragma/report.py")) not in LEGACY_ASSERTION_MAPPERS


def analysis_policy_observation(model, target, evidence, shared, project):
    """Rederive current policy, or identify an exact weaker historical policy.

    Callers must first verify that the saved command and audit parameters equal
    the retained raw artifacts. This function does not authenticate artifacts,
    grant review approval, infer missing guards, or invoke any analyzer.
    """
    from fragma.analysis_policy import validate_actual_policy

    analysis = model["analysis"]
    require(isinstance(analysis, dict) and isinstance(target, dict), "malformed analysis policy inputs")
    argv = evidence["analysis_command"]["argv"]
    audit = evidence["analyzer_audit"]["parameters"]
    if "runtime_checks" in analysis or "validated_analysis_policy" in evidence:
        require(isinstance(evidence.get("validated_analysis_policy"), dict),
                "current analysis policy envelope is missing or malformed")
        policy_hash = shared.get(str(Path(project) / "fragma/analysis_policy.py"))
        require(isinstance(policy_hash, str) and SHA.fullmatch(policy_hash),
                "current analysis policy implementation is not an inventoried input")
        actual = validate_actual_policy(analysis, target, argv, audit)
        require(canonical(actual) == canonical(evidence["validated_analysis_policy"]),
                "saved analysis policy disagrees with actual command/audit")
        review = evidence.get("validated_review")
        if review is not None:
            require(isinstance(review, dict), "malformed current analysis review")
            context = review.get("review_context", {})
            require(isinstance(context, dict), "malformed current analysis review context")
            require(context.get("file_hashes", {}).get("fragma/analysis_policy.py") == policy_hash and
                    canonical(context.get("analysis")) == canonical(actual["model"]) and
                    canonical(context.get("analysis_pipeline")) == canonical(actual["pipeline"]) and
                    canonical(context) == canonical(target.get("review_context")),
                    "current reviewed policy/pipeline differs from actual analysis or input identity")
        return actual

    identity = tuple(shared.get(str(Path(project) / name))
                     for name in ("fragma/suite.py", "config/profiles.json"))
    require(identity in LEGACY_ANALYSIS_POLICIES, "missing analysis policy has unknown historical identity")
    require("analysis_pipeline" not in target, "historical identity cannot authorize a new analysis pipeline")
    require(analysis.get("wp_model") == "Typed" and analysis.get("arithmetic_flags") == LEGACY_ARITHMETIC_FLAGS,
            "historical arithmetic/memory model is not the inspected policy")
    require(isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv),
            "malformed historical analyzer command")
    require(all(argv.count(flag) == 1 for flag in LEGACY_ARITHMETIC_FLAGS),
            "historical arithmetic flags missing or ambiguous")
    require(not any(arg.startswith(("-warn-invalid-pointer", "-no-warn-invalid-pointer",
                "-rte", "-no-rte")) for arg in argv),
            "historical policy contains new or contradictory pointer/RTE flags")
    parameters = audit.get("eva", {}).get("correctness-parameters", {})
    require(parameters.get("-warn-invalid-pointer") == "false",
            "historical pointer-formation audit is missing or not the observed disabled setting")
    for flag in LEGACY_ARITHMETIC_FLAGS:
        positive = flag.replace("-no-warn-", "-warn-", 1)
        require(not any(arg == positive or arg.startswith((positive + "=", flag + "=")) for arg in argv)
                and parameters.get(positive) == "false", "historical arithmetic command/audit mismatch")

    def argument(option, expected):
        positions = [index for index, arg in enumerate(argv) if arg == option]
        require(len(positions) == 1 and positions[0] + 1 < len(argv)
                and argv[positions[0] + 1] == expected, "historical pipeline mismatch: " + option)

    require(argv.count("-then") == 1 and argv.count("-report") == 1,
            "historical analysis/report pipeline is missing or ambiguous")
    require(not any((arg.startswith("-then") and arg != "-then") or
                    arg.startswith(("-wp-model=", "-wp-fct=", "-main=", "-wp=", "-eva=")) or
                    arg in ("-no-wp", "-no-eva") for arg in argv),
            "historical pipeline contains an alternate or opposing selector")
    if target.get("analysis") == "wp":
        functions = target.get("analysis_functions", target["functions"])
        require(argv.count("-wp") == 1 and "-eva" not in argv and argv.count("-wp-rte") == 1,
                "historical WP engine/RTE pipeline mismatch")
        argument("-wp-model", "Typed")
        argument("-wp-fct", ",".join(functions))
        require(argv.index("-wp") < argv.index("-then") < argv.index("-report"),
                "historical WP/report phase order changed")
        pipeline = {"kind": "legacy-wp", "functions": functions}
    else:
        require(target.get("analysis") == "eva" and argv.count("-eva") == 1 and "-wp" not in argv,
                "historical EVA pipeline mismatch")
        argument("-main", target["entry"])
        require(argv.index("-eva") < argv.index("-then") < argv.index("-report"),
                "historical EVA/report phase order changed")
        require(parameters.get("-main") == target["entry"], "historical EVA entry audit mismatch")
        pipeline = {"kind": "legacy-eva", "entry": target["entry"]}
    return {"schema_version": 1, "status": "legacy-observed", "current_policy": False,
            "model": {"wp_model": "Typed", "arithmetic_flags": list(LEGACY_ARITHMETIC_FLAGS)},
            "pipeline": pipeline, "actual_pointer_formation": "false",
            "runner_sha256": identity[0], "profile_registry_sha256": identity[1]}


def common24_observation(project, target, evidence, goals, properties, evaluation, shared):
    """Recheck the opt-in exact source/report inventory without granting review."""
    from fragma import common24, frontend_policy
    project = Path(project).resolve()
    if frontend_policy.identity(target, root=project) is None:
        require(evidence.get("common24_source") is None and evidence.get("common24_inventory") is None,
                "common24 inventory has no declared frontend policy")
        return evaluation, None
    helper = str(project / "fragma/common24.py")
    require(isinstance(shared.get(helper), str) and SHA.fullmatch(shared[helper]),
            "common24 inventory implementation is not an inventoried input")
    hashes = hash_records(evidence["integrity_inputs"])
    texts = {}
    for field in ("harness", "wp_strategy_file"):
        path = project / target[field]
        require(hashes.get(str(path)) == file_hash(path), "common24 source/strategy input changed")
        texts[field] = path.read_text()
    observed = common24.evaluate_inventory(target, goals, properties, evaluation,
        source_path=project / target["harness"], source_text=texts["harness"],
        strategy_text=texts["wp_strategy_file"])
    require(canonical(observed) == canonical(evidence.get("common24_inventory")) and
            canonical(observed["source"]) == canonical(evidence.get("common24_source")),
            "saved common24 inventory differs from authenticated source and raw reports")
    review = evidence.get("validated_review")
    if review is not None:
        require(review.get("review_context", {}).get("file_hashes", {}).get("fragma/common24.py") == shared[helper],
                "review does not bind the common24 inventory implementation")
    return common24.apply_policy(evaluation, observed), observed


def model_policy_observation(model, read):
    """Check current model calibration against its actual retained byte audit."""
    from fragma.analysis_policy import validate_actual_model_policy

    if ("runtime_checks" not in model.get("analysis", {}) and
            "validated_model_policy" not in model and "analysis_policy_audit" not in model):
        return {"status": "legacy-observed", "current_policy": False}
    audit = model["analysis_policy_audit"]
    raw = strict_json(read(audit["path"], audit["sha256"]))
    require(canonical({key: value for key, value in raw.items() if key != "sources"}) == canonical(audit["parameters"]),
            "actual model correctness audit differs from saved parameters")
    matches = [row for row in model["checks"] if row.get("name") == "eva-arithmetic-and-memory-byte-order"]
    require(len(matches) == 1 and matches[0].get("status") == "passed", "missing or ambiguous model EVA evidence")
    command = matches[0]["details"]
    require(type(command.get("exit_code")) is int and command["exit_code"] == 0,
            "model policy analyzer did not complete")
    argv = command["command"]
    require(isinstance(argv, list) and argv.count("-audit-prepare") == 1 and
            argv.index("-audit-prepare") + 1 < len(argv) and
            argv[argv.index("-audit-prepare") + 1] == audit["path"] and
            argv.count("-eva") == 1 and argv[-3:] == ["-eva", "-eva-slevel", "10"] and
            not any(arg in argv for arg in ("-wp", "-rte", "-then")),
            "model correctness audit is not bound to the recorded calibration command")
    actual = validate_actual_model_policy(model["analysis"], argv, audit["parameters"])
    require(canonical(model.get("validated_model_policy")) == canonical(actual),
            "saved model policy disagrees with actual command/audit")
    checks = [row for row in model["checks"] if row.get("name") == "analysis-runtime-policy"]
    require(len(checks) == 1 and checks[0].get("status") == "passed" and
            canonical(checks[0].get("details")) == canonical(actual),
            "model policy check is missing, ambiguous or inconsistent")
    return actual


def strict_json(text):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReplayError("duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid(value):
        raise ReplayError("non-finite JSON constant: " + value)

    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise ReplayError("non-finite JSON number: " + token)
        return value

    try:
        return json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid,
                          parse_float=finite_float)
    except json.JSONDecodeError as exc:
        raise ReplayError("malformed JSON: " + str(exc)) from exc


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, reason):
    if not condition:
        raise ReplayError(reason)


def hash_records(records):
    require(isinstance(records, list), "input inventory must be an array")
    result = {}
    for row in records:
        require(isinstance(row, dict), "input record must be an object")
        path, sha = row.get("absolute_path"), row.get("sha256")
        require(isinstance(path, str) and Path(path).is_absolute(), "input has no absolute path")
        require(isinstance(sha, str) and SHA.fullmatch(sha), "input has malformed SHA256")
        require(path not in result, "duplicate input path: " + path)
        result[path] = sha
    return result


def metadata_claims(value):
    """Cross-check explicit tool/model hash claims against the run's inventory."""
    claims = []
    if isinstance(value, dict):
        path = value.get("absolute_path", value.get("path", value.get("resolved_path")))
        sha = value.get("sha256")
        if isinstance(path, str) and path.startswith("/") and sha is not None:
            claims.append((path, sha))
        if isinstance(value.get("directory"), str) and isinstance(value.get("files"), dict):
            claims += [(str(Path(value["directory"]) / name), expected) for name, expected in value["files"].items()]
        for item in value.values():
            # Older inventories bind a library's resolved file, with the loader
            # alias retained as its dictionary key. Keep that edge in semantic
            # identity without inventing an unrecorded invocation-path receipt.
            claims.extend(metadata_claims(item))
    elif isinstance(value, list):
        for item in value:
            claims.extend(metadata_claims(item))
    return claims


@dataclass(frozen=True)
class RootBindings:
    """Explicit role-to-root bindings, e.g. project/kernel/build:x86/switch.

    Unknown absolute locations remain literal identities; they are never erased
    or equated by basename. Nested roots use the most specific declared role.
    """
    roots: dict[str, str]

    def validate(self):
        require("project" in self.roots and self.roots, "project root binding is required")
        seen = set()
        for role, path in self.roots.items():
            require(isinstance(role, str) and re.fullmatch(r"[a-zA-Z0-9:_.-]+", role), "invalid root role")
            require(role != "run", "run root is derived from the actual summary location")
            require(isinstance(path, str) and Path(path).is_absolute() and path != "/", "invalid or broad root")
            normalized = os.path.normpath(path)
            require(normalized not in seen, "ambiguous duplicate root binding")
            seen.add(normalized)


class Mapper:
    def __init__(self, roots, run):
        roots.validate()
        self.roots = {**roots.roots, "run": str(run)}
        self.aliases = {}

    def path(self, value):
        require(isinstance(value, str) and value, "missing typed path")
        if value.startswith("<") and value.endswith(">"):
            require(value in ("<built-in>", "<command-line>", "<stdin>"), "unrecognized synthetic source path")
            return "synthetic:" + value
        require(Path(value).is_absolute(), "normalization requires an absolute source path: " + value)
        value = os.path.normpath(value)
        if value in self.aliases:
            return self.aliases[value]
        matches = [(len(Path(root).parts), role, Path(value).relative_to(root).as_posix())
                   for role, root in self.roots.items() if Path(value).is_relative_to(root)]
        if matches:
            _, role, relative = max(matches)
            return role + ":" + relative
        return "absolute:" + value

    def argv(self, values, *, omit_resources=False):
        if isinstance(values, str):
            values = shlex.split(values)
        require(isinstance(values, list) and values and all(isinstance(v, str) for v in values), "malformed command argv")
        result, index = [], 0
        while index < len(values):
            value = values[index]
            require(value not in (";", "&&", "||", "|", ">", "<"), "shell command is outside replay scope")
            if omit_resources and value in RESOURCE_OPTIONS:
                require(index + 1 < len(values), "missing resource option value")
                index += 2
                continue
            if value == "-cpp-command":
                require(index + 1 < len(values), "missing CPP command")
                result += [value, self.argv(values[index + 1])]
                index += 2
                continue
            if value.startswith("/"):
                result.append({"path": self.path(value)})
            elif value.startswith(("-I/", "-L/")):
                result.append({"option": value[:2], "path": self.path(value[2:])})
            elif value.startswith("-fmacro-prefix-map="):
                source, separator, replacement = value[len("-fmacro-prefix-map="):].partition("=")
                require(separator and source.startswith("/"), "unsupported macro prefix map")
                result.append({"option": "-fmacro-prefix-map", "source": self.path(source), "replacement": replacement})
            else:
                # In particular, do not alter -D string literals or unrecognized
                # embedded paths. A changed opaque value changes the identity.
                result.append(value)
            index += 1
        return result

    def metadata(self, value, field=None):
        if isinstance(value, dict):
            if {"path", "line", "function", "kind", "status", "property"} <= value.keys():
                value = {key: item for key, item in value.items() if key != "report_row"}
            return {(self.path(key) if key.startswith("/") else key): self.metadata(item, key)
                    for key, item in value.items()}
        if field in COMMAND_FIELDS and isinstance(value, (str, list)) and value:
            return self.argv(value)
        if field in ARGV_FIELDS and isinstance(value, list) and value:
            return self.argv(value)
        if field in PATH_LIST_FIELDS and isinstance(value, str):
            return [self.path(path) if path.startswith("/") else {"literal_search_directory": path}
                    for path in value.split(os.pathsep)]
        if isinstance(value, list):
            return [self.metadata(item) for item in value]
        if field in PATH_FIELDS and isinstance(value, str) and value.startswith("/"):
            return self.path(value)
        return value


def normalize_linemarkers(text, mapper):
    """Only C linemarker filename fields change; C/ACSL text stays byte-exact."""
    lines, state = [], "code"
    for line in text.splitlines(keepends=True):
        suffix = "\n" if line.endswith("\n") else ""
        body = line[:-1] if suffix else line
        match = LINE_MARKER.fullmatch(body)
        if match and state == "code":
            path = match[2]
            if not path.startswith(("/", "<")):
                # Relative locations affect diagnostics; preserving them is
                # conservative until an exact preprocessor cwd map exists.
                lines.append(line)
                continue
            lines.append(match[1] + json.dumps(mapper.path(path)) + match[3] + suffix)
        else:
            lines.append(line)
        # A linemarker-shaped line inside a C/ACSL comment or literal is content,
        # not source metadata. Preserve it and only advance lexical state here.
        index = 0
        while index < len(line):
            if state == "comment":
                if line.startswith("*/", index): state, index = "code", index + 2
                else: index += 1
            elif state in ('"', "'"):
                if line[index] == "\\": index += 2
                elif line[index] == state: state, index = "code", index + 1
                else: index += 1
            elif line.startswith("//", index):
                break
            elif line.startswith("/*", index): state, index = "comment", index + 2
            elif line[index] in ('"', "'"): state, index = line[index], index + 1
            else: index += 1
    return "".join(lines)


def goal_view(row, mapper):
    return {**{key: row[key] for key in ("goal", "property", "line", "function", "smoke", "passed", "verdict", "outcome")},
            "path": mapper.path(row["path"])}


def property_view(row, mapper):
    return {**{key: row[key] for key in ("line", "function", "kind", "status", "outcome", "property", "names")},
            "path": mapper.path(row["path"]), "exported_identity_ambiguous": row.get("exported_identity_ambiguous", False)}


def warning_view(row, mapper):
    require(isinstance(row, dict) and isinstance(row.get("message"), str), "unstructured warning cannot be compared")
    require(set(row) <= {"plugin", "severity", "message", "path", "file", "line", "function", "log_line", "raw_lines"}, "unknown warning fields")
    result = {key: row[key] for key in ("plugin", "severity", "message", "line", "function") if key in row}
    path = row.get("path", row.get("file"))
    if path:
        result["path"] = mapper.path(path)
    raw = row.get("raw_lines", [])
    require(isinstance(raw, list) and all(isinstance(line, str) for line in raw), "invalid warning source excerpts")
    result["raw_lines"] = [result["path"] + line[len(path):] if path and line.startswith(path + ":") else line for line in raw]
    return result


def sorted_rows(rows):
    # Keep multiplicity: turning diagnostics/properties into a set hides losses.
    return sorted(rows, key=canonical)


def analysis_limits(evidence, summary, shared, project):
    argv = evidence["analysis_command"]["argv"]

    def argument(option):
        positions = [index for index, value in enumerate(argv) if value == option]
        require(len(positions) == 1 and positions[0] + 1 < len(argv), "missing or duplicate resource flag: " + option)
        value = argv[positions[0] + 1]
        require(re.fullmatch(r"[1-9][0-9]*", value), "invalid command resource limit")
        return int(value)

    if "analysis_limits" in evidence:
        limits = evidence["analysis_limits"]
        require(isinstance(limits, dict) and set(limits) == {"wall_timeout_seconds", "solver_timeout_seconds", "jobs"}, "unsupported analysis limit schema")
        require(all(type(value) is int and value > 0 for value in limits.values()), "analysis limits must be positive integers")
        require(limits["wall_timeout_seconds"] <= 86400 and limits["solver_timeout_seconds"] <= 3600 and limits["jobs"] <= 256, "analysis resource limits out of range")
        require(summary.get("analysis_limits") == limits, "summary/target analysis limits disagree")
        if evidence["target"]["analysis"] == "wp":
            require(limits["solver_timeout_seconds"] == argument("-wp-timeout") and limits["jobs"] == argument("-wp-par"), "recorded limits disagree with actual command")
        return limits, "recorded"
    runner = shared.get(str(Path(project) / "fragma/suite.py"))
    if runner in LEGACY_WALL_RUNNERS and evidence["target"]["analysis"] == "wp":
        timeout, jobs = argument("-wp-timeout"), argument("-wp-par")
        return {"wall_timeout_seconds": max(180, timeout * 60), "solver_timeout_seconds": timeout, "jobs": jobs}, "derived-from-pinned-legacy-runner"
    return None, "unavailable-in-legacy-receipt"


def outcome_view(target, evidence, mapper):
    evaluation = evidence["evaluation"]
    for name in ("accepted", "verified", "local_policy_passed"):
        require(type(evaluation.get(name)) is bool, "evaluation has a non-Boolean " + name)
    require(evidence.get("accepted") is evaluation["accepted"] and evidence.get("status") == evaluation.get("status"), "target/evaluation verdicts disagree")
    smoke = evaluation.get("smoke", {})
    result = {"status": evaluation["status"], "accepted": evaluation["accepted"],
              "verified": evaluation["verified"], "local_policy_passed": evaluation["local_policy_passed"],
              "goals": sorted_rows([goal_view(row, mapper) for row in evidence["goals"]]),
              "properties": sorted_rows([property_view(row, mapper) for row in evidence["properties"]]),
              "warnings": sorted_rows([warning_view(row, mapper) for row in evidence["warnings"]]),
              "smoke": {key: value for key, value in smoke.items() if key != "goals"}}
    for field in ("issues", "unresolved_dependencies", "dependency_report_omissions", "trusted_dependencies",
                  "confirmed_invalid_properties", "native_invalid_properties", "reviewed_unreachable_properties",
                  "required_companion", "companion_evidence", "review_context"):
        result[field] = mapper.metadata(evaluation.get(field, [] if field == "native_invalid_properties" else None))
    result["unselected_property_ambiguities"] = sorted_rows([property_view(row, mapper)
        for row in evaluation.get("unselected_property_ambiguities", [])])
    result["reviewed_smoke"] = [{"goal_record": goal_view(row["goal_record"], mapper),
        **mapper.metadata({key: value for key, value in row.items() if key != "goal_record"})}
        for row in evaluation.get("reviewed_smoke", [])]
    result["reviewed_warnings"] = [{"warning": warning_view(row["warning"], mapper),
        "review": mapper.metadata(row["review"])} for row in evaluation.get("reviewed_warnings", [])]
    return result


def tool_identity(tools, mapper):
    require(type(tools.get("schema_version")) is int and tools["schema_version"] == 1, "unsupported toolchain receipt schema")
    require(tools.get("ok") is True and tools.get("issues") == [], "toolchain preflight did not pass")
    require(isinstance(tools.get("lock_sha256"), str) and SHA.fullmatch(tools["lock_sha256"]), "toolchain lock hash missing")
    runtime = tools["runtime_receipt"]
    # ldd's raw output embeds ASLR load addresses. Its parsed libraries, hashes,
    # command/status and all shipped support files remain semantic inputs.
    commands = [{key: value for key, value in row.items() if key != "output"}
                for row in runtime["linker_commands"]]
    selected = {**tools, "runtime_receipt": {**runtime, "linker_commands": commands}}
    selected["tools"] = {name: {key: value for key, value in row.items() if key not in ("output",)}
                         for name, row in tools["tools"].items()}
    return mapper.metadata(selected)


def profile_identity(model, mapper):
    require(type(model.get("schema_version")) is int and model["schema_version"] == 1, "unsupported profile receipt schema")
    require(model.get("status") == "passed" and model.get("level") == "L1", "configured L1 evidence required")
    require(model.get("checks") and all(row.get("status") == "passed" for row in model["checks"]), "profile checks incomplete")
    fields = ("profile_id", "profile_sha256", "kernel_revision", "compiler", "frama_c", "generator",
              "generator_headers", "header_hashes", "exported_header_inputs", "fixture_sha256", "build", "analysis", "execution_environment")
    selected = {key: model.get(key) for key in fields}
    selected["machdep"] = {key: model["machdep"][key] for key in ("sha256", "checked_fields")}
    selected["build"] = {key: value for key, value in model["build"].items() if key != "calibration"}
    selected["configured_calibration_inputs"] = model["build"]["calibration"]["input_hashes"]
    # Inherited/supplied labels are procedural; actual settings stay bound.
    selected["execution_environment"] = {key: value for key, value in model["execution_environment"].items() if key != "source"}
    return mapper.metadata(selected)


def build_replay_view(summary_path, *, roots, policy=POLICY):
    """Validate retained evidence and return three distinct canonical identities.

    Physical snapshots are never rewritten. A changed historical input that is
    not needed to reparse a report remains its old recorded hash; this function
    does not claim that a historical execution is presently rerunnable.
    """
    # Local import permits the suite to use this module without an import cycle.
    from fragma.suite import warnings_from_log

    require(policy == POLICY, "unsupported replay policy")
    summary_path = Path(summary_path).resolve()
    run = summary_path.parent
    mapper = Mapper(roots, run)
    artifacts = {}

    def read(path, expected=None, *, binary=False):
        path = Path(path)
        require(path.is_file() and not path.is_symlink(), "missing or symlinked retained artifact: " + str(path))
        actual = file_hash(path)
        require(expected is None or actual == expected, "retained artifact hash changed: " + str(path))
        artifacts[str(path)] = actual
        return path.read_bytes() if binary else path.read_text()

    try:
        summary = strict_json(read(summary_path))
        require(type(summary.get("schema_version")) is int and summary["schema_version"] == 1, "unsupported run schema")
        require(summary.get("output") == str(run), "summary output is not its actual retained run directory")
        require(summary.get("status") in ("passed", "incomplete") and type(summary.get("accepted")) is bool, "run is not terminal")
        started, completed = datetime.fromisoformat(summary["started_at"]), datetime.fromisoformat(summary["completed_at"])
        require(started.tzinfo is not None and completed.tzinfo is not None and completed >= started, "invalid or unordered observed execution timestamps")
        require(isinstance(summary.get("revision"), str) and re.fullmatch(r"[0-9a-f]{40}", summary["revision"]), "run has no exact kernel revision")
        selected = summary.get("selected_targets")
        require(isinstance(selected, list) and selected and all(isinstance(item, str) for item in selected) and len(selected) == len(set(selected)), "invalid target selection")
        records = summary.get("targets")
        require(isinstance(records, list) and [row["target"]["id"] for row in records] == selected, "missing, duplicate or reordered target receipt")
        require(summary["accepted"] is all(row.get("accepted") is True for row in records), "suite acceptance disagrees with targets")
        require(summary["status"] == ("passed" if summary["accepted"] else "incomplete"), "suite status disagrees with acceptance")
        require(canonical(summary.get("counts")) == canonical(dict(Counter(row["status"] for row in records))), "suite counts disagree with targets")
        shared = hash_records(summary["integrity_inputs"])
        tools = strict_json(read(run / "toolchain.json"))
        models = summary["profiles"]
        require(set(models) == {row["target"]["profile"] for row in records}, "profile inventory differs from selected targets")
        inventoried = dict(shared)
        for evidence in records:
            for filename, expected in hash_records(evidence["integrity_inputs"]).items():
                require(filename not in inventoried or inventoried[filename] == expected, "conflicting run input inventories")
                inventoried[filename] = expected
        for filename, expected in metadata_claims([tools, *models.values()]):
            require(isinstance(expected, str) and SHA.fullmatch(expected) and inventoried.get(filename) == expected,
                    "tool/model metadata claim is missing or contradicts inventoried hash: " + filename)
        identities, executions, outcomes, reevaluations, limit_evidence = {}, {}, {}, [], {}
        policy_evidence = {}
        for identifier, model in models.items():
            require(model.get("profile_id") == identifier and model.get("kernel_revision") == summary["revision"], "profile label/revision disagrees with selected model")
            require(digest(strict_json(read(run / ("profile-" + identifier) / "profile.json"))) == digest(model), "profile receipt differs from summary")
            identities["profile:" + identifier] = profile_identity(model, mapper)
            identities["profile:" + identifier]["analysis_policy"] = model_policy_observation(model, read)
        for evidence in records:
            target, identifier = evidence["target"], evidence["target"]["id"]
            directory = run / identifier
            require(digest(strict_json(read(directory / "result.json"))) == digest(evidence), "target receipt differs from summary")
            require(evidence["provenance"].get("passed") is True and not evidence.get("changed_inputs"), "source/integrity gate failed")
            hashes = hash_records(evidence["integrity_inputs"])
            for filename, expected in shared.items():
                require(filename not in hashes or hashes[filename] == expected, "shared/target input hash conflict")
            for filename, expected in hashes.items():
                if Path(filename).is_relative_to(run):
                    read(filename, expected, binary=True)
            audit = evidence["analyzer_audit"]
            raw_audit = strict_json(read(audit["path"], audit["sha256"]))
            require(raw_audit and digest({key: value for key, value in raw_audit.items() if key != "sources"}) == digest(audit["parameters"]), "analyzer parameter audit differs")
            observed_policy = analysis_policy_observation(models[target["profile"]], target,
                                                         evidence, shared, roots.roots["project"])
            policy_evidence[identifier] = observed_policy["status"]
            sources = raw_audit.get("sources")
            require(isinstance(sources, dict) and sources and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) for value in sources.values()), "invalid raw consumed-source audit")
            observed_paths = {str((Path(name) if Path(name).is_absolute() else Path(evidence["input"]["cwd"]) / name).resolve()) for name in sources}
            require(observed_paths == {row["absolute_path"] for row in audit["inputs"]}, "raw consumed-source inventory differs")
            dependencies = read(directory / "headers.d").replace("\\\n", "")
            require(dependencies.startswith("fragma:"), "unexpected compiler dependency target")
            dependency_paths = {str((Path(name) if Path(name).is_absolute() else Path(evidence["input"]["cwd"]) / name).resolve())
                for name in shlex.split(dependencies.split(":", 1)[1].replace("$$", "$"), comments=False)}
            require(dependency_paths == {row["absolute_path"] for row in evidence["input"]["inputs"]}, "compiler dependency inventory differs")
            retained = audit["retained_preprocessing"]
            require(isinstance(retained, list) and retained, "missing actual preprocessor artifacts")
            retained_paths = {}
            for row in retained:
                path = Path(row["absolute_path"])
                require(path.is_relative_to(directory / "tmp") and str(path.relative_to(directory)) == row["path"], "retained preprocessor path escapes target")
                require(str(path) not in retained_paths, "duplicate retained preprocessor artifact")
                read(path, row["sha256"])
                retained_paths[str(path)] = row
                if path.name in ("__fc_builtin_macros.h", "__fc_machdep.h") or re.fullmatch(r"ppannot[0-9a-f]+\.c", path.name):
                    kind = "ppannot.c" if path.name.startswith("ppannot") else path.name
                    mapper.aliases[str(path)] = "generated:" + identifier + ":" + kind + ":" + row["sha256"]
            actual_retained = {str(path) for path in (directory / "tmp").rglob("*") if path.is_file()}
            require(set(retained_paths) == actual_retained, "retained preprocessor inventory incomplete")
            streams = audit["parsed_streams"]
            expected_sources = [target[field] for field in ("harness", "driver") if target.get(field)]
            require([row["source"] for row in streams] == expected_sources, "parsed stream/source inventory differs")
            stream_hashes = {}
            for row in streams:
                require(row["absolute_path"] in retained_paths and row["sha256"] == retained_paths[row["absolute_path"]]["sha256"] and row["path"].endswith(".pp"), "actual parsed stream not bound to retained artifact")
                text = read(row["absolute_path"], row["sha256"])
                stream_hashes[row["source"]] = hashlib.sha256(normalize_linemarkers(text, mapper).encode()).hexdigest()
            from fragma import common24_calibration, frontend_policy
            observed_frontend = frontend_policy.observation(roots.roots["project"], target,
                models[target["profile"]], evidence, shared, read=read)
            observed_compiler = common24_calibration.observation(roots.roots["project"], target,
                models[target["profile"]], evidence, shared, read=read)
            command = evidence["analysis_command"]
            require(type(command["returncode"]) is int and command["returncode"] == 0 and command["timed_out"] is False, "analysis process did not complete")
            read(command["log"], command["log_sha256"])
            require(digest(warnings_from_log(Path(command["log"]))) == digest(evidence["warnings"]), "raw diagnostics disagree with embedded warnings")
            source_files = [Path(roots.roots["project"]) / source for source in expected_sources]
            for path in source_files:
                require(str(path) in hashes and file_hash(path) == hashes[str(path)], "assertion source unavailable or changed")
            if target["analysis"] == "wp":
                strict_json(read(directory / "wp.json"))
                goals = report.parse_wp_report(directory / "wp.json")
            else:
                require(target["analysis"] == "eva", "unsupported analyzer")
                goals = []
            read(directory / "properties.tsv")
            selected_functions = set(target.get("analysis_functions", target["functions"]))
            if target.get("entry"):
                selected_functions.add(target["entry"])
            properties = report.parse_properties(directory / "properties.tsv", source_files=source_files,
                source_root=evidence["input"]["cwd"], selected_functions=selected_functions,
                predicate_starts=assertion_predicate_starts(shared, roots.roots["project"]))
            # report_row was added to the TSV parser after the initial passing
            # runs. It is physical receipt position, not property/source identity.
            strip_row = lambda rows: [{key: value for key, value in row.items() if key != "report_row"} for row in rows]
            require(digest(goals) == digest(evidence["goals"]) and digest(strip_row(properties)) == digest(strip_row(evidence["properties"])), "raw analyzer reports disagree with embedded outcomes")
            ordinary_counts = dict(Counter(row["outcome"] for row in goals if not row["smoke"]))
            require(evidence["evaluation"]["counts"]["goals"] == ordinary_counts, "goal counts disagree with raw report")
            require(all(row.get("review_status") in ("reviewed", "reviewed-assumption") for row in evidence["assumptions"]), "assumption approvals are incomplete")
            reevaluated = report.evaluate_target(target, goals, properties,
                returncode=command["returncode"], warnings=evidence["warnings"],
                validated_review=evidence.get("validated_review"), validated_native=evidence.get("validated_native"))
            reevaluated, observed_inventory = common24_observation(roots.roots["project"], target,
                evidence, goals, properties, reevaluated, shared)
            reevaluations.append(reevaluated)
            external = {mapper.path(path): sha for path, sha in hashes.items() if not Path(path).is_relative_to(run)}
            identities[identifier] = {"target": mapper.metadata(target), "external_inputs": external,
                "consumed_inputs": mapper.metadata(evidence["input"]["inputs"]),
                "analyzer_inputs": mapper.metadata(audit["inputs"]), "parsed_streams": stream_hashes,
                "analyzer_parameters": mapper.metadata(audit["parameters"]),
                "assumptions": mapper.metadata(evidence["assumptions"]),
                "preprocessor": mapper.argv(evidence["input"]["frama_cpp_command"]),
                "analysis": mapper.argv(command["argv"], omit_resources=True),
                "review": mapper.metadata(evidence.get("validated_review")),
                "native": mapper.metadata(evidence.get("validated_native")),
                "analysis_policy": observed_policy}
            if observed_frontend is not None:
                identities[identifier]["frontend_policy"] = frontend_policy.logical_observation(observed_frontend)
                identities[identifier]["common24_inventory"] = observed_inventory["inventory"]
            if observed_compiler is not None:
                identities[identifier]["compiler_calibration"] = common24_calibration.logical_observation(observed_compiler, mapper)
            limits, limit_origin = analysis_limits(evidence, summary, shared, roots.roots["project"])
            limit_evidence[identifier] = limit_origin
            executions[identifier] = {"argv": mapper.argv(command["argv"]), "cwd": mapper.path(command["cwd"]), "analysis_limits": limits,
                "returncode": command["returncode"], "timed_out": command["timed_out"]}
            outcomes[identifier] = outcome_view(target, evidence, mapper)
        finalized = report.finalize_companions(reevaluations)
        for row, evidence in zip(finalized, records):
            for field in ("accepted", "verified", "status", "local_policy_passed"):
                require(canonical(row[field]) == canonical(evidence["evaluation"][field]), "saved evaluation disagrees with recomputed policy: " + field)
            require(digest(outcome_view(evidence["target"], {**evidence, "evaluation": row}, mapper)) ==
                    digest(outcomes[evidence["target"]["id"]]), "saved dependency/review/smoke outcome disagrees with recomputed policy")
        input_view = {"revision": summary["revision"], "targets": sorted(selected),
                      "shared_inputs": {mapper.path(path): sha for path, sha in shared.items()},
                      "tools": tool_identity(tools, mapper), "identities": identities}
        outcome = {"accepted": summary["accepted"], "status": summary["status"], "targets": outcomes}
        return {"schema_version": 1, "policy": policy, "status": "comparable",
                "accepted": summary["accepted"], "inputs": input_view, "execution": executions, "outcomes": outcome,
                "input_id": digest(input_view), "execution_id": digest(executions), "outcome_id": digest(outcome),
                "evidence_id": digest(artifacts), "artifacts": artifacts,
                "run_instance": {"directory": str(run), "started_at": summary["started_at"],
                    "completed_at": summary["completed_at"], "summary_sha256": artifacts[str(summary_path)]},
                "limit_evidence": limit_evidence,
                "analysis_policy_evidence": policy_evidence,
                "limits": ["No cache acceptance or transferred review authorization.",
                           "Raw build/review/native receipt hashes remain conservative input anchors.",
                           "Legacy-observed analysis retains its disabled pointer-formation setting; it is not current-policy evidence.",
                           "Historical external inputs are identified, not claimed currently rerunnable."]}
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ReplayError):
            raise
        raise ReplayError("cannot construct replay view: " + str(exc)) from exc


def differences(left, right, path=""):
    if canonical(left) == canonical(right):
        return []
    if isinstance(left, dict) and isinstance(right, dict):
        result = []
        for key in sorted(left.keys() | right.keys()):
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in left or key not in right:
                result.append({"path": child, "kind": "added" if key not in left else "removed"})
            else:
                result.extend(differences(left[key], right[key], child))
        return result
    return [{"path": path or "/", "kind": "changed", "left_sha256": digest(left), "right_sha256": digest(right)}]


def compare_replays(left, right):
    for value in (left, right):
        require(type(value.get("schema_version")) is int and value.get("schema_version") == 1 and value.get("policy") == POLICY and value.get("status") == "comparable", "invalid replay view")
        require(type(value.get("accepted")) is bool, "replay acceptance must be Boolean")
        for field, identity in (("inputs", "input_id"), ("execution", "execution_id"), ("outcomes", "outcome_id")):
            require(value.get(identity) == digest(value[field]), "replay view digest mismatch: " + field)
        require(value["accepted"] is value["outcomes"].get("accepted"), "view/outcome acceptance differs")
        require(value["outcomes"].get("status") == ("passed" if value["accepted"] else "incomplete"), "view/outcome status differs")
        targets = value["inputs"].get("targets")
        require(isinstance(targets, list) and targets and len(targets) == len(set(targets)), "empty or duplicate replay target selection")
        require(set(targets) == set(value["outcomes"]["targets"]) == set(value["execution"]), "replay target identity inventory differs")
        require(value.get("artifacts") and value.get("evidence_id") == digest(value["artifacts"]), "replay artifact inventory digest differs")
        instance = value.get("run_instance")
        require(isinstance(instance, dict) and set(instance) == {"directory", "started_at", "completed_at", "summary_sha256"}, "invalid observed execution identity")
        require(isinstance(instance["directory"], str) and Path(instance["directory"]).is_absolute(), "observed run directory is not absolute")
        require(value["artifacts"].get(str(Path(instance["directory"]) / "summary.json")) == instance["summary_sha256"], "run identity does not bind its actual summary artifact")
    inputs_equal = left["input_id"] == right["input_id"]
    execution_equal = left["execution_id"] == right["execution_id"]
    outcomes_equal = left["outcome_id"] == right["outcome_id"]
    both = left["accepted"] and right["accepted"]
    limits_known = all(row.get("analysis_limits") is not None for view in (left, right) for row in view["execution"].values())
    instances = [view["run_instance"] for view in (left, right)]
    distinct = (instances[0]["directory"] != instances[1]["directory"] and
                instances[0]["summary_sha256"] != instances[1]["summary_sha256"] and
                (instances[0]["started_at"], instances[0]["completed_at"]) !=
                (instances[1]["started_at"], instances[1]["completed_at"]) and
                left["evidence_id"] != right["evidence_id"])
    passed = inputs_equal and execution_equal and outcomes_equal and both and limits_known and distinct
    status = ("same-evidence" if not distinct else "replay-passed" if passed else "inputs-changed" if not inputs_equal else
              "execution-changed" if not execution_equal else "outcomes-changed" if not outcomes_equal else "execution-limits-unavailable" if not limits_known else "matching-incomplete")
    policy_scopes = [{identifier: value["inputs"].get("identities", {}).get(identifier, {})
                     .get("analysis_policy", {}).get("status", "unavailable")
                     for identifier in value["inputs"]["targets"]} for value in (left, right)]
    return {"schema_version": 1, "policy": POLICY, "status": status, "replay_passed": passed,
            "inputs_equal": inputs_equal, "execution_equal": execution_equal,
            "outcomes_equal": outcomes_equal, "both_accepted": both,
            "execution_limits_known": limits_known,
            "distinct_execution_evidence": distinct,
            "analysis_policy_scope": policy_scopes,
            "current_analysis_policy_on_both": all(status == "checked" for scopes in policy_scopes for status in scopes.values()),
            "input_diffs": differences(left["inputs"], right["inputs"]),
            "execution_diffs": differences(left["execution"], right["execution"]),
            "outcome_diffs": differences(left["outcomes"], right["outcomes"]),
            "evidence_ids": [left["evidence_id"], right["evidence_id"]]}
