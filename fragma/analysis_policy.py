"""Closed analysis semantics and independently checked execution policies.

This deliberately supports one recorded integer policy and one pointer policy.
It is not a raw Frama-C argument escape hatch or a general pipeline executor.
"""

from __future__ import annotations

import copy
from pathlib import Path
import re


class AnalysisPolicyError(ValueError):
    """Missing, unsupported or contradictory analysis semantics."""


ARITHMETIC_FLAGS = (
    "-no-warn-signed-overflow", "-no-warn-unsigned-overflow",
    "-no-warn-signed-downcast", "-no-warn-unsigned-downcast",
    "-no-warn-right-shift-negative",
)
RUNTIME_CHECKS = {"pointer_formation": "object-or-null"}
SEMANTIC_KEYS = {"wp_model", "arithmetic_flags", "runtime_checks"}
DOCUMENTARY_KEYS = {"shift_count_validity", "signed_arithmetic", "pointer_arithmetic"}
GENERATED_KEYS = {"machdep", "cpp_command", "cpp_extra_args", "calibration_cpp_extra_args", "compiler_flags"}
POINTER_FLAG = "-warn-invalid-pointer"
SEMANTIC_OPTIONS = {
    "warn-signed-overflow", "warn-unsigned-overflow", "warn-signed-downcast",
    "warn-unsigned-downcast", "warn-right-shift-negative", "warn-invalid-pointer",
}
STAGE_OPTIONS = {
    "-wp", "-no-wp", "-eva", "-no-eva", "-rte", "-no-rte", "-wp-model",
    "-wp-fct", "-wp-rte", "-wp-no-rte", "-main", "-eva-slevel", "-rte-select",
    "-rte-use-eva-results", "-rte-no-use-eva-results", "-then",
}


def model_identity(analysis):
    """Current-only semantic identity; a missing pointer policy is not defaulted.

    Historical report comparison may describe the old recorded model separately.
    It must never call this current validator after silently adding a default.
    """
    if not isinstance(analysis, dict) or set(analysis) - SEMANTIC_KEYS - DOCUMENTARY_KEYS - GENERATED_KEYS:
        raise AnalysisPolicyError("unknown analysis-policy setting")
    if analysis.get("wp_model") != "Typed":
        raise AnalysisPolicyError("unsupported WP memory model")
    if analysis.get("arithmetic_flags") != list(ARITHMETIC_FLAGS):
        raise AnalysisPolicyError("unsupported or incomplete arithmetic policy")
    runtime = analysis.get("runtime_checks")
    if not isinstance(runtime, dict) or runtime != RUNTIME_CHECKS:
        raise AnalysisPolicyError("missing or unsupported runtime-check policy")
    return {key: copy.deepcopy(analysis[key]) for key in ("wp_model", "arithmetic_flags", "runtime_checks")}


def analyzer_flags(analysis):
    """Generate flags from distinct integer semantics and runtime requirements."""
    identity = model_identity(analysis)
    return [*identity["arithmetic_flags"], POINTER_FLAG]


def _functions(value, field):
    if (not isinstance(value, list) or not value or
            not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) for item in value) or
            len(set(value)) != len(value)):
        raise AnalysisPolicyError("invalid or empty " + field)
    return list(value)


def pipeline_identity(target):
    """Compute a closed plan; the declaration cannot omit selected helpers."""
    if not isinstance(target, dict):
        raise AnalysisPolicyError("target must be an object")
    analysis = target.get("analysis")
    if analysis not in ("wp", "eva"):
        raise AnalysisPolicyError("unsupported target analysis")
    default = "wp-rte" if analysis == "wp" else "eva"
    declaration = target.get("analysis_pipeline", {"kind": default})
    if (not isinstance(declaration, dict) or set(declaration) != {"kind"} or
            declaration["kind"] not in (("wp-rte",) if analysis == "wp" else ("eva", "rte-eva"))):
        raise AnalysisPolicyError("unsupported analysis pipeline")
    kernel_functions = _functions(target.get("functions"), "kernel function inventory")
    selected = _functions(target.get("analysis_functions", kernel_functions), "analysis function inventory")
    if not set(kernel_functions) <= set(selected):
        raise AnalysisPolicyError("analysis inventory omits a selected kernel function")
    if analysis == "wp":
        if any(key in target for key in ("eva_builtins", "eva_auto_builtins")):
            raise AnalysisPolicyError("EVA-specific settings on a WP target")
        return {"kind": "wp-rte", "functions": selected}
    entry = target.get("entry")
    if not isinstance(entry, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", entry):
        raise AnalysisPolicyError("invalid EVA entry")
    builtins = target.get("eva_builtins", [])
    if (not isinstance(builtins, list) or
            not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*", value)
                    for value in builtins) or
            len({value.split(":", 1)[0] for value in builtins}) != len(builtins)):
        raise AnalysisPolicyError("invalid explicit EVA builtin inventory")
    auto_builtins = target.get("eva_auto_builtins", True)
    if type(auto_builtins) is not bool:
        raise AnalysisPolicyError("EVA auto-builtins setting must be Boolean")
    result = {"kind": declaration["kind"], "entry": entry, "eva_slevel": 100,
              "eva_builtins": list(builtins), "eva_auto_builtins": auto_builtins}
    if declaration["kind"] == "rte-eva":
        result.update(rte_functions=[*selected, *([] if entry in selected else [entry])],
                      rte_use_eva_results=False)
    return result


def before_eva_options(target):
    """Insert this before the existing -eva command in the same Frama project."""
    pipeline = pipeline_identity(target)
    if pipeline["kind"] != "rte-eva":
        return []
    return ["-rte", "-rte-select", ",".join(pipeline["rte_functions"]),
            "-rte-no-use-eva-results", "-then"]


def _check_model_command(analysis, argv, audit_parameters):
    identity = model_identity(analysis)
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
        raise AnalysisPolicyError("analysis command is not an argv array")
    if any("=" in arg and arg.split("=", 1)[0] in STAGE_OPTIONS for arg in argv):
        raise AnalysisPolicyError("noncanonical analysis option spelling")
    if any(arg.startswith("-then") and arg != "-then" for arg in argv):
        raise AnalysisPolicyError("unregistered project or phase selector")
    if any(arg in ("-no-wp", "-no-eva", "-no-rte", "-wp-no-rte", "-rte-use-eva-results") for arg in argv):
        raise AnalysisPolicyError("opposing analysis stage control")
    expected_flags = analyzer_flags(analysis)
    observed_flags = []
    for arg in argv:
        option = arg.lstrip("-").removeprefix("no-").split("=", 1)[0]
        if option in SEMANTIC_OPTIONS:
            observed_flags.append(arg)
    if observed_flags != expected_flags:
        raise AnalysisPolicyError("actual semantic flags are missing, duplicated or contradictory")
    first_analysis = min((index for index, arg in enumerate(argv) if arg in ("-wp", "-rte", "-eva")), default=len(argv))
    if first_analysis == len(argv) or any(argv.index(flag) >= first_analysis for flag in expected_flags):
        raise AnalysisPolicyError("semantic flags must precede every analysis phase")
    try:
        correctness = audit_parameters["eva"]["correctness-parameters"]
        if not isinstance(correctness, dict):
            raise AnalysisPolicyError("missing actual correctness audit")
        required = {flag.removeprefix("-no"): "false" for flag in ARITHMETIC_FLAGS}
        required[POINTER_FLAG] = "true"
        if any(correctness.get(key) != value for key, value in required.items()):
            raise AnalysisPolicyError("actual audited semantic settings differ")
    except (KeyError, TypeError) as exc:
        raise AnalysisPolicyError("missing actual correctness audit") from exc
    return identity, correctness


def validate_actual_model_policy(analysis, argv, audit_parameters):
    """Check model-calibration semantic settings, not suite goals or pipelines.

    The model validator separately checks its exact compiler, fixtures, EVA
    assertions and negative controls. It uses a different precision budget from
    a suite target, so it must not pretend to be an ordinary target pipeline.
    """
    identity, _ = _check_model_command(analysis, argv, audit_parameters)
    return {"schema_version": 1, "status": "checked", "model": identity,
            "actual_pointer_formation": "true"}


def validate_actual_policy(analysis, target, argv, audit_parameters):
    """Verify generated command structure and final actual correctness values.

    Every exported guard still has to pass the ordinary strict report policy.
    This check cannot make a missing, Unknown or conditional property Valid.
    The named s390 L2 auditor additionally requires its exact guard inventory.
    """
    identity, correctness = _check_model_command(analysis, argv, audit_parameters)
    pipeline = pipeline_identity(target)
    report_tail = ["-then", "-report", "-report-absolute-path", "-report-csv"]
    if (len(argv) < 5 or argv[-5:-1] != report_tail or not Path(argv[-1]).is_absolute() or
            any(argv.count(option) != 1 for option in report_tail[1:])):
        raise AnalysisPolicyError("analysis must end with exactly one unchanged report phase")
    engine = "-wp" if target["analysis"] == "wp" else "-eva"
    if engine not in argv or argv.index(engine) >= len(argv) - 5:
        raise AnalysisPolicyError("analysis engine must precede the final report phase")
    if target["analysis"] == "eva" and correctness.get("-main") != pipeline["entry"]:
        raise AnalysisPolicyError("actual audited EVA entry differs")
    if target["analysis"] == "eva":
        # Frama-C 33's cumulative CLI map starts from the empty @default
        # override category. This is NOT the separate automatic-builtin
        # registry. Require its exact audit spelling, not generic category
        # stripping, map deduplication, or a fabricated effective setting.
        overrides = ",".join(pipeline["eva_builtins"])
        audited_overrides = "@default," + overrides if overrides else ""
        if (correctness.get("-eva-builtins-auto") != ("true" if pipeline["eva_auto_builtins"] else "false") or
                correctness.get("-eva-builtin") != audited_overrides):
            raise AnalysisPolicyError("actual audited EVA builtin semantics differ")

    def argument(option):
        if argv.count(option) != 1 or argv.index(option) + 1 == len(argv):
            raise AnalysisPolicyError("missing or duplicated analysis selector: " + option)
        return argv[argv.index(option) + 1]

    if pipeline["kind"] == "wp-rte":
        if (argv.count("-wp") != 1 or "-eva" in argv or argv.count("-wp-rte") != 1 or
                argument("-wp-model") != identity["wp_model"] or
                argument("-wp-fct") != ",".join(pipeline["functions"])):
            raise AnalysisPolicyError("actual WP/RTE function selection differs")
    elif (argv.count("-eva") != 1 or "-wp" in argv or
          any(arg in argv for arg in ("-wp-model", "-wp-fct", "-wp-rte")) or
          argument("-main") != pipeline["entry"] or argument("-eva-slevel") != str(pipeline["eva_slevel"])):
        raise AnalysisPolicyError("actual EVA selection or precision differs")
    builtin_indices = [index for index, arg in enumerate(argv)
        if arg.split("=", 1)[0].lstrip("-").startswith((
            "eva-builtin", "eva-no-builtin", "no-eva-builtin",
            "val-builtin", "val-no-builtin", "no-val-builtin"))]
    if target["analysis"] == "wp":
        if builtin_indices:
            raise AnalysisPolicyError("EVA builtin controls on a WP command")
    else:
        eva_index = argv.index("-eva")
        expected_eva = ["-eva", "-main", pipeline["entry"], "-eva-slevel", str(pipeline["eva_slevel"])]
        if not pipeline["eva_auto_builtins"]:
            expected_eva.append("-eva-no-builtins-auto")
        if pipeline["eva_builtins"]:
            expected_eva += ["-eva-builtin", ",".join(pipeline["eva_builtins"])]
        if (argv[eva_index:-5] != expected_eva or
                any(index < eva_index for index in builtin_indices)):
            raise AnalysisPolicyError("actual EVA phase or builtin controls differ")
    rte_options = [arg for arg in argv if arg == "-rte" or arg.startswith("-rte-")]
    if pipeline["kind"] == "rte-eva":
        prefix = before_eva_options(target)
        if (argv.count("-rte") != 1 or argv.count("-eva") != 1 or
                rte_options != ["-rte", "-rte-select", "-rte-no-use-eva-results"] or
                argv[argv.index("-rte"):argv.index("-eva")] != prefix or
                argv.count("-then") != 2):
            raise AnalysisPolicyError("RTE must precede EVA exactly once without result reuse")
    elif rte_options or argv.count("-then") != 1:
        raise AnalysisPolicyError("unregistered analysis stage")
    return {"schema_version": 1, "status": "checked", "model": identity,
            "pipeline": pipeline, "actual_pointer_formation": "true"}
