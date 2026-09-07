"""Strict Frama-C 33 report parsing and property/dependency regression policy.

WP's process status and `passed` field are not proof certificates. In particular,
smoke-test `passed: true, verdict: timeout` means no contradiction was found;
it does not prove that a contract is consistent. The consolidated property TSV
is also required because WP can prove a downstream goal under unproved guards.
"""
from __future__ import annotations

from collections import Counter
import copy
import hashlib
import csv
import io
import json
import math
from pathlib import Path
import re


class ReportError(ValueError):
    """A report is absent, malformed, incomplete, or an unknown format."""


WP_VERDICTS = {"valid", "invalid", "unknown", "timeout", "failed", "noresult", "error"}
CSV_HEADER = ["directory", "file", "line", "function", "property kind", "status", "property"]
CSV_STATUSES = {
    "Valid": "valid", "Invalid": "invalid", "Unknown": "unknown",
    "Partially proven": "pending", "Considered valid": "assumed",
    "Inconsistent": "inconsistent", "Never tried": "unknown",
    "Valid_under_hyp": "pending", "Invalid_under_hyp": "pending",
    "Valid_but_dead": "unreachable", "Invalid_but_dead": "unreachable",
    "Unknown_but_dead": "unreachable", "Considered_valid": "assumed",
    "Valid (under hypotheses)": "pending", "Invalid (under hypotheses)": "pending",
    "Valid (dead)": "unreachable", "Invalid (dead)": "unreachable",
    "Unknown (dead)": "unreachable", "Unreachable": "unreachable", "Dead": "unreachable",
    "Invalid or unreachable": "unreachable",
}


def _read(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReportError(f"Cannot read report {path}: {exc}") from exc
    if not text.strip():
        raise ReportError(f"Empty report: {path}")
    return text


def _wp_rows(data):
    if not isinstance(data, list) or not data:
        raise ReportError("WP report must contain a nonempty goal array")
    result, seen = [], set()
    for index, original in enumerate(data):
        if not isinstance(original, dict):
            raise ReportError(f"WP goal {index} is not an object")
        row = copy.deepcopy(original)
        for field in ("goal", "property", "function", "file", "verdict"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                raise ReportError(f"WP goal {index} has no {field}")
        if row["goal"] in seen:
            raise ReportError("Duplicate WP goal: " + row["goal"])
        seen.add(row["goal"])
        if type(row.get("line")) is not int or row["line"] < 1:
            raise ReportError("WP goal has no valid source line: " + row["goal"])
        if type(row.get("smoke")) is not bool or type(row.get("passed")) is not bool:
            raise ReportError("WP goal has no Boolean smoke/passed fields: " + row["goal"])
        if row["verdict"] not in WP_VERDICTS:
            raise ReportError("Unknown WP verdict: " + row["verdict"])
        provers = row.get("provers")
        if not isinstance(provers, list) or not provers:
            raise ReportError("WP goal has no prover result: " + row["goal"])
        for prover in provers:
            if not isinstance(prover, dict) or not isinstance(prover.get("prover"), str):
                raise ReportError("Malformed WP prover record")
            elapsed = prover.get("time")
            if type(elapsed) not in (float, int) or not math.isfinite(elapsed) or elapsed < 0:
                raise ReportError("Invalid WP prover elapsed time")
            if type(prover.get("success")) is not int or prover["success"] < 0:
                raise ReportError("Invalid WP prover success count")
        if row["smoke"]:
            # A smoke goal attempts to prove inconsistency; successful ordinary
            # theorem proving is therefore a failing smoke check.
            if row["verdict"] in ("failed", "error"):
                row["outcome"] = "tool-error"
            elif row["verdict"] == "valid" or not row["passed"]:
                row["outcome"] = "inconsistent"
            else:
                row["outcome"] = "inconclusive"
        else:
            if row["passed"] != (row["verdict"] == "valid"):
                raise ReportError("Contradictory WP verdict/passed fields: " + row["goal"])
            if row["verdict"] == "valid" and not any(prover["success"] > 0 for prover in provers):
                raise ReportError("Valid WP goal has no successful prover result: " + row["goal"])
            row["outcome"] = {"failed": "tool-error", "error": "tool-error", "noresult": "unknown"}.get(row["verdict"], row["verdict"])
        row["path"] = str(Path(row["file"]).resolve())
        row["solver_seconds"] = sum(prover["time"] for prover in provers)
        result.append(row)
    return result


def parse_wp_report(path):
    try:
        raw = json.loads(_read(path))
    except (json.JSONDecodeError, ValueError) as exc:
        raise ReportError(f"Malformed WP JSON {path}: {exc}") from exc
    return _wp_rows(raw)


def named_assertions(source_files, *, predicate_starts=True):
    """Locate uniquely named ACSL assertions without scanning C string contents.

    The TSV exporter omits assertion labels. Exact file+line mapping ties a
    concrete calibration result back to its named declaration. Frama-C can
    locate a multiline assertion at its predicate's first token, so both exact
    start lines are mapped. Interior lines are not guessed. Multiple assertions
    on one mapped line are ambiguous and require separate source lines.
    """
    if type(predicate_starts) is not bool:
        raise ReportError("Assertion location policy must be Boolean")
    result, owners = {}, {}
    lexical = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)
    for source in source_files:
        path = Path(source).resolve()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ReportError(f"Cannot map assertion source {path}: {exc}") from exc
        for token in lexical.finditer(text):
            if not token[0].startswith(("/*@", "//@")):
                continue
            for assertion in re.finditer(r"\bassert\s+([A-Za-z_]\w*)\s*:\s*", token[0]):
                owner = (str(path), token.start() + assertion.start())
                offsets = (assertion.start(), assertion.end()) if predicate_starts else (assertion.start(),)
                for offset in offsets:
                    line = text.count("\n", 0, token.start() + offset) + 1
                    key = (str(path), line)
                    if key in owners and owners[key] != owner:
                        raise ReportError(f"Ambiguous named assertions at {path}:{line}")
                    result[key], owners[key] = assertion[1], owner
    return result


def parse_properties(path, *, source_files=(), names_by_location=None, source_root=None,
                     selected_functions=None, predicate_starts=True):
    """Read every exported row, retaining unselected location ambiguities.

    Frama-C 33 sorts distinct callsites using their source column, but drops
    that column from TSV output. The default remains strict. A caller may
    provide its complete selected-function scope to retain (never deduplicate)
    identical-status rows outside that scope. These rows cannot support a
    selected proof, calibration, or dependency claim.
    """
    if selected_functions is not None:
        if (not isinstance(selected_functions, (list, tuple, set, frozenset)) or
                not selected_functions or
                not all(isinstance(name, str) and name for name in selected_functions)):
            raise ReportError("Selected property scope must contain nonempty function names")
        selected_functions = set(selected_functions)
    text = _read(path)
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter="\t", quoting=csv.QUOTE_NONE, strict=True))
    except csv.Error as exc:
        raise ReportError(f"Malformed property TSV: {exc}") from exc
    if not rows or rows[0] != CSV_HEADER:
        raise ReportError("Unexpected Frama-C property TSV header")
    if len(rows) == 1:
        raise ReportError("Property report contains only a header, no properties")
    names = named_assertions(source_files, predicate_starts=predicate_starts)
    for location, name in (names_by_location or {}).items():
        if not isinstance(location, tuple) or len(location) not in (2, 3) or not isinstance(name, str) or not name:
            raise ReportError("Assertion map keys must be (path,line[,function]) and values nonempty names")
        key = (str(Path(location[0]).resolve()), int(location[1]), *location[2:])
        if key in names and names[key] != name:
            raise ReportError("Conflicting assertion location names")
        names[key] = name
    base = Path(source_root or Path.cwd()).resolve()
    result, seen = [], {}
    for number, values in enumerate(rows[1:], 2):
        if len(values) != len(CSV_HEADER):
            raise ReportError(f"Malformed property TSV row {number}: expected {len(CSV_HEADER)} columns")
        raw = dict(zip(CSV_HEADER, values))
        if not raw["function"] or not raw["property"] or not raw["property kind"] or not raw["file"]:
            raise ReportError(f"Property TSV row {number} lacks identity")
        try:
            line = int(raw["line"])
        except ValueError as exc:
            raise ReportError(f"Invalid property TSV line at row {number}") from exc
        if line < 1 or raw["status"] not in CSV_STATUSES:
            raise ReportError(f"Unknown property status/source line at row {number}: {raw['status']}")
        full_path = Path(raw["directory"]) / raw["file"]
        if not full_path.is_absolute():
            full_path = base / full_path
        full_path = str(full_path.resolve())
        identity = (full_path, line, raw["function"], raw["property kind"], raw["property"])
        previous = seen.get(identity, [])
        if previous and (selected_functions is None or raw["function"] in selected_functions or
                         any(row["status"] != raw["status"] for row in previous)):
            raise ReportError(f"Duplicate property TSV row: {identity}")
        row = {"path": full_path, "file": raw["file"], "directory": raw["directory"],
               "line": line, "function": raw["function"], "kind": raw["property kind"],
               "status": raw["status"], "outcome": CSV_STATUSES[raw["status"]],
               "property": raw["property"], "names": [], "report_row": number}
        if previous:
            row["exported_identity_ambiguous"] = True
            for prior in previous:
                prior["exported_identity_ambiguous"] = True
        seen.setdefault(identity, []).append(row)
        mapped = names.get((full_path, line, raw["function"]), names.get((full_path, line)))
        if mapped and row["kind"] == "user assertion":
            row["names"].extend([mapped, row["function"] + "_assert_" + mapped])
        label = re.match(r"^([A-Za-z_]\w*):\s", raw["property"])
        if label:
            row["names"].append(label[1])
            suffix = {"postcondition": "ensures", "user assertion": "assert", "loop invariant": "loop_invariant"}.get(row["kind"])
            if suffix:
                row["names"].append(f'{row["function"]}_{suffix}_{label[1]}')
        result.append(row)
    return result


def _property_aliases(row, goals):
    aliases = set(row.get("names", []))
    for goal in goals:
        if goal["smoke"] or goal["function"] != row["function"] or goal["line"] != row["line"] or goal["path"] != row["path"]:
            continue
        prop = goal["property"]
        kind = row["kind"]
        # Frama-C also exports ACSL exits clauses as TSV postconditions.
        compatible = ((kind == "postcondition" and ("_ensures" in prop or "_exits" in prop)) or
                      (kind == "termination clause" and ("_terminates" in prop or "_termination" in prop)) or
                      (kind == "assigns clause" and "_assigns" in prop) or
                      (kind == "loop invariant" and "_loop_invariant" in prop) or
                      (kind == "loop variant" and "_loop_variant" in prop) or
                      (kind.startswith("precondition") and "_requires" in prop) or
                      (kind == "user assertion" and "_assert_" in prop) or
                      (kind not in ("postcondition", "termination clause", "assigns clause", "loop invariant", "user assertion") and "_assert_rte_" in prop))
        if compatible:
            aliases.add(prop)
    return aliases


def _review_path(root, filename):
    if not isinstance(filename, str) or not filename.strip():
        raise ReportError("Review has no exact file path")
    path = (root / filename).resolve()
    if not path.is_relative_to(root):
        raise ReportError("Review file is outside its validated source root")
    return str(path)


def _review_metadata(record, root):
    if not isinstance(record, dict):
        raise ReportError("Review record must be an object")
    hashes = record.get("file_hashes")
    evidence = record.get("review_evidence")
    if not isinstance(hashes, dict) or not hashes:
        raise ReportError("Review requires nonempty file_hashes")
    normalized = {}
    for filename, digest in hashes.items():
        path = _review_path(root, filename)
        if path in normalized or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ReportError("Review has duplicate paths or malformed SHA256 hashes")
        normalized[path] = digest
    if (not isinstance(evidence, list) or not evidence or
            not all(isinstance(item, str) and item.strip() for item in evidence) or
            len(set(evidence)) != len(evidence)):
        raise ReportError("Review requires distinct nonempty review_evidence paths")
    for filename in evidence:
        _review_path(root, filename)
    return normalized


def _validated_reviews(target, envelope, goals, properties, warnings, analysis_funcs):
    """Match externally checked reviews one-to-one; never verify provenance here.

    The suite must check current source/model/build/command hashes and evidence
    before supplying this explicit envelope. A manifest's own reviewed_* fields
    are not authorization. Exact copies in the envelope bind the approval to the
    declared target; status='passed' is the caller's assertion, not a certificate.
    """
    empty = {"context": None, "smoke": {}, "warnings": {}, "unreachable_properties": []}
    declared = any(target.get(key) for key in ("reviewed_smoke", "reviewed_warnings"))
    if envelope is None:
        if declared:
            raise ReportError("Declared reviews require externally validated review metadata")
        return empty
    if not isinstance(envelope, dict) or envelope.get("status") != "passed":
        raise ReportError("Review metadata has not passed the external provenance gate")
    for field, target_field in (("target_id", "id"), ("profile", "profile"), ("analysis", "analysis")):
        if not isinstance(envelope.get(field), str) or envelope[field] != target.get(target_field):
            raise ReportError("Review envelope is for a different " + field)
    source_root = envelope.get("source_root")
    if not isinstance(source_root, str) or not Path(source_root).is_absolute():
        raise ReportError("Review requires an absolute validated source_root")
    root = Path(source_root).resolve()
    context = envelope.get("review_context")
    if not isinstance(context, dict) or context != target.get("review_context"):
        raise ReportError("Review context differs from the declared context")
    if not isinstance(context.get("kernel_revision"), str) or not re.fullmatch(r"[0-9a-f]{40}", context["kernel_revision"]):
        raise ReportError("Review context requires an exact kernel revision")
    if target.get("kernel_revision", context["kernel_revision"]) != context["kernel_revision"]:
        raise ReportError("Review context has a different kernel revision")
    context_hashes = _review_metadata(context, root)
    approved = {**empty, "context": copy.deepcopy(context)}
    for category in ("reviewed_smoke", "reviewed_warnings"):
        records = envelope.get(category)
        if not isinstance(records, list) or records != target.get(category, []):
            raise ReportError("Validated " + category + " differ from the declared records")
        for record in records:
            hashes = _review_metadata(record, root)
            if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                raise ReportError("Review has no individual rationale")
            if any(context_hashes.get(path) != digest for path, digest in hashes.items()):
                raise ReportError("Review file hashes are not bound by the validated context")
            if category == "reviewed_smoke":
                for field in ("goal", "property", "function", "file"):
                    if not isinstance(record.get(field), str) or not record[field].strip():
                        raise ReportError("Smoke review is missing " + field)
                if type(record.get("line")) is not int or record["line"] < 1:
                    raise ReportError("Smoke review requires an exact source line")
                path = _review_path(root, record["file"])
                if path not in hashes or record["function"] not in analysis_funcs:
                    raise ReportError("Smoke review is outside its hashed selected-function scope")
                if not re.fullmatch(r".+_wp_smoke_dead_(?:call|code)_s[0-9]+", record["property"]):
                    raise ReportError("Only individually reviewed dead-call/dead-code smoke may be scoped out")
                matched = [goal for goal in goals if goal["smoke"] and
                           all(goal[field] == record[field] for field in ("goal", "property", "function", "line")) and
                           goal["path"] == path]
                if len(matched) != 1 or matched[0]["outcome"] != "inconsistent":
                    raise ReportError("Smoke review is stale, ambiguous, or not a proved dead path: " + record["goal"])
                if record["goal"] in approved["smoke"]:
                    raise ReportError("Duplicate smoke review: " + record["goal"])
                approved["smoke"][record["goal"]] = copy.deepcopy(record)
                trap = record.get("unreachable_property")
                if trap is not None:
                    if (not isinstance(trap, dict) or
                            not all(isinstance(trap.get(field), str) and trap[field] for field in ("file", "function", "kind", "status", "property")) or
                            type(trap.get("line")) is not int):
                        raise ReportError("Malformed reviewed unreachable property identity")
                    trap_path = _review_path(root, trap["file"])
                    dead_call = re.fullmatch(r"(.+)_wp_smoke_dead_call_s[0-9]+", record["property"])
                    if (trap_path != path or trap["line"] != record["line"] or trap["function"] in analysis_funcs or
                            trap["kind"] != "user assertion" or trap["property"] != r"\false" or
                            CSV_STATUSES.get(trap["status"]) != "unreachable" or
                            not dead_call or dead_call[1] != trap["function"]):
                        raise ReportError("Reviewed false property is not the exact unselected dead-call trap")
                    located = [row for row in properties if row["path"] == trap_path and
                               all(row[field] == trap[field] for field in ("line", "function", "kind", "status", "property"))]
                    if len(located) != 1 or any(item["property_record"] == located[0] for item in approved["unreachable_properties"]):
                        raise ReportError("Reviewed unreachable property is absent, ambiguous, or duplicated")
                    approved["unreachable_properties"].append({"property_record": copy.deepcopy(located[0]),
                        "review": copy.deepcopy(record), "defect_evidence": False})
            else:
                for field in ("message", "plugin"):
                    if not isinstance(record.get(field), str) or not record[field].strip():
                        raise ReportError("Warning review is missing exact " + field)
                functions = record.get("functions")
                if (record.get("severity") != "warning" or not isinstance(functions, list) or
                        not all(isinstance(func, str) and func for func in functions) or
                        len(set(functions)) != len(functions) or set(functions) != analysis_funcs):
                    raise ReportError("Warning review must bind warning severity and the exact analyzed functions")
                if re.search(r"skipp\w* (?:a )?(?:goal|function|property)", record["message"], re.I):
                    raise ReportError("A review cannot waive skipped proof goals, functions, or properties")
                if ("file" in record) != ("line" in record):
                    raise ReportError("Located warning review requires both file and line")
                record_path = None
                if "file" in record:
                    record_path = _review_path(root, record["file"])
                    if record_path not in hashes or type(record["line"]) is not int or record["line"] < 1:
                        raise ReportError("Located warning review is outside its hashed source location")
                matched = []
                for index, warning in enumerate(warnings):
                    if not isinstance(warning, dict) or not all(warning.get(field) == record[field] for field in ("message", "plugin", "severity")):
                        continue
                    warning_file = warning.get("path", warning.get("file"))
                    if warning_file is not None or warning.get("line") is not None or record_path is not None:
                        if (warning_file is None or record_path is None or warning.get("line") != record["line"] or
                                _review_path(root, warning_file) != record_path):
                            continue
                    if "function" in warning and warning["function"] not in analysis_funcs:
                        continue
                    matched.append(index)
                if len(matched) != 1 or matched[0] in approved["warnings"]:
                    raise ReportError("Warning review is stale, ambiguous, or duplicated: " + record["message"])
                approved["warnings"][matched[0]] = copy.deepcopy(record)
    for index, record in approved["warnings"].items():
        if record["message"] == "Missing RTE guards":
            companions = [other for other, warning in enumerate(warnings) if isinstance(warning, dict) and
                          warning.get("plugin") == record["plugin"] and
                          (warning.get("message", "").startswith("Skipped RTE guards:") or
                           warning.get("message", "").startswith("-wp-rte can annotate"))]
            if not companions or any(other not in approved["warnings"] for other in companions):
                raise ReportError("Missing RTE guards cannot be reviewed without every observed companion guard diagnostic")
    return approved


def _validated_native(target, envelope, properties):
    """Match independently gated native observations without rewriting EVA.

    Only the exact ambiguous negative assertion can use this corroboration.
    Unknown/valid analyzer claims and failed positive dependencies still block.
    The suite, not this policy function, authenticates source and runtime inputs.
    """
    if envelope is None:
        return {}
    if (not isinstance(envelope, dict) or envelope.get("status") != "passed" or
            envelope.get("kind") != "native-specification-calibration" or
            target.get("role") != "calibration" or target.get("analysis") != "eva"):
        raise ReportError("Native observations require a passed external gate for an EVA calibration")
    for field, expected in (("target_id", target.get("id")), ("profile", target.get("profile")),
                            ("source", target.get("source")), ("entry", target.get("entry"))):
        if not isinstance(expected, str) or envelope.get(field) != expected:
            raise ReportError("Native observation has a different " + field)
    expected_digest = hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if envelope.get("target_sha256") != expected_digest:
        raise ReportError("Native observation target declaration changed")
    revision, root = envelope.get("kernel_revision"), envelope.get("source_root")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision) or not isinstance(root, str) or not Path(root).is_absolute():
        raise ReportError("Native observation lacks exact revision/source-root identity")
    root = Path(root).resolve()
    assertion_source = target["driver"] if "driver" in target else target.get("harness")
    expected_path = _review_path(root, assertion_source)
    receipt = envelope.get("receipt")
    if (not isinstance(receipt, dict) or not isinstance(receipt.get("sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", receipt["sha256"])):
        raise ReportError("Native observation lacks a hashed runtime receipt")
    _review_path(root, receipt.get("path"))
    observed = envelope.get("properties")
    required, negative = target.get("required_properties", []), set(target.get("expected_invalid", []))
    if (not negative or not isinstance(observed, list) or not all(isinstance(row, dict) for row in observed) or
            [row.get("name") for row in observed] != required):
        raise ReportError("Native observations must exactly cover the ordered required properties")
    accepted = {}
    for observation in observed:
        name = observation["name"]
        if (type(observation.get("expected")) is not bool or type(observation.get("observed")) is not bool or
                observation["expected"] != (name not in negative) or
                observation["observed"] != observation["expected"] or observation.get("reached") is not True):
            raise ReportError("Native observation is not the expected reached Boolean check: " + name)
        if (observation.get("function") != target["entry"] or type(observation.get("line")) is not int or
                observation["line"] < 1 or _review_path(root, observation.get("file")) != expected_path or
                any(not isinstance(observation.get(key), str) or not observation[key].strip()
                    for key in ("acsl", "native_expression"))):
            raise ReportError("Native observation lacks exact reviewed assertion identity: " + name)
        matched = [row for row in properties if row["path"] == expected_path and
                   row["line"] == observation["line"] and row["function"] == target["entry"] and
                   row["kind"] == "user assertion" and name in row.get("names", [])]
        if len(matched) != 1:
            raise ReportError("Native observation is missing or ambiguous in the analyzer report: " + name)
        if name in negative:
            if matched[0]["status"] not in ("Invalid", "Invalid or unreachable"):
                raise ReportError("Native false observation does not match an EVA invalid/ambiguous assertion: " + name)
            accepted[name] = {"property_record": copy.deepcopy(matched[0]),
                              "observation": copy.deepcopy(observation), "receipt": copy.deepcopy(receipt),
                              "classification": "native-corroborated-false-specification",
                              "analyzer_status_unchanged": True, "kernel_defect_evidence": False}
        elif matched[0]["outcome"] != "valid":
            raise ReportError("Native execution cannot replace a failed positive EVA property: " + name)
    return accepted


def evaluate_target(target, wp_goals, properties, *, returncode, warnings, validated_review=None,
                    validated_native=None):
    """Evaluate proof evidence only; caller still enforces provenance/models.

    A calibration can meet expected outcomes while never becoming a verified
    kernel function. Expected WP uncertainty requires an independently confirmed
    companion, finalized only after all selected targets have been gated. Reviews
    require the explicit externally gated envelope documented in _validated_reviews;
    this function checks exact matching but does not read or approve source hashes.
    """
    result = {"target_id": target.get("id"), "profile": target.get("profile"),
              "source": target.get("source"), "role": target.get("role", "proof"),
              "analysis": target.get("analysis"), "status": "incomplete",
              "functions": copy.deepcopy(target.get("functions", [])),
              "accepted": False, "verified": False, "local_policy_passed": False,
              "issues": [], "warnings": copy.deepcopy(warnings), "unresolved_dependencies": [],
              "dependency_report_omissions": [],
              "trusted_dependencies": [], "confirmed_invalid_properties": [], "native_invalid_properties": [],
              "unselected_property_ambiguities": [],
              "review_context": None, "reviewed_smoke": [], "reviewed_warnings": [],
              "reviewed_unreachable_properties": [],
              "required_companion": target.get("required_companion"),
              "expected_unresolved": copy.deepcopy(target.get("expected_unresolved", [])),
              "expected_invalid": copy.deepcopy(target.get("expected_invalid", [])),
              "companion_property_map": copy.deepcopy(target.get("companion_property_map", {})),
              "companion_mapping_reason": target.get("companion_mapping_reason"),
              "smoke": {"count": 0, "inconsistent": 0, "inconclusive": 0,
                        "reviewed_unreachable": 0, "consistency_proved": False, "goals": []}}

    def issue(kind, message, **data):
        result["issues"].append({"kind": kind, "message": message, **data})

    if type(returncode) is not int or returncode != 0:
        issue("tool-error", "Analyzer process did not complete successfully", returncode=returncode)
    funcs = target.get("functions")
    analysis_funcs = target.get("analysis_functions", funcs)
    required = target.get("required_properties")
    structure_valid = True
    for name, values in (("functions", funcs), ("analysis_functions", analysis_funcs), ("required_properties", required)):
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values) or len(set(values)) != len(values):
            issue("incomplete", "Target must declare nonempty distinct " + name)
            structure_valid = False
    if not structure_valid:
        result["status"] = "tool-error" if returncode != 0 else "incomplete"
        return result
    funcs, analysis_funcs, required = set(funcs or []), set(analysis_funcs or []), set(required or [])
    expected_unresolved = set(target.get("expected_unresolved", []))
    expected_invalid = set(target.get("expected_invalid", []))
    if expected_invalid & expected_unresolved or not (expected_unresolved | expected_invalid) <= required:
        issue("incomplete", "Calibration expectations must be disjoint subsets of required properties")
    if (expected_invalid or expected_unresolved) and target.get("role") != "calibration":
        issue("incomplete", "Only calibration targets can declare expected failures")
    if expected_unresolved and not target.get("required_companion"):
        issue("incomplete", "Expected solver uncertainty requires an independent invalidating companion")
    mapping = target.get("companion_property_map", {})
    if (not isinstance(mapping, dict) or set(mapping) != expected_unresolved or
            not all(isinstance(name, str) and name for name in mapping.values())):
        issue("incomplete", "Every expected unresolved property requires an exact companion property mapping")
    if not funcs <= analysis_funcs:
        issue("incomplete", "analysis_functions must include every source function")
    if not isinstance(properties, list) or not properties:
        issue("incomplete", "Missing or empty consolidated property report")
        properties = []
    normalized_properties = []
    for row in properties:
        if not isinstance(row, dict) or not all(key in row for key in ("status", "function", "path", "line", "kind", "property")):
            issue("tool-error", "Malformed consolidated property record")
            continue
        if row["status"] not in CSV_STATUSES:
            issue("tool-error", "Unknown consolidated property status", property_status=row["status"])
            continue
        row = copy.deepcopy(row)
        row["outcome"] = CSV_STATUSES[row["status"]]
        normalized_properties.append(row)
    properties = normalized_properties
    if not isinstance(warnings, list):
        issue("tool-error", "Warnings must be a diagnostic array")
        warnings = []
    goals = []
    if target.get("analysis") == "wp":
        try:
            goals = _wp_rows(wp_goals)
        except ReportError as exc:
            issue("incomplete" if not wp_goals else "tool-error", str(exc))
    try:
        reviews = _validated_reviews(target, validated_review, goals, properties, warnings, analysis_funcs)
        result["review_context"] = reviews["context"]
        result["reviewed_unreachable_properties"] = reviews["unreachable_properties"]
    except (ReportError, OSError, ValueError) as exc:
        issue("review-required", str(exc))
        reviews = {"smoke": {}, "warnings": {}}
    try:
        native = _validated_native(target, validated_native, properties)
    except (ReportError, OSError, ValueError) as exc:
        issue("review-required", str(exc))
        native = {}
    if target.get("analysis") == "wp":
        for func in analysis_funcs:
            if not any(not goal["smoke"] and goal["function"] == func for goal in goals):
                issue("incomplete", "No proof goals for selected function", function=func)
        for goal in goals:
            if goal["function"] not in analysis_funcs:
                issue("incomplete", "WP report contains an unexpected function", function=goal["function"])
            if goal["smoke"]:
                result["smoke"]["count"] += 1
                result["smoke"]["goals"].append(copy.deepcopy(goal))
                if goal["outcome"] == "inconsistent":
                    result["smoke"]["inconsistent"] += 1
                    if goal["goal"] in reviews["smoke"]:
                        result["smoke"]["reviewed_unreachable"] += 1
                        result["reviewed_smoke"].append({"goal_record": copy.deepcopy(goal),
                            "review": reviews["smoke"][goal["goal"]], "classification": "reviewed-dead-path",
                            "consistency_proved": False, "defect_evidence": False})
                    else:
                        issue("inconsistent", "Smoke test detected inconsistent assumptions or a dead path requiring individual review", goal=goal["goal"])
                elif goal["outcome"] == "tool-error":
                    issue("tool-error", "Smoke test tool failure", goal=goal["goal"])
                else:
                    result["smoke"]["inconclusive"] += 1
                continue
            prop, outcome = goal["property"], goal["outcome"]
            if outcome == "valid":
                continue
            if prop in expected_unresolved and outcome in ("unknown", "timeout"):
                continue
            if prop in expected_invalid and outcome == "invalid":
                continue
            issue(outcome, "Required proof goal did not pass", goal=goal["goal"], property=prop)
        for name in required:
            matched = [goal for goal in goals if not goal["smoke"] and goal["property"] == name]
            if not matched:
                issue("incomplete", "Missing required named property", property=name)
            elif name in expected_unresolved and all(goal["outcome"] == "valid" for goal in matched):
                issue("review-required", "Expected unresolved property became valid", property=name)
            elif name in expected_invalid:
                if any(goal["outcome"] == "invalid" for goal in matched):
                    result["confirmed_invalid_properties"].append(name)
                else:
                    issue("review-required" if all(goal["outcome"] == "valid" for goal in matched) else "incomplete", "Expected invalidity was not established", property=name)
        for name in target.get("required_goals", []):
            if not any(goal["goal"] == name for goal in goals):
                issue("incomplete", "Missing named baseline proof goal", goal=name)
        for goal in goals:
            if goal["smoke"]:
                continue
            located = [row for row in properties if row["path"] == goal["path"] and
                       row["line"] == goal["line"] and row["function"] == goal["function"]]
            if not any(goal["property"] in _property_aliases(row, [goal]) for row in located):
                # Frama-C 33's -report-csv omits loop variants (observed in the
                # real MPI calibration). Their WP goals still must all pass;
                # every exported guard/assertion dependency is checked below.
                if "_loop_variant" in goal["property"]:
                    result["dependency_report_omissions"].append({"goal": goal["goal"],
                        "reason": "Frama-C 33 TSV exporter omits loop variants; WP goal retained."})
                    continue
                issue("incomplete", "WP property is missing from the consolidated dependency report", property=goal["property"], goal=goal["goal"])
        if target.get("require_smoke") and not result["smoke"]["count"]:
            issue("incomplete", "Required smoke test evidence is missing")
    elif target.get("analysis") == "eva":
        if wp_goals:
            issue("incomplete", "EVA target unexpectedly supplied WP goals")
        analysis_funcs.add(target.get("entry", "main"))
        for func in funcs | {target.get("entry", "main")}:
            if not any(row["function"] == func for row in properties):
                issue("incomplete", "No property evidence for selected EVA function", function=func)
        for name in required:
            matched = [row for row in properties if row["function"] in analysis_funcs and name in row.get("names", [])]
            if not matched:
                issue("incomplete", "Missing required named EVA property; provide exact source-location mapping", property=name)
            elif name in expected_invalid:
                if all(row["outcome"] == "invalid" for row in matched):
                    result["confirmed_invalid_properties"].append(name)
                elif name in native and len(matched) == 1 and matched[0] == native[name]["property_record"]:
                    result["confirmed_invalid_properties"].append(name)
                    result["native_invalid_properties"].append(native[name])
                else:
                    issue("review-required" if all(row["outcome"] == "valid" for row in matched) else "incomplete", "Expected EVA invalidity was not established", property=name)
            elif not all(row["outcome"] == "valid" for row in matched):
                issue("incomplete", "Required EVA property is not unconditionally valid", property=name)
    else:
        issue("unsupported", "Unsupported analysis kind", analysis=target.get("analysis"))
    selected_rows = [row for row in properties if row["function"] in analysis_funcs]
    result["unselected_property_ambiguities"] = [copy.deepcopy(row) for row in properties
        if row.get("exported_identity_ambiguous") and row["function"] not in analysis_funcs]
    if not selected_rows:
        issue("incomplete", "Consolidated report has no selected-function properties")
    selected_identities = set()
    for row in selected_rows:
        identity = tuple(row[field] for field in ("path", "line", "function", "kind", "property"))
        if row.get("exported_identity_ambiguous") or identity in selected_identities:
            issue("incomplete", "Selected property has an ambiguous exported identity",
                  function=row["function"], path=row["path"], line=row["line"], property=row["property"])
        selected_identities.add(identity)
        outcome = row["outcome"]
        aliases = _property_aliases(row, goals)
        if outcome == "valid":
            continue
        if outcome == "assumed" and row["kind"] in ("precondition", "axiom", "assumption"):
            result["trusted_dependencies"].append(row)
            continue
        if outcome == "pending":
            result["unresolved_dependencies"].append({**row, "aliases": sorted(aliases),
                "note": "Consolidated status is conditional; TSV does not identify every supporting hypothesis."})
        if aliases & expected_invalid and outcome == "invalid":
            continue
        if outcome == "unreachable" and any(name in native and row == native[name]["property_record"]
                                             for name in aliases & expected_invalid):
            continue
        if aliases & expected_unresolved and outcome in ("unknown", "pending"):
            continue
        issue("incomplete" if outcome in ("pending", "assumed", "unreachable") else outcome,
              "Consolidated property is not unconditionally proved", property=row["property"],
              function=row["function"], path=row["path"], line=row["line"], property_status=row["status"])
    for index, warning in enumerate(warnings):
        if (not isinstance(warning, (dict, str)) or
                (isinstance(warning, dict) and
                 (not isinstance(warning.get("message"), str) or warning.get("severity") not in ("warning", "error", "unsupported")))):
            issue("tool-error", "Malformed warning diagnostic", warning_index=index)
            continue
        message = warning.get("message", "") if isinstance(warning, dict) else str(warning)
        severity = warning.get("severity") if isinstance(warning, dict) else None
        if severity == "error":
            issue("tool-error", message)
        elif index in reviews["warnings"]:
            result["reviewed_warnings"].append({"warning_index": index, "warning": copy.deepcopy(warning),
                "review": reviews["warnings"][index]})
        elif severity == "unsupported" or re.search(r"\bunsupported\b|not supported|skipp\w* (?:a )?(?:goal|function|property|RTE guards)", message, re.I):
            issue("unsupported", message)
        elif "Missing RTE guards" in message and "runtime-safety" in target.get("claims", []):
            issue("incomplete", "Runtime-safety claim lacks RTE guards")
    result["counts"] = {"goals": dict(Counter(goal["outcome"] for goal in goals if not goal["smoke"])),
                        "properties": dict(Counter(row["outcome"] for row in selected_rows))}
    result["solver_seconds"] = sum(goal["solver_seconds"] for goal in goals)
    if result["issues"]:
        kinds = {item["kind"] for item in result["issues"]}
        result["status"] = next((kind for kind in ("tool-error", "inconsistent", "unsupported", "review-required", "incomplete", "invalid", "timeout", "unknown") if kind in kinds), "failed")
        return result
    result["local_policy_passed"] = True
    if expected_unresolved:
        result["status"] = "needs-companion"
    else:
        result["accepted"] = True
        result["verified"] = target.get("role", "proof") == "proof"
        result["status"] = "passed" if result["verified"] else "calibration-passed"
    return result


def finalize_companions(results):
    """Return copied evaluation records after cross-target calibration policy.

    Pass evaluations after source/model/toolchain gates have updated `accepted`.
    Missing or failed companions never turn solver uncertainty into refutation.
    """
    records = copy.deepcopy(list(results.values()) if isinstance(results, dict) else list(results))
    lookup = {record["target_id"]: record for record in records}
    if len(lookup) != len(records):
        raise ReportError("Duplicate target IDs during companion policy")
    for record in records:
        companion_id = record.get("required_companion")
        if not companion_id or record.get("status") != "needs-companion":
            continue
        companion = lookup.get(companion_id)
        mapping = record.get("companion_property_map", {})
        unresolved = record.get("expected_unresolved", [])
        mapped = (isinstance(mapping, dict) and isinstance(unresolved, list) and bool(unresolved) and
                  set(mapping) == set(unresolved) and
                  all(isinstance(name, str) and name for name in mapping.values()))
        success = bool(mapped and record.get("local_policy_passed") is True and
                       isinstance(record.get("companion_mapping_reason"), str) and
                       record["companion_mapping_reason"].strip() and
                       companion and companion.get("accepted") is True and
                       companion.get("local_policy_passed") is True and companion.get("verified") is False and
                       companion.get("status") == "calibration-passed" and companion.get("role") == "calibration" and
                       record.get("role") == "calibration" and
                       set(mapping.values()) <= set(companion.get("confirmed_invalid_properties", [])) and
                       set(mapping.values()) <= set(companion.get("expected_invalid", [])) and
                       companion.get("profile") == record.get("profile") and
                       companion.get("source") == record.get("source") and
                       bool(record.get("functions")) and
                       set(companion.get("functions", [])) == set(record["functions"]) and
                       companion.get("analysis") != record.get("analysis"))
        record["accepted"] = success
        record["verified"] = False
        if success:
            record["status"] = "calibration-passed"
            record["companion_evidence"] = {"target_id": companion_id,
                "property_map": mapping, "confirmed_invalid_properties": companion["confirmed_invalid_properties"],
                "mapping_reason": record.get("companion_mapping_reason"),
                "mapping_status": "declared-specification-link",
                "solver_uncertainty_unchanged": True, "kernel_defect_evidence": False}
        else:
            record["status"] = "incomplete"
            record["issues"].append({"kind": "incomplete", "message": "Independent invalidating calibration companion is missing, failed, or does not establish the exact mapped properties", "companion": companion_id})
    return {record["target_id"]: record for record in records} if isinstance(results, dict) else records


parse_wp_json = parse_wp_report
parse_report_csv = parse_properties
apply_companion_policy = finalize_companions
