"""Pure source and complete-inventory gates for the shared common24 target.

The v1 inventory describes the unchanged six-function source graph and the
Frama-C 33 Typed/WP-split exporter, not an architecture or an old run directory.
Callers must authenticate source bytes, raw reports and frontend/model evidence
before using this result. This module neither reads files nor grants acceptance,
warning approvals, consistency, behavioral calibration or architecture support.
"""
from __future__ import annotations

from collections import Counter
import copy
import hashlib
from pathlib import Path
import re

from fragma import provenance, report


class Common24Error(ValueError):
    pass


KERNEL_FUNCTIONS = ("__get_unaligned_be24", "__get_unaligned_le24",
                    "__put_unaligned_be24", "__put_unaligned_le24")
PROJECT_FUNCTIONS = ("fragma_roundtrip_be24", "fragma_roundtrip_le24")
FUNCTIONS = KERNEL_FUNCTIONS + PROJECT_FUNCTIONS
INVENTORY = "frama-c33-typed-common24-v1"
PRELUDE = '''#include "inline-policy.h"
#define inline FRAGMA_COMMON24_INLINE
typedef unsigned char u8;
typedef unsigned int u32;
#include "byteproof.h"
'''
STRATEGY_SHA256 = "9a9c584c56d36329f866e060500d5d64557c63ffc538cf9551fe073b94d53017"
# Reviewed source/specification identities, not verdicts copied from another ABI.
BLOCK_SHA256 = dict(zip(FUNCTIONS, (
    "2821723ffbee914e08abe82c1bce3b08b47c17c6c513b821449564809db12e3b",
    "5f72fb1586c239c9b9813f37c814a84435a87a60bcf3e6167bfe9415928e3722",
    "3ee128bf07d516029b347d68a31b8ae065198d6e57c05e8a35cfcbcea5def6f5",
    "a0312b4baf50595670a00b2ab47f25abf4604a2d9e5e9583269d29c3695a1c06",
    "42e622ae88ac491d3dbb0e4702991751a1c99b20362b79a13c79f7266733cfa8",
    "9cbf25c2e273e5e0ce259abb02d67fda3376594f8d073e05922514b1a21adb88")))
TOKEN_SHA256 = dict(zip(FUNCTIONS, (
    "8720d5e58de09ee04bb766f86789a53d28e31d60f5c70a608e0917ed27a8f7db",
    "9c41856eebd11483f152b5f79825f51c31be37ee42dcdd30e773d645154a6867",
    "65e8dd668d917b4e84be9747cd8ffa4edb351916063c9b1157a5480980033957",
    "f307545d826467623c607060f4cabe6138198d5aa460cead648c4318dc3eda9e",
    "bbd5750718273417eeca26627e4f090e1d0f56f91fb83b34cf51859a3c5bb5f9",
    "53823b0464c3eed2ec4a7bb93be5a68b4c84586ddef953d73fdcd01c29d77454")))
READER_ASSERTIONS = ("decode_decompose_low", "decode_decompose_middle",
                     "extracted_high", "extracted_middle", "extracted_low")
WRITER_ASSERTIONS = ("decompose_low", "decompose_middle", "decompose_high")
REQUIRED_PROPERTIES = tuple(
    [f"get_unaligned_{endian}24_ensures_decoded_{kind}"
     for endian in ("be", "le") for kind in ("value", "range")]
    + [f"put_unaligned_{endian}24_ensures_byte_{byte}"
       for endian in ("be", "le") for byte in range(3)]
    + [f"fragma_roundtrip_{endian}24_ensures_roundtrip" for endian in ("be", "le")])


def require(condition, message):
    if not condition:
        raise Common24Error(message)


def check_target(target):
    require(isinstance(target, dict), "common24 target must be an object")
    for field, expected in (("functions", KERNEL_FUNCTIONS),
                            ("analysis_functions", FUNCTIONS),
                            ("project_functions", PROJECT_FUNCTIONS),
                            ("required_properties", REQUIRED_PROPERTIES)):
        require(target.get(field) == list(expected), "common24 exact target inventory: " + field)
    require(target.get("analysis") == "wp" and target.get("input_mode") == "standalone"
            and target.get("source") == "include/linux/unaligned.h",
            "common24 requires the standalone WP helper source")


def check_source(target, *, source_path, source_text, strategy_text):
    """Check the immutable six annotated blocks; prelude/line positions may move."""
    check_target(target)
    require(isinstance(source_text, str) and isinstance(strategy_text, str),
            "source and strategy must be explicit decoded text")
    require(isinstance(source_path, (str, Path)) and Path(source_path).is_absolute(),
            "source path must be explicitly absolute")
    declarations = list(re.finditer(
        r"^(?:static inline )?(?:u32|void) ([A-Za-z_]\w*)\(", source_text, re.M))
    require([m[1] for m in declarations] == list(FUNCTIONS),
            "source must contain exactly the four helpers and two witnesses")
    functions = []
    outside_blocks = []
    previous_end = 0
    for declaration in declarations:
        name = declaration[1]
        contract_start = source_text.rfind("/*@", 0, declaration.start())
        require(contract_start >= 0, "missing source contract: " + name)
        end = source_text.find("\n}", declaration.end())
        require(end >= 0, "missing function end: " + name)
        outside_blocks.append(source_text[previous_end:contract_start])
        previous_end = end + 2
        block = source_text[contract_start:end + 2]
        block_sha = hashlib.sha256(block.encode()).hexdigest()
        require(block_sha == BLOCK_SHA256[name], "annotated source block changed: " + name)
        parsed = provenance.extract_function(source_text, name)
        token_sha = provenance.token_hash(parsed.tokens)
        expected_prefix = ("static", "inline", "u32" if name.startswith("__get") else "void") \
            if name in KERNEL_FUNCTIONS else ("u32",)
        require(token_sha == TOKEN_SHA256[name] and parsed.declaration_prefix == expected_prefix,
                "source declarator/body changed: " + name)
        functions.append({"function": name, "line": parsed.line,
                          "annotated_block_sha256": block_sha,
                          "c_token_sha256": token_sha,
                          "declaration_prefix": list(parsed.declaration_prefix)})
    outside_blocks.append(source_text[previous_end:])
    prelude_tokens = provenance.tokenize(outside_blocks[0])
    require(prelude_tokens == provenance.tokenize(PRELUDE),
            "source prelude type/include/macro policy changed; selector must come from the CLI")
    # tokenize deliberately rejects empty input; the sentinel makes a comments-
    # only gap observable without weakening malformed-comment/directive checks.
    require(all(provenance.tokenize(text + "\n;") == (";",) for text in outside_blocks[1:]),
            "unexpected token/directive between functions or after the source graph")
    require(len(re.findall(r"/\*@", source_text)) == 22,
            "unexpected or missing source annotation outside the six blocks")
    strategy_sha = hashlib.sha256(strategy_text.encode()).hexdigest()
    require(strategy_sha == STRATEGY_SHA256, "checked byte strategy changed")
    return {"schema_version": 1, "status": "checked", "inventory": INVENTORY,
            "source_path": str(source_path), "functions": functions,
            "strategy_sha256": strategy_sha,
            "prelude_token_sha256": provenance.token_hash(prelude_tokens)}


def _expected(source):
    """Build every ordinary goal and every source-located TSV kind from v1."""
    goals, rows, assertions, guards, calls, smoke = {}, Counter(), [], [], [], []

    def row(name, line, kind, count=1):
        rows[(name, line, kind)] += count

    def goal(name, line, identity, prop=None):
        goals["typed_" + identity] = (name, line, identity if prop is None else prop)

    for function in source["functions"]:
        name, line = function["function"], function["line"]
        stem = name.lstrip("_")
        row(name, line, "postcondition")  # implicit exits false
        if name.startswith("__get"):
            row(name, line - 6, "precondition")
            row(name, line - 5, "termination clause")
            row(name, line, "assigns clause")
            labels, guard_lines = READER_ASSERTIONS, [line + 7]
            ensures = [(line - 3, "decoded_value"), (line - 2, "decoded_range")]
            goal(name, line, stem + "_assigns")
            for kind, count in (("mem_access", 3), ("pointer_value", 3), ("shift", 2)):
                row(name, line + 7, kind, count)
                for index in range(count):
                    goal(name, line + 7, stem + "_assert_rte_" + kind
                         + ("_" + str(index + 1) if index else ""))
            smoke.append((name, line, re.escape(stem + "_wp_smoke_default_requires")))
        elif name.startswith("__put"):
            row(name, line - 7, "precondition")
            row(name, line - 6, "termination clause")
            row(name, line - 5, "assigns clause")
            labels, guard_lines = WRITER_ASSERTIONS, [line + offset for offset in (5, 6, 7)]
            ensures = [(line - 4 + index, "byte_" + str(index)) for index in range(3)]
            for index in range(9):
                goal(name, line - 5, stem + "_assigns_part" + str(index + 1), stem + "_assigns")
            for index, guard_line in enumerate(guard_lines):
                for kind in ("mem_access", "pointer_value"):
                    row(name, guard_line, kind)
                    goal(name, guard_line, stem + "_assert_rte_" + kind
                         + ("_" + str(index + 1) if index else ""))
            smoke.append((name, line, re.escape(stem + "_wp_smoke_default_requires")))
        else:
            row(name, line - 4, "termination clause")
            row(name, line, "assigns clause")
            labels, guard_lines = (), []
            ensures = [(line - 2, "roundtrip")]
            goal(name, line - 4, stem + "_terminates")
            goal(name, line, stem + "_exits")
            for mode, count in (("normal", 3), ("exit", 2)):
                for index in range(count):
                    goal(name, line, stem + "_assigns_" + mode + "_part" + str(index + 1), stem + "_assigns")
            endian = name.removeprefix("fragma_roundtrip_")
            for offset, operation, requirement in ((3, "put", "writable"), (4, "get", "readable")):
                callee = "__" + operation + "_unaligned_" + endian
                row(name, line + offset, "precondition of " + callee)
                prop = stem + "_call_" + callee + "_" + callee.lstrip("_") + "_requires_" + requirement
                goal(name, line + offset, prop, callee.lstrip("_") + "_requires_" + requirement)
                calls.append({"function": name, "callee": callee, "line": line + offset})
                smoke.append((name, line + offset, re.escape(callee.lstrip("_") + "_wp_smoke_dead_call_s") + r"\d+"))
            smoke += [(name, line + 4, re.escape(stem + "_wp_smoke_dead_code_s") + r"\d+")] * 2
        for ensure_line, label in ensures:
            row(name, ensure_line, "postcondition")
            goal(name, ensure_line, stem + "_ensures_" + label)
        for index, label in enumerate(labels):
            assertion_line = line + 2 + index
            row(name, assertion_line, "user assertion")
            goal(name, assertion_line, stem + "_assert_" + label)
            assertions.append({"function": name, "line": assertion_line, "name": label})
        for guard_line in guard_lines:
            guards.append({"function": name, "line": guard_line,
                           "required_kinds": {kind: rows[(name, guard_line, kind)]
                                              for kind in ("mem_access", "pointer_value", "shift")
                                              if rows[(name, guard_line, kind)]}})
    require(len(goals) == 94 and sum(rows.values()) == 82 and len(smoke) == 12,
            "internal common24 exporter inventory is incomplete")
    return goals, rows, assertions, guards, calls, smoke


def evaluate_inventory(target, goals, properties, evaluation, *, source_path, source_text, strategy_text):
    """Return strict progress, independently of generic acceptance/warning policy.

    Inputs must be the strict parser's full rows, never a selected/filtered view.
    Exporter inventory changes fail closed instead of inheriting a past verdict.
    """
    source = check_source(target, source_path=source_path, source_text=source_text,
                          strategy_text=strategy_text)
    expected_goals, expected_rows, assertions, guards, calls, expected_smoke = _expected(source)
    require(isinstance(goals, list) and isinstance(properties, list) and isinstance(evaluation, dict),
            "complete parsed reports and evaluation are required")
    issues = []
    source_path = str(source_path)
    ordinary, smoke = [], []
    seen_goals = set()
    for item in goals:
        require(isinstance(item, dict) and type(item.get("smoke")) is bool,
                "malformed parsed goal")
        require(all(isinstance(item.get(field), str) for field in ("goal", "property", "function", "path"))
                and type(item.get("line")) is int and item["line"] > 0,
                "malformed parsed goal identity/location")
        require(type(item.get("passed")) is bool and item.get("verdict") in report.WP_VERDICTS,
                "malformed parsed goal verdict")
        identity = item.get("goal")
        require(isinstance(identity, str), "goal identity is missing")
        if identity in seen_goals:
            issues.append("duplicate goal: " + identity)
        seen_goals.add(identity)
        (smoke if item["smoke"] else ordinary).append(item)
    observed_goals = {}
    for item in ordinary:
        observed_goals[item["goal"]] = (item.get("function"), item.get("line"), item.get("property"))
        if item.get("path") != source_path or item.get("passed") is not True or item.get("verdict") != "valid":
            issues.append("ordinary goal not valid at authenticated source: " + item["goal"])
    if observed_goals != expected_goals:
        issues.append("ordinary goal identity/location inventory differs")
    observed_rows = Counter()
    identities = set()
    for item in properties:
        require(isinstance(item, dict), "malformed parsed property")
        require(all(isinstance(item.get(field), str) for field in ("function", "kind", "path", "property", "status"))
                and type(item.get("line")) is int and item["line"] > 0
                and isinstance(item.get("names"), list)
                and all(isinstance(name, str) for name in item["names"]),
                "malformed parsed property identity/location")
        key = (item.get("function"), item.get("line"), item.get("kind"))
        observed_rows[key] += 1
        identity = (*key, item.get("path"), item.get("property"))
        if identity in identities or item.get("exported_identity_ambiguous"):
            issues.append("duplicate or ambiguous consolidated property")
        identities.add(identity)
        if item.get("path") != source_path or item.get("status") != "Valid":
            issues.append("consolidated property is not exactly Valid at authenticated source")
    if observed_rows != expected_rows:
        issues.append("consolidated source/kind inventory differs")
    for item in assertions:
        matched = [row for row in properties if (row.get("function"), row.get("line"), row.get("kind"))
                   == (item["function"], item["line"], "user assertion")]
        if len(matched) != 1 or item["name"] not in matched[0].get("names", []):
            issues.append("source assertion label missing: " + item["function"] + ":" + item["name"])
    for function in source["functions"]:
        matched = [row for row in properties if (row.get("function"), row.get("line"), row.get("kind"))
                   == (function["function"], function["line"], "postcondition")]
        if len(matched) != 1 or matched[0].get("property", "").strip() != "\\false":
            issues.append("implicit exit clause missing: " + function["function"])
    for item in properties:
        kind, text, name = item.get("kind"), item.get("property", ""), item.get("function")
        if kind == "termination clause" and text != "\\true":
            issues.append("source termination clause differs")
        if kind == "assigns clause":
            expected = "assigns *(p + (0 .. 2));" if name in KERNEL_FUNCTIONS[2:] else "assigns \\nothing;"
            if text != expected:
                issues.append("source frame clause differs")
        if kind == "precondition":
            label = "readable" if name in KERNEL_FUNCTIONS[:2] else "writable"
            if label not in item.get("names", []):
                issues.append("source precondition label differs")
        if isinstance(kind, str) and kind.startswith("precondition of "):
            label = "readable" if "__get_" in kind else "writable"
            if label not in item.get("names", []):
                issues.append("direct-call precondition label differs")
    for name, line, prop in expected_goals.values():
        if "_ensures_" not in prop:
            continue
        label = prop.split("_ensures_", 1)[1]
        matched = [row for row in properties if (row.get("function"), row.get("line"), row.get("kind"))
                   == (name, line, "postcondition")]
        if len(matched) != 1 or label not in matched[0].get("names", []):
            issues.append("functional postcondition label differs: " + prop)
    for guard in guards:
        name, line = guard["function"], guard["line"]
        actual = Counter((row.get("kind"), row.get("property")) for row in properties
                         if row.get("function") == name and row.get("line") == line)
        expected = Counter()
        if name in KERNEL_FUNCTIONS[:2]:
            for index in range(3):
                expected[("mem_access", f"\\valid_read(p + {index})")] += 1
                expected[("pointer_value", f"\\null ≡ p + {index} ∨ \\object_pointer(p + {index})")] += 1
            for index in ((0, 1) if name.endswith("be24") else (1, 2)):
                expected[("shift", f"0 ≤ (int)*(p + {index})")] += 1
        else:
            start = next(row["line"] for row in source["functions"] if row["function"] == name)
            index = line - start - 5
            temporary = "tmp" if index == 0 else "tmp_" + str(index - 1)
            expected[("mem_access", f"\\valid({temporary})")] += 1
            expected[("pointer_value", "\\null ≡ p + 1 ∨ \\object_pointer(p + 1)")] += 1
        if actual != expected:
            issues.append("source runtime-guard predicates differ: " + name + ":" + str(line))
    unmatched_smoke = list(expected_smoke)
    for item in smoke:
        if item["goal"] != "typed_" + item.get("property", ""):
            issues.append("smoke goal/property identity differs")
        match = next((entry for entry in unmatched_smoke if
            item.get("path") == source_path and item.get("function") == entry[0]
            and item.get("line") == entry[1] and re.fullmatch(entry[2], item.get("property", ""))), None)
        if match is None:
            issues.append("unexpected smoke identity/location")
        else:
            unmatched_smoke.remove(match)
    if unmatched_smoke:
        issues.append("missing smoke inventory")
    dependency_fields = ("unresolved_dependencies", "trusted_dependencies", "dependency_report_omissions")
    require(all(isinstance(evaluation.get(field), list) for field in dependency_fields)
            and isinstance(evaluation.get("issues"), list)
            and all(isinstance(item, dict) for item in evaluation["issues"]),
            "dependency evaluation inventory missing")
    missing_links = [item for item in evaluation["issues"] if
                     item.get("message") == "WP property is missing from the consolidated dependency report"]
    closure = not any(evaluation[field] for field in dependency_fields) and not missing_links
    if not closure:
        issues.append("dependency closure is conditional, trusted or omitted")
    return {"schema_version": 1, "inventory": INVENTORY,
            "status": "complete" if not issues else "incomplete", "ordinary_complete": not issues,
            "source": source, "ordinary_counts": dict(Counter(g.get("verdict") for g in ordinary)),
            "selected_property_counts": dict(Counter(p.get("status") for p in properties)),
            "property_kind_counts": dict(Counter(p.get("kind") for p in properties)),
            "source_assertions": assertions, "source_guard_sites": guards,
            "direct_call_preconditions": calls, "required_functional_properties": list(REQUIRED_PROPERTIES),
            "expected_ordinary_goals": sorted(expected_goals), "issues": issues,
            "dependency_closure_unconditional": closure, "missing_dependency_links": missing_links,
            "smoke": {"count": len(smoke), "verdict_counts": dict(Counter(g.get("verdict") for g in smoke)),
                      "goals": smoke, "consistency_proved": False},
            "consistency_proved": False, "certified": False,
            "boundary": "Inventory progress only; raw/frontend/model gates and fresh warning/smoke/report policy remain mandatory."}


def apply_policy(evaluation, inventory):
    """Copy generic policy, blocking acceptance when the rederived gate is open.

    Callers must supply evaluate_inventory's fresh result, not an unverified saved
    Boolean. A complete inventory never changes generic warnings or acceptance.
    """
    require(isinstance(evaluation, dict), "generic evaluation must be an object")
    result = copy.deepcopy(evaluation)
    complete = (isinstance(inventory, dict)
                and type(inventory.get("schema_version")) is int
                and inventory["schema_version"] == 1
                and inventory.get("inventory") == INVENTORY
                and inventory.get("status") == "complete"
                and inventory.get("ordinary_complete") is True
                and inventory.get("issues") == [])
    if complete:
        return result
    require(isinstance(result.get("issues"), list), "generic evaluation issues must be an array")
    details = inventory.get("issues") if isinstance(inventory, dict) else None
    if not isinstance(details, list) or not details:
        details = ["Missing, malformed or incomplete common24 inventory envelope"]
    result.update(accepted=False, verified=False, local_policy_passed=False, status="incomplete")
    result["issues"].append({"kind": "incomplete",
        "message": "Common24 source/goal/property inventory is incomplete",
        "inventory": INVENTORY, "inventory_issues": copy.deepcopy(details)})
    return result
