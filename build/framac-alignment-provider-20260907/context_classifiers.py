"""Pure observations for the unchanged 55 private alignment-context pairs.

No imports, file access, subprocesses, module-loading or import-time actions.
The caller supplies the SHA-checked old diagnose-v2 module as ``old`` and keeps
the complete raw streams/printed source in its own authenticated command record.
Only old.re, old.compiler_values and old.analyzer_values are used here.

The caller is responsible for transport, version, machine-policy, generated
header, preprocessing, artifact, private-runtime and input-identity gates.
This module cannot award support or validate any of those prerequisites.
"""


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _check_case(case):
    matrix = (
        "c11-member", "gnu-member", "gnu-typedef-core", "gnu-typedef-array",
        "gnu-record", "locals", "combined-directives", "redeclarations",
        "c11-redeclaration-conflict",
    )
    controls = (
        "c11-zero", "gnu-zero", "c11-nonpower", "gnu-nonpower",
        "c11-underalign", "gnu-underalign", "c11-placement-typedef",
        "c11-placement-function", "c11-placement-parameter", "c11-placement-register",
    )
    fixture, alignment, fields = case["fixture"], case["alignment"], case["fields"]
    _require(fixture in matrix + controls, "Case is outside the fixed 19 fixtures")
    _require((fixture in matrix and type(alignment) is int
              and alignment in (16, 2 ** 28, 2 ** 29, 2 ** 32, 2 ** 33))
             or (fixture in controls and alignment is None),
             "Request is outside the fixed 55 cases")
    _require(type(fields) is list and 0 < len(fields) <= 32
             and all(type(field) is str and field for field in fields)
             and len(set(fields)) == len(fields), "Invalid fixed witness fields")


def _unknown(reason, messages, blocks):
    return {"status": "unclassified", "reason": reason,
            "primary_diagnostics": messages, "diagnostic_blocks": blocks}


def _compiler_blocks(old, stderr):
    return [{"source": match[1], "line": int(match[2]), "column": int(match[3]),
             "kind": match[4], "message": match[5]}
            for match in old.re.finditer(
                r"(?m)^(.+):(\d+):(\d+): (error|note): (.+)$", stderr)]


def _compiler_patterns(old, case):
    fixture, alignment = case["fixture"], case["alignment"]
    patterns = {}
    if alignment == 2 ** 33:
        patterns["above-maximum"] = r"requested alignment must be 4294967296 bytes or smaller"
    if fixture in ("gnu-zero", "c11-nonpower", "gnu-nonpower"):
        patterns["non-power-of-two"] = r"requested alignment is not a power of 2"
    if fixture == "c11-underalign":
        patterns["below-natural-alignment"] = (
            r"requested alignment is less than minimum alignment of 4 for type 'int'")
    if fixture == "gnu-typedef-array" and alignment in (16, 2 ** 28):
        patterns["array-element-size-alignment"] = (
            r"size of array element of type 'fragma_aligned_int' "
            r"\(aka 'int'\) \(4 bytes\) isn't a multiple of its alignment "
            r"\(" + str(alignment) + r" bytes\)")
    if fixture == "c11-redeclaration-conflict":
        if alignment in (2 ** 28, 2 ** 29, 2 ** 32):
            reflected = alignment if alignment == 2 ** 28 else 4
            patterns["redeclaration-alignment"] = (
                r"redeclaration has different alignment requirement \("
                + str(reflected) + r" vs 16\)")
        if alignment == 2 ** 33:
            patterns["missing-definition-alignas"] = old.re.escape(
                "'_Alignas' must be specified on definition if it is specified on any declaration")
    placements = {
        "c11-placement-typedef": "'_Alignas' attribute only applies to variables and fields",
        "c11-placement-function": "'_Alignas' attribute only applies to variables and fields",
        "c11-placement-parameter": "'_Alignas' attribute cannot be applied to a function parameter",
        "c11-placement-register": "'_Alignas' attribute cannot be applied to a variable with 'register' storage class",
    }
    if fixture in placements:
        patterns["invalid-placement"] = old.re.escape(placements[fixture])
    return patterns


def compiler_observation(old, code, stdout, stderr, case):
    """Observe one fixed compiler result; unknown diagnostics stay unresolved."""
    blocks = _compiler_blocks(old, stderr)
    messages = [block["message"] for block in blocks if block["kind"] == "error"]
    try:
        _check_case(case)
        _require(type(code) is int, "Compiler return code is not an integer")
        if code == 0:
            _require(not stderr, "Compiler accepted with diagnostics; unresolved")
            values = old.compiler_values(stdout, case["fields"], case["fixture"])
            return {"status": "constant-witness-observed", **values,
                    "primary_diagnostics": [], "diagnostic_blocks": []}
        _require(code == 1 and not stdout and messages,
                 "Not a clean named compiler rejection")
        _require(len(messages) == len(old.re.findall(r"\berror:", stderr))
                 and not old.re.search(r"\b(?:warning|fatal error):", stderr),
                 "Unexpected or unparsed compiler primary diagnostic")
        _require(all(block["source"].endswith("/" + case["fixture"] + ".c")
                     for block in blocks), "Compiler diagnostic refers to another source")
        patterns = _compiler_patterns(old, case)
        classes = []
        for message in messages:
            matches = [name for name, pattern in patterns.items()
                       if old.re.fullmatch(pattern, message)]
            _require(len(matches) == 1, "Unclassified compiler primary diagnostic: " + message)
            classes.append(matches[0])
        # Preserve notes, but do not let arbitrary additional diagnostic text
        # become invisible behind one matching primary error.
        expected_note = None
        if case["fixture"] == "c11-redeclaration-conflict":
            expected_note = ("declared with '_Alignas' attribute here"
                             if case["alignment"] == 2 ** 33
                             else "previous declaration is here")
        notes = [block["message"] for block in blocks if block["kind"] == "note"]
        _require(notes == ([] if expected_note is None else [expected_note]),
                 "Unexpected compiler note inventory")
        summaries = []
        for line in stderr.splitlines():
            if old.re.fullmatch(r".+:\d+:\d+: (?:error|note): .+", line):
                continue
            summary = old.re.fullmatch(r"([1-9][0-9]*) errors? generated\.", line)
            if summary:
                summaries.append(int(summary[1]))
                continue
            _require(not line.strip() or old.re.fullmatch(r"\s*(?:[0-9]+\s*)?\|.*", line),
                     "Unclassified compiler diagnostic text: " + line)
        _require(summaries == [len(messages)], "Compiler error summary/count differs")
        return {"status": "named-rejection-observed", "classes": classes,
                "primary_diagnostics": messages, "diagnostic_blocks": blocks}
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        return _unknown(type(exc).__name__ + ": " + str(exc), messages, blocks)


def _analyzer_blocks(old, stdout):
    # Failure is retained as raw diagnostic evidence, never accepted below as
    # a named user-input rejection.
    return [{"source": match[1], "line": int(match[2]), "kind": match[3],
             "message": " ".join(line.strip() for line in match[4].splitlines())}
            for match in old.re.finditer(
                r"(?m)^\[kernel\] ([^\n]+):(\d+): (User Error|Error|Failure):[ \t]*\n"
                r"((?:  [^\n]*(?:\n|$))+)", stdout)]


def _analyzer_envelope(old, stdout, case):
    """Consume the entire fixed preprocessing/Parsing prefix, in order.

    The main recorder separately validates both command strings as exact argv,
    actual generated inputs and line markers. This is only the stdout grammar;
    a matching shell-looking string is not evidence that it was executed.
    """
    match = old.re.fullmatch(
        r'\[kernel:pp\] \n  preprocessing with "([^\n]+)"\n'
        r'\[kernel\] Parsing ([^\n]+) \(with preprocessing\)\n'
        r'\[kernel:pp\] \n  Full preprocessing command: ([^\n]+)\n'
        r'([\s\S]*)', stdout)
    _require(match is not None, "Unexpected analyzer preprocessing/Parsing stdout envelope")
    source = match[2]
    _require(source.startswith("/") and source.endswith("/" + case["fixture"] + ".c"),
             "Analyzer Parsing source differs from the fixed fixture")
    return source, match[4]


def _analyzer_patterns(old, case):
    fixture, alignment = case["fixture"], case["alignment"]
    patterns = {}
    if alignment == 2 ** 33:
        patterns["above-maximum"] = r"requested alignment exceeds 2\^32 bytes"
    if fixture in ("gnu-zero", "gnu-nonpower"):
        patterns["non-power-of-two"] = r"GNU alignment must be a positive power of two"
    if fixture == "c11-nonpower":
        patterns["non-power-of-two"] = r"C11 alignment must be a positive power of two"
    if fixture == "c11-underalign":
        patterns["below-natural-alignment"] = (
            r"Invalid _Alignas\(1\): shall not reduce original alignof\(int\): 4")
    if fixture == "gnu-typedef-array" and alignment in (16, 2 ** 28):
        # This is the literal typedef-name spelling from the source template.
        # A different actual type-printer spelling remains unresolved, not a
        # reason to accept arbitrary type names or alignment numbers.
        patterns["array-element-size-alignment"] = (
            r"size of array element 'fragma_aligned_int' \(4 bytes\) is not a multiple "
            r"of its alignment \(" + str(alignment) + r" bytes\)")
    if (fixture == "c11-redeclaration-conflict"
            and alignment in (2 ** 28, 2 ** 29, 2 ** 32)):
        patterns["redeclaration-alignment"] = (
            r"fragma_c11_conflict was previously declared with incompatible _Alignas\(16\) at "
            r"[A-Za-z0-9_./:-]+/c11-redeclaration-conflict\.c:6")
    placements = {
        "c11-placement-typedef": "Storage, inline or _Alignas specifier not allowed in typedef",
        "c11-placement-function": "_Alignas not allowed on functions",
        "c11-placement-parameter": "_Alignas not allowed on function parameters",
        "c11-placement-register": "_Alignas not allowed on register variables",
    }
    if fixture in placements:
        patterns["invalid-placement"] = old.re.escape(placements[fixture])
    return patterns


def _unsupported_patterns():
    # These exact source limitations are not language-invalidity categories.
    # Most cannot occur in the unchanged literals-only fixtures; if they do,
    # reporting the limitation is still unresolved support, never a pass.
    return {
        "unsupported-typed-gnu-expression": r"Unsupported typed expression in aligned attribute: .+",
        "unsupported-recursive-gnu-expression": r"unsupported or recursive GNU alignment constant expression",
        "unsupported-pragma": r"pragma pack/align is unsupported by the private alignment policy",
        "unsupported-acsl-expression": r"ACSL expression alignment is unsupported by the private alignment policy",
    }


def analyzer_observation(old, code, stdout, stderr, printed, case):
    """Observe one fixed candidate parse; no early policy gates are included."""
    blocks = _analyzer_blocks(old, stdout)
    messages = [block["message"] for block in blocks]
    try:
        _check_case(case)
        _require(type(code) is int, "Analyzer return code is not an integer")
        _require(not old.re.search(r"\b(?:failure|fatal|exception)\b", stdout, old.re.I),
                 "Analyzer Failure/fatal/exception diagnostic is not a user-input rejection")
        source, residual = _analyzer_envelope(old, stdout, case)
        if code == 0:
            _require(not stderr.strip()
                     and not old.re.search(r"\b(?:warning|error|fatal|aborted)\b", stdout, old.re.I),
                     "Analyzer accepted with diagnostics; unresolved")
            _require(residual == "", "Unexpected analyzer stdout after successful preprocessing/Parsing")
            _require(type(printed) is str, "Missing retained printed analyzer source")
            values = old.analyzer_values(printed, case["fields"])
            return {"status": "constant-witness-observed", **values,
                    "primary_diagnostics": [], "diagnostic_blocks": []}
        _require(code == 1 and not stderr.strip()
                 and not old.re.search(r"\bwarning\b|syntax error|fatal error", stdout, old.re.I),
                 "Not a clean named analyzer rejection")
        rejection = old.re.fullmatch(
            r"\[kernel\] " + old.re.escape(source)
            + r":([1-9][0-9]*): (User Error|Error):[ \t]*\n"
            r"((?:  [^\n]*\n)+)"
            r"\[kernel\] Frama-C aborted: invalid user input\.\n", residual)
        _require(rejection is not None,
                 "Unexpected analyzer rejection block/terminal stdout envelope")
        _require(len(blocks) == 1
                 and len(old.re.findall(r"(?:User Error|Error|Failure):", stdout)) == 1,
                 "Missing, additional or unparsed analyzer primary diagnostic blocks")
        _require(blocks[0]["source"] == source and blocks[0]["kind"] in ("User Error", "Error"),
                 "Analyzer diagnostic source/category differs from the exact Parsing source")
        message = messages[0]
        patterns = _analyzer_patterns(old, case)
        matches = [name for name, pattern in patterns.items()
                   if old.re.fullmatch(pattern, message)]
        unsupported = [name for name, pattern in _unsupported_patterns().items()
                       if old.re.fullmatch(pattern, message)]
        _require(len(matches) + len(unsupported) == 1,
                 "Unclassified analyzer primary diagnostic: " + message)
        if unsupported:
            return {"status": "unsupported-observation", "classes": unsupported,
                    "primary_diagnostics": messages, "diagnostic_blocks": blocks,
                    "language_rejection_established": False}
        return {"status": "named-rejection-observed", "classes": matches,
                "primary_diagnostics": messages, "diagnostic_blocks": blocks}
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        return _unknown(type(exc).__name__ + ": " + str(exc), messages, blocks)


def compare(case, compiler, analyzer):
    """Compare old-shaped command rows without mutating either input.

    Category correspondence does not establish equal error counts or complete
    detection: an analyzer may stop at the first invalid directive. Keep both
    ordered lists and counts, and never erase the compound missing-definition
    category to manufacture correspondence.
    """
    left, right = compiler["classification"], analyzer["classification"]
    row = {"case": case, "compiler": left["status"], "analyzer": right["status"]}
    if case.get("control_expectation") == "reject":
        row["negative_control_unexpected_acceptance_by"] = [
            tool for tool, command in (("compiler", compiler), ("analyzer", analyzer))
            if command["returncode"] == 0]
    if case.get("control_expectation") == "accept":
        row["positive_control_unexpected_rejection_by"] = [
            tool for tool, command in (("compiler", compiler), ("analyzer", analyzer))
            if type(command["returncode"]) is int and command["returncode"] != 0]
    if left["status"] == right["status"] == "constant-witness-observed":
        differences = {name: {"compiler": left["values"][name], "analyzer": right["values"][name]}
                       for name in case["fields"] if left["values"][name] != right["values"][name]}
        row.update(status="constant-mismatch" if differences else "constants-agree-not-support",
                   differences=differences)
    elif left["status"] == right["status"] == "named-rejection-observed":
        compiler_classes, analyzer_classes = left["classes"], right["classes"]
        compiler_only = sorted(set(compiler_classes) - set(analyzer_classes))
        analyzer_only = sorted(set(analyzer_classes) - set(compiler_classes))
        row.update(
            status=("rejection-category-mismatch" if compiler_only or analyzer_only
                    else "named-rejections-correspond-not-support"),
            compiler_rejection_classes=list(compiler_classes),
            analyzer_rejection_classes=list(analyzer_classes),
            compiler_only_rejection_classes=compiler_only,
            analyzer_only_rejection_classes=analyzer_only,
            compiler_primary_count=len(left["primary_diagnostics"]),
            analyzer_primary_count=len(right["primary_diagnostics"]),
            all_independent_invalid_conditions_established=False,
        )
    elif (left["status"] in ("unclassified", "unsupported-observation")
          or right["status"] in ("unclassified", "unsupported-observation")):
        row["status"] = "unresolved-observation"
    else:
        row["status"] = "acceptance-rejection-mismatch"
    return row
