"""Closed, target-local frontend policies and checks of actual consumed C.

This is not an arbitrary preprocessor-flags interface. The sole initial policy
selects the genuine kernel inline spelling for the common 24-bit byte helpers.
No architecture name chooses a default, and observing an attribute in the input
does not prove its code-generation or instrumentation effects.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import posixpath
import re
import shlex

from fragma import elf, provenance
from fragma.sources import SourceError, sha256


HARNESS = "common/annotated/unaligned24.verified.c"
FIXTURE = "common/annotated/kernel-model-check.c"
HEADER = "common/annotated/inline-policy.h"
STRATEGY = "common/annotated/byteproof.h"
MACRO = "FRAGMA_COMMON24_INLINE_POLICY"
FUNCTIONS = ("__get_unaligned_be24", "__get_unaligned_le24",
             "__put_unaligned_be24", "__put_unaligned_le24")
WITNESSES = ("fragma_roundtrip_be24", "fragma_roundtrip_le24")
VARIANTS = {"no-instrument": (1, "__attribute__((__no_instrument_function__))"),
            "patchable-entry-0": (2, "__attribute__((patchable_function_entry(0, 0)))")}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceError("frontend policy: " + message)


_ACSL_TOKEN = re.compile(
    r'''(?:u8|u|U|L)?"(?:\\.|[^"\\\n])*"|(?:u8|u|U|L)?'(?:\\.|[^'\\\n])*'|'''
    r'''\\?[A-Za-z_][A-Za-z_0-9]*|0[xX][0-9a-fA-F]+[uUlL]*|'''
    r'''[0-9]+(?:\.(?!\.)[0-9]*)?(?:[eE][+-]?[0-9]+)?[uUlLfF]*|'''
    r'''<==>|==>|<-->|<=>|\.\.\.|\.\.|<<|>>|<=|>=|==|!=|&&|\|\||->|\+\+|--|'''
    r'''[()[\]{},;:.?~!+*/%<>=&|^_\\-]''')


def annotation_tokens(source: str) -> list[list[str]]:
    """Lex ordered block ACSL, ignoring only whitespace outside quoted literals.

    Comments inside C strings are not annotations. This closed lexer covers the
    common24 contracts/strategy; unfamiliar annotation spelling fails closed.
    """
    require(isinstance(source, str), "annotation source must be text")
    result, index = [], 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = len(source) if end < 0 else end + 1
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            require(end >= 0, "unterminated source annotation/comment")
            if source.startswith("/*@", index):
                body, cursor, tokens = source[index + 3:end], 0, []
                while cursor < len(body):
                    if body[cursor].isspace():
                        cursor += 1
                        continue
                    match = _ACSL_TOKEN.match(body, cursor)
                    require(match is not None, "unsupported or malformed common24 annotation token")
                    tokens.append(match.group())
                    cursor = match.end()
                require(bool(tokens), "empty common24 annotation")
                result.append(tokens)
            index = end + 2
        elif source[index] in ('"', "'"):
            quote = source[index]
            index += 1
            while index < len(source) and source[index] != quote:
                require(source[index] != "\n", "unterminated source literal")
                if source[index] == "\\":
                    index += 1
                index += 1
            require(index < len(source), "unterminated source literal")
            index += 1
        else:
            index += 1
    return result


def annotation_identity(raw: str, strategy: str, expanded: str) -> dict:
    expected = annotation_tokens(strategy) + annotation_tokens(raw)
    actual = annotation_tokens(expanded)
    require(actual == expected, "actual ACSL contracts/assertions/strategy differ or are reordered")
    encoded = json.dumps(actual, ensure_ascii=True, separators=(",", ":")).encode()
    return {"schema_version": 1, "normalization": "ordered-common24-acsl-tokens-v1",
            "block_count": len(actual), "ordered_tokens_sha256": hashlib.sha256(encoded).hexdigest(),
            "block_token_sha256": [provenance.token_hash(tuple(block)) for block in actual]}


def identity(target: dict, *, root: Path | None = None) -> dict | None:
    """Validate an opt-in policy without inventing one for older targets."""
    require(isinstance(target, dict), "target must be an object")
    def controlled_path(field, expected):
        name = target.get(field)
        if not isinstance(name, str):
            return False
        return posixpath.normpath(name) == expected or (root is not None and
            (Path(root) / name).resolve() == (Path(root) / expected).resolve())
    controlled = controlled_path("harness", HARNESS) or controlled_path("kernel_model_check", FIXTURE)
    if "frontend_policy" not in target:
        require(not controlled, "common24 inputs require an explicit policy")
        return None
    value = target["frontend_policy"]
    require(isinstance(value, dict) and set(value) == {"schema_version", "kind", "variant"},
            "expected exactly schema_version, kind and variant")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1,
            "unsupported schema version")
    require(value["kind"] == "common24-inline" and isinstance(value["variant"], str)
            and value["variant"] in VARIANTS, "unknown policy kind or variant")
    require(target.get("input_mode") == "standalone" and target.get("harness") == HARNESS
            and target.get("kernel_model_check") == FIXTURE
            and target.get("source") == "include/linux/unaligned.h",
            "common24 policy requires its standalone harness and genuine-header fixture")
    require(not any(key in target for key in ("cpp_definitions", "cpp_extra_args", "cpp_flags")),
            "arbitrary target preprocessor overrides are not supported")
    return dict(value)


def cpp_arguments(target: dict) -> list[str]:
    policy = identity(target)
    return [] if policy is None else [f"-D{MACRO}={VARIANTS[policy['variant']][0]}"]


def required_files(target: dict) -> list[str]:
    return [] if identity(target) is None else [HEADER, "fragma/frontend_policy.py", "fragma/elf.py"]


def add_cpp_arguments(argv: list[str], target: dict) -> list[str]:
    """Append the one allowed definition once; reject pre-existing selectors."""
    extra = cpp_arguments(target)
    if extra:
        require(isinstance(argv, list) and all(isinstance(arg, str) for arg in argv),
                "malformed compiler argv")
        require(not any(MACRO in arg for arg in argv), "pre-existing inline selector")
    return [*argv, *extra]


def expected_prefix(target: dict, function: str) -> tuple[str, ...]:
    policy = identity(target)
    require(policy is not None and function in FUNCTIONS, "unknown selected helper")
    text = ("static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) "
            + VARIANTS[policy["variant"]][1] + (" u32 " if function.startswith("__get_") else " void "))
    return provenance.extract_function(text + function + "(void) {}", function).declaration_prefix


def _typedefs(source: str, label: str) -> dict:
    """The fixed standalone closure has exactly these two C typedefs."""
    tokens = provenance.tokenize(source)
    declarations = []
    for index, token in enumerate(tokens):
        if token == "typedef":
            end = next((i for i in range(index + 1, len(tokens)) if tokens[i] == ";"), None)
            require(end is not None, label + " has an incomplete typedef")
            declarations.append(tokens[index:end + 1])
    expected = [("typedef", "unsigned", "char", "u8", ";"),
                ("typedef", "unsigned", "int", "u32", ";")]
    require(declarations == expected, label + " must contain the exact unique u8/u32 typedefs")
    return {"u8": ["unsigned", "char"], "u32": ["unsigned", "int"]}


def fixture_object(data: bytes, target: dict, model: dict) -> dict:
    """Check a bounded relocatable ELF container and two named metadata objects.

    This does not verify instructions, relocations, target ISA, or all ELF/ABI
    semantics. Extended section numbering is deliberately unsupported.
    """
    policy = identity(target)
    require(policy is not None, "fixture object requires an explicit policy")
    try:
        obj = elf.parse_relocatable(data, model)
    except elf.ELFError as exc:
        raise SourceError("frontend policy: " + str(exc)) from exc
    expected = ("inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) "
                + VARIANTS[policy["variant"]][1]).encode() + b"\0"
    wanted = {b"fragma_common24_effective_inline", b"fragma_common24_expected_inline"}
    observed = {}
    for symbol in obj.symbols:
        name, value, length, info, other, section = (symbol.name, symbol.value, symbol.size,
                                                   symbol.info, symbol.other, symbol.section)
        if name not in wanted:
            continue
        require(name not in observed and info == 0x11 and other == 0 and 0 < section < len(obj.sections)
                and obj.sections[section].kind == 1 and length == len(expected),
                "invalid or duplicate inline metadata symbol")
        content = obj.section_bytes(section)
        require(value + length <= len(content) and content[value:value + length] == expected,
                "compiler-produced inline metadata differs from selected policy")
        observed[name] = expected[:-1].decode()
    require(set(observed) == wanted, "missing compiler-produced inline metadata symbols")
    return {"class": obj.bits, "byte_order": "little" if obj.little else "big", "type": "relocatable",
            "machine_observed": obj.machine, "inline_metadata": {name.decode(): value for name, value in sorted(observed.items())},
            "scope": "ELF container and named inline metadata only; no ISA or generated-code verification"}


def _input_row(section: dict, path: str, label: str) -> dict:
    inputs = section.get("inputs")
    require(isinstance(inputs, list) and all(isinstance(row, dict) for row in inputs),
            label + " has no valid consumed input inventory")
    rows = [row for row in inputs if row.get("absolute_path") == path]
    require(len(rows) == 1, label + " must bind a unique consumed input: " + path)
    return rows[0]


def _argv(receipt: dict, label: str) -> list[str]:
    require(isinstance(receipt, dict) and type(receipt.get("returncode")) is int
            and receipt["returncode"] == 0 and receipt.get("timed_out") is False,
            label + " did not complete successfully")
    argv = receipt.get("argv")
    require(isinstance(argv, list) and argv and all(isinstance(arg, str) and "\x00" not in arg for arg in argv),
            label + " has malformed argv")
    return argv


def _option(argv: list[str], flag: str) -> str:
    positions = [i for i, arg in enumerate(argv) if arg == flag]
    require(len(positions) == 1 and positions[0] + 1 < len(argv)
            and not any(arg.startswith(flag + "=") for arg in argv), "missing or ambiguous " + flag)
    return argv[positions[0] + 1]


def _selector(argv: list[str], target: dict, label: str) -> None:
    flag = cpp_arguments(target)[0]
    require([arg for arg in argv if MACRO in arg] == [flag],
            label + " must contain exactly the canonical inline selector")


def validate_actual(root: Path, target: dict, model: dict, prepared: dict,
                    fixture: dict | None, command: dict, audit: dict,
                    *, read=None) -> dict | None:
    """Rederive the frontend envelope from checked command and stream artifacts.

    A replay caller supplies its hash-checking read(path, sha256) function after
    independently checking the retained .pp inventory. This function itself
    never runs a compiler or analyzer. Raw paths/hashes are artifact bindings,
    not path-independent replay identities.
    """
    policy = identity(target, root=root)
    if policy is None:
        return None
    root = Path(root).resolve()

    def checked_read(path, expected, *, binary=False):
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
                "missing artifact digest")
        path = Path(path)
        require(path.is_absolute() and not path.is_symlink(), "artifact path must be absolute and not a symlink")
        if read is None or not path.is_relative_to(Path(prepared["path"]).parent):
            require(path.is_file() and sha256(path) == expected, "artifact changed: " + str(path))
            data = path.read_bytes()
        else:
            data = read(str(path), expected, binary=True)
        require(isinstance(data, bytes) and hashlib.sha256(data).hexdigest() == expected,
                "reader did not return the bound artifact bytes")
        return data if binary else data.decode()

    expected_cpp = [model["compiler"]["path"], *model["analysis"]["compiler_flags"],
                    "-nostdinc", "-D__KERNEL__", *cpp_arguments(target), "-E", "-C"]
    _selector(expected_cpp, target, "model preprocessing")
    require(shlex.split(prepared["frama_cpp_command"]) == expected_cpp,
            "prepared CPP command differs from the explicit profile/policy")
    actual = _argv(command, "analyzer")
    require(shlex.split(_option(actual, "-cpp-command")) == expected_cpp,
            "actual analyzer CPP differs from the explicit profile/policy")
    require(actual.count("-cpp-extra-args=-std=gnu11") == 1
            and not any(arg.startswith("-cpp-") and arg not in
                        ("-cpp-command", "-cpp-frama-c-compliant", "-cpp-extra-args=-std=gnu11")
                        for arg in actual), "actual analyzer contains alternate CPP extra arguments")
    for flag in ("-cpp-frama-c-compliant", "-pp-annot", "-keep-temp-files"):
        require(actual.count(flag) == 1, "actual analyzer must select " + flag)
    require(not any(arg.startswith(("-no-cpp", "-no-pp-annot", "-no-keep-temp-files",
                    "-cpp-frama-c-compliant=", "-pp-annot=", "-keep-temp-files="))
                    for arg in actual), "opposing or alternate ACSL preprocessing options")
    source = str(root / HARNESS)
    require(prepared.get("frama_input") == source and actual.count(source) == 1,
            "actual analyzer must consume the declared harness once")
    require(command.get("cwd") == prepared.get("cwd"), "analyzer preprocessing cwd changed")

    dependency = _argv(prepared["preprocess"], "dependency preprocessing")
    _selector(dependency, target, "dependency preprocessing")
    output = Path(prepared["path"]).parent
    expected_dependency = [*expected_cpp[:-2], "-D__FRAMAC__", "-E", "-C", "-MD", "-MF",
                           str(output / "headers.d"), "-MT", "fragma", source]
    require(dependency == expected_dependency and prepared["preprocess"].get("cwd") == prepared["cwd"],
            "dependency command differs from native ACSL preprocessing policy")
    genuine = _argv(fixture, "genuine-header fixture")
    _selector(genuine, target, "genuine-header fixture")
    # Import here to avoid an inputs -> frontend_policy -> inputs import cycle.
    from fragma.inputs import command_without_outputs
    entries = [entry for entry in model["build"]["matched_commands"]
               if entry.get("file") == str(Path(model["build"]["source"]) / "lib/string.c")]
    require(len(entries) == 1 and fixture.get("original_compile_command") == entries[0],
            "fixture compile entry is not the genuine command checked by the model")
    base = add_cpp_arguments(command_without_outputs(entries[0]), target)
    expected_fixture = [*base, "-Werror", "-MD", "-MF", str(output / "model-headers.d"),
                        "-MT", "fragma", "-c", str(root / FIXTURE), "-o", str(output / "kernel-model.o")]
    require(genuine == expected_fixture and genuine[0] == expected_cpp[0]
            and fixture.get("cwd") == prepared["cwd"] == entries[0]["directory"],
            "genuine-header fixture command mismatch")
    require(json.dumps(fixture.get("frontend_policy"), sort_keys=True, allow_nan=False) ==
            json.dumps(policy, sort_keys=True, allow_nan=False), "fixture did not record the selected frontend policy")
    require(checked_read(fixture["log"], fixture["log_sha256"]) == "",
            "genuine-header fixture produced unexpected diagnostics")
    require(fixture.get("diagnostics") == {"absolute_path": fixture["log"], "sha256": fixture["log_sha256"]},
            "fixture diagnostics inventory differs from its command log")
    object_observation = None
    for field, expected_path in (("object", output / "kernel-model.o"),
                                 ("dependencies", output / "model-headers.d")):
        item = fixture.get(field)
        require(isinstance(item, dict) and item.get("absolute_path") == str(expected_path),
                "missing or misplaced fixture " + field)
        data = checked_read(item["absolute_path"], item["sha256"], binary=True)
        require(bool(data), "empty fixture " + field)
        if field == "object":
            object_observation = fixture_object(data, target, model)
        else:
            dependencies = data.decode().replace("\\\n", "")
            require(dependencies.startswith("fragma:"), "invalid fixture dependency target")
            names = shlex.split(dependencies.split(":", 1)[1].replace("$$", "$"), comments=False)
            paths = {str((Path(name) if Path(name).is_absolute() else Path(prepared["cwd"]) / name).resolve())
                     for name in names}
            require(paths and paths == {row["absolute_path"] for row in fixture["inputs"]},
                    "fixture dependency inventory disagrees with consumed input records")
    fixture_row = _input_row(fixture, str(root / FIXTURE), "genuine-header fixture")
    require(fixture_row.get("sha256") == fixture.get("fixture_sha256"),
            "fixture source digest differs from its consumed input record")
    fixture_source = checked_read(root / FIXTURE, fixture.get("fixture_sha256"))
    require("#include <linux/types.h>" in fixture_source and "#include <linux/unaligned.h>" in fixture_source,
            "fixture lacks genuine kernel type/helper headers")
    for section, label in ((prepared, "dependency preprocessing"), (fixture, "genuine-header fixture"),
                           (audit, "analyzer audit")):
        rows = [item for item in section.get("inputs", []) if item.get("absolute_path") == str(root / HEADER)]
        require(len(rows) == 1, label + " did not consume the declared inline header exactly once")
        checked_read(root / HEADER, rows[0]["sha256"])
    source_row = _input_row(prepared, source, "dependency preprocessing")
    require(_input_row(audit, source, "analyzer audit").get("sha256") == source_row.get("sha256"),
            "harness digest differs between dependency and analyzer inputs")
    raw = checked_read(source, source_row["sha256"])
    typedefs = _typedefs(raw, "raw standalone harness")
    strategy_row = _input_row(prepared, str(root / STRATEGY), "dependency preprocessing")
    require(_input_row(audit, str(root / STRATEGY), "analyzer audit").get("sha256") == strategy_row.get("sha256"),
            "strategy digest differs between dependency and analyzer inputs")
    strategy = checked_read(root / STRATEGY, strategy_row["sha256"])
    streams = audit.get("parsed_streams")
    require(isinstance(streams, list) and len(streams) == 1 and streams[0].get("source") == HARNESS,
            "actual parsed-stream inventory is missing or ambiguous")
    stream = streams[0]
    require(str(stream.get("path", "")).endswith(".pp") and
            sum(item == {key: value for key, value in stream.items() if key != "source"}
                for item in audit.get("retained_preprocessing", [])) == 1,
            "actual .pp stream is not uniquely bound to retained preprocessing")
    expanded = checked_read(stream["absolute_path"], stream["sha256"])
    require(_typedefs(expanded, "actual parsed stream") == typedefs, "actual typedefs differ from the raw source")
    annotations = annotation_identity(raw, strategy, expanded)
    observations = []
    for name in FUNCTIONS:
        original = provenance.extract_function(raw, name)
        parsed = provenance.extract_function(expanded, name)
        require(original.tokens == parsed.tokens, "preprocessing changed selected helper C: " + name)
        require(parsed.declaration_prefix == expected_prefix(target, name),
                "actual inline expansion differs for " + name)
        observations.append({"function": name, "declaration_prefix": list(parsed.declaration_prefix),
                             "c_token_sha256": provenance.token_hash(parsed.tokens)})
    witnesses = []
    for name in WITNESSES:
        original = provenance.extract_function(raw, name)
        parsed = provenance.extract_function(expanded, name)
        require(original.tokens == parsed.tokens and original.declaration_prefix == parsed.declaration_prefix == ("u32",),
                "preprocessing changed project witness C/declaration: " + name)
        witnesses.append({"function": name, "declaration_prefix": list(parsed.declaration_prefix),
                          "c_token_sha256": provenance.token_hash(parsed.tokens)})
    return {"schema_version": 1, "status": "checked", "policy": policy,
            "cpp_definition": cpp_arguments(target)[0], "functions": observations,
            "witnesses": witnesses, "annotations": annotations,
            "typedefs": typedefs, "fixture_object": object_observation,
            "harness_sha256": source_row["sha256"], "strategy_sha256": strategy_row["sha256"],
            "parsed_stream": dict(stream), "fixture_sha256": fixture["fixture_sha256"],
            "inline_header": {"absolute_path": str(root / HEADER), "sha256": sha256(root / HEADER)},
            "limitations": ["An observed attribute is not a proof of instrumentation or generated code.",
                            "Source contracts, runtime guards, warnings and calibration are separate gates."]}


def observation(root: Path, target: dict, model: dict, evidence: dict,
                shared: dict, *, read=None) -> dict | None:
    """Verify a saved opt-in envelope; never backfill missing legacy evidence."""
    policy = identity(target, root=root)
    saved = evidence.get("validated_frontend_policy")
    if policy is None:
        require(saved is None, "frontend envelope has no declared policy")
        return None
    require(isinstance(saved, dict), "declared policy lacks its actual frontend envelope")
    require(isinstance(shared, dict), "shared input inventory must be an object")
    combined = {}

    def add(filename, expected):
        require(isinstance(filename, str) and Path(filename).is_absolute()
                and isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
                "malformed frontend input-integrity record")
        require(filename not in combined or combined[filename] == expected,
                "conflicting shared and target input digests")
        combined[filename] = expected

    for filename, expected in shared.items():
        add(filename, expected)
    records = evidence.get("integrity_inputs")
    require(isinstance(records, list) and records, "missing target input-integrity inventory")
    for row in records:
        require(isinstance(row, dict), "malformed target input-integrity record")
        add(row.get("absolute_path"), row.get("sha256"))

    def bound(row):
        require(isinstance(row, dict) and isinstance(row.get("absolute_path"), str)
                and isinstance(row.get("sha256"), str)
                and combined.get(row["absolute_path"]) == row["sha256"],
                "frontend metadata is absent from or contradicts the combined input inventory")

    for section in (evidence["input"], evidence["kernel_model_check"], evidence["analyzer_audit"]):
        require(isinstance(section, dict) and isinstance(section.get("inputs"), list) and section["inputs"],
                "missing consumed input records")
        for row in section["inputs"]:
            bound(row)
    fixture = evidence["kernel_model_check"]
    for field in ("object", "dependencies", "diagnostics"):
        bound(fixture.get(field))
    for row in evidence["analyzer_audit"].get("parsed_streams", []):
        bound(row)
    bound({"absolute_path": str(Path(root).resolve() / FIXTURE), "sha256": fixture.get("fixture_sha256")})
    helper = str(Path(root).resolve() / "fragma/frontend_policy.py")
    elf_helper = str(Path(root).resolve() / "fragma/elf.py")
    require(isinstance(combined.get(helper), str) and isinstance(combined.get(elf_helper), str),
            "frontend implementation is not an inventoried input")
    actual = validate_actual(root, target, model, evidence["input"], evidence["kernel_model_check"],
                             evidence["analysis_command"], evidence["analyzer_audit"], read=read)
    require(json.dumps(actual, sort_keys=True, allow_nan=False) ==
            json.dumps(saved, sort_keys=True, allow_nan=False), "saved frontend envelope differs from actual inputs")
    review = evidence.get("validated_review")
    if review is not None:
        context = review["review_context"]
        require(json.dumps(context.get("preprocessing", {}).get("frontend_policy"), sort_keys=True, allow_nan=False) ==
                json.dumps(policy, sort_keys=True, allow_nan=False),
                "review does not bind the observed frontend policy")
        expected_hashes = {HARNESS: actual["harness_sha256"], FIXTURE: actual["fixture_sha256"],
                           HEADER: actual["inline_header"]["sha256"], STRATEGY: actual["strategy_sha256"],
                           "fragma/frontend_policy.py": combined[helper], "fragma/elf.py": combined[elf_helper]}
        require(all(context.get("file_hashes", {}).get(filename) == expected
                    and combined.get(str(Path(root).resolve() / filename)) == expected
                    for filename, expected in expected_hashes.items()),
                "review does not bind the observed frontend policy and implementation")
    return actual


def logical_observation(observed: dict | None) -> dict | None:
    """Path-independent part; replay separately normalizes actual stream bytes."""
    if observed is None:
        return None
    return {key: observed[key] for key in ("schema_version", "status", "policy", "cpp_definition",
                                          "functions", "witnesses", "annotations", "typedefs", "fixture_object", "harness_sha256",
                                          "strategy_sha256", "fixture_sha256", "limitations")} | {
        "inline_header_sha256": observed["inline_header"]["sha256"]}
