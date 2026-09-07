"""Conservative source-identity gates, independent of the analysis toolchain.

This module compares C preprocessing tokens; it does not preprocess files or
claim to validate C grammar. Analysis must still parse the selected configuration.
The extractor supports ordinary, explicitly named function definitions. It fails
closed on unbalanced delimiters, duplicate definitions (including #if branches),
old-style declarations, and unrecognised post-declarator syntax. Macro-generated
definitions require a separately checked, preprocessed provenance workflow.

Function checks include the named declarator, parameters and complete body.
Return types, storage qualifiers, and attributes before the name are reported
separately, because standalone harnesses commonly substitute these. Neither
body equality nor translation-unit token equality verifies substituted headers,
macro meanings, caller preconditions, or the compiler's execution model.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any


class ProvenanceError(ValueError):
    """The requested source identity could not be established."""


@dataclass(frozen=True)
class Token:
    value: str
    kind: str = "c"
    line: int = 0
    start: int = 0
    end: int = 0


@dataclass(frozen=True)
class Function:
    name: str
    tokens: tuple[str, ...]
    declaration_prefix: tuple[str, ...]
    line: int


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_NUMBER = re.compile(r"(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[A-Za-z_0-9.])*")
_LITERAL_START = re.compile(r"(?:u8|u|U|L)?[\"']")
_PUNCTUATORS = tuple(sorted((
    "%:%:", ">>=", "<<=", "...", "->", "++", "--", "<<", ">>", "<=", ">=",
    "==", "!=", "&&", "||", "*=", "/=", "%=", "+=", "-=", "&=", "^=", "|=",
    "##", "<:", ":>", "<%", "%>", "%:", "[", "]", "(", ")", "{", "}",
    ".", "&", "*", "+", "-", "~", "!", "/", "%", "<", ">", "^", "|", "?",
    ":", ";", "=", ",", "#",
), key=len, reverse=True))


def _lex(source: str) -> tuple[Token, ...]:
    if not isinstance(source, str):
        raise ProvenanceError("C source must be text")
    if "\x00" in source:
        raise ProvenanceError("NUL byte in C source")
    # Trigraph expansion precedes splicing/comment recognition. Refuse rather
    # than applying an implicit compiler-dependent trigraph setting.
    if re.search(r"\?\?[=/\'()!<>-]", source):
        raise ProvenanceError("trigraph syntax is unsupported")
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    source = re.sub(r"\\\n", "", source)
    tokens: list[Token] = []
    i, line = 0, 1
    beginning = True
    directive = False
    directive_tokens: list[Token] = []

    def add(value: str, start: int, end: int, kind: str = "c") -> None:
        nonlocal beginning
        token = Token(value, "pp" if directive and kind == "c" else kind,
                      line, start, end)
        tokens.append(token)
        if directive:
            directive_tokens.append(token)
        beginning = False

    while i < len(source):
        ch = source[i]
        if ch in " \t\v\f":
            i += 1
            continue
        if ch == "\n":
            if directive:
                tokens.append(Token("<pp-end>", "boundary", line, i, i + 1))
            directive, beginning = False, True
            directive_tokens = []
            line += 1
            i += 1
            continue
        if source.startswith("//", i):
            newline = source.find("\n", i + 2)
            i = len(source) if newline == -1 else newline
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end == -1:
                raise ProvenanceError(f"unterminated block comment at line {line}")
            # Newlines inside a block comment do not terminate a directive: the
            # entire comment is replaced by one space in translation phase 3.
            line += source[i:end + 2].count("\n")
            i = end + 2
            continue
        if beginning and (ch == "#" or source.startswith("%:", i)):
            if source.startswith("%:", i):
                raise ProvenanceError(f"preprocessor digraph unsupported at line {line}")
            directive = True
            add("<pp-start>", i, i + 1, "boundary")
            i += 1
            continue
        if ch == "#" and not directive:
            raise ProvenanceError(f"preprocessor marker away from line start at line {line}")
        # A header name is one preprocessing token: apparent comments inside
        # it must not be stripped. Keep literal include spelling intact.
        if (directive and len(directive_tokens) == 2
                and directive_tokens[1].value in ("include", "include_next")
                and ch == "<"):
            end = source.find(">", i + 1)
            if end == -1 or "\n" in source[i:end + 1]:
                raise ProvenanceError(f"unterminated include header at line {line}")
            add(source[i:end + 1], i, end + 1)
            i = end + 1
            continue
        literal = _LITERAL_START.match(source, i)
        if literal:
            start = i
            quote = literal.group()[-1]
            i += len(literal.group())
            content_start = i
            while i < len(source) and source[i] != quote:
                if source[i] == "\n":
                    raise ProvenanceError(f"newline in C literal at line {line}")
                if source[i] == "\\":
                    i += 1
                i += 1
            if i >= len(source):
                raise ProvenanceError(f"unterminated C literal at line {line}")
            if quote == "'" and i == content_start:
                raise ProvenanceError(f"empty character constant at line {line}")
            i += 1
            add(source[start:i], start, i)
            continue
        match = _IDENTIFIER.match(source, i) or _NUMBER.match(source, i)
        if match:
            add(match.group(), i, match.end())
            i = match.end()
            continue
        punctuator = next((p for p in _PUNCTUATORS if source.startswith(p, i)), None)
        if punctuator is None:
            raise ProvenanceError(f"unsupported C character {ch!r} at line {line}")
        if punctuator in ("<:", ":>", "<%", "%>", "%:", "%:%:"):
            raise ProvenanceError(f"C digraph unsupported at line {line}")
        # Whitespace here changes object-like/function-like macro semantics.
        if (directive and len(directive_tokens) == 3
                and directive_tokens[1].value == "define" and punctuator == "("
                and directive_tokens[2].end == i):
            add("<macro-function>", i, i, "boundary")
        add(punctuator, i, i + len(punctuator))
        i += len(punctuator)
    if directive:
        tokens.append(Token("<pp-end>", "boundary", line, i, i))
    if not tokens:
        raise ProvenanceError("C source is empty after removing comments")
    return tuple(tokens)


def tokenize(source: str) -> tuple[str, ...]:
    """Return nonempty preprocessing tokens, preserving directive boundaries."""
    return tuple(token.value for token in _lex(source))


def token_hash(tokens: tuple[str, ...]) -> str:
    # JSON retains token boundaries: ['ab', 'c'] cannot collide with ['a', 'bc'].
    return hashlib.sha256(json.dumps(tokens, ensure_ascii=True,
                                    separators=(",", ":")).encode()).hexdigest()


def extract_function(source: str, name: str) -> Function:
    """Extract exactly one explicit definition; never return an empty match."""
    if not isinstance(name, str) or _IDENTIFIER.fullmatch(name) is None:
        raise ProvenanceError(f"invalid C function name: {name!r}")
    all_tokens = _lex(source)
    normal = [(i, token) for i, token in enumerate(all_tokens) if token.kind == "c"]
    matching: dict[int, int] = {}
    stack: list[int] = []
    depths: list[int] = []
    opening = {"(": ")", "[": "]", "{": "}"}
    for i, (_, token) in enumerate(normal):
        depths.append(len(stack))
        if token.value in opening:
            stack.append(i)
        elif token.value in opening.values():
            if not stack or opening[normal[stack[-1]][1].value] != token.value:
                raise ProvenanceError(f"unbalanced delimiter {token.value!r} at line {token.line}")
            start = stack.pop()
            matching[start], matching[i] = i, start
    if stack:
        token = normal[stack[-1]][1]
        raise ProvenanceError(f"unclosed delimiter {token.value!r} at line {token.line}")
    definitions: list[Function] = []
    for i, (raw, token) in enumerate(normal):
        if token.value != name or depths[i] or i + 1 >= len(normal):
            continue
        if normal[i + 1][1].value != "(":
            continue
        close = matching[i + 1]
        if close + 1 >= len(normal):
            raise ProvenanceError(f"incomplete declarator for {name} at line {token.line}")
        following = normal[close + 1][1].value
        if following in (";", ",", "=", ")", "]"):
            continue  # declaration/reference, not a definition
        if following != "{":
            raise ProvenanceError(f"unsupported post-declarator syntax for {name} at line {token.line}")
        prefix_start = raw
        while prefix_start and all_tokens[prefix_start - 1].value not in (";", "}", "<pp-end>"):
            prefix_start -= 1
        prefix = tuple(t.value for t in all_tokens[prefix_start:raw])
        if not prefix or "=" in prefix or "{" in prefix or "<pp-start>" in prefix:
            raise ProvenanceError(f"unsupported declaration prefix for {name} at line {token.line}")
        if any(normal[j][1].value in (";", "{", "}") for j in range(i + 2, close)):
            raise ProvenanceError(f"unsupported parameter declaration for {name} at line {token.line}")
        end = normal[matching[close + 1]][0] + 1
        body_tokens = tuple(t.value for t in all_tokens[raw:end])
        definitions.append(Function(name, body_tokens, prefix, token.line))
    if len(definitions) != 1:
        raise ProvenanceError(f"expected exactly one definition of {name}; found {len(definitions)}")
    return definitions[0]


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ProvenanceError(f"{label} must be a nonempty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value.startswith("-"):
        raise ProvenanceError(f"{label} must stay inside its source root: {value!r}")
    return str(path)


def _read_local(root: Path, relative: str) -> bytes:
    root = root.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ProvenanceError(f"source symlink escapes root: {relative}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ProvenanceError(f"cannot read {path}: {error}") from error


def _git(tree: Path, *args: str) -> bytes:
    try:
        process = subprocess.run(["git", "--no-optional-locks", "-C", str(tree), *args],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProvenanceError(f"cannot read kernel git source: {error}") from error
    if process.returncode:
        raise ProvenanceError("kernel git source unavailable: "
                              + process.stderr.decode("utf-8", errors="replace").strip())
    return process.stdout


def check_target(target: dict[str, Any], kernel_tree: Path, revision: str | None,
                 root: Path) -> dict[str, Any]:
    """Check manifest source identity and return JSON-serializable evidence.

    Required fields: source, harness, functions (or function), and
    provenance.mode ('translation-unit' or 'functions'). A non-None revision is
    resolved to a commit and read using git show, never from the mutable file.
    A changed declaration prefix requires a nonempty target assumptions list;
    the returned item remains explicitly conditional on those model assumptions.
    """
    result: dict[str, Any] = {"passed": False, "errors": [], "functions": []}
    try:
        source_path = _relative_path(target.get("source"), "source")
        source_identity: dict[str, Any] = {"path": source_path, "kind": "git-blob" if revision else "working-tree"}
        result["source"] = source_identity
        mode = target.get("provenance", {}).get("mode")
        if mode not in ("translation-unit", "functions", "pinned-translation-unit"):
            raise ProvenanceError(f"unsupported provenance mode: {mode!r}")
        if mode == "pinned-translation-unit":
            if revision is None:
                raise ProvenanceError("pinned translation-unit mode requires a revision")
            if target.get("harness") is not None:
                raise ProvenanceError("pinned translation units do not accept a project harness")
            harness_path = source_path
            result["harness"] = {"path": source_path, "kind": "pinned-source-identity"}
        else:
            harness_path = _relative_path(target.get("harness"), "harness")
            result["harness"] = {"path": harness_path, "kind": "project-copy"}
        result["mode"] = mode
        functions = target.get("functions", [target["function"]] if "function" in target else [])
        if (not isinstance(functions, list) or not functions
                or any(not isinstance(name, str) or not _IDENTIFIER.fullmatch(name) for name in functions)
                or len(set(functions)) != len(functions)):
            raise ProvenanceError("functions must be a nonempty list of distinct C identifiers")
        tree = Path(kernel_tree)
        if revision is not None:
            if not isinstance(revision, str) or not revision or revision.startswith("-"):
                raise ProvenanceError("invalid kernel revision")
            commit = _git(tree, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
            source_identity["revision"] = commit
            source_bytes = _git(tree, "show", commit + ":" + source_path)
        else:
            source_identity["revision"] = None
            source_bytes = _read_local(tree, source_path)
        source_identity["sha256"] = hashlib.sha256(source_bytes).hexdigest()
        source_identity["blob_sha256"] = source_identity["sha256"]
        # Working-tree changes are evidence distinct from the pinned blob. They
        # do not alter the blob used for comparison; consumers decide whether
        # they also use the checkout for preprocessing and must reject drift.
        try:
            source_identity["checkout_head"] = _git(tree, "rev-parse", "--verify", "HEAD").decode().strip()
            source_identity["checkout_status"] = _git(tree, "status", "--porcelain=v1", "--", source_path).decode().splitlines()
        except ProvenanceError as error:
            source_identity["checkout_metadata_error"] = str(error)
        try:
            working_bytes = _read_local(tree, source_path)
            source_identity["checkout_sha256"] = hashlib.sha256(working_bytes).hexdigest()
            source_identity["checkout_matches_source"] = working_bytes == source_bytes
        except ProvenanceError as error:
            source_identity["checkout_read_error"] = str(error)
            source_identity["checkout_matches_source"] = False
        harness_bytes = (source_bytes if mode == "pinned-translation-unit" else
                         _read_local(Path(root), harness_path))
        result["harness"]["sha256"] = hashlib.sha256(harness_bytes).hexdigest()
        try:
            source = source_bytes.decode("utf-8")
            harness = harness_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProvenanceError(f"source must be UTF-8: {error}") from error
        source_tokens, harness_tokens = tokenize(source), tokenize(harness)
        result["source"]["token_sha256"] = token_hash(source_tokens)
        result["harness"]["token_sha256"] = token_hash(harness_tokens)
        if mode in ("translation-unit", "pinned-translation-unit") and source_tokens != harness_tokens:
            result["errors"].append("translation unit has non-comment token changes")
        for name in functions:
            original = extract_function(source, name)
            annotated = extract_function(harness, name)
            body_equal = original.tokens == annotated.tokens
            declaration_equal = original.declaration_prefix == annotated.declaration_prefix
            item = {
                "name": name, "passed": body_equal,
                "source_line": original.line, "harness_line": annotated.line,
                "source_token_sha256": token_hash(original.tokens),
                "harness_token_sha256": token_hash(annotated.tokens),
                "declaration_prefix_equal": declaration_equal,
                "source_declaration_prefix": list(original.declaration_prefix),
                "harness_declaration_prefix": list(annotated.declaration_prefix),
                "source_declaration_sha256": token_hash(original.declaration_prefix),
                "harness_declaration_sha256": token_hash(annotated.declaration_prefix),
            }
            if not body_equal:
                result["errors"].append(f"{name}: parameter list or body token changes")
            if not declaration_equal:
                item["model_assumptions"] = target.get("assumptions", [])
                if (not isinstance(item["model_assumptions"], list)
                        or not item["model_assumptions"]
                        or any(not isinstance(a, str) or not a.strip() for a in item["model_assumptions"])):
                    item["passed"] = False
                    result["errors"].append(f"{name}: declaration prefix changed without declared model assumptions")
            result["functions"].append(item)
        result["passed"] = not result["errors"]
    except (ProvenanceError, OSError, TypeError, AttributeError) as error:
        result["errors"].append(str(error))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--harness", required=True)
    parser.add_argument("--function", action="append", required=True)
    parser.add_argument("--mode", choices=("translation-unit", "functions"), default="functions")
    parser.add_argument("--revision", help="Pinned git revision; omit to check working files")
    args = parser.parse_args(argv)
    result = check_target({"source": args.source, "harness": args.harness,
                           "functions": args.function, "provenance": {"mode": args.mode}},
                          args.kernel_tree, args.revision, args.root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
