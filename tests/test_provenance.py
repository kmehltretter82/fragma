"""Source gates must fail closed, especially when both extractions are empty."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma.provenance import (
    ProvenanceError, check_target, extract_function, main, tokenize, token_hash,
)


class LexerTests(unittest.TestCase):
    def test_comments_and_whitespace(self):
        self.assertEqual(tokenize("int f(void) { return 3; }"),
                         tokenize("/*@ ensures \\result == 3; */\nint\tf(void)\n{ // note\nreturn /*x*/3; }"))

    def test_strings_are_not_comments(self):
        source = 'const char *s = "// /* { } \\\" "; char c = \'/\';'
        self.assertIn('"// /* { } \\\" "', tokenize(source))
        self.assertNotEqual(tokenize('char *s = "a b";'), tokenize('char *s = "ab";'))

    def test_literal_prefixes_and_numbers(self):
        tokens = tokenize('L"text" u8"more" 1e+2 0x1p-3 .5f')
        self.assertEqual(tokens, ('L"text"', 'u8"more"', '1e+2', '0x1p-3', '.5f'))

    def test_operator_boundaries(self):
        self.assertNotEqual(tokenize("a+++b;"), tokenize("a+ + +b;"))
        self.assertNotEqual(tokenize("unsignedlong x;"), tokenize("unsigned/**/long x;"))

    def test_splicing_precedes_line_comments(self):
        self.assertEqual(tokenize("// hidden \\\nint bad;\nint good;"), tokenize("int good;"))
        self.assertEqual(tokenize("int f(void) { ret\\\nurn 1; }"), tokenize("int f(void) { return 1; }"))

    def test_preprocessor_boundaries_matter(self):
        self.assertNotEqual(tokenize("#define A 1\nint x;"), tokenize("#define A 1 int x;"))
        self.assertNotEqual(tokenize("#define F(x) (x)"), tokenize("#define F (x) (x)"))
        self.assertEqual(tokenize("#define F (x) (x)"), tokenize("#define F/**/(x) (x)"))
        self.assertEqual(tokenize("#define A 1 /* multi\nline */ + 2"), tokenize("#define A 1 + 2"))

    def test_header_tokens(self):
        self.assertIn("<path//literal.h>", tokenize("#include <path//literal.h>"))
        self.assertIn("<path/*literal.h>", tokenize("#include <path/*literal.h>"))

    def test_malformed_lexical_input(self):
        for source in ("", "  /* only a comment */", "/* open", 'char *x = "open;',
                       "int x;\x00", "char c = '';", 'char *x = "line\nline";',
                       "int x = `bad`;", "??=define A 1", "%:define A 1", "int x #foo;",
                       "#include <unterminated"):
            with self.subTest(source=source), self.assertRaises(ProvenanceError):
                tokenize(source)

    def test_hash_respects_token_boundaries(self):
        self.assertNotEqual(token_hash(("a", "bc")), token_hash(("ab", "c")))


class ExtractionTests(unittest.TestCase):
    def test_nested_braces_and_literals(self):
        source = 'static int f(int x) { char *s = "} {"; if (x) { int a[] = {1, 2}; return a[0]; } return 0; }'
        function = extract_function(source, "f")
        self.assertEqual(function.declaration_prefix, ("static", "int"))
        self.assertEqual(function.tokens[0], "f")
        self.assertEqual(function.tokens[-1], "}")
        self.assertIn('"} {"', function.tokens)

    def test_prototype_and_calls_do_not_count_as_definitions(self):
        source = "int f(int x); int g(void) { return f(1); } int f(int x) { return x; }"
        self.assertIn("x", extract_function(source, "f").tokens)

    def test_missing_and_wrong_names(self):
        for source in ("int x;", "int f(void);", "int f_fake(void) { return 1; }",
                       "#define f(x) (x)", "MAKE_FN(f) { return 1; }"):
            with self.subTest(source=source), self.assertRaises(ProvenanceError):
                extract_function(source, "f")
        with self.assertRaises(ProvenanceError):
            extract_function("int x;", "f.*")

    def test_duplicate_and_conditional_definitions(self):
        for source in ("int f(void) { return 1; } int f(void) { return 2; }",
                       "#ifdef CONFIG_X\nint f(void) { return 1; }\n#else\nint f(void) { return 2; }\n#endif"):
            with self.subTest(source=source), self.assertRaisesRegex(ProvenanceError, "found 2"):
                extract_function(source, "f")

    def test_unbalanced_and_unsupported_definitions(self):
        for source in ("int f(void) {", "int f(void) { return (1]; }",
                       "int f(void)", "int f(x) int x; { return x; }",
                       "int f(void) POST_ATTRIBUTE { return 1; }",
                       "f(void) { return 1; }", "int f(int x;) { return x; }"):
            with self.subTest(source=source), self.assertRaises(ProvenanceError):
                extract_function(source, "f")

    def test_directives_inside_function_are_retained(self):
        source = "int f(void) {\n#ifdef CONFIG_X\nreturn 1;\n#else\nreturn 2;\n#endif\n}"
        tokens = extract_function(source, "f").tokens
        self.assertIn("CONFIG_X", tokens)
        self.assertIn("<pp-start>", tokens)

    def test_macro_definition_is_not_a_function(self):
        source = "#define DECL int f(void) { return 0; }\nint f(void) { return 1; }"
        self.assertEqual(extract_function(source, "f").tokens[-3:], ("1", ";", "}"))


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.kernel = self.root / "kernel"
        self.kernel.mkdir()
        self.source = "int f(int x) { if (x) { return x + 1; } return 0; }\n"
        (self.kernel / "source.c").write_text(self.source)
        (self.root / "harness.c").write_text("/*@ requires x >= 0; */\n" + self.source)
        self.target = {"source": "source.c", "harness": "harness.c", "functions": ["f"],
                       "provenance": {"mode": "translation-unit"}}

    def check(self, revision=None):
        return check_target(self.target, self.kernel, revision, self.root)

    def test_identical_with_hashes(self):
        result = self.check()
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(self.source.encode()).hexdigest())
        self.assertEqual(result["source"]["token_sha256"], result["harness"]["token_sha256"])
        self.assertTrue(result["source"]["checkout_matches_source"])
        json.dumps(result)

    def test_changed_token(self):
        (self.root / "harness.c").write_text(self.source.replace("x + 1", "x - 1"))
        self.assertFalse(self.check()["passed"])

    def test_changed_non_target_token_fails_whole_translation_unit(self):
        (self.root / "harness.c").write_text(self.source + "int unrelated;\n")
        self.assertFalse(self.check()["passed"])
        self.target["provenance"]["mode"] = "functions"
        self.assertTrue(self.check()["passed"])

    def test_changed_parameter_list_fails(self):
        self.target["provenance"]["mode"] = "functions"
        (self.root / "harness.c").write_text(self.source.replace("int x)", "unsigned x)"))
        self.assertFalse(self.check()["passed"])

    def test_changed_prefix_requires_explicit_assumptions(self):
        self.target["provenance"]["mode"] = "functions"
        (self.root / "harness.c").write_text("static " + self.source)
        self.assertFalse(self.check()["passed"])
        self.target["assumptions"] = ["reviewed-static-substitution"]
        result = self.check()
        self.assertTrue(result["passed"], result)
        self.assertFalse(result["functions"][0]["declaration_prefix_equal"])
        self.assertEqual(result["functions"][0]["model_assumptions"], self.target["assumptions"])

    def test_missing_files(self):
        for field in ("source", "harness"):
            with self.subTest(field=field):
                old = self.target[field]
                self.target[field] = "missing.c"
                result = self.check()
                self.assertFalse(result["passed"])
                self.assertIn("cannot read", result["errors"][0])
                self.target[field] = old

    def test_empty_both_sides_cannot_pass(self):
        for source in ("", "/* comment */", "int other(void) { return 0; }"):
            with self.subTest(source=source):
                (self.kernel / "source.c").write_text(source)
                (self.root / "harness.c").write_text(source)
                self.assertFalse(self.check()["passed"])

    def test_malformed_both_sides_cannot_pass(self):
        for source in ("int f(void) {", "int f(void) { return 0; } /*",
                       "int f(void) { return 0; } int f(void) { return 1; }"):
            with self.subTest(source=source):
                (self.kernel / "source.c").write_text(source)
                (self.root / "harness.c").write_text(source)
                self.assertFalse(self.check()["passed"])

    def test_invalid_metadata(self):
        for functions in ([], ["f", "f"], ["f.*"], "f", None, [None]):
            with self.subTest(functions=functions):
                self.target["functions"] = functions
                self.assertFalse(self.check()["passed"])

    def test_unsupported_mode_and_unsafe_paths(self):
        self.target["provenance"]["mode"] = "magic"
        self.assertFalse(self.check()["passed"])
        self.target["provenance"]["mode"] = "functions"
        for value in ("../harness.c", "/etc/passwd", "", "-bad.c"):
            with self.subTest(value=value):
                self.target["source"] = value
                self.assertFalse(self.check()["passed"])

    def test_symlink_outside_root(self):
        (self.kernel / "outside.c").symlink_to(self.root / "harness.c")
        self.target["source"] = "outside.c"
        self.assertFalse(self.check()["passed"])

    def test_pinned_blob_is_distinct_from_checkout(self):
        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.kernel), *args], stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-q")
        git("add", "source.c")
        git("-c", "user.name=Provenance Test", "-c", "user.email=provenance@example.invalid",
            "commit", "-qm", "fixture")
        commit = git("rev-parse", "HEAD")
        (self.kernel / "source.c").write_text(self.source.replace("x + 1", "x + 2"))
        result = self.check(commit)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["source"]["revision"], commit)
        self.assertFalse(result["source"]["checkout_matches_source"])
        self.assertTrue(result["source"]["checkout_status"])
        self.assertFalse(self.check()["passed"])
        self.assertFalse(self.check("missing-revision")["passed"])
        self.target["source"] = "missing.c"
        self.assertFalse(self.check(commit)["passed"])

    def test_cli_failure_is_nonzero(self):
        with patch("builtins.print"):
            status = main(["--kernel-tree", str(self.kernel), "--root", str(self.root),
                           "--source", "missing.c", "--harness", "harness.c", "--function", "f"])
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
