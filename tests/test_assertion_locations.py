"""Retain exact identities when TSV locations begin at an assertion predicate."""

from pathlib import Path
import tempfile
import unittest

from fragma.report import ReportError, named_assertions, parse_properties


class AssertionLocationTests(unittest.TestCase):
    def test_multiline_label_maps_declaration_and_predicate_start_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "driver.c"
            source.write_text("void f(void) {\n"
                              "/*@ assert quantified:\n"
                              "    \\forall integer j;\n"
                              "    0 <= j < 8 ==> j != 9; */\n"
                              "}\n")
            names = named_assertions([source])
            self.assertEqual(names, {(str(source), 2): "quantified", (str(source), 3): "quantified"})
            self.assertEqual(named_assertions([source], predicate_starts=False), {(str(source), 2): "quantified"})
            report = Path(temporary) / "properties.tsv"
            report.write_text("directory\tfile\tline\tfunction\tproperty kind\tstatus\tproperty\n"
                              f"{temporary}\tdriver.c\t3\tf\tuser assertion\tValid\t∀ ℤ j; 0 ≤ j < 8 ⇒ j ≢ 9\n")
            row = parse_properties(report, source_files=[source])[0]
            self.assertEqual(row["names"], ["quantified", "f_assert_quantified"])

    def test_multiline_alias_cannot_hide_another_named_assertion_on_same_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "driver.c"
            source.write_text("void f(void) {\n"
                              "/*@ assert first:\n"
                              "    1; assert second: 1; */\n"
                              "}\n")
            with self.assertRaisesRegex(ReportError, "Ambiguous"):
                named_assertions([source])

    def test_c_strings_do_not_create_assertion_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "driver.c"
            source.write_text('const char *s = "/*@ assert fake: 1; */";\n')
            self.assertEqual(named_assertions([source]), {})


if __name__ == "__main__":
    unittest.main()
