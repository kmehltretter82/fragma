"""Positive-source assertion identities, with no compiler/analyzer execution.

Synthetic C below tests only the mapping parser; it is not compiled or accepted
as proof/ELF evidence. Optional retained readback observes historical raw streams
without relabeling their old provider status.
"""
import inspect
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma import common24_calibration as calibration, inputs


FUNCTION = "fragma_common24_compiler_calibration"


def block(case, number, *, call=None):
    symbol = "__compiletime_assert_" + str(number)
    call = symbol if call is None else call
    return ('do { __attribute__((__noreturn__)) extern void ' + symbol
        + '(void) __attribute__((__error__("fragma common24 " "' + case + '"))); '
        + 'if (!(!((1U) != ((1U) ^ (0 == (1)))))) ' + call + '(); } while (0);')


def expansion(offset=0, *, blocks=None, name=FUNCTION, header=""):
    rows = [block(case, offset + index) for index, case in enumerate(calibration.CASES)] if blocks is None else blocks
    return header + '\nvoid ' + name + '(void);\nvoid ' + name + '(void)\n{\n' + '\n'.join(rows) + '\n}\n'


def diagnostic(case, symbol):
    return ("fixture.c:46:9: error: call to '" + symbol
        + "' declared with attribute error: fragma common24 " + case + "\n")


def forbidden(*args, **kwargs):
    raise AssertionError("compiler/analyzer/native/subprocess transport forbidden")


class NoProcesses(unittest.TestCase):
    def setUp(self):
        for patcher in (patch.object(subprocess, "Popen", side_effect=forbidden),
                        patch.object(subprocess, "run", side_effect=forbidden),
                        patch.object(inputs, "run_recorded", side_effect=forbidden)):
            patcher.start(); self.addCleanup(patcher.stop)


class AssertionSymbolTests(NoProcesses):
    def test_zero_and_header_shifted_offsets_have_exact_ordered_maps(self):
        for offset in (0, 2):
            with self.subTest(offset=offset):
                expected = {case: "__compiletime_assert_" + str(offset + index)
                            for index, case in enumerate(calibration.CASES)}
                actual = calibration.assertion_symbols(expansion(offset))
                self.assertEqual(actual, expected)
                self.assertEqual(list(actual), list(calibration.CASES))

    def test_unrelated_header_assertions_do_not_shift_or_pollute_observed_map(self):
        header = ('static inline void header_check(void) { '
            '__attribute__((__noreturn__)) extern void __compiletime_assert_0(void) '
            '__attribute__((__error__("header assertion"))); '
            'if (0) __compiletime_assert_0(); }\n'
            'static inline void header_check_two(void) { '
            '__attribute__((__noreturn__)) extern void __compiletime_assert_1(void) '
            '__attribute__((__error__("another unrelated header assertion"))); '
            'if (0) __compiletime_assert_1(); }\n')
        self.assertEqual(calibration.assertion_symbols(expansion(2, header=header)),
                         calibration.assertion_symbols(expansion(2)))

    def test_missing_reordered_duplicated_unknown_labels_are_rejected(self):
        rows = [block(case, index) for index, case in enumerate(calibration.CASES)]
        corruptions = [rows[:-1], [rows[1], rows[0], *rows[2:]], [*rows, rows[0]],
            [rows[0], rows[1].replace('"decode_le"', '"decode_be"'), *rows[2:]],
            [rows[0].replace('"decode_be"', '"unrelated_case"'), *rows[1:]]]
        for changed in corruptions:
            with self.subTest(changed=changed[:2]), self.assertRaises(ValueError):
                calibration.assertion_symbols(expansion(blocks=changed))

    def test_duplicate_nonconsecutive_and_malformed_symbols_are_rejected(self):
        text = expansion(2)
        for replacement in ("__compiletime_assert_2", "__compiletime_assert_999",
                            "__compiletime_assert_-3", "__compiletime_assert_x",
                            "__compiletime_assert_03", "unrelated_assert_3"):
            changed = text.replace("__compiletime_assert_3(", replacement + "(")
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                calibration.assertion_symbols(changed)

    def test_calls_must_match_their_ordered_declarations_inside_the_function(self):
        text = expansion(2)
        first_call, second_call = "__compiletime_assert_2();", "__compiletime_assert_3();"
        changed = [text.replace(first_call, ""), text.replace(first_call, second_call),
            text.replace(first_call, first_call + " " + first_call),
            text.replace(first_call, "(void)\"" + first_call + "\";"),
            text.replace(first_call, "/* " + first_call + " */"),
            text.replace(first_call, "PLACEHOLDER()").replace(second_call, first_call).replace("PLACEHOLDER()", second_call)]
        outside = 'void wrong_place(void) { ' + first_call + ' }\n'
        changed.append(outside + text.replace(first_call, ""))
        for source in changed:
            with self.subTest(source=source[:80]), self.assertRaises(ValueError):
                calibration.assertion_symbols(source)

    def test_assertions_in_wrong_function_or_duplicate_definition_are_rejected(self):
        wrong = expansion(2, name="other_function")
        for source in (wrong, wrong + 'void ' + FUNCTION + '(void) {}\n',
                       expansion(2) + expansion(2), 'void ' + FUNCTION + '(void);\n'):
            with self.subTest(source=source[:60]), self.assertRaises(ValueError):
                calibration.assertion_symbols(source)

    def test_explicit_expected_symbol_is_required_and_keyword_only(self):
        parameter = inspect.signature(calibration.validate_wrong).parameters["symbol"]
        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(parameter.default, inspect.Parameter.empty)
        with self.assertRaises(TypeError):
            calibration.validate_wrong("decode_be", {"returncode": 1, "timed_out": False},
                                       diagnostic("decode_be", "__compiletime_assert_2"), "", False)

    def test_negative_diagnostic_uses_only_the_supplied_positive_symbol(self):
        command = {"returncode": 1, "timed_out": False}
        expected = calibration.assertion_symbols(expansion(2))["decode_be"]
        good = diagnostic("decode_be", expected)
        calibration.validate_wrong("decode_be", command, good, "", False, symbol=expected)
        for text in (good.replace(expected, "__compiletime_assert_0"), good + good,
                     good + "cc1: warning: extra\n", good + "cc1: error: unrelated\n",
                     good.replace("decode_be", "decode_le")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                calibration.validate_wrong("decode_be", command, text, "", False, symbol=expected)
        for wrong in ("__compiletime_assert_0", "wrong", "__compiletime_assert_-2", None, True):
            with self.subTest(symbol=wrong), self.assertRaises(ValueError):
                calibration.validate_wrong("decode_be", command, good, "", False, symbol=wrong)


class CommandReadbackTests(NoProcesses):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix="common24 symbol streams ")
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.binding = {"base_argv": ["/inert/target-gcc", "-O2"], "source": "/inert/calibration.c",
                        "cwd": "/inert/configured-build", "big_endian": False}
        # validate_commands checks presence only. Separate provider ELF tests
        # require a genuine bounded function; these inert bytes claim no ELF.
        (self.output / "positive.o").write_bytes(b"inert object-presence unit fixture")

    def streams(self, *, positive_offset=2, negative_offset=2):
        commands = []
        for index, (name, argv) in enumerate(calibration.command_plan(self.binding, self.output)):
            stdout, stderr = self.output / (name + ".stdout"), self.output / (name + ".stderr")
            stdout.write_text(expansion(positive_offset) if name == "preprocess" else "")
            stderr.write_text(diagnostic(calibration.CASES[index - 3],
                "__compiletime_assert_" + str(negative_offset + index - 3)) if index >= 3 else "")
            commands.append({"name": name, "argv": argv, "cwd": self.binding["cwd"],
                "returncode": 1 if index >= 3 else 0, "timed_out": False,
                "log": str(stderr), "log_sha256": calibration.sha(stderr),
                "stdout": {"path": str(stdout), "sha256": calibration.sha(stdout)},
                "stderr": {"path": str(stderr), "sha256": calibration.sha(stderr)}})
        return commands

    def test_command_readback_derives_shifted_identity_from_positive_stream(self):
        commands = self.streams()
        calibration.validate_commands(self.binding, self.output, commands)

    def test_rehashed_error_symbol_cannot_supply_its_own_expected_identity(self):
        commands = self.streams()
        path = self.output / "wrong-decode_be.stderr"
        path.write_text(diagnostic("decode_be", "__compiletime_assert_999"))
        commands[3]["log_sha256"] = calibration.sha(path)
        commands[3]["stderr"]["sha256"] = calibration.sha(path)
        with self.assertRaises(ValueError):
            calibration.validate_commands(self.binding, self.output, commands)

    def test_negative_inventory_cannot_override_different_positive_mapping(self):
        commands = self.streams(positive_offset=0, negative_offset=2)
        with self.assertRaises(ValueError):
            calibration.validate_commands(self.binding, self.output, commands)


@unittest.skipUnless(os.environ.get("FRAGMA_COMMON24_ASSERTION_RESULTS"),
                     "optional explicit retained ARM64/RISC-V assertion streams; no execution")
class RetainedAssertionTests(NoProcesses):
    def test_actual_positive_maps_and_first_negative_with_original_status_preserved(self):
        base = Path(os.environ["FRAGMA_COMMON24_ASSERTION_RESULTS"]).resolve()
        before = {}
        for identifier, offset in (("common.unaligned24.arm64", 0), ("common.unaligned24.riscv64", 2)):
            with self.subTest(target=identifier):
                directory = base / identifier / "compiler-calibration"
                receipt_path = directory / "receipt.json"
                receipt = json.loads(receipt_path.read_text())
                stream, errors, stdout = (directory / name for name in
                    ("preprocess.stdout", "wrong-decode_be.stderr", "wrong-decode_be.stdout"))
                for path in (receipt_path, stream, errors, stdout):
                    before[str(path)] = calibration.sha(path)
                actual = calibration.assertion_symbols(stream.read_text())
                self.assertEqual(actual, {case: "__compiletime_assert_" + str(offset + index)
                    for index, case in enumerate(calibration.CASES)})
                command = next(row for row in receipt["commands"] if row["name"] == "wrong-decode_be")
                calibration.validate_wrong("decode_be", command, errors.read_text(), stdout.read_text(),
                    (directory / "wrong-decode_be.o").exists(), symbol=actual["decode_be"])
                if offset == 2:
                    self.assertEqual(receipt["status"], "error")
                    with self.assertRaises(ValueError):
                        calibration.validate_wrong("decode_be", command, errors.read_text(), "", False,
                                                   symbol="__compiletime_assert_0")
        self.assertEqual(before, {name: calibration.sha(name) for name in before})


if __name__ == "__main__":
    unittest.main()
