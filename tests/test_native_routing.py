"""Explicit native evidence routes cannot compete or change provider authority."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fragma.__main__ import main
from fragma.suite import SuiteError, native_evidence_routes, validate_native_evidence


class NativeRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.selected = [{"id": name, "role": "calibration", "analysis": "eva"}
                         for name in ("string-case", "s390-case")]
        self.strings = self.write("strings", {"kind": "fragma-native-spec-sensitivity",
                                              "cases": [{"target_id": "string-case"}]})
        self.s390 = self.write("s390", {"kind": "fragma-s390-spec-sensitivity", "target_id": "s390-case"})

    def write(self, name, value):
        path = self.root / (name + ".json")
        path.write_text(json.dumps({"schema_version": 1, **value}))
        return path

    def test_distinct_providers_and_legacy_single_path_are_explicit(self):
        routes, paths = native_evidence_routes([self.strings, self.s390], self.selected)
        self.assertEqual(routes, {"string-case": self.strings, "s390-case": self.s390})
        self.assertEqual(paths, [self.strings, self.s390])
        self.assertEqual(native_evidence_routes(self.strings, self.selected)[0], {"string-case": self.strings})
        self.assertEqual(native_evidence_routes(None, self.selected), ({}, []))

    def test_duplicate_paths_and_competing_selected_witnesses_fail(self):
        competitor = self.write("competitor", {"kind": "fragma-native-spec-sensitivity",
                                                "cases": [{"target_id": "string-case"}]})
        for paths in ([self.strings, self.strings], [self.strings, competitor]):
            with self.subTest(paths=paths), self.assertRaises(SuiteError):
                native_evidence_routes(paths, self.selected)

    def test_non_paths_unrelated_inventory_and_unsupported_providers_fail(self):
        unrelated = self.write("unrelated", {"kind": "fragma-s390-spec-sensitivity", "target_id": "not-selected"})
        unsupported = self.write("unsupported", {"kind": "plugin.from.receipt", "target_id": "string-case"})
        for paths in (str(self.strings), [str(self.strings)], [unrelated], [unsupported]):
            with self.subTest(paths=paths), self.assertRaises(SuiteError):
                native_evidence_routes(paths, self.selected)

    def test_routing_does_not_grant_proof_role_authority(self):
        with self.assertRaises(SuiteError):
            native_evidence_routes(self.s390, [{**self.selected[1], "role": "proof"}])

    def test_only_fixed_provider_validator_receives_the_complete_context(self):
        context = (self.root, self.root / "kernel", self.selected[0], "a" * 40, {"model": 1}, {"build": 2})
        for path, provider in ((self.strings, "native_sensitivity"), (self.s390, "s390_sensitivity")):
            with self.subTest(provider=provider), \
                    patch("fragma." + provider + ".validate_native_receipt", return_value={"checked": True}) as validate:
                self.assertEqual(validate_native_evidence(*context, path), {"checked": True})
                validate.assert_called_once_with(*context, path)

    def test_cli_repeated_evidence_is_forwarded_without_implicit_selection(self):
        with patch("fragma.suite.run_suite", return_value={"status": "passed", "output": "test", "accepted": True}) as run, \
                patch("builtins.print"):
            self.assertEqual(main(["run", "--target", "calibration.s390.byte-order.eva",
                "--native-evidence", str(self.strings), "--native-evidence", str(self.s390)]), 0)
        self.assertEqual(run.call_args.kwargs["native_evidence"], [self.strings, self.s390])
        self.assertEqual(run.call_args.kwargs["ids"], ["calibration.s390.byte-order.eva"])


if __name__ == "__main__":
    unittest.main()
