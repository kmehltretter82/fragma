"""Authentic synthetic read-back; only compiler/Git process transports are mocked.

Context, source/gate/ELF/control/receipt validators and normalization run normally.
No emitted code or analyzer runs, and no reviewed production evidence is created.
"""

import ast
import copy
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma import common24_calibration as calibration
from fragma import common24_controls as controls
from fragma import analysis_policy, frontend_policy, inputs, integrity, provenance, replay
from tests import test_common24_calibration_context as context_fixtures
from tests.test_common24_calibration import expanded_assertions
from tests.test_elf import calibration_elf


ROOT = Path(__file__).resolve().parents[1]


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.fixture = self.make_fixture()

    def make_fixture(self):
        fixture = context_fixtures.SyntheticContextTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        for name in [*calibration.required_files(fixture.target), "fragma/common24.py",
                     frontend_policy.HARNESS, frontend_policy.STRATEGY]:
            fixture.write(fixture.root / name, (ROOT / name).read_bytes())
        harness = (ROOT / frontend_policy.HARNESS).read_text()
        functions = [provenance.extract_function(harness, name) for name in calibration.HELPERS]
        header = "\n".join(" ".join([*function.declaration_prefix, *function.tokens])
                           for function in functions) + "\n"
        for name, text in {"include/linux/unaligned.h": header,
                           "include/linux/build_bug.h": "/* synthetic pinned error macro input */\n"}.items():
            fixture.write(fixture.source / name, text)
            fixture.git_blobs[name] = text.encode()
        fixture.binding = fixture.context()
        fixture.gate = fixture.make_gate()
        fixture.calibration_output = fixture.output / "compiler-calibration"
        fixture.compiler_calls = []
        fixture.expanded = "\n".join(" ".join([
            *frontend_policy.expected_prefix(fixture.target, function.name), *function.tokens])
            for function in functions)
        fixture.expanded += "\n" + expanded_assertions()
        fixture.positive_dependencies = [fixture.root / calibration.SOURCE,
            *(fixture.source / "include/linux" / name for name in
              ("types.h", "unaligned.h", "compiler_types.h", "build_bug.h")), fixture.generated]

        def compiler(argv, *, cwd, env, log, stdout_file, timeout):
            self.assertEqual(argv[0], str(fixture.compiler))
            self.assertEqual(cwd, fixture.build_path)
            self.assertEqual(env, calibration.compiler_environment(log.parent))
            self.assertEqual(timeout, 60)
            fixture.compiler_calls.append(list(argv))
            name = log.name.removesuffix(".stderr")
            log.write_text("")
            stdout_file.write_text("")
            code = 0
            if name in controls.NAMES:
                code = 1
                log.write_text("".join(str(fixture.root / frontend_policy.FIXTURE)
                    + ':' + str(line) + ':1: error: static assertion failed: "' + message + '"\n'
                    for line, message in controls.DIAGNOSTICS[name]))
            elif name == "positive":
                (log.parent / "positive.o").write_bytes(calibration_elf())
                names = [str(path).replace("\\", "\\\\").replace(" ", "\\ ")
                         for path in fixture.positive_dependencies]
                (log.parent / "positive.d").write_text("fragma: " + " ".join(names) + "\n")
            elif name == "macros":
                stdout_file.write_text("#define __OPTIMIZE__ 1\n"
                    "#define __compiletime_error(msg) __attribute__((__error__(msg)))\n"
                    "#define FRAGMA_COMMON24_WRONG_CASE 0\n")
            elif name == "preprocess":
                stdout_file.write_text(fixture.expanded)
            else:
                case = name.removeprefix("wrong-")
                index = calibration.CASES.index(case)
                code = 1
                log.write_text("fixture.c:1:1: error: call to '__compiletime_assert_" + str(index)
                    + "' declared with attribute error: fragma common24 " + case + "\n")
            return {"argv": list(argv), "cwd": str(cwd), "returncode": code,
                "timed_out": False, "seconds": 0.01, "log": str(log), "log_sha256": calibration.sha(log)}

        # This is the sole compiler boundary mock; every production validator runs.
        with patch.object(inputs, "run_recorded", side_effect=compiler):
            fixture.observed = calibration.run(fixture.root, fixture.target, fixture.model,
                fixture.build, fixture.kernel, fixture.revision, fixture.calibration_output,
                calibration.compiler_environment(fixture.calibration_output),
                kernel_model_gate=fixture.gate, kernel_model_output=fixture.output)
        self.assertEqual(fixture.observed["status"], calibration.STATUS,
                         (fixture.calibration_output / "receipt.json").read_text())
        self.assertEqual(len(fixture.compiler_calls), 27)
        self.assertEqual(fixture.observed["commands_checked"], 25)
        self.assertEqual(fixture.observed["artifact_count"], 52)
        fixture.evidence = {"kernel_model_check": fixture.gate,
            "validated_compiler_calibration": fixture.observed,
            "integrity_inputs": copy.deepcopy(fixture.observed["tracked_files"]),
            "validated_review": None,
            "assumptions": [{"id": "synthetic-pending", "review_status": "pending"}]}
        fixture.shared = {row["absolute_path"]: row["sha256"] for row in fixture.observed["tracked_files"]}
        fixture.mapper = replay.Mapper(replay.RootBindings({"project": str(fixture.root),
            "kernel": str(fixture.kernel), "build:arm-gcc": str(fixture.build_path)}), fixture.output)
        return fixture

    def observe(self, *, evidence=None, shared=None, target=None, read=None):
        fixture = self.fixture
        return calibration.observation(fixture.root, fixture.target if target is None else target,
            fixture.model, fixture.evidence if evidence is None else evidence,
            fixture.shared if shared is None else shared, read=read)

    def test_real_readback_binds_all_artifacts_with_binary_reader(self):
        seen = []
        def read(path, expected, *, binary=False):
            self.assertTrue(binary)
            self.assertEqual(calibration.sha(path), expected)
            self.assertTrue(Path(path).is_relative_to(self.fixture.output))
            seen.append(path)
            return Path(path).read_bytes()
        observed = self.observe(read=read)
        self.assertEqual(observed, self.fixture.observed)
        required = {row["absolute_path"] for row in observed["tracked_files"]
                    if Path(row["absolute_path"]).is_relative_to(self.fixture.output)}
        self.assertEqual(set(seen), required)
        self.assertTrue(any(path.endswith("positive.o") for path in seen))
        self.assertEqual(len(self.fixture.compiler_calls), 27)

    def test_absent_legacy_evidence_is_not_backfilled(self):
        self.assertIsNone(calibration.observation(self.fixture.root, {}, {}, {}, {}))
        with self.assertRaisesRegex(calibration.CalibrationError, "no declared setting"):
            calibration.observation(self.fixture.root, {}, {}, self.fixture.evidence, {})
        self.assertIsNone(calibration.logical_observation(None, self.fixture.mapper))

    def test_hash_checks_regular_input_before_open_and_allows_compiler_symlink(self):
        # Mock the unsupported file kind; never open or create a special file.
        with patch.object(Path, "is_file", return_value=False), \
                patch.object(Path, "read_bytes") as read:
            with self.assertRaisesRegex(calibration.CalibrationError, "non-regular input"):
                calibration.sha(self.fixture.compiler)
            read.assert_not_called()
        link = self.fixture.root / "compiler-link"
        link.symlink_to(self.fixture.compiler)
        self.assertEqual(calibration.sha(link), calibration.sha(self.fixture.compiler))

    def test_required_envelope_missing_failed_or_altered_rejected(self):
        for envelope in (None, {}, {**self.fixture.observed, "status": "native-corroborated"},
                         {**self.fixture.observed, "commands_checked": 24}):
            evidence = copy.deepcopy(self.fixture.evidence)
            evidence["validated_compiler_calibration"] = envelope
            with self.subTest(envelope=envelope), self.assertRaises(calibration.CalibrationError):
                self.observe(evidence=evidence)

    def test_receipt_cannot_move_outside_expected_sibling_even_with_rebinding(self):
        evidence = copy.deepcopy(self.fixture.evidence)
        old = Path(evidence["validated_compiler_calibration"]["receipt"]["absolute_path"])
        moved = self.fixture.output / "other-receipt.json"
        moved.write_bytes(old.read_bytes())
        row = calibration.record(moved)
        evidence["validated_compiler_calibration"]["receipt"] = row
        evidence["integrity_inputs"].append(row)
        with self.assertRaisesRegex(calibration.CalibrationError, "receipt path/hash"):
            self.observe(evidence=evidence, shared={**self.fixture.shared, str(moved): row["sha256"]})

    def test_required_tracked_artifact_and_input_cannot_be_omitted(self):
        candidates = (self.fixture.calibration_output / "positive.o",
                      self.fixture.root / calibration.SOURCE,
                      self.fixture.output / "compiler-controls/receipt.json")
        for path in candidates:
            evidence = copy.deepcopy(self.fixture.evidence)
            evidence["integrity_inputs"] = [row for row in evidence["integrity_inputs"]
                                            if row["absolute_path"] != str(path)]
            shared = {name: value for name, value in self.fixture.shared.items() if name != str(path)}
            with self.subTest(path=path), self.assertRaisesRegex(calibration.CalibrationError, "omitted"):
                self.observe(evidence=evidence, shared=shared)

    def test_conflicting_integrity_and_current_drift_rejected(self):
        evidence = copy.deepcopy(self.fixture.evidence)
        evidence["integrity_inputs"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(calibration.CalibrationError, "conflicting"):
            self.observe(evidence=evidence)
        source = self.fixture.root / calibration.SOURCE
        source.write_bytes(source.read_bytes() + b"\n/* drift */\n")
        with self.assertRaisesRegex(calibration.CalibrationError, "reviewed calibration source changed"):
            self.observe()

    def test_changed_raw_receipt_rejected_before_saved_labels(self):
        receipt = Path(self.fixture.observed["receipt"]["absolute_path"])
        receipt.write_bytes(receipt.read_bytes() + b"\n")
        with self.assertRaisesRegex(calibration.CalibrationError, "receipt bytes changed"):
            self.observe()

    def test_consumed_only_kernel_header_drift_is_rederived(self):
        header = self.fixture.source / "include/linux/build_bug.h"
        header.write_text("/* changed after compiler observation */\n")
        with self.assertRaises(ValueError):
            self.observe()

    def test_scoped_review_binds_policy_and_current_implementation(self):
        evidence = copy.deepcopy(self.fixture.evidence)
        context = {"compiler_calibration": calibration.review_identity(self.fixture.target),
            "file_hashes": {name: calibration.sha(self.fixture.root / name)
                            for name in calibration.required_files(self.fixture.target)}}
        evidence["validated_review"] = {"status": "passed", "review_context": context}
        self.assertEqual(self.observe(evidence=evidence), self.fixture.observed)
        altered = copy.deepcopy(evidence)
        altered["validated_review"]["review_context"]["compiler_calibration"]["cases"] = []
        with self.assertRaisesRegex(calibration.CalibrationError, "review compiler policy"):
            self.observe(evidence=altered)
        for name in calibration.required_files(self.fixture.target):
            altered = copy.deepcopy(evidence)
            altered["validated_review"]["review_context"]["file_hashes"].pop(name)
            with self.subTest(name=name), self.assertRaisesRegex(calibration.CalibrationError, "review compiler implementation"):
                self.observe(evidence=altered)

    def test_pending_assumptions_are_not_upgraded_by_compiler_observation(self):
        before = copy.deepcopy(self.fixture.evidence)
        observed = self.observe()
        self.assertEqual(self.fixture.evidence, before)
        self.assertIsNone(self.fixture.evidence["validated_review"])
        self.assertEqual(self.fixture.evidence["assumptions"][0]["review_status"], "pending")
        for field in ("accepted", "verified", "reviewed_assumptions", "reviewed_smoke", "reviewed_warnings"):
            self.assertNotIn(field, observed)
        # A static integration invariant, not a synthetic proof acceptance run:
        # retain the actual replay guard before any logical compiler identity.
        tree = ast.parse(inspect.getsource(replay.build_replay_view))
        guards = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Name) and node.func.id == "require"
                  and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
                  and node.args[1].value == "assumption approvals are incomplete"]
        self.assertEqual(len(guards), 1)
        guard = compile(ast.Expression(guards[0].args[0]), "<replay pending guard>", "eval")
        self.assertFalse(eval(guard, {"evidence": self.fixture.evidence}))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "logical_observation"
                 and isinstance(node.func.value, ast.Name) and node.func.value.id == "common24_calibration"]
        self.assertEqual(len(calls), 1)
        self.assertLess(guards[0].lineno, calls[0].lineno)

    def test_real_review_hook_requires_compiler_policy_and_file_bindings(self):
        fixture = self.fixture
        target = copy.deepcopy(fixture.target)
        note = "synthetic-review-evidence.txt"
        fixture.write(fixture.root / note, "Unit fixture only; no production review approval.\n")
        tools = {"lock_sha256": "a" * 64}
        prepared = {"frama_cpp_command": "inert-compiler -E -C",
                    "annotations": "native-acsl"}
        preprocessing = {"cpp_command": prepared["frama_cpp_command"],
            "annotations": prepared["annotations"], "input_mode": target["input_mode"],
            "extra_args": ["-std=gnu11"], "frontend_policy": frontend_policy.identity(target)}
        names = {target[field] for field in ("harness", "kernel_model_check", "wp_strategy_file")}
        names.update(frontend_policy.required_files(target))
        names.update(calibration.required_files(target))
        names.update({"fragma/analysis_policy.py", "fragma/common24.py",
            str(fixture.yaml.relative_to(fixture.root)),
            str((fixture.source / target["source"]).relative_to(fixture.root)),
            str((fixture.build_path / "fragma-build.json").relative_to(fixture.root))})
        hashes = {name: calibration.sha(fixture.root / name) for name in names}
        target["reviewed_warnings"] = [{"file_hashes": {calibration.SOURCE: hashes[calibration.SOURCE]},
                                        "review_evidence": [note]}]
        target["review_context"] = {"kernel_revision": fixture.revision, "profile": target["profile"],
            "toolchain_lock_sha256": tools["lock_sha256"],
            "analysis": analysis_policy.model_identity(fixture.model["analysis"]),
            "analysis_pipeline": analysis_policy.pipeline_identity(target),
            "preprocessing": preprocessing, "compiler_calibration": calibration.review_identity(target),
            "proof_search": {key: target[key] for key in ("wp_strategy", "wp_strategy_file",
                "wp_strategy_provers", "wp_auto_depth", "wp_smoke_timeout") if key in target},
            "file_hashes": hashes, "review_evidence": [note]}
        def validate(value):
            return integrity.validate_review(fixture.root, value, fixture.revision, fixture.model,
                                             fixture.build, tools, prepared)
        self.assertEqual(validate(target)["status"], "passed")
        # These authenticate only the review-input hook, not warning exemptions.
        for replacement in (None, {}, {**calibration.review_identity(target), "cases": []}):
            changed = copy.deepcopy(target)
            changed["review_context"]["compiler_calibration"] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "compiler-calibration policy"):
                validate(changed)
        for name in calibration.required_files(target):
            changed = copy.deepcopy(target)
            changed["review_context"]["file_hashes"].pop(name)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "omits"):
                validate(changed)
        path = fixture.root / "fragma/common24_controls.py"
        path.write_bytes(path.read_bytes() + b"\n# review drift\n")
        with self.assertRaisesRegex(ValueError, "reviewed inputs changed"):
            validate(target)

    def test_logical_identity_is_portable_but_semantic_commands_remain_bound(self):
        first = calibration.logical_observation(self.observe(), self.fixture.mapper)
        other = self.make_fixture()
        second_observed = calibration.observation(other.root, other.target, other.model,
            other.evidence, other.shared)
        second = calibration.logical_observation(second_observed, other.mapper)
        self.assertNotEqual(self.fixture.observed["receipt"], other.observed["receipt"])
        self.assertEqual(first, second)
        self.assertNotIn(str(self.fixture.root), json.dumps(first))
        self.assertNotIn(str(other.root), json.dumps(second))
        self.assertEqual(len(first["commands"]), 25)
        self.assertEqual(len(first["control_commands"]), 2)
        changed = copy.deepcopy(second_observed)
        raw = calibration.read_json(changed["receipt"]["absolute_path"])
        raw["commands"][0]["argv"].append("-DOPAQUE_POLICY=changed")
        path = Path(changed["receipt"]["absolute_path"])
        path.write_text(json.dumps(raw))
        changed["receipt"] = calibration.record(path)
        # Normalization itself never erases changed opaque semantic arguments.
        self.assertNotEqual(first, calibration.logical_observation(changed, other.mapper))
        with self.assertRaises(calibration.CalibrationError):
            calibration.observation(other.root, other.target, other.model,
                {**other.evidence, "validated_compiler_calibration": changed}, other.shared)


if __name__ == "__main__":
    unittest.main()
