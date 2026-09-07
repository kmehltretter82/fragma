"""Wave-two registry and actual configured-context checks; no subprocesses.

The optional retained-model tests inspect genuine local build/model receipts,
not invented successful gates. Set FRAGMA_COMMON24_NEXT_PROFILE_MODELS to the
explicit three-profile parent directory. No fixture compilation, preprocessing,
analyzer or native execution is permitted here; those remain separate evidence.
"""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch

from fragma import analysis_policy, common24, common24_calibration as calibration
from fragma import common24_controls as controls, frontend_policy, inputs, integrity
from fragma import profiles, provenance, sources, suite


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config/common-byte-wave2-targets.json"
MAPPING = {"common.unaligned24.arm64": "arm64-gcc",
           "common.unaligned24.riscv64": "riscv64-gcc",
           "common.unaligned24.sh": "sh-gcc"}
ASSUMPTIONS = {"common24-wave2-types", "common24-wave2-frontend"}
POLICY = {"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"}
PROFILE_FLAGS = {
    "arm64-gcc": {"-mgeneral-regs-only", "-mlittle-endian", "-mabi=lp64",
                  "-mbranch-protection=pac-ret", "-Wa,-march=armv8.5-a"},
    "riscv64-gcc": {"-mabi=lp64", "-march=rv64imac_zicsr_zifencei_zacas_zabha",
                    "-mno-save-restore", "-mcmodel=medany", "-mstrict-align"},
    "sh-gcc": {"-m4", "-m4-nofpu", "-m4a", "-m4a-nofpu", "-ml", "-mno-fdpic"},
}


def forbidden(*args, **kwargs):
    raise AssertionError("subprocess/compiler/analyzer/native execution forbidden in next-profile tests")


class NoProcesses(unittest.TestCase):
    def setUp(self):
        for patcher in (patch.object(subprocess, "Popen", side_effect=forbidden),
                        patch.object(subprocess, "run", side_effect=forbidden),
                        patch.object(os, "system", side_effect=forbidden),
                        patch.object(inputs, "run_recorded", side_effect=forbidden)):
            patcher.start(); self.addCleanup(patcher.stop)
        self.revision, self.registry, self.ledger = suite.load_registry(ROOT)
        self.targets = [self.registry[name] for name in MAPPING]


class RegistryTests(NoProcesses):
    def test_exact_distinct_registered_targets_and_profile_mapping(self):
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(manifest["kernel_revision"], self.revision)
        self.assertEqual({target["id"]: target["profile"] for target in manifest["targets"]}, MAPPING)
        self.assertEqual({item["id"] for item in manifest["assumptions"]}, ASSUMPTIONS)
        for target in self.targets:
            with self.subTest(profile=target["profile"]):
                common24.check_target(target)
                self.assertEqual(target["suite"], "extended")
                self.assertEqual(target["role"], "proof")
                self.assertEqual(target["compiler_calibration"],
                    {"kind": "common24-fixed22", "source": calibration.SOURCE})
                self.assertEqual(target["frontend_policy"], POLICY)
                self.assertEqual(frontend_policy.cpp_arguments(target),
                                 ["-DFRAGMA_COMMON24_INLINE_POLICY=1"])

    def test_first_wave_assumptions_and_reviews_are_not_inherited(self):
        old = json.loads((ROOT / "config/common-byte-targets.json").read_text())
        old_ids = {item["id"] for item in old["assumptions"]}
        old_profiles = {target["profile"] for target in old["targets"]}
        self.assertTrue(ASSUMPTIONS.isdisjoint(old_ids))
        self.assertTrue(set(MAPPING.values()).isdisjoint(old_profiles))
        for target in self.targets:
            self.assertEqual(set(target["assumptions"]), ASSUMPTIONS)
            self.assertIs(target["require_smoke"], True)
            records = [self.ledger[name] for name in target["assumptions"]]
            for record in records:
                self.assertIs(record["implementation_proved"], False)
                if record["review_status"] not in ("reviewed", "reviewed-assumption"):
                    for key in ("reviewed_profiles", "reviewed_by", "review_context", "review_evidence"):
                        self.assertNotIn(key, record)
                else:
                    # Permit a later genuine wave-two review, never old scope.
                    self.assertIn(target["profile"], record["reviewed_profiles"])
                    self.assertLessEqual(set(record["reviewed_profiles"]), set(MAPPING.values()))
                    self.assertTrue(record["reviewed_by"])
                    self.assertTrue(record["review_evidence"])
                    self.assertNotIn(record["review_evidence"], [a.get("review_evidence") for a in old["assumptions"]])
            context = target.get("review_context")
            if context is None:
                self.assertFalse(target.get("reviewed_warnings"))
                self.assertFalse(target.get("reviewed_smoke"))
            else:
                self.assertEqual(context["profile"], target["profile"])
                self.assertEqual(context["compiler_calibration"], calibration.review_identity(target))

    def test_borrowed_first_wave_review_is_rejected_by_production_profile_gate(self):
        old = json.loads((ROOT / "config/common-byte-targets.json").read_text())["targets"][0]
        for target in self.targets:
            forged = copy.deepcopy(target)
            forged["reviewed_warnings"] = copy.deepcopy(old["reviewed_warnings"])
            forged["review_context"] = copy.deepcopy(old["review_context"])
            with self.subTest(profile=target["profile"]), self.assertRaisesRegex(ValueError, "profile"):
                integrity.validate_review(ROOT, forged, self.revision, {}, {}, {}, {})

    def test_no_architecture_derived_policy_or_arbitrary_override(self):
        for target in self.targets:
            for mutation in (lambda t: t.pop("frontend_policy"),
                             lambda t: t["frontend_policy"].update(variant="automatic"),
                             lambda t: t["frontend_policy"].update(flags=[]),
                             lambda t: t.update(cpp_definitions={"u32": "unsigned long"})):
                value = copy.deepcopy(target); mutation(value)
                with self.subTest(profile=target["profile"], mutation=mutation), self.assertRaises(ValueError):
                    frontend_policy.identity(value, root=ROOT)

    def test_four_reused_kernel_functions_and_unchanged_full_annotated_source(self):
        old = json.loads((ROOT / "config/common-byte-targets.json").read_text())["targets"]
        prior = {(target["source"], name) for target in old for name in target["functions"]}
        added = {(target["source"], name) for target in self.targets for name in target["functions"]}
        self.assertEqual(added, prior)
        self.assertEqual(len(added), 4)
        harness = ROOT / frontend_policy.HARNESS
        strategy = (ROOT / frontend_policy.STRATEGY).read_text()
        for target in self.targets:
            observed = common24.check_source(target, source_path=harness,
                source_text=harness.read_text(), strategy_text=strategy)
            self.assertEqual(observed["status"], "checked")
            self.assertEqual(len(observed["functions"]), 6)
            self.assertEqual(len(frontend_policy.annotation_tokens(strategy)
                                 + frontend_policy.annotation_tokens(harness.read_text())), 24)

    def test_fixed_fixture_checks_type_identity_without_long_or_size_t_width_assumptions(self):
        path = ROOT / frontend_policy.FIXTURE
        self.assertEqual(sources.sha256(path), controls.FIXTURE_SHA256)
        tokens = provenance.tokenize(path.read_text())
        spelling = " ".join(tokens)
        self.assertIn("__builtin_types_compatible_p ( u32 , FRAGMA_COMMON24_EXPECT_U32 )", spelling)
        self.assertIn("sizeof ( u32 ) == 4", spelling)
        self.assertNotIn("sizeof ( long )", spelling)
        self.assertNotIn("sizeof ( size_t )", spelling)
        self.assertNotIn("# define u32", spelling)
        self.assertEqual(len(controls.DIAGNOSTICS["wrong-type"]), 5)
        self.assertEqual(len(controls.DIAGNOSTICS["wrong-inline"]), 1)


@unittest.skipUnless(os.environ.get("FRAGMA_COMMON24_NEXT_PROFILE_MODELS"),
                     "optional explicit actual configured wave-two models; read-only and no subprocesses")
class RetainedContextTests(NoProcesses):
    def setUp(self):
        super().setUp()
        self.before = {}
        self.contexts = []
        self.addCleanup(self.check_unchanged)
        base = Path(os.environ["FRAGMA_COMMON24_NEXT_PROFILE_MODELS"]).resolve()
        for target in self.targets:
            path = base / target["profile"] / "profile.json"
            model = json.loads(path.read_text())
            build = inputs.load_build(ROOT, target["profile"], self.revision)
            binding = calibration.context(ROOT, target, model, build, self.revision)
            self.contexts.append((target, model, build, binding))
            for record in integrity.merge_records(binding["tracked_inputs"], [integrity.receipt(path)]):
                self.before[record["absolute_path"]] = record["sha256"]

    def check_unchanged(self):
        self.assertEqual(self.before, {name: sources.sha256(Path(name)) for name in self.before})

    def test_real_contexts_match_current_profiles_builds_and_actual_model_policy(self):
        registered = profiles.load_profiles(ROOT)
        for target, model, build, binding in self.contexts:
            with self.subTest(profile=target["profile"]):
                self.assertEqual(model["status"], "passed")
                self.assertEqual(model["level"], "L1")
                self.assertEqual(model["profile_sha256"], profiles._digest(registered[target["profile"]]))
                self.assertEqual(model["kernel_revision"], self.revision)
                self.assertEqual(binding["model_sha256"], calibration.digest(model))
                self.assertEqual(binding["target_sha256"], calibration.digest(target))
                self.assertEqual(binding["frontend_options"], ["-DFRAGMA_COMMON24_INLINE_POLICY=1"])
                self.assertIs(binding["big_endian"], False)
                self.assertEqual(analysis_policy.model_identity(model["analysis"])["runtime_checks"],
                                 {"pointer_formation": "object-or-null"})
                self.assertEqual(integrity.changed_files(binding["tracked_inputs"]), [])

    def test_every_planned_command_preserves_the_exact_genuine_kernel_flags(self):
        for target, model, build, binding in self.contexts:
            base = inputs.command_without_outputs(inputs.compile_entry(build, "lib/string.c"))
            self.assertEqual(binding["base_argv"], base)
            self.assertLessEqual(PROFILE_FLAGS[target["profile"]], set(base))
            self.assertEqual([arg for arg in base if re.fullmatch(r"-O(?:[0-9gsz]|fast)", arg)], ["-O2"])
            self.assertIn("-nostdinc", base)
            self.assertFalse(any("musl" in arg for arg in base))
            output = ROOT / "build/unused next profile unit plan" / target["profile"]
            self.assertFalse(output.exists())
            argv_only = {"base_argv": base, "fixture": binding["fixture"], "selector": binding["frontend_options"]}
            commands = [calibration.expected_gate_argv(binding, output)]
            commands += [row["argv"] for row in controls.command_plan(argv_only, target, output / "compiler-controls")]
            commands += [argv for _, argv in calibration.command_plan(binding, output / "compiler-calibration")]
            self.assertEqual(len(commands), 28)
            for command in commands:
                self.assertEqual(command[:len(base)], base)
                self.assertEqual(command[0], model["compiler"]["path"])
                self.assertTrue("-c" in command or "-E" in command)
            self.assertFalse(output.exists())

    def test_lp64_wrong_type_differs_in_width_but_sh_control_is_same_width_distinct_type(self):
        for target, model, build, binding in self.contexts:
            fields = model["machdep"]["checked_fields"]
            lp64 = target["profile"] != "sh-gcc"
            self.assertEqual(fields["sizeof_int"], 4)
            self.assertEqual(fields["sizeof_long"], 8 if lp64 else 4)
            self.assertEqual(fields["sizeof_ptr"], 8 if lp64 else 4)
            self.assertEqual(fields["size_t"], "unsigned long" if lp64 else "unsigned int")
            argv_only = {"base_argv": binding["base_argv"], "fixture": binding["fixture"],
                         "selector": binding["frontend_options"]}
            commands = controls.command_plan(argv_only, target, ROOT / "build/unused next profile unit plan")
            self.assertEqual([arg for arg in commands[0]["argv"] if "EXPECT_U32" in arg],
                             ["-DFRAGMA_COMMON24_EXPECT_U32=unsigned long"])
            self.assertFalse(any("EXPECT_U32" in arg for arg in commands[1]["argv"]))
            self.assertEqual([arg for arg in commands[0]["argv"] if frontend_policy.MACRO in arg],
                             ["-DFRAGMA_COMMON24_INLINE_POLICY=1"])
            self.assertEqual([arg for arg in commands[1]["argv"] if frontend_policy.MACRO in arg],
                             ["-DFRAGMA_COMMON24_INLINE_POLICY=2"])

    def test_other_profile_model_and_mutated_genuine_build_are_rejected(self):
        for index, (target, model, build, binding) in enumerate(self.contexts):
            wrong = self.contexts[(index + 1) % len(self.contexts)][1]
            with self.subTest(profile=target["profile"]), self.assertRaises(ValueError):
                calibration.context(ROOT, target, wrong, build, self.revision)
            altered = copy.deepcopy(build); altered["files"][".config"] = "0" * 64
            with self.assertRaises(ValueError):
                calibration.context(ROOT, target, model, altered, self.revision)

    def test_changed_model_compiler_registration_or_pointer_policy_is_not_a_valid_context(self):
        for target, model, build, binding in self.contexts:
            for mutation in (lambda m: m.update(profile_sha256="0" * 64),
                             lambda m: m["compiler"].update(path="/unrelated/host-compiler"),
                             lambda m: m["analysis"].pop("runtime_checks"),
                             lambda m: m["machdep"].update(sha256="0" * 64)):
                altered = copy.deepcopy(model); mutation(altered)
                with self.subTest(profile=target["profile"], mutation=mutation), self.assertRaises(ValueError):
                    calibration.context(ROOT, target, altered, build, self.revision)


if __name__ == "__main__":
    unittest.main()
