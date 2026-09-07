"""Fast negative tests for profile/model gates; actual tool checks use the CLI."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from fragma.profiles import (ProfileError, check_machine_description,
                             _defines, _normalize_machdep_compiler_dialect, _run,
                             compiler_capabilities, load_architectures,
                             load_profiles, validate_profile, validate_registration)
from fragma import analysis_policy


ROOT = Path(__file__).resolve().parent.parent
MACHINE = """sizeof_short: 2
sizeof_int: 4
sizeof_long: 8
sizeof_longlong: 8
sizeof_ptr: 8
alignof_long: 8
alignof_ptr: 8
alignof_longlong: 8
little_endian: true
char_is_unsigned: true
wchar_t: unsigned short
size_t: unsigned long
"""


class ProfilesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="fragma-profile-test-")
        self.addCleanup(self.directory.cleanup)
        self.machine = Path(self.directory.name) / "fixture.yaml"
        self.machine.write_text(MACHINE)
        self.profiles = load_profiles(ROOT)

    def test_complete_baseline_registry(self):
        self.assertEqual(len(load_architectures(ROOT)["architectures"]), 21)
        self.assertEqual(len(self.profiles), 21)
        self.assertEqual({p["architecture"] for p in self.profiles.values()},
                         {a["id"] for a in load_architectures(ROOT)["architectures"]})

    def test_kernel_selectors_are_not_compiler_target_aliases(self):
        profile = self.profiles["s390x-gcc"]
        self.assertEqual(profile["kernel"]["arch"], "s390")
        self.assertEqual(profile["compiler_target"], "s390x-linux-gnu")
        self.assertEqual(profile["abi"]["byte_order"], "big")

    def test_generated_cross_compiler_name_becomes_exact_frama_dialect(self):
        cases = (("arm-gcc", "arm-linux-gnueabi-gcc", "gcc"),
                 ("mips32el-clang", "clang-21", "clang"))
        for profile_id, generated, dialect in cases:
            path = Path(self.directory.name) / (profile_id + ".yaml")
            path.write_text("sizeof_int: 4\ncompiler: " + generated + "\nsizeof_ptr: 4\n")
            with self.subTest(profile=profile_id):
                result = _normalize_machdep_compiler_dialect(
                    self.profiles[profile_id], path)
                self.assertEqual(result["generated_value"], generated)
                self.assertEqual(result["dialect"], dialect)
                self.assertEqual(result["changed_fields"], ["compiler"])
                self.assertEqual(path.read_text(),
                                 "sizeof_int: 4\ncompiler: " + dialect + "\nsizeof_ptr: 4\n")

    def test_machdep_dialect_normalization_rejects_ambiguous_or_relabelled_input(self):
        profile = self.profiles["arm-gcc"]
        for text in ("sizeof_int: 4\n", "compiler: arm-linux-gnueabi-gcc\ncompiler: gcc\n",
                     "compiler: unrelated-gcc\n"):
            self.machine.write_text(text)
            with self.subTest(text=text), self.assertRaises(ProfileError):
                _normalize_machdep_compiler_dialect(profile, self.machine)

    def test_registered_mips_profile_binds_mt7621_o32_clang_and_seed(self):
        profile = self.profiles["mips32el-clang"]
        architecture = next(row for row in load_architectures(ROOT)["architectures"]
                            if row["id"] == "mips")
        self.assertEqual(architecture["baseline_profile"], profile["id"])
        self.assertEqual(profile["compiler_family"], "clang")
        self.assertEqual(profile["compiler_target_args"], [
            "--target=mipsel-linux-gnu", "-mabi=32", "-EL",
            "-march=mips32r2", "-msoft-float"])
        self.assertEqual(profile["kernel"]["required_config"]["CONFIG_SOC_MT7621"], "y")
        self.assertEqual(profile["kernel"]["required_config"]["CONFIG_SMP"], "y")
        seed = ROOT / profile["kernel"]["seed_config"]
        self.assertEqual(hashlib.sha256(seed.read_bytes()).hexdigest(),
                         profile["kernel"]["seed_config_sha256"])
        validate_registration(profile)

    def test_mips_profile_cannot_be_relabelled_to_another_abi_or_soc(self):
        base = self.profiles["mips32el-clang"]
        mutations = [
            ("compiler_target_args", ["--target=mipsel-linux-gnu", "-mabi=64", "-EL",
                                      "-march=mips32r2", "-msoft-float"]),
            ("compiler_target", "mips-unknown-linux-gnu"),
            ("compiler_version", "21.1.7"),
        ]
        for field, value in mutations:
            profile = copy.deepcopy(base)
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ProfileError):
                validate_registration(profile)
        for field, value in (("bits", 64), ("byte_order", "big"),
                             ("pointer_alignment", 8)):
            profile = copy.deepcopy(base)
            profile["abi"][field] = value
            with self.subTest(abi=field), self.assertRaises(ProfileError):
                validate_registration(profile)
        for field, value in (("CONFIG_SOC_MT7621", "n"), ("CONFIG_SMP", "n"),
                             ("CONFIG_CPU_MIPS32_R2", "n"),
                             ("CONFIG_MIPS_MT_SMP", "n"), ("CONFIG_NR_CPUS", "2")):
            profile = copy.deepcopy(base)
            profile["kernel"]["required_config"][field] = value
            with self.subTest(config=field), self.assertRaises(ProfileError):
                validate_registration(profile)
        for field, value in (("config_recipe", ["defconfig"]),
                             ("seed_config", "profiles/other.config"),
                             ("seed_config_sha256", "0" * 64)):
            profile = copy.deepcopy(base)
            profile["kernel"][field] = value
            with self.subTest(kernel=field), self.assertRaises(ProfileError):
                validate_registration(profile)

    def test_semantic_flags_include_kernel_char_and_wchar(self):
        for profile in self.profiles.values():
            if profile["status"] == "experimental":
                self.assertIn("-funsigned-char", profile["common_flags"])
                self.assertIn("-fshort-wchar", profile["common_flags"])
                self.assertIn("-fno-strict-overflow", profile["common_flags"])
        self.assertIn("-mabi=lp64", self.profiles["riscv64-gcc"]["flags"])

    def test_all_configured_profiles_require_explicit_pointer_formation(self):
        for profile in self.profiles.values():
            if profile["status"] != "experimental":
                continue
            with self.subTest(profile=profile["id"]):
                self.assertEqual({"pointer_formation": "object-or-null"},
                                 profile["analysis"]["runtime_checks"])
                self.assertEqual(list(analysis_policy.ARITHMETIC_FLAGS), profile["analysis"]["arithmetic_flags"])
                self.assertEqual("-warn-invalid-pointer", analysis_policy.analyzer_flags(profile["analysis"])[-1])

    def test_missing_old_or_unknown_pointer_policy_is_not_defaulted(self):
        for value in (None, False, {}, {"pointer_formation": "disabled"},
                      {"pointer_formation": "object-or-null", "unchecked_extension": True}):
            profile = copy.deepcopy(self.profiles["s390x-gcc"])
            profile["analysis"]["runtime_checks"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ProfileError, "analysis policy"):
                validate_registration(profile)
        profile = copy.deepcopy(self.profiles["s390x-gcc"])
        del profile["analysis"]["runtime_checks"]
        with self.assertRaisesRegex(ProfileError, "analysis policy"):
            validate_profile(ROOT, profile)

    def test_unregistered_analyzer_flags_fail_before_tools_run(self):
        profile = copy.deepcopy(self.profiles["s390x-gcc"])
        profile["analysis"]["arithmetic_flags"].append("-no-warn-invalid-pointer")
        with patch("fragma.profiles._run") as run:
            with self.assertRaisesRegex(ProfileError, "analysis policy"):
                validate_profile(ROOT, profile)
            run.assert_not_called()

    def test_32bit_profiles_do_not_define_config_64bit(self):
        for name in ("arm-gcc", "powerpc32-gcc", "m68k-gcc", "sh-gcc",
                     "mips32el-clang"):
            with self.subTest(profile=name):
                self.assertNotIn("-DCONFIG_64BIT=1", _defines(self.profiles[name]))
                self.assertIn("-DFRAGMA_POINTER_BYTES=4", _defines(self.profiles[name]))

    def test_m68k_layout_does_not_inherit_host_alignment(self):
        profile = self.profiles["m68k-gcc"]
        self.assertEqual(profile["abi"]["pointer_alignment"], 2)
        self.assertIn("-DFRAGMA_NATURAL_SIZE=10", _defines(profile))
        self.assertIn("-DFRAGMA_NATURAL_SIZE=12", _defines(self.profiles["arm-gcc"]))

    def test_active_compilers_have_explicit_version_requirements(self):
        for profile in self.profiles.values():
            if profile["status"] == "experimental":
                expected = "21.1.8" if profile.get("compiler_family") == "clang" else "15.2.0"
                self.assertEqual(profile["compiler_version"], expected)

    def test_known_machine_fields(self):
        result = check_machine_description(self.profiles["x86_64-gcc"], self.machine)
        self.assertTrue(result["little_endian"])

    def test_wrong_width_is_rejected(self):
        self.machine.write_text(MACHINE.replace("sizeof_ptr: 8", "sizeof_ptr: 4"))
        with self.assertRaisesRegex(ProfileError, "sizeof_ptr"):
            check_machine_description(self.profiles["x86_64-gcc"], self.machine)

    def test_wrong_byte_order_is_rejected_even_with_identical_widths(self):
        with self.assertRaisesRegex(ProfileError, "little_endian"):
            check_machine_description(self.profiles["s390x-gcc"], self.machine)

    def test_missing_field_is_rejected(self):
        self.machine.write_text(MACHINE.replace("char_is_unsigned: true\n", ""))
        with self.assertRaisesRegex(ProfileError, "char_is_unsigned"):
            check_machine_description(self.profiles["x86_64-gcc"], self.machine)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaisesRegex(ProfileError, "Unknown profile"):
            validate_profile(ROOT, "not-a-profile")

    def test_planned_profile_is_not_passing_evidence(self):
        result = validate_profile(ROOT, "nios2-gcc")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["level"], "L0")
        self.assertTrue(result["gaps"])
        self.assertEqual(result["checks"], [])

    def test_missing_compiler_never_uses_host(self):
        profile = copy.deepcopy(self.profiles["s390x-gcc"])
        profile["compiler"] = "fragma-deliberately-absent-compiler-72571"
        result = validate_profile(ROOT, profile, output=Path(self.directory.name) / "output")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["level"], "L0")
        self.assertNotIn("compiler", result)
        self.assertTrue(any("Missing target compiler" in gap for gap in result["gaps"]))

    def test_explicit_empty_environment_never_discovers_host_compiler(self):
        result = validate_profile(ROOT, "x86_64-gcc", output=Path(self.directory.name) / "empty-env", env={})
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn("compiler", result)
        self.assertEqual(result["execution_environment"]["source"], "supplied")

    def test_capability_discovery_honors_explicit_path(self):
        capabilities = compiler_capabilities(ROOT, env={"PATH": str(Path(self.directory.name) / "no-tools")})
        self.assertTrue(all(row["compiler_path"] is None for row in capabilities["profiles"]))

    def test_injected_path_selects_compiler_and_does_not_mutate_environment(self):
        prefix = Path(self.directory.name) / "tools"
        prefix.mkdir()
        compiler = prefix / "gcc"
        compiler.write_text("#!/bin/sh\nprintf '%s\\n' '0.0.0'\n")
        compiler.chmod(0o755)
        supplied = {"PATH": str(prefix), "CPATH": "/must/not/be/included", "LC_ALL": "different"}
        before, ambient = copy.deepcopy(supplied), dict(os.environ)
        result = validate_profile(ROOT, "x86_64-gcc", output=Path(self.directory.name) / "injected-env", env=supplied)
        self.assertEqual(result["compiler"]["path"], str(compiler))
        self.assertEqual(result["compiler"]["version"], "0.0.0")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["execution_environment"]["settings"]["PATH"], str(prefix))
        self.assertEqual(supplied, before)
        self.assertEqual(dict(os.environ), ambient)

    def test_subprocess_receives_supplied_loader_paths_but_no_include_injection(self):
        supplied = {"PATH": "/explicit/tool/bin", "LD_LIBRARY_PATH": "/explicit/lib",
                    "CAML_LD_LIBRARY_PATH": "/explicit/ocaml/stublibs", "FRAGMA_ENV_TEST": "supplied",
                    "CPATH": "/inject/c", "C_INCLUDE_PATH": "/inject/headers",
                    "CPLUS_INCLUDE_PATH": "/inject/cpp", "OBJC_INCLUDE_PATH": "/inject/objc"}
        before = copy.deepcopy(supplied)
        program = "import json, os; print(json.dumps(dict(os.environ)))"
        with patch.dict(os.environ, {"FRAGMA_AMBIENT_ONLY": "must-not-leak"}):
            result = _run([sys.executable, "-c", program], Path(self.directory.name), "env-probe", env=supplied)
        self.assertEqual(result["exit_code"], 0)
        observed = json.loads(result["stdout"])
        for key in ("PATH", "LD_LIBRARY_PATH", "CAML_LD_LIBRARY_PATH", "FRAGMA_ENV_TEST"):
            self.assertEqual(observed[key], supplied[key])
        for key in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "FRAGMA_AMBIENT_ONLY"):
            self.assertNotIn(key, observed)
        self.assertEqual(observed["LC_ALL"], "C")
        self.assertEqual(supplied, before)

    def test_supplied_environment_does_not_fall_back_to_historical_frama(self):
        prefix = Path(self.directory.name) / "compiler-only"
        prefix.mkdir()
        compiler = prefix / "gcc"
        compiler.write_text("#!/bin/sh\ncase \"$1\" in\n-dumpmachine) printf '%s\\n' 'x86_64-linux-gnu';;\n*) printf '%s\\n' '15.2.0';;\nesac\n")
        compiler.chmod(0o755)
        result = validate_profile(ROOT, "x86_64-gcc", output=Path(self.directory.name) / "no-frama", env={"PATH": str(prefix)})
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("frama_c", result)
        self.assertTrue(any("supplied environment" in gap for gap in result["gaps"]))

    def test_supplied_frama_variable_selects_exact_executable(self):
        prefix = Path(self.directory.name) / "compiler-and-frama"
        prefix.mkdir()
        compiler, frama = prefix / "gcc", prefix / "selected-frama"
        compiler.write_text("#!/bin/sh\ncase \"$1\" in\n-dumpmachine) printf '%s\\n' 'x86_64-linux-gnu';;\n*) printf '%s\\n' '15.2.0';;\nesac\n")
        frama.write_text("#!/bin/sh\nprintf '%s\\n' 'deliberately-wrong-version'\n")
        compiler.chmod(0o755)
        frama.chmod(0o755)
        result = validate_profile(ROOT, "x86_64-gcc", output=Path(self.directory.name) / "selected-frama-output",
                                  env={"PATH": str(prefix), "FRAMA_C": str(frama)})
        self.assertEqual(result["frama_c"]["path"], str(frama))
        self.assertEqual(result["frama_c"]["version"], "deliberately-wrong-version")
        self.assertEqual(result["status"], "failed")

    def test_existing_evidence_is_not_overwritten(self):
        output = Path(self.directory.name) / "evidence"
        output.mkdir()
        receipt = output / "profile.json"
        receipt.write_text("previous evidence")
        with self.assertRaisesRegex(ProfileError, "not empty"):
            validate_profile(ROOT, "x86_64-gcc", output=output)
        self.assertEqual(receipt.read_text(), "previous evidence")

    def test_unknown_semantic_settings_are_rejected(self):
        profile = copy.deepcopy(self.profiles["s390x-gcc"])
        profile["abi"]["char_unsigned"] = None
        with self.assertRaisesRegex(ProfileError, "signedness"):
            validate_profile(ROOT, profile)


if __name__ == "__main__":
    unittest.main()
