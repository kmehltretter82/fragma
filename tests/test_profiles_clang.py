"""Inert checks for opt-in Hexagon Clang profile plumbing, not model support.

The candidate ABI and tool identities are test fixtures only. Every subprocess
and toolchain probe is mocked; the model pipeline must stop before generating
a machine description, compiling calibration code, or awarding L1.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma import profiles
from fragma.llvm_build import TOOL_KEYS
from fragma.sources import SourceError


ROOT = Path(__file__).resolve().parents[1]
TARGET_ARGS = ["--target=hexagon-linux-musl", "-mv68"]
TARGET = "hexagon-unknown-linux-musl"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ClangProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fragma-clang-profile-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "prefix/bin"
        self.bin.mkdir(parents=True)
        self.compiler, self.frama = self.bin / "clang", self.bin / "frama-c"
        for path in (self.compiler, self.frama):
            path.write_text("inert identity fixture; never execute\n")
            path.chmod(0o755)
        self.registered = profiles.load_profiles(ROOT)
        self.candidate = copy.deepcopy(self.registered["arm-gcc"])
        self.candidate.update(id="hexagon-clang-fixture", architecture="hexagon", compiler="clang",
            compiler_family="clang", compiler_version="21.1.8", compiler_target=TARGET,
            compiler_target_args=list(TARGET_ARGS), header_type="asm-generic/posix_types.h",
            generic_bitsperlong=True,
            flags=["-G0", "-fno-short-enums", "-mlong-calls", "-ffixed-r19",
                   "-DTHREADINFO_REG=r19", "-D__linux__"], runtime_methods=[])
        self.candidate.pop("generator_headers", None)
        self.candidate["kernel"] = {"arch": "hexagon", "config_recipe": ["comet_defconfig"],
            "required_config": {"CONFIG_HEXAGON": "y", "CONFIG_HEXAGON_ARCH_VERSION": "68"},
            "llvm": {"schema_version": 1, "target": "hexagon-linux-musl", "observed_target": TARGET,
                     "cpu": 68, "tools": {name: {"path": str(self.compiler), "sha256": digest(self.compiler)}
                                          for name in TOOL_KEYS}}}
        self.helper = self.bin.parent / "lib/frama-c/lib/make_machdep/make_machdep.py"
        self.schema = self.bin.parent / "share/frama-c/share/machdeps/machdep-schema.yaml"
        for path in (self.helper, self.schema):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# inert identity fixture; not a machine description\n")
        self.candidate["machdep_generator_sha256"] = digest(self.helper)
        self.candidate["machdep_schema_sha256"] = digest(self.schema)
        self.env = {"PATH": str(self.bin), "FRAMA_C": str(self.frama), "LC_ALL": "ignored",
                    "CPATH": "/untrusted/host/include", "C_INCLUDE_PATH": "/untrusted/c/include"}
        self.version_output = "Debian clang version 21.1.8\nTarget: x86_64-pc-linux-gnu\n"
        self.version_stderr, self.version_status = "", 0
        self.target_output, self.target_stderr, self.target_status = TARGET + "\n", "", 0
        self.tree = "b" * 40
        self.tool_spec = {"compiler_family": "clang", "version": "21.1.8",
            "version_args": ["--version"], "version_pattern": r"clang version (\d+\.\d+\.\d+)",
            "target": TARGET, "target_args": list(TARGET_ARGS), "require_binary_hash": True,
            "reference_sha256": digest(self.compiler), "resource_include_tree_sha256": "c" * 64}
        self.lock_path = self.root / "toolchain/lock.json"
        self.lock_path.parent.mkdir()
        self.write_lock()
        self.run = self._patch("fragma.profiles.subprocess.run", side_effect=self.metadata_command)
        self.probe = self._patch("fragma.toolchain.probe", return_value={
            "status": "ok", "name": "clang", "compiler_family": "clang",
            "path": str(self.compiler), "resolved_path": str(self.compiler.resolve()),
            "sha256": digest(self.compiler), "version": "21.1.8", "target": TARGET,
            "target_args": list(TARGET_ARGS), "reference_hash_matches": True,
            "command": [str(self.compiler), "--version"],
            "target_command": [str(self.compiler), *TARGET_ARGS, "-dumpmachine"],
            "compiler_resources": {"status": "ok", "include_tree_sha256": "c" * 64,
                                   "scope": "synthetic mocked resource identity; no header support"}})
        self.roster = self._patch("fragma.profiles.validate_roster", return_value={"status": "passed"})

    def _patch(self, name, **kwargs):
        patcher = patch(name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def write_lock(self, spec=None):
        self.lock_path.write_text(json.dumps({"schema_version": 1, "tools": {
            "clang": self.tool_spec if spec is None else spec}}))

    def metadata_command(self, command, **kwargs):
        args = [str(arg) for arg in command]
        if args == [str(self.compiler), "--version"]:
            return subprocess.CompletedProcess(args, self.version_status,
                                               self.version_output, self.version_stderr)
        if args == [str(self.compiler), *TARGET_ARGS, "-dumpmachine"]:
            return subprocess.CompletedProcess(args, self.target_status,
                                               self.target_output, self.target_stderr)
        if args == [str(self.frama), "-version"]:
            return subprocess.CompletedProcess(args, 0, self.candidate["frama_c_version"] + "\n", "")
        if args[0] == "git" and "rev-parse" in args:
            return subprocess.CompletedProcess(args, 0, self.tree + "\n", "")
        raise AssertionError("Unexpected command; no generator/compiler/analyzer execution is allowed: " + repr(args))

    def validate(self, *, candidate=None, name="model-output"):
        with patch("fragma.profiles.load_profiles", return_value=self.registered):
            return profiles.validate_profile(self.root, candidate or self.candidate, kernel=self.root / "kernel-git",
                                             output=self.root / name, env=self.env)

    def capabilities(self, *, candidate=None, env=None):
        candidate = self.candidate if candidate is None else candidate
        with patch("fragma.profiles.load_profiles", return_value={candidate["id"]: candidate}), \
                patch("fragma.profiles.load_architectures",
                      return_value={"kernel_revision": candidate["kernel_revision"]}):
            return profiles.compiler_capabilities(self.root, env=self.env if env is None else env)

    def assert_no_model(self, result):
        self.assertNotEqual(result["status"], "passed")
        self.assertEqual(result["level"], "L0")
        for key in ("machdep", "generator", "analysis", "validated_model_policy", "runtime", "build"):
            self.assertNotIn(key, result)
        self.assertFalse(list(Path(result["output"]).glob("*.yaml")))
        self.assertEqual(json.loads((Path(result["output"]) / "profile.json").read_text()), result)

    def test_target_flags_precede_profile_and_common_flags_without_mutation(self):
        before = copy.deepcopy(self.candidate)
        result = profiles.compiler_flags(self.candidate)
        self.assertEqual(result, TARGET_ARGS + self.candidate["flags"] + self.candidate["common_flags"])
        self.assertEqual(profiles.compiler_version_args(self.candidate), ["--version"])
        result.append("test-return-value-is-independent")
        self.assertEqual(self.candidate, before)
        self.run.assert_not_called()

    def test_all_existing_gcc_flag_and_version_arguments_are_unchanged(self):
        before = copy.deepcopy(self.registered)
        for profile in self.registered.values():
            if profile["status"] != "experimental":
                continue
            with self.subTest(profile=profile["id"]):
                self.assertEqual(profiles.compiler_flags(profile), profile["flags"] + profile["common_flags"])
                self.assertEqual(profiles.compiler_version_args(profile), ["-dumpfullversion"])
        self.assertEqual(self.registered, before)
        self.run.assert_not_called()

    def test_candidate_registration_does_not_activate_hexagon_registry(self):
        profiles.validate_registration(self.candidate)
        self.assertEqual(self.registered["hexagon-clang"]["status"], "planned")
        self.assertIsNone(self.registered["hexagon-clang"]["abi"])
        self.assertEqual(sum(row["status"] == "experimental" for row in self.registered.values()), 10)
        self.run.assert_not_called()

    def test_unknown_compiler_families_rejected_before_tools(self):
        for family in (None, "", "llvm", "unknown", 7, False):
            candidate = copy.deepcopy(self.candidate)
            candidate["compiler_family"] = family
            with self.subTest(family=family), self.assertRaises(profiles.ProfileError):
                profiles.validate_registration(candidate)
        self.run.assert_not_called()

    def test_missing_or_malformed_target_selectors_rejected_before_tools(self):
        values = (None, [], "--target=hexagon-linux-musl -mv68", tuple(TARGET_ARGS),
                  [TARGET_ARGS[0]], [TARGET_ARGS[1]], list(reversed(TARGET_ARGS)),
                  [*TARGET_ARGS, TARGET_ARGS[0]], [*TARGET_ARGS, TARGET_ARGS[1]],
                  [*TARGET_ARGS, "-O2"], ["--target=x86_64-linux-gnu", "-mv68"],
                  ["--target=hexagon-linux-musl", "-mv69"],
                  ["-target", "hexagon-linux-musl", "-mv68"], [TARGET_ARGS[0], 68])
        for value in values:
            candidate = copy.deepcopy(self.candidate)
            candidate["compiler_target_args"] = value
            with self.subTest(value=value), self.assertRaises(profiles.ProfileError):
                profiles.validate_registration(candidate)
        candidate = copy.deepcopy(self.candidate)
        del candidate["compiler_target_args"]
        with self.assertRaises(profiles.ProfileError):
            profiles.validate_registration(candidate)
        self.run.assert_not_called()

    def test_host_architecture_target_version_or_config_cannot_relabel_candidate(self):
        changes = (("architecture", "x86"), ("compiler_target", "x86_64-linux-gnu"),
                   ("compiler_target", "hexagon-linux-musl"), ("compiler_version", "21.1.7"))
        for key, value in changes:
            candidate = copy.deepcopy(self.candidate)
            candidate[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(profiles.ProfileError):
                profiles.validate_registration(candidate)
        for config in (None, "2", "69", 68):
            candidate = copy.deepcopy(self.candidate)
            candidate["kernel"]["required_config"]["CONFIG_HEXAGON_ARCH_VERSION"] = config
            with self.subTest(config=config), self.assertRaises(profiles.ProfileError):
                profiles.validate_registration(candidate)
        candidate = copy.deepcopy(self.candidate)
        candidate["kernel"]["arch"] = "x86"
        with self.assertRaises(profiles.ProfileError):
            profiles.validate_registration(candidate)
        self.run.assert_not_called()

    def test_target_cpu_forwarding_and_response_flags_cannot_override_either_flag_list(self):
        changes = (["--target=x86_64-linux-gnu"], ["--target=hexagon-linux-musl"],
                   ["--target", "x86_64-linux-gnu"], ["-target", "x86_64-linux-gnu"],
                   ["-mv68"], ["-mv69"], ["-mcpu=hexagonv69"], ["-march=x86-64"],
                   ["-Xclang", "-target-cpu"], ["-Xpreprocessor", "-D__HEXAGON_ARCH__=2"],
                   ["-Wp,-D__HEXAGON_ARCH__=2"], ["@unreviewed-options"],
                   ["--config=unreviewed.cfg"], ["--config", "unreviewed.cfg"],
                   ["--config-system-dir=/unreviewed"], ["--config-user-dir=/unreviewed"],
                   ["--driver-mode=g++"], ["-cc1"], ["-Xarch_host", "-mv69"],
                   ["-Xarch_hexagon", "-mv69"], ["-Xassembler", "-mv69"], ["-Wa,-mv69"],
                   ["-D__HEXAGON_ARCH__=2"], ["-U__HEXAGON_ARCH__"], ["-D__HEXAGON_V69__=1"],
                   ["-D__hexagon__=0"], ["-U__hexagon__"], ["-D", "__hexagon__=0"],
                   ["-U", "__HEXAGON_ARCH__"], ["-O2 --target=x86_64-linux-gnu"], ["-O2\x00"],
                   ["-resource-dir=/unreviewed"], ["--resource-dir=/unreviewed"],
                   ["--sysroot=/unreviewed"], ["-isysroot", "/unreviewed"],
                   ["-I/unreviewed"], ["-I", "/unreviewed"], ["-isystem", "/unreviewed"],
                   ["-include", "unreviewed.h"], ["-imacros", "unreviewed.h"],
                   ["-idirafter", "/unreviewed"], ["-iquote", "/unreviewed"],
                   ["-iprefix", "/unreviewed"], ["-iwithprefix", "unreviewed"],
                   ["-B/unreviewed"], ["--gcc-toolchain=/unreviewed"],
                   ["--gcc-install-dir=/unreviewed"], ["-fplugin=unreviewed.so"],
                   ["-fpass-plugin=unreviewed.so"])
        for field in ("flags", "common_flags"):
            for change in changes:
                candidate = copy.deepcopy(self.candidate)
                candidate[field].extend(change)
                with self.subTest(field=field, change=change), self.assertRaises(profiles.ProfileError):
                    profiles.validate_registration(candidate)
        self.run.assert_not_called()

    def test_clang_generator_headers_fail_closed_before_any_query(self):
        output = self.root / "header-output"
        output.mkdir()
        with self.assertRaisesRegex(profiles.ProfileError, "(?i)(clang|hexagon|generator.*header)"):
            profiles._generator_headers(self.candidate, self.root, str(self.compiler), output, env=self.env)
        self.assertEqual(list(output.iterdir()), [])
        self.run.assert_not_called()

    def test_riscv_generator_header_receipt_cannot_be_borrowed_for_clang(self):
        candidate = copy.deepcopy(self.candidate)
        candidate["generator_headers"] = copy.deepcopy(self.registered["riscv64-gcc"]["generator_headers"])
        output = self.root / "borrowed-header-output"
        output.mkdir()
        with self.assertRaises(profiles.ProfileError):
            profiles._generator_headers(candidate, self.root, str(self.compiler), output, env=self.env)
        self.assertEqual(list(output.iterdir()), [])
        self.run.assert_not_called()

    def test_gcc_without_generator_header_settings_preserves_legacy_route(self):
        candidate = copy.deepcopy(self.registered["arm-gcc"])
        candidate.pop("generator_headers", None)
        self.assertEqual(profiles._generator_headers(candidate, self.root, str(self.compiler),
                                                    self.root / "unused-output", env=self.env), ([], None))
        self.run.assert_not_called()

    def test_model_metadata_queries_use_explicit_clang_target_and_cpu(self):
        before = copy.deepcopy(self.env)
        result = self.validate()
        expected = [[str(self.compiler), "--version"],
                    [str(self.compiler), *TARGET_ARGS, "-dumpmachine"],
                    [str(self.compiler), "--version"], [str(self.frama), "-version"]]
        self.assertEqual([call.args[0] for call in self.run.call_args_list], expected)
        self.assertEqual(result["compiler"]["version"], "21.1.8")
        self.assertEqual(result["compiler"]["target"], TARGET)
        self.assertEqual(result["compiler"]["sha256"], digest(self.compiler))
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("header" in gap.lower() for gap in result["gaps"]), result["gaps"])
        self.assertTrue(all(row["status"] == "passed" for row in result["checks"]))
        self.probe.assert_called_once()
        self.assertEqual(self.probe.call_args.args[:2], ("clang", self.tool_spec))
        for call in self.run.call_args_list:
            self.assertEqual(call.kwargs["env"]["LC_ALL"], "C")
            self.assertNotIn("CPATH", call.kwargs["env"])
            self.assertNotIn("C_INCLUDE_PATH", call.kwargs["env"])
        self.assertEqual(self.env, before)
        self.assert_no_model(result)

    def test_wrong_clang_version_fails_before_toolchain_or_frama(self):
        for index, version in enumerate(("Debian clang version 21.1.7\n", "gcc version 21.1.8\n",
                                          "Debian clang version 21.1.8git\n", "21.1.8\n",
                                          "clang version 21.1.8\nclang version 21.1.8\n")):
            with self.subTest(version=version):
                self.version_output = version
                result = self.validate(name=f"wrong-version-{index}")
                self.assertEqual(result["checks"][-1]["name"], "compiler-version")
                self.assertEqual(result["checks"][-1]["status"], "failed")
                self.assertNotIn("frama_c", result)
                self.assert_no_model(result)
        self.probe.assert_not_called()

    def test_failed_clang_version_command_is_not_accepted_from_stdout(self):
        self.version_status = 1
        result = self.validate()
        self.assertEqual(result["checks"][-1]["name"], "compiler-version")
        self.assertEqual(result["checks"][-1]["status"], "failed")
        self.probe.assert_not_called()
        self.assert_no_model(result)

    def test_wrong_host_or_noncanonical_target_fails_before_toolchain(self):
        for index, target in enumerate(("x86_64-pc-linux-gnu\n", "hexagon-linux-musl\n", "\n")):
            with self.subTest(target=target):
                self.target_output = target
                result = self.validate(name=f"wrong-target-{index}")
                self.assertEqual(result["checks"][-1]["name"], "compiler-target")
                self.assertEqual(result["checks"][-1]["status"], "failed")
                self.assertNotIn("frama_c", result)
                self.assert_no_model(result)
        self.probe.assert_not_called()

    def test_failed_target_command_is_not_accepted_from_stdout(self):
        self.target_status = 1
        result = self.validate()
        self.assertEqual(result["checks"][-1]["name"], "compiler-target")
        self.assertEqual(result["checks"][-1]["status"], "failed")
        self.probe.assert_not_called()
        self.assert_no_model(result)

    def test_target_query_diagnostics_do_not_certify_ignored_selectors(self):
        self.target_stderr = "warning: argument unused during compilation: '-mv68'\n"
        result = self.validate()
        self.assertEqual(result["checks"][-1]["name"], "compiler-target")
        self.assertEqual(result["checks"][-1]["status"], "failed")
        self.probe.assert_not_called()
        self.assert_no_model(result)

    def test_clang_lock_target_arguments_must_match_exactly(self):
        for index, value in enumerate((None, [], list(reversed(TARGET_ARGS)),
                                      ["--target=x86_64-linux-gnu", "-mv68"], [*TARGET_ARGS, "-O2"])):
            with self.subTest(value=value):
                spec = {**self.tool_spec, "target_args": value}
                self.write_lock(spec)
                result = self.validate(name=f"wrong-lock-target-args-{index}")
                self.assertEqual(result["checks"][-1]["name"], "compiler-toolchain-lock")
                self.assertEqual(result["checks"][-1]["status"], "failed")
                self.assertNotIn("frama_c", result)
                self.assert_no_model(result)
        self.probe.assert_not_called()

    def test_clang_lock_requires_family_version_query_binary_and_resource_pins(self):
        changes = (("compiler_family", "gcc"), ("version_args", ["-dumpfullversion"]),
                   ("version", "21.1.7"), ("target", "x86_64-linux-gnu"),
                   ("require_binary_hash", False), ("reference_sha256", None),
                   ("resource_include_tree_sha256", None), ("resource_include_tree_sha256", "invalid"))
        for index, (key, value) in enumerate(changes):
            with self.subTest(key=key, value=value):
                self.write_lock({**self.tool_spec, key: value})
                result = self.validate(name=f"wrong-lock-requirement-{index}")
                self.assertEqual(result["checks"][-1]["name"], "compiler-toolchain-lock")
                self.assertEqual(result["checks"][-1]["status"], "failed")
                self.assertNotIn("frama_c", result)
                self.assert_no_model(result)
        self.probe.assert_not_called()

    def test_clang_tool_probe_failure_blocks_before_frama(self):
        self.probe.return_value = {"status": "resource-hash-mismatch"}
        result = self.validate()
        self.assertEqual(result["checks"][-1]["status"], "failed")
        self.assertNotIn("frama_c", result)
        self.probe.assert_called_once()
        self.assert_no_model(result)

    def test_clang_capabilities_use_pinned_probe_without_host_target_query(self):
        before = copy.deepcopy(self.env)
        result = self.capabilities()
        row = result["profiles"][0]
        self.assertEqual(row["status"], "available")
        self.assertEqual(row["compiler_path"], str(self.compiler))
        self.assertEqual(row["compiler_family"], "clang")
        self.assertEqual(row["compiler_target_args"], TARGET_ARGS)
        self.assertEqual(row["observed_version"], "21.1.8")
        self.assertEqual(row["observed_target"], TARGET)
        self.assertEqual(row["compiler_observation"], self.probe.return_value)
        expected_env = {key: value for key, value in self.env.items()
                        if key not in ("CPATH", "C_INCLUDE_PATH")}
        expected_env["LC_ALL"] = "C"
        self.probe.assert_called_once_with("clang", self.tool_spec, expected_env)
        self.run.assert_not_called()
        self.assertEqual(self.env, before)
        self.assertNotIn("level", row)
        self.assertIn("never L1/L2 support", result["note"])

    def test_clang_capabilities_reject_selected_alias_or_hash_mismatch(self):
        alias = self.bin / "selected-clang"
        alias.write_bytes(self.compiler.read_bytes())
        alias.chmod(0o755)
        before = copy.deepcopy(self.probe.return_value)
        changes = ({"path": str(alias)}, {"sha256": "e" * 64})
        for change in changes:
            with self.subTest(change=change):
                self.probe.reset_mock()
                self.probe.return_value = {**before, **change}
                selected = {**self.env, "FRAGMA_TOOL_CLANG": str(alias)}
                result = self.capabilities(env=selected)
                row = result["profiles"][0]
                self.assertEqual(row["status"], "compiler-mismatch")
                self.assertEqual(row["compiler_path"], str(self.compiler))
                self.assertEqual(row["compiler_observation"], self.probe.return_value)
                self.assertTrue(any("identity" in gap for gap in row["gaps"]))
                self.probe.assert_called_once()
                self.assertEqual(self.probe.call_args.args[2]["FRAGMA_TOOL_CLANG"], str(alias))
        self.run.assert_not_called()

    def test_clang_lock_does_not_enable_incomplete_or_planned_profile_queries(self):
        incomplete = copy.deepcopy(self.candidate)
        del incomplete["compiler_target_args"]
        for candidate in (incomplete, self.registered["hexagon-clang"]):
            with self.subTest(profile=candidate["id"]):
                result = self.capabilities(candidate=candidate)
                row = result["profiles"][0]
                self.assertEqual(row["status"], "compiler-mismatch")
                self.assertTrue(row["gaps"])
                self.assertNotIn("compiler_observation", row)
                self.assertNotIn("observed_target", row)
        self.probe.assert_not_called()
        self.run.assert_not_called()

    def test_clang_capability_probe_failure_is_preserved_without_promotion(self):
        failed = {**self.probe.return_value, "status": "resource-error",
                  "reason": "pinned builtin header resource tree changed"}
        self.probe.return_value = failed
        result = self.capabilities()
        row = result["profiles"][0]
        self.assertEqual(row["status"], "compiler-mismatch")
        self.assertEqual(row["compiler_observation"], failed)
        self.assertTrue(row["gaps"])
        self.assertNotIn("level", row)
        self.probe.assert_called_once()
        self.run.assert_not_called()

    def build_fixture(self):
        build, source = self.root / "configured-build", self.root / "pinned-source"
        build.mkdir()
        source.mkdir()
        entry = {"directory": str(build), "file": str(source / "lib/string.c"),
                 "arguments": [str(self.compiler), *TARGET_ARGS, *self.candidate["flags"],
                               *self.candidate["common_flags"], "-c", str(source / "lib/string.c"),
                               "-o", "lib/string.o"]}
        files = {".config": "CONFIG_HEXAGON=y\nCONFIG_HEXAGON_ARCH_VERSION=68\n",
                 "compile_commands.json": json.dumps([entry]),
                 "include/generated/autoconf.h": "/* inert autoconf fixture */\n",
                 "include/config/auto.conf": "CONFIG_HEXAGON=y\nCONFIG_HEXAGON_ARCH_VERSION=68\n",
                 "lib/string.o": "inert object identity; never execute\n", "prepare.log": "inert build receipt\n"}
        for name, content in files.items():
            path = build / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        llvm_receipt = {"schema_version": 1, "family": "clang", "cpu": 68,
                        "target": {"requested": "hexagon-linux-musl", "observed": TARGET}}
        validation = {"matched_command": entry, "config_sha256": digest(build / ".config"),
            "compilation_database_sha256": digest(build / "compile_commands.json"),
            "object": {"path": str(build / "lib/string.o"), "sha256": digest(build / "lib/string.o")},
            "target_execution": False, "model_support_awarded": False}
        receipt = {"schema_version": 1, "status": "prepared", "profile_id": self.candidate["id"],
            "revision": self.candidate["kernel_revision"], "source": str(source), "source_tree": self.tree,
            "compiler": str(self.compiler), "compiler_sha256": digest(self.compiler), "output": str(build),
            "files": {name: digest(build / name) for name in files}, "llvm": llvm_receipt,
            "llvm_validation": validation}
        (build / "fragma-build.json").write_text(json.dumps(receipt))
        return build, source, receipt, validation

    def test_configured_build_delegates_llvm_verification_with_pinned_source(self):
        build, source, receipt, validation = self.build_fixture()
        with patch("fragma.llvm_build.verify_llvm_build", return_value=validation) as verify:
            checked = profiles._check_build(self.candidate, build, self.root / "kernel-git",
                                            str(self.compiler), env=self.env)
        verify.assert_called_once_with(self.candidate, build, receipt["llvm"], source=source)
        self.assertEqual(checked["matched_commands"], [validation["matched_command"]])
        self.assertEqual(checked["source"], str(source))
        self.assertEqual(checked["build_path"], str(build))
        self.assertNotIn("level", checked)

    def test_configured_build_rejects_changed_llvm_validation_receipt(self):
        build, source, receipt, validation = self.build_fixture()
        receipt["llvm_validation"]["object"]["sha256"] = "f" * 64
        (build / "fragma-build.json").write_text(json.dumps(receipt))
        fresh_validation = {**validation, "object": {**validation["object"], "sha256": digest(build / "lib/string.o")}}
        with patch("fragma.llvm_build.verify_llvm_build", return_value=fresh_validation):
            with self.assertRaises(profiles.ProfileError):
                profiles._check_build(self.candidate, build, self.root / "kernel-git", str(self.compiler), env=self.env)

    def test_configured_build_rejects_model_flags_absent_from_genuine_command(self):
        build, source, receipt, validation = self.build_fixture()
        for extra in ("-fpack-struct", "-fshort-enums"):
            candidate = copy.deepcopy(self.candidate)
            candidate["flags"].append(extra)
            with self.subTest(extra=extra), \
                    patch("fragma.llvm_build.verify_llvm_build", return_value=validation):
                with self.assertRaises(profiles.ProfileError):
                    profiles._check_build(candidate, build, self.root / "kernel-git", str(self.compiler), env=self.env)

    def test_configured_build_wraps_llvm_source_errors_without_host_fallback(self):
        build, source, receipt, validation = self.build_fixture()
        with patch("fragma.llvm_build.verify_llvm_build", side_effect=SourceError("LLVM build: source mismatch")) as verify:
            with self.assertRaisesRegex(profiles.ProfileError, "source mismatch"):
                profiles._check_build(self.candidate, build, self.root / "kernel-git", str(self.compiler), env=self.env)
        verify.assert_called_once_with(self.candidate, build, receipt["llvm"], source=source)
        self.assertFalse(any("-c" in call.args[0] for call in self.run.call_args_list))


if __name__ == "__main__":
    unittest.main()
