"""Inert integration checks for GCC and opt-in LLVM kernel preparation.

Every external command and LLVM metadata/build validator is mocked. Temporary
compiler files identify paths and hashes only; no compiler or target is run.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma.build import prepare_build
from fragma.inputs import load_build
from fragma.sources import SourceError, sha256


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fragma build integration ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "pinned source"
        self.source.mkdir()
        self.identity = {"revision": "a" * 40, "git_tree": "b" * 40}
        (self.source / ".fragma-source.json").write_text(json.dumps(self.identity))
        self.bin = self.root / "tools"
        self.bin.mkdir()
        for name in ("gcc", "example-linux-gcc", "clang", "unknown-cc"):
            path = self.bin / name
            path.write_text("inert identity fixture; never execute\n")
            path.chmod(0o755)
        self.env = {"PATH": str(self.bin), "LANG": "C.UTF-8",
                    "CPATH": "/untrusted/include", "MAKEFLAGS": "--environment-overrides",
                    "HOME": str(self.root / "user")}
        self.profile = {"id": "native-gcc", "compiler": "gcc",
                        "kernel": {"arch": "x86", "config_recipe": ["defconfig"]}}
        self.llvm_profile = {"id": "hexagon-clang", "compiler": "clang",
                             "compiler_family": "clang", "compiler_version": "21.1.8",
                             "kernel": {"arch": "hexagon", "config_recipe": ["comet_defconfig"]}}
        self.assignments = ["LLVM=1", "LLVM_IAS=1", f"CC={self.bin / 'clang'}",
                            "HOSTCC=/pinned/clang", "HOSTCXX=/pinned/clang++",
                            "LD=/pinned/ld.lld", "AR=/pinned/llvm-ar",
                            "LLVM_LINK=/pinned/llvm-link", "NM=/pinned/llvm-nm",
                            "OBJCOPY=/pinned/llvm-objcopy", "OBJDUMP=/pinned/llvm-objdump",
                            "READELF=/pinned/llvm-readelf", "STRIP=/pinned/llvm-strip",
                            "HOSTAR=/pinned/llvm-ar", "HOSTLD=/pinned/ld.lld",
                            "KBUILD_HOSTLDFLAGS=--ld-path=/pinned/ld.lld"]
        self.clean_env = {"PATH": str(self.bin), "LANG": "C.UTF-8", "LC_ALL": "C"}
        self.llvm_receipt = {"schema_version": 1, "family": "clang", "cpu": 68,
                             "environment": self.clean_env}
        self.validation = {"target_execution": False, "model_support_awarded": False}
        self.run = self._patch("fragma.build.subprocess.run",
                               return_value=subprocess.CompletedProcess([], 0))
        self.prepare_llvm = self._patch("fragma.llvm_build.prepare_llvm",
                                       return_value=(self.assignments, self.llvm_receipt,
                                                     self.clean_env))
        self.verify_llvm = self._patch("fragma.llvm_build.verify_llvm_build",
                                      return_value=self.validation)

    def _patch(self, name, **kwargs):
        patcher = patch(name, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _output(self, profile=None):
        return self.root / "build" / "kernel" / (profile or self.profile)["id"]

    def _database_command(self, output):
        return ["python3", str(self.source / "scripts/clang-tools/gen_compile_commands.py"),
                "-d", str(output), "-o", str(output / "compile_commands.json")]

    def _assert_retained(self, record):
        output = Path(record["output"])
        self.assertEqual(json.loads((output / "fragma-build.json").read_text()), record)
        self.assertTrue((output / "prepare.log").is_file())

    def test_native_gcc_exact_commands_and_environment_are_unchanged(self):
        before = dict(self.env)
        record = prepare_build(self.root, self.source, self.profile, self.env, jobs=3)
        output = self._output()
        base = ["make", "-C", str(self.source), f"O={output}", "ARCH=x86",
                f"CC={self.bin / 'gcc'}"]
        expected = [base + ["defconfig"], base + ["-j3", "prepare", "lib/string.o"],
                    self._database_command(output)]
        self.assertEqual([call.args[0] for call in self.run.call_args_list], expected)
        self.assertEqual([row["argv"] for row in record["commands"]], expected)
        for call in self.run.call_args_list:
            self.assertIs(call.kwargs["env"], self.env)
            self.assertIs(call.kwargs["stderr"], subprocess.STDOUT)
            self.assertFalse(call.kwargs["check"])
        self.assertEqual(self.env, before)
        self.assertEqual(record["status"], "prepared")
        self.assertEqual(record["compiler"], str(self.bin / "gcc"))
        self.assertEqual(record["compiler_sha256"], sha256(self.bin / "gcc"))
        self.assertEqual(record["revision"], self.identity["revision"])
        self.assertEqual(record["source_tree"], self.identity["git_tree"])
        self.assertEqual(record["files"], {})
        self.assertNotIn("llvm", record)
        self.assertNotIn("llvm_validation", record)
        self.assertNotIn("validation_error", record)
        self.assertNotIn("seed_config", record)
        self.prepare_llvm.assert_not_called()
        self.verify_llvm.assert_not_called()
        self._assert_retained(record)

    def test_cross_gcc_keeps_explicit_prefix(self):
        profile = deepcopy(self.profile)
        profile.update(id="cross-gcc", compiler="example-linux-gcc", compiler_family="gcc")
        profile["kernel"]["arch"] = "arm"
        record = prepare_build(self.root, self.source, profile, self.env)
        base = ["make", "-C", str(self.source), f"O={self._output(profile)}", "ARCH=arm",
                f"CC={self.bin / 'example-linux-gcc'}",
                f"CROSS_COMPILE={self.bin / 'example-linux-'}"]
        self.assertEqual(record["commands"][0]["argv"], base + ["defconfig"])
        self.assertEqual(record["commands"][1]["argv"], base + ["-j4", "prepare", "lib/string.o"])
        self.prepare_llvm.assert_not_called()
        self.verify_llvm.assert_not_called()

    def test_named_build_records_config_delta_and_exact_object_inventory(self):
        objects = ["arch/arm/kernel/bios32.o", "arch/arm/net/bpf_jit_32.o"]
        symbols = ["BPF_SYSCALL", "BPF_JIT"]
        record = prepare_build(
            self.root, self.source, self.profile, self.env, jobs=2,
            build_id="arm32-recent", config_enable=symbols,
            object_targets=objects,
        )
        output = self.root / "build/kernel/arm32-recent"
        base = ["make", "-C", str(self.source), f"O={output}", "ARCH=x86",
                f"CC={self.bin / 'gcc'}"]
        configure = [str(self.source / "scripts/config"), "--file",
                     str(output / ".config"), "--enable", "BPF_SYSCALL",
                     "--enable", "BPF_JIT"]
        expected = [base + ["defconfig"], configure, base + ["olddefconfig"],
                    base + ["-j2", "prepare", *objects],
                    self._database_command(output)]
        self.assertEqual([row["argv"] for row in record["commands"]], expected)
        self.assertEqual(record["build_id"], "arm32-recent")
        self.assertEqual(record["profile_id"], self.profile["id"])
        self.assertEqual(record["config_enable"], symbols)
        self.assertEqual(record["object_targets"], objects)
        self.assertEqual(record["output"], str(output))
        loaded = load_build(self.root, self.profile["id"], self.identity["revision"],
                            "arm32-recent")
        self.assertEqual(loaded["build_id"], "arm32-recent")
        with self.assertRaisesRegex(SourceError, "revision/profile"):
            load_build(self.root, "another-profile", self.identity["revision"],
                       "arm32-recent")

    def test_invalid_named_build_inputs_fail_before_output(self):
        cases = [
            {"build_id": "../escape"},
            {"build_id": True},
            {"config_enable": ["CONFIG_BPF_JIT"]},
            {"config_enable": ["BPF_JIT", "BPF_JIT"]},
            {"object_targets": []},
            {"object_targets": ["../outside.o"]},
            {"object_targets": ["arch/arm/mm/fault.c"]},
            {"object_targets": ["-f.o"]},
        ]
        for index, options in enumerate(cases):
            profile = {**self.profile, "id": f"invalid-build-{index}"}
            with self.subTest(options=options), self.assertRaises(SourceError):
                prepare_build(self.root, self.source, profile, self.env, **options)
            self.assertFalse(self._output(profile).exists())
        self.run.assert_not_called()

    def test_gcc_subarch_is_retained_on_both_make_commands(self):
        profile = deepcopy(self.profile)
        profile["kernel"].update(arch="um", subarch="x86_64")
        record = prepare_build(self.root, self.source, profile, self.env)
        for command in record["commands"][:2]:
            self.assertEqual(command["argv"].count("SUBARCH=x86_64"), 1)
            self.assertIn("ARCH=um", command["argv"])
            self.assertFalse(any(arg.startswith("LLVM") for arg in command["argv"]))

    def test_non_gcc_without_explicit_family_rejected_before_output(self):
        for compiler in ("clang", "unknown-cc"):
            with self.subTest(compiler=compiler):
                profile = {**self.profile, "compiler": compiler}
                with self.assertRaisesRegex(SourceError, "cross compiler prefix"):
                    prepare_build(self.root, self.source, profile, self.env)
                self.assertFalse(self._output(profile).exists())
        self.run.assert_not_called()
        self.prepare_llvm.assert_not_called()
        self.verify_llvm.assert_not_called()

    def test_unsupported_family_rejected_before_output(self):
        profile = {**self.profile, "compiler_family": "unknown"}
        with self.assertRaisesRegex(SourceError, "unsupported compiler family"):
            prepare_build(self.root, self.source, profile, self.env)
        self.assertFalse(self._output(profile).exists())
        self.run.assert_not_called()
        self.prepare_llvm.assert_not_called()

    def test_missing_compiler_rejected_before_output(self):
        profile = {**self.profile, "compiler": "missing-compiler"}
        with self.assertRaisesRegex(SourceError, "compiler unavailable"):
            prepare_build(self.root, self.source, profile, self.env)
        self.assertFalse(self._output(profile).exists())
        self.run.assert_not_called()

    def test_llvm_preflight_failure_does_not_create_output(self):
        self.prepare_llvm.side_effect = SourceError("LLVM build: wrong pinned identity")
        with self.assertRaisesRegex(SourceError, "wrong pinned identity"):
            prepare_build(self.root, self.source, self.llvm_profile, self.env)
        self.assertFalse(self._output(self.llvm_profile).exists())
        self.run.assert_not_called()
        self.verify_llvm.assert_not_called()

    def test_llvm_uses_explicit_assignments_clean_env_and_success_only_validation(self):
        before = dict(self.env)
        events = []
        self.run.side_effect = lambda *args, **kwargs: (
            events.append("command") or subprocess.CompletedProcess(args[0], 0))
        self.verify_llvm.side_effect = lambda *args, **kwargs: (
            events.append("verify") or self.validation)
        record = prepare_build(self.root, self.source, self.llvm_profile, self.env, jobs=2)
        output = self._output(self.llvm_profile)
        base = ["make", "-C", str(self.source), f"O={output}", "ARCH=hexagon"] + self.assignments
        expected = [base + ["comet_defconfig"], base + ["-j2", "prepare", "lib/string.o"],
                    self._database_command(output)]
        self.prepare_llvm.assert_called_once_with(self.llvm_profile, str(self.bin / "clang"), self.env)
        self.verify_llvm.assert_called_once_with(self.llvm_profile, output, self.llvm_receipt,
                                                source=self.source)
        self.assertEqual(events, ["command", "command", "command", "verify"])
        self.assertEqual([call.args[0] for call in self.run.call_args_list], expected)
        for call in self.run.call_args_list:
            self.assertIs(call.kwargs["env"], self.clean_env)
        self.assertEqual(self.env, before)
        for command in record["commands"][:2]:
            self.assertEqual(sum(arg.startswith("CC=") for arg in command["argv"]), 1)
            self.assertFalse(any(arg.startswith("CROSS_COMPILE=") for arg in command["argv"]))
        self.assertEqual(record["llvm"], self.llvm_receipt)
        self.assertEqual(record["llvm_validation"], self.validation)
        self.assertEqual(record["status"], "prepared")
        self.assertEqual(record["files"]["prepare.log"], sha256(output / "prepare.log"))
        self._assert_retained(record)

    def test_llvm_validation_failures_are_retained_as_failed_builds(self):
        for index, error in enumerate((SourceError("target mismatch"), OSError("object unreadable"))):
            with self.subTest(error=type(error).__name__):
                profile = {**self.llvm_profile, "id": f"llvm-validation-{index}"}
                self.verify_llvm.reset_mock()
                self.verify_llvm.side_effect = error
                record = prepare_build(self.root, self.source, profile, self.env)
                self.assertEqual(record["status"], "failed")
                self.assertEqual(record["validation_error"], str(error))
                self.assertEqual(record["llvm"], self.llvm_receipt)
                self.assertNotIn("llvm_validation", record)
                self.assertEqual(len(record["commands"]), 3)
                self.assertTrue(all(row["returncode"] == 0 for row in record["commands"]))
                self.verify_llvm.assert_called_once_with(profile, self._output(profile),
                                                        self.llvm_receipt, source=self.source)
                self.assertIn("LLVM validation failed: " + str(error),
                              (self._output(profile) / "prepare.log").read_text())
                self._assert_retained(record)

    def test_llvm_command_failure_retained_without_validation(self):
        for failed_index in range(3):
            with self.subTest(failed_index=failed_index):
                profile = {**self.llvm_profile, "id": f"llvm-command-{failed_index}"}
                self.run.reset_mock()
                self.run.side_effect = [subprocess.CompletedProcess([], 0)] * failed_index + [
                    subprocess.CompletedProcess([], 7)]
                record = prepare_build(self.root, self.source, profile, self.env)
                self.assertEqual(record["status"], "failed")
                self.assertEqual(len(record["commands"]), failed_index + 1)
                self.assertEqual(record["commands"][-1]["returncode"], 7)
                self.assertEqual(self.run.call_count, failed_index + 1)
                self.assertNotIn("llvm_validation", record)
                self.assertNotIn("validation_error", record)
                self.assertEqual(record["llvm"], self.llvm_receipt)
                self.verify_llvm.assert_not_called()
                self._assert_retained(record)

    def test_gcc_command_failure_retained_without_llvm_fields(self):
        self.run.return_value = subprocess.CompletedProcess([], 2)
        record = prepare_build(self.root, self.source, self.profile, self.env)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(len(record["commands"]), 1)
        self.assertEqual(record["commands"][0]["returncode"], 2)
        self.assertNotIn("llvm", record)
        self.assertNotIn("llvm_validation", record)
        self.prepare_llvm.assert_not_called()
        self.verify_llvm.assert_not_called()
        self._assert_retained(record)

    def test_seed_config_is_copied_recorded_and_uses_olddefconfig(self):
        seed = self.root / "explicit seed.config"
        seed.write_text("CONFIG_TEST_FIXTURE=y\n")
        record = prepare_build(self.root, self.source, self.profile, self.env, seed_config=seed)
        output = self._output()
        self.assertEqual(record["seed_config"], {"path": str(seed.resolve()), "sha256": sha256(seed)})
        self.assertEqual((output / ".config").read_text(), seed.read_text())
        self.assertEqual(record["files"][".config"], sha256(seed))
        self.assertEqual(record["commands"][0]["argv"][-1], "olddefconfig")
        self.assertNotIn("defconfig", record["commands"][0]["argv"])
        self.assertEqual(seed.read_text(), "CONFIG_TEST_FIXTURE=y\n")
        self._assert_retained(record)

    def test_unpinned_profile_seed_remains_an_explicit_legacy_hint(self):
        seed = self.root / "profiles/unpinned.config"
        seed.parent.mkdir()
        seed.write_text("CONFIG_UNPINNED=y\n")
        profile = deepcopy(self.profile)
        profile["id"] = "legacy-unpinned-seed"
        profile["kernel"]["seed_config"] = "profiles/unpinned.config"
        record = prepare_build(self.root, self.source, profile, self.env)
        self.assertNotIn("seed_config", record)
        self.assertEqual(record["commands"][0]["argv"][-1], "defconfig")
        self.assertFalse((self._output(profile) / ".config").is_file())

    def test_registered_seed_is_automatic_pinned_and_cannot_be_overridden(self):
        seed = self.root / "profiles/target.config"
        seed.parent.mkdir()
        seed.write_text("CONFIG_TARGET_FIXTURE=y\n")
        profile = deepcopy(self.profile)
        profile["id"] = "registered-seed"
        profile["kernel"].update(seed_config="profiles/target.config",
                                 seed_config_sha256=sha256(seed))
        record = prepare_build(self.root, self.source, profile, self.env)
        output = self._output(profile)
        self.assertEqual(record["seed_config"],
                         {"path": str(seed.resolve()), "sha256": sha256(seed)})
        self.assertEqual(record["commands"][0]["argv"][-1], "olddefconfig")
        self.assertEqual((output / ".config").read_text(), seed.read_text())

        for index, change in enumerate(("wrong-hash", "escape", "override")):
            candidate = deepcopy(profile)
            candidate["id"] = f"bad-registered-seed-{index}"
            explicit = None
            if change == "wrong-hash":
                candidate["kernel"]["seed_config_sha256"] = "0" * 64
            elif change == "escape":
                candidate["kernel"]["seed_config"] = "../target.config"
            else:
                explicit = self.root / "different.config"
                explicit.write_text("CONFIG_DIFFERENT=y\n")
            with self.subTest(change=change), self.assertRaises(SourceError):
                prepare_build(self.root, self.source, candidate, self.env,
                              seed_config=explicit)
            self.assertFalse(self._output(candidate).exists())

    def test_llvm_build_artifact_hashes_are_retained(self):
        output = self._output(self.llvm_profile)
        artifacts = {".config": b"CONFIG_HEXAGON_ARCH_VERSION=68\n",
                     "include/generated/autoconf.h": b"/* inert autoconf fixture */\n",
                     "include/config/auto.conf": b"CONFIG_TEST_FIXTURE=y\n",
                     "compile_commands.json": b"[]\n",
                     "lib/string.o": b"inert object identity fixture; not executable\n"}

        def command(argv, **kwargs):
            for name, data in artifacts.items():
                path = output / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            return subprocess.CompletedProcess(argv, 0)

        self.run.side_effect = command
        record = prepare_build(self.root, self.source, self.llvm_profile, self.env)
        self.assertEqual(set(record["files"]), set(artifacts) | {"prepare.log"})
        for name, digest in record["files"].items():
            self.assertEqual(digest, sha256(output / name))
        self._assert_retained(record)

    def test_existing_output_is_not_overwritten_or_revalidated(self):
        output = self._output(self.llvm_profile)
        output.mkdir(parents=True)
        sentinel = output / "fragma-build.json"
        sentinel.write_text("keep existing evidence\n")
        with self.assertRaisesRegex(SourceError, "build directory already exists"):
            prepare_build(self.root, self.source, self.llvm_profile, self.env)
        self.assertEqual(sentinel.read_text(), "keep existing evidence\n")
        self.assertEqual(list(output.iterdir()), [sentinel])
        self.run.assert_not_called()
        self.prepare_llvm.assert_not_called()
        self.verify_llvm.assert_not_called()

    def test_invalid_jobs_do_not_create_output(self):
        with self.assertRaisesRegex(SourceError, "jobs must be positive"):
            prepare_build(self.root, self.source, self.profile, self.env, jobs=0)
        self.assertFalse(self._output().exists())
        self.run.assert_not_called()

    def test_missing_snapshot_marker_does_not_create_output(self):
        unmarked = self.root / "unmarked source"
        unmarked.mkdir()
        with self.assertRaisesRegex(SourceError, "pinned snapshot"):
            prepare_build(self.root, unmarked, self.profile, self.env)
        self.assertFalse(self._output().exists())
        self.run.assert_not_called()

    def test_invalid_profile_id_does_not_create_output(self):
        profile = {**self.profile, "id": "../not-a-profile"}
        with self.assertRaisesRegex(SourceError, "invalid profile ID"):
            prepare_build(self.root, self.source, profile, self.env)
        self.assertFalse((self.root / "build").exists())
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
