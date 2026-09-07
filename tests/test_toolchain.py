"""Failure-oriented checks for discovery, pins, and side-effect-free preflight."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fragma.toolchain import (ToolchainError, discover, installed_packages,
                             inventory, prepare_environment, probe, verify_artifact)


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fragma toolchain ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.switch = self.root / "switch with spaces"
        self.bin = self.switch / "bin"
        self.bin.mkdir(parents=True)
        (self.switch / ".opam-switch" / "packages" / "demo.1.0").mkdir(parents=True)
        (self.switch / ".opam-switch" / "switch-state").write_text('installed: ["demo.1.0"]\n')
        (self.switch / ".opam-switch" / "packages" / "demo.1.0" / "opam").write_text('opam-version: "2.0"\n')
        (self.root / "toolchain").mkdir()
        self.export = self.root / "toolchain" / "opam-switch.export"
        self.export.write_text('installed: ["demo.1.0"]\n')
        self.env = {"PATH": str(self.bin), "FRAGMA_SWITCH_PREFIX": str(self.switch)}
        self.spec = {"version": "1.0", "version_args": ["--version"],
                     "version_pattern": r"^demo (\d+\.\d+)", "required": True}

    def executable(self, name="demo", version="1.0", plugins="WP  prover\nEva  analyzer\n", target="test-elf"):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\nimport sys\n"
            f"print({plugins!r} if '-plugins' in sys.argv else "
            f"{target!r} if '-dumpmachine' in sys.argv else {'demo ' + version!r})\n")
        path.chmod(0o755)
        return path

    def write_lock(self, tools=None):
        lock = {"schema_version": 1, "tools": tools or {"frama-c": self.spec},
            "required_plugins": ["WP", "Eva"], "required_scripts": [],
            "opam": {"installed": ["demo.1.0"], "export": "toolchain/opam-switch.export",
                "export_sha256": hashlib.sha256(self.export.read_bytes()).hexdigest()},
            "artifacts": {"demo": {"sha256": hashlib.sha256(b"pinned archive").hexdigest()}}}
        (self.root / "toolchain" / "lock.json").write_text(json.dumps(lock))

    def test_exact_version_at_path_with_spaces(self):
        path = self.executable()
        result = probe("demo", self.spec, self.env)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["command"], [str(path), "--version"])
        self.assertEqual(len(result["sha256"]), 64)

    def test_wrong_version_fails(self):
        self.executable(version="1.1")
        self.assertEqual(probe("demo", self.spec, self.env)["status"], "version-mismatch")

    def test_missing_tool_is_explicit(self):
        self.assertEqual(probe("demo", self.spec, self.env)["status"], "missing")

    def test_explicit_bad_executable_cannot_fall_back(self):
        self.executable()
        env = {**self.env, "FRAGMA_TOOL_DEMO": str(self.root / "missing executable")}
        self.assertEqual(probe("demo", self.spec, env)["status"], "missing")

    def test_prebuilt_hash_is_enforced(self):
        self.executable()
        spec = {**self.spec, "require_binary_hash": True, "reference_sha256": "0" * 64}
        self.assertEqual(probe("demo", spec, self.env)["status"], "hash-mismatch")

    def test_wrong_compiler_target_fails(self):
        self.executable(target="wrong-elf")
        spec = {**self.spec, "target": "expected-elf"}
        self.assertEqual(probe("demo", spec, self.env)["status"], "target-mismatch")

    def test_prepare_does_not_mutate_environment(self):
        source = {"HOME": str(self.root / "user"), "PATH": "/usr/bin::/bin",
                  "FRAGMA_TOOLCHAIN_PREFIX": str(self.root / "prefix")}
        before = dict(source)
        env = prepare_environment(self.root, self.switch, source)
        self.assertEqual(source, before)
        self.assertEqual(env["HOME"], source["HOME"])
        self.assertTrue(env["PATH"].startswith(str(self.bin) + ":"))
        self.assertNotIn("", env["PATH"].split(":"))

    def test_explicit_switch_missing_state_fails_closed(self):
        with self.assertRaisesRegex(ToolchainError, "missing its state"):
            prepare_environment(self.root, self.root / "does not exist", self.env)

    def test_explicit_prefix_does_not_discover_historical_switch(self):
        user = self.root / "user"
        historic = user / ".opam" / "fragma" / ".opam-switch"
        historic.mkdir(parents=True)
        (historic / "switch-state").write_text('installed: ["demo.1.0"]\n')
        env = {"HOME": str(user), "PATH": "", "FRAGMA_TOOLCHAIN_PREFIX": str(self.root / "new prefix")}
        self.assertIsNone(discover(self.root, environ=env)["switch_prefix"])

    def test_empty_or_ambiguous_package_state_rejected(self):
        path = self.switch / ".opam-switch" / "switch-state"
        for source in ('installed: []', 'installed: ["demo.1.0"]\ninstalled: ["demo.1.0"]',
                       'installed: ["demo.1.0" junk]', 'installed: ["demo.1.0" "demo.1.0"]'):
            with self.subTest(source=source):
                path.write_text(source)
                with self.assertRaises(ToolchainError):
                    installed_packages(self.switch)

    def test_inventory_accepts_complete_components_and_packages(self):
        self.executable("frama-c")
        self.write_lock()
        result = inventory(self.root, self.env)
        self.assertTrue(result["ok"], result["issues"])

    def test_changed_transitive_package_set_fails(self):
        self.executable("frama-c")
        self.write_lock()
        state = self.switch / ".opam-switch" / "switch-state"
        state.write_text('installed: ["demo.1.1"]\n')
        result = inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertEqual(result["opam"]["missing"], ["demo.1.0"])
        self.assertEqual(result["opam"]["unexpected"], ["demo.1.1"])

    def test_two_exact_package_profiles_keep_missing_post_dependency_visible(self):
        self.executable("frama-c")
        self.write_lock()
        lock_path = self.root / "toolchain" / "lock.json"
        lock = json.loads(lock_path.read_text())
        lock["opam"]["complete_installed"] = ["demo.1.0", "post.1.0"]
        lock_path.write_text(json.dumps(lock))
        historical = inventory(self.root, self.env)
        self.assertTrue(historical["ok"])
        self.assertEqual(historical["opam"]["package_profile"], "historical-analysis")
        self.assertEqual(historical["opam"]["missing_post_dependencies"], ["post.1.0"])
        self.assertFalse(historical["opam"]["dependency_closure_complete"])
        (self.switch / ".opam-switch" / "switch-state").write_text('installed: ["demo.1.0" "post.1.0"]')
        metadata = self.switch / ".opam-switch" / "packages" / "post.1.0"
        metadata.mkdir()
        (metadata / "opam").write_text('opam-version: "2.0"\n')
        complete = inventory(self.root, self.env)
        self.assertTrue(complete["ok"], complete["issues"])
        self.assertEqual(complete["opam"]["package_profile"], "complete")
        self.assertTrue(complete["opam"]["dependency_closure_complete"])

    def test_extra_package_is_not_accepted_as_complete(self):
        self.executable("frama-c")
        self.write_lock()
        lock_path = self.root / "toolchain" / "lock.json"
        lock = json.loads(lock_path.read_text())
        lock["opam"]["complete_installed"] = ["demo.1.0", "post.1.0"]
        lock_path.write_text(json.dumps(lock))
        (self.switch / ".opam-switch" / "switch-state").write_text('installed: ["demo.1.0" "post.1.0" "extra.1.0"]')
        result = inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertFalse(result["opam"]["dependency_closure_complete"])

    def test_missing_plugin_fails_despite_successful_version(self):
        self.executable("frama-c", plugins="WP prover")
        self.write_lock()
        result = inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertEqual(result["plugins"]["status"], "missing")

    def test_modified_export_fails(self):
        self.executable("frama-c")
        self.write_lock()
        self.export.write_text("different export\n")
        result = inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertEqual(result["opam"]["status"], "hash-mismatch")

    def test_missing_pinned_prover_configuration_fails(self):
        self.executable("frama-c")
        self.write_lock()
        lock_path = self.root / "toolchain" / "lock.json"
        lock = json.loads(lock_path.read_text())
        lock["why3"] = {"config": "toolchain/missing.conf", "sha256": "0" * 64,
                        "required_provers": ["cvc5"]}
        lock_path.write_text(json.dumps(lock))
        result = inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertEqual(result["why3"]["status"], "hash-mismatch")

    def test_successful_prover_listing_missing_required_prover_fails(self):
        self.executable("frama-c")
        self.write_lock()
        config = self.root / "toolchain" / "why3.conf"
        config.write_text("[main]\nmagic = 14\n")
        lock_path = self.root / "toolchain" / "lock.json"
        lock = json.loads(lock_path.read_text())
        lock["why3"] = {"config": "toolchain/why3.conf",
                        "sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                        "required_provers": ["cvc5"]}
        lock_path.write_text(json.dumps(lock))
        result = inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertEqual(result["why3"]["missing"], ["cvc5"])

    def test_unrelated_missing_cross_compiler_does_not_block(self):
        self.executable("frama-c")
        self.write_lock({"frama-c": self.spec, "other-arch-gcc": {**self.spec, "required": False}})
        result = inventory(self.root, self.env)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["tools"]["other-arch-gcc"]["status"], "missing")

    def test_archive_verification_rejects_corruption_and_missing(self):
        self.write_lock()
        artifact = self.root / "archive with spaces"
        with self.assertRaises(ToolchainError):
            verify_artifact(self.root, "demo", artifact)
        artifact.write_bytes(b"pinned archive")
        self.assertEqual(len(verify_artifact(self.root, "demo", artifact)), 64)
        artifact.write_bytes(b"changed archive")
        with self.assertRaisesRegex(ToolchainError, "Checksum mismatch"):
            verify_artifact(self.root, "demo", artifact)

    def test_setup_default_is_read_only_and_preserves_paths(self):
        checkout = Path(__file__).resolve().parents[1]
        prefix = self.root / "new install with spaces"
        build = self.root / "new build with spaces"
        cache = self.root / "new cache with spaces"
        result = subprocess.run(["sh", str(checkout / "toolchain" / "install.sh"),
            "--prefix", str(prefix), "--build-dir", str(build), "--download-cache", str(cache)],
            capture_output=True, text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["mode"], "plan")
        self.assertEqual(plan["prefix"], str(prefix))
        self.assertFalse(prefix.exists())
        self.assertFalse(build.exists())
        self.assertFalse(cache.exists())

    def test_setup_rejects_existing_installation_without_changing_it(self):
        checkout = Path(__file__).resolve().parents[1]
        sentinel = self.switch / "user sentinel"
        sentinel.write_text("preserve this")
        result = subprocess.run(["sh", str(checkout / "toolchain" / "install.sh"),
            "--apply", "--prefix", str(self.switch)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing nonempty installation", result.stderr)
        self.assertEqual(sentinel.read_text(), "preserve this")

    def test_setup_cannot_resume_unmarked_existing_installation(self):
        checkout = Path(__file__).resolve().parents[1]
        result = subprocess.run(["sh", str(checkout / "toolchain" / "install.sh"),
            "--apply", "--resume", "--prefix", str(self.switch)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without a fragma setup marker", result.stderr)


if __name__ == "__main__":
    unittest.main()
