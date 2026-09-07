"""Target-aware Clang inventory with inert tools and mocked subprocesses only."""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma import integrity, toolchain


class ToolchainClangTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fragma-clang-inventory-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("clang-real", "gcc", "frama-c", "cc1", "as", "ld"):
            path = self.bin / name
            path.write_bytes(("inert identity only: " + name).encode())
            path.chmod(0o755)
        (self.bin / "clang").symlink_to("clang-real")
        self.resource = self.root / "clang-resource"
        include = self.resource / "include"
        (include / "nested").mkdir(parents=True)
        (include / "empty").mkdir()
        (include / "stddef.h").write_text("/* synthetic builtin header */\n")
        (include / "nested/detail.inc").write_text("/* non-h suffix is still bound */\n")
        self.env = {"PATH": str(self.bin), "LC_ALL": "C"}
        self.spec = {
            "compiler_family": "clang", "version": "21.1.8", "version_args": ["--version"],
            "target": "hexagon-unknown-linux-musl",
            "target_args": ["--target=hexagon-linux-musl", "-mv68"],
            "require_binary_hash": True,
            "reference_sha256": toolchain.sha256(self.bin / "clang"),
            "resource_include_tree_sha256": toolchain.clang_resource_tree(self.resource)["include_tree_sha256"],
            "required": True,
        }
        self.gcc_spec = {"version": "15.2.0", "version_args": ["-dumpfullversion"],
                         "target": "x86_64-linux-gnu", "required": True}
        self.commands = []
        self.responder = self.fake_process
        run = patch("fragma.toolchain.subprocess.run", side_effect=self.dispatch)
        self.addCleanup(run.stop)
        self.mock_run = run.start()
        popen = patch("subprocess.Popen", side_effect=AssertionError("unmocked process launch"))
        self.addCleanup(popen.stop)
        popen.start()

    def dispatch(self, argv, **kwargs):
        self.assertFalse(kwargs.get("shell", False))
        self.assertGreater(kwargs["timeout"], 0)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.commands.append(list(argv))
        return self.responder(argv, **kwargs)

    def fake_process(self, argv, **kwargs):
        name, args = Path(argv[0]).name, argv[1:]
        if name.startswith("clang"):
            if args == ["--version"]:
                output = "Ubuntu clang version 21.1.8 (inert mock)\n"
            elif args == [*self.spec["target_args"], "-dumpmachine"]:
                output = "hexagon-unknown-linux-musl\n"
            elif args == [*self.spec["target_args"], "-print-resource-dir"]:
                output = str(self.resource) + "\n"
            else:
                self.fail("unexpected Clang command: " + repr(argv))
        elif name == "gcc":
            if args == ["-dumpfullversion"]:
                output = "15.2.0\n"
            elif args == ["-dumpmachine"]:
                output = "x86_64-linux-gnu\n"
            elif len(args) == 1 and args[0] in ["-print-prog-name=" + c for c in ("cc1", "as", "ld")]:
                output = str(self.bin / args[0].split("=", 1)[1]) + "\n"
            else:
                self.fail("unexpected GCC command: " + repr(argv))
        elif name == "frama-c":
            self.assertIn(args, (["-version"], ["-plugins"]))
            output = "33.0 (synthetic)\n" if args == ["-version"] else "WP  synthetic plugin\n"
        else:
            self.fail("unexpected external command: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0, output, "")

    def probe(self, spec=None):
        return toolchain.probe("clang", self.spec if spec is None else spec, self.env)

    def write_lock(self, *, clang_required=True):
        directory = self.root / "toolchain"
        directory.mkdir(exist_ok=True)
        export = directory / "test.export"
        export.write_text('installed: ["demo.1.0"]\n')
        switch = self.root / "switch"
        package = switch / ".opam-switch/packages/demo.1.0"
        package.mkdir(parents=True, exist_ok=True)
        (switch / ".opam-switch/switch-state").write_text('installed: ["demo.1.0"]\n')
        (package / "opam").write_text('opam-version: "2.0"\n')
        self.env["FRAGMA_SWITCH_PREFIX"] = str(switch)
        lock = {"schema_version": 1, "tools": {
            "frama-c": {"version": "33.0", "version_args": ["-version"], "required": True},
            "gcc": self.gcc_spec, "clang": {**self.spec, "required": clang_required}},
            "required_plugins": ["WP"], "required_scripts": [],
            "opam": {"installed": ["demo.1.0"], "export": "toolchain/test.export",
                     "export_sha256": toolchain.sha256(export)}}
        (directory / "lock.json").write_text(json.dumps(lock))

    def test_closed_clang_probe_records_exact_target_resource_and_alias_identity(self):
        before = copy.deepcopy(self.spec)
        record = self.probe()
        self.assertEqual(record["status"], "ok", record)
        path = str(self.bin / "clang")
        self.assertEqual(self.commands, [[path, "--version"],
            [path, *self.spec["target_args"], "-dumpmachine"],
            [path, *self.spec["target_args"], "-print-resource-dir"]])
        self.assertEqual(record["path"], path)
        self.assertEqual(record["resolved_path"], str(self.bin / "clang-real"))
        self.assertEqual(record["compiler_family"], "clang")
        self.assertEqual(record["target_args"], self.spec["target_args"])
        self.assertEqual(record["target"], self.spec["target"])
        self.assertEqual(record["target_query"], {
            "command": [path, *self.spec["target_args"], "-dumpmachine"],
            "returncode": 0, "stdout": "hexagon-unknown-linux-musl\n", "stderr": ""})
        self.assertEqual(record["binary_before"], record["binary_final"])
        self.assertEqual(record["compiler_resources"]["include_tree_sha256"],
                         self.spec["resource_include_tree_sha256"])
        self.assertEqual(self.spec, before)
        receipts = integrity.metadata_records(record["compiler_resources"])
        self.assertEqual({r["absolute_path"] for r in receipts},
                         {str(self.resource / "include/stddef.h"), str(self.resource / "include/nested/detail.inc")})

    def test_legacy_gcc_record_and_all_query_arguments_are_unchanged(self):
        path = str(self.bin / "gcc")
        record = toolchain.probe("gcc", self.gcc_spec, self.env)
        self.assertEqual(record, {
            "name": "gcc", "requested_executable": "gcc", "required": True,
            "path": path, "expected_version": "15.2.0", "status": "ok",
            "command": [path, "-dumpfullversion"], "returncode": 0, "output": "15.2.0",
            "sha256": toolchain.sha256(self.bin / "gcc"), "resolved_path": path,
            "version": "15.2.0", "reference_hash_matches": None,
            "target_command": [path, "-dumpmachine"], "target": "x86_64-linux-gnu"})
        self.commands.clear()
        runtime = toolchain._runtime_receipt({"gcc": record}, self.env)
        self.assertEqual(self.commands, [[path, "-print-prog-name=" + c] for c in ("cc1", "as", "ld")])
        self.assertEqual(set(runtime), {"linker_commands", "libraries", "compiler_components", "support_data"})
        self.assertEqual(set(runtime["compiler_components"]["gcc"]), {"cc1", "as", "ld"})
        self.assertEqual(record, toolchain.probe("gcc", {**self.gcc_spec, "compiler_family": "gcc"}, self.env))

    def test_invalid_family_or_target_arguments_never_launch_a_process(self):
        cases = [None, [], (), "--target=hexagon-linux-musl -mv68",
                 ["--target=hexagon-linux-musl"], ["-mv68", "--target=hexagon-linux-musl"],
                 ["--target=x86_64-linux-gnu", "-mv68"],
                 [*self.spec["target_args"], "--target=hexagon-linux-musl"],
                 [*self.spec["target_args"], "-mv60"], ["@target-options"],
                 ["--target", "hexagon-linux-musl", "-mv68"]]
        for args in cases:
            with self.subTest(args=args):
                record = self.probe({**self.spec, "target_args": args})
                self.assertEqual(record["status"], "invalid-specification")
        for family in ("unknown", "gcc", None):
            with self.subTest(family=family):
                self.assertEqual(self.probe({**self.spec, "compiler_family": family})["status"],
                                 "invalid-specification")
        for args in ([], self.spec["target_args"]):
            record = toolchain.probe("gcc", {**self.gcc_spec, "target_args": args}, self.env)
            self.assertEqual(record["status"], "invalid-specification")
        self.mock_run.assert_not_called()

    def test_clang_requires_exact_version_query_and_both_strict_pins(self):
        mutations = [
            ("version", "21.1.7"), ("version_args", ["-dumpfullversion"]),
            ("target", "x86_64-pc-linux-gnu"), ("require_binary_hash", False),
            ("require_binary_hash", 1), ("reference_sha256", None),
            ("reference_sha256", "z" * 64), ("resource_include_tree_sha256", None),
            ("resource_include_tree_sha256", "0" * 63),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                self.assertEqual(self.probe({**self.spec, key: value})["status"], "invalid-specification")
        missing = dict(self.spec)
        del missing["version_args"]
        self.assertEqual(self.probe(missing)["status"], "invalid-specification")
        self.mock_run.assert_not_called()

    def test_mips32el_is_a_distinct_exact_clang_route(self):
        spec = {**self.spec,
                "target": "mipsel-unknown-linux-gnu",
                "target_args": ["--target=mipsel-linux-gnu", "-mabi=32", "-EL",
                                "-march=mips32r2", "-msoft-float"]}
        self.assertIsNone(toolchain._compiler_specification_error(spec))
        for change in (["--target=mipsel-linux-gnu", "-mabi=64", "-EL",
                        "-march=mips32r2", "-msoft-float"],
                       ["--target=mips-linux-gnu", "-mabi=32", "-EB",
                        "-march=mips32r2", "-msoft-float"],
                       [*spec["target_args"], "-O2"]):
            with self.subTest(change=change):
                self.assertIsNotNone(toolchain._compiler_specification_error(
                    {**spec, "target_args": change}))
        self.mock_run.assert_not_called()

    def test_changed_compiler_binary_fails_before_target_and_resource_queries(self):
        (self.bin / "clang-real").write_bytes(b"changed inert compiler")
        self.assertEqual(self.probe()["status"], "hash-mismatch")
        self.mock_run.assert_not_called()

    def test_compiler_binary_or_alias_drift_during_queries_is_rejected(self):
        binary = self.bin / "clang-real"
        original = binary.read_bytes()
        alias = self.bin / "clang"
        alternate = self.bin / "clang-copy"
        alternate.write_bytes(original)
        alternate.chmod(0o755)
        for phase in ("--version", "-dumpmachine", "-print-resource-dir"):
            for change_alias in (False, True):
                binary.write_bytes(original)
                alias.unlink()
                alias.symlink_to("clang-real")
                self.commands.clear()
                def responder(argv, **kwargs):
                    result = self.fake_process(argv, **kwargs)
                    if argv[-1] == phase:
                        if change_alias:
                            alias.unlink()
                            alias.symlink_to("clang-copy")
                        else:
                            binary.write_bytes(b"changed during mocked metadata query")
                    return result
                self.responder = responder
                with self.subTest(phase=phase, change_alias=change_alias):
                    record = self.probe()
                    self.assertEqual(record["status"], "hash-mismatch", record)
                    self.assertEqual(record["binary_before"]["sha256"], self.spec["reference_sha256"])
                    observed = record["binary_after_version"] if phase == "--version" else record["binary_final"]
                    self.assertNotEqual(observed, record["binary_before"])
                    if phase == "--version":
                        self.assertEqual(self.commands, [[str(alias), "--version"]])

    def test_fixed_clang_version_marker_cannot_be_weakened_by_pattern(self):
        for output in ("LLVM version 21.1.8\n", "clang version 21.1.7\n",
                       "clang version 21.1.8git\n", "clang version 21.1.8\nclang version 21.1.8\n"):
            def responder(argv, **kwargs):
                result = self.fake_process(argv, **kwargs)
                if argv[-1] == "--version":
                    result.stdout = output
                return result
            self.responder = responder
            with self.subTest(output=output):
                self.assertEqual(self.probe({**self.spec, "version_pattern": r"(21\.1\.8)"})["status"],
                                 "version-mismatch")

    def test_wrong_host_default_target_or_target_query_warning_is_rejected(self):
        for output, error, code in (("x86_64-pc-linux-gnu\n", "", 0),
                                    ("hexagon-linux-musl\n", "", 0),
                                    ("hexagon-unknown-linux-musl\n", "unexpected warning", 0),
                                    ("hexagon-unknown-linux-musl\n", "target query failed", 1)):
            def responder(argv, **kwargs):
                result = self.fake_process(argv, **kwargs)
                if argv[-1] == "-dumpmachine":
                    result.stdout, result.stderr, result.returncode = output, error, code
                return result
            self.responder = responder
            with self.subTest(output=output, error=error, code=code):
                record = self.probe()
                self.assertEqual(record["status"], "target-mismatch")
                self.assertEqual(record["target_query"], {
                    "command": [str(self.bin / "clang"), *self.spec["target_args"], "-dumpmachine"],
                    "returncode": code, "stdout": output, "stderr": error})
        self.assertFalse(any(argv[-1] == "-print-resource-dir" for argv in self.commands))

    def test_resource_tree_digest_covers_all_files_empty_directories_and_links(self):
        include = self.resource / "include"
        (include / "alias.h").symlink_to("stddef.h")
        (include / "alias-dir").symlink_to("nested", target_is_directory=True)
        tree = toolchain.clang_resource_tree(self.resource)
        expected = hashlib.sha256(json.dumps(tree["entries"], sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(tree["include_tree_sha256"], expected)
        self.assertEqual(tree["entries"]["empty"], {"kind": "directory"})
        self.assertEqual(tree["entries"]["alias.h"]["target"], "stddef.h")
        self.assertEqual(tree["entries"]["alias-dir"]["target_kind"], "directory")
        self.assertIn("alias-dir/detail.inc", tree["entries"])
        before = tree["include_tree_sha256"]
        (include / "nested/detail.inc").write_text("changed non-header-suffix input\n")
        self.assertNotEqual(toolchain.clang_resource_tree(self.resource)["include_tree_sha256"], before)

    def test_resource_tree_rejects_escapes_cycles_missing_and_empty_roots(self):
        include = self.resource / "include"
        outside = self.root / "outside.h"
        outside.write_text("outside fixture\n")
        alias = include / "alias"
        for target in (outside, include, self.root / "missing"):
            alias.symlink_to(target)
            with self.subTest(target=str(target)), self.assertRaises((toolchain.ToolchainError, OSError, RuntimeError)):
                toolchain.clang_resource_tree(self.resource)
            alias.unlink()
        with self.assertRaises(toolchain.ToolchainError):
            toolchain.clang_resource_tree(Path("relative-resource"))
        empty = self.root / "empty-resource"
        (empty / "include").mkdir(parents=True)
        with self.assertRaises(toolchain.ToolchainError):
            toolchain.clang_resource_tree(empty)

    def test_missing_changed_or_failed_resource_queries_never_return_ok(self):
        for output, code, error in (("relative/path\n", 0, ""),
                                    (str(self.root / "missing") + "\n", 0, ""),
                                    (str(self.resource) + "\n", 1, ""),
                                    (str(self.resource) + "\n", 0, "warning"),
                                    (str(self.resource) + "\nother\n", 0, "")):
            def responder(argv, **kwargs):
                result = self.fake_process(argv, **kwargs)
                if argv[-1] == "-print-resource-dir":
                    result.stdout, result.returncode, result.stderr = output, code, error
                return result
            self.responder = responder
            with self.subTest(output=output, code=code, error=error):
                self.assertEqual(self.probe()["status"], "resource-error")
        self.responder = self.fake_process
        (self.resource / "include/stddef.h").write_text("changed resource header\n")
        record = self.probe()
        self.assertEqual(record["status"], "resource-error")
        self.assertNotEqual(record["compiler_resources"]["include_tree_sha256"],
                            self.spec["resource_include_tree_sha256"])

    def test_runtime_clang_uses_read_only_pinned_rescan_never_gcc_components(self):
        record = self.probe()
        self.assertEqual(record["status"], "ok")
        self.commands.clear()
        runtime = toolchain._runtime_receipt({"clang": record}, self.env)
        self.assertEqual(self.commands, [])
        self.assertEqual(runtime["compiler_components"]["clang"]["compiler_resources"]["status"], "ok")
        (self.resource / "include/stddef.h").write_text("changed after initial probe\n")
        runtime = toolchain._runtime_receipt({"clang": record}, self.env)
        self.assertEqual(runtime["compiler_components"]["clang"]["compiler_resources"]["status"], "resource-error")
        self.assertEqual(self.commands, [])

    def test_same_content_symlink_retargeting_changes_the_resource_pin(self):
        include = self.resource / "include"
        (include / "copy.h").write_bytes((include / "stddef.h").read_bytes())
        alias = include / "alias.h"
        alias.symlink_to("stddef.h")
        spec = {**self.spec, "resource_include_tree_sha256":
                toolchain.clang_resource_tree(self.resource)["include_tree_sha256"]}
        record = self.probe(spec)
        self.assertEqual(record["status"], "ok")
        alias.unlink()
        alias.symlink_to("copy.h")
        self.assertEqual(toolchain.sha256(alias), toolchain.sha256(include / "stddef.h"))
        runtime = toolchain._runtime_receipt({"clang": record}, self.env)
        self.assertEqual(runtime["compiler_components"]["clang"]["compiler_resources"]["status"], "resource-error")

    def test_special_resource_entry_is_rejected_without_opening_it(self):
        path = self.resource / "include/nested/detail.inc"
        real = Path.lstat
        def observed(candidate, *args, **kwargs):
            value = real(candidate, *args, **kwargs)
            if candidate == path:
                fields = list(value)
                fields[0] = stat.S_IFIFO | 0o600
                return os.stat_result(fields)
            return value
        real_open = os.open
        def bounded_open(candidate, *args, **kwargs):
            self.assertNotEqual(Path(candidate), path, "special-file mock must not be opened")
            return real_open(candidate, *args, **kwargs)
        with patch("pathlib.Path.lstat", observed), patch("fragma.toolchain.os.open", side_effect=bounded_open):
            with self.assertRaises(toolchain.ToolchainError):
                toolchain.clang_resource_tree(self.resource)

    def test_inventory_required_and_optional_clang_resource_failures_are_distinct(self):
        self.write_lock()
        result = toolchain.inventory(self.root, self.env)
        self.assertTrue(result["ok"], result["issues"])
        (self.resource / "include/stddef.h").write_text("different header\n")
        result = toolchain.inventory(self.root, self.env)
        self.assertFalse(result["ok"])
        self.assertEqual(result["tools"]["clang"]["status"], "resource-error")
        self.assertTrue(any(issue.startswith("clang:") for issue in result["issues"]))
        self.write_lock(clang_required=False)
        result = toolchain.inventory(self.root, self.env)
        self.assertTrue(result["ok"], result["issues"])
        self.assertEqual(result["tools"]["clang"]["status"], "resource-error")
        self.assertEqual(result["tools"]["gcc"]["status"], "ok")

    def test_inventory_catches_drift_between_probe_and_runtime_required_only(self):
        original = (self.resource / "include/stddef.h").read_bytes()
        real_runtime = toolchain._runtime_receipt
        def change_before_runtime(tools, env):
            (self.resource / "include/stddef.h").write_text("changed between phases\n")
            return real_runtime(tools, env)
        for required in (True, False):
            (self.resource / "include/stddef.h").write_bytes(original)
            self.write_lock(clang_required=required)
            with patch("fragma.toolchain._runtime_receipt", side_effect=change_before_runtime):
                result = toolchain.inventory(self.root, self.env)
            self.assertEqual(result["ok"], not required)
            self.assertEqual(result["tools"]["clang"]["status"], "resource-error")
            self.assertEqual(result["tools"]["gcc"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
