"""Unmocked context/gate validation; no compiler, analyzer or native execution.

Default tests use a complete temporary input tree and a synthetic read-only Git
transport. Opt in to real retained evidence with both FRAGMA_COMMON24_CONTEXT_RESULTS
and FRAGMA_COMMON24_CONTEXT_KERNEL; only git rev-parse/show may execute there.
"""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fragma import analysis_policy, common24_calibration as calibration
from fragma import frontend_policy, inputs, integrity, profiles
from fragma.sources import sha256
from tests.test_frontend_policy import fixture_elf


ROOT = Path(__file__).resolve().parents[1]
CALIBRATION_SOURCE = "common/annotated/compiler-calibration.c"
REAL_RUN, REAL_POPEN = subprocess.run, subprocess.Popen


def configured_targets():
    manifest = json.loads((ROOT / "config/common-byte-targets.json").read_text())
    targets = copy.deepcopy(manifest["targets"])
    for target in targets:
        target["compiler_calibration"] = {"kind": "common24-fixed22", "source": CALIBRATION_SOURCE}
    return manifest["kernel_revision"], targets


def forbid_execution(*args, **kwargs):
    raise AssertionError("compiler/analyzer/native execution is forbidden in context tests")


class SyntheticContextTests(unittest.TestCase):
    """Real validators and receipts; only the Git process transport is synthetic."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="common24 context ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project with spaces"
        self.kernel = self.root / "git source"
        self.source = self.root / "kernel snapshot"
        self.revision, targets = configured_targets()
        self.target = next(row for row in targets if row["profile"] == "arm-gcc")
        self.build_path = self.root / "build/kernel/arm-gcc"
        self.output = self.root / "results/genuine gate"
        self.output.mkdir(parents=True)
        self.kernel.mkdir(parents=True)
        self.git_blobs = {}
        self.git_calls = []
        for name in ("config/profiles.json", "config/architectures.json", CALIBRATION_SOURCE,
                     frontend_policy.FIXTURE, frontend_policy.HEADER, "profiles/calibration.c"):
            self.write(self.root / name, (ROOT / name).read_bytes())
        # These files are bound as tool inputs, not imported as fake validators.
        self.write(self.root / "fragma/frontend_policy.py", b"synthetic tracked frontend identity\n")
        self.write(self.root / "fragma/analysis_policy.py", b"synthetic tracked analysis identity\n")
        for name in frontend_policy.required_files(self.target):
            if not (self.root / name).exists():
                self.write(self.root / name, (ROOT / name).read_bytes())
        self.compiler = self.root / "tools/target compiler"
        self.write(self.compiler, b"inert compiler identity; never executed\n")
        self.write(self.root / "tools/generator.py", b"inert model-generator identity\n")
        self.write(self.root / "tools/probe.h", b"/* synthetic model probe */\n")
        for name, contents in {
            "lib/string.c": "int synthetic_string_tu;\n",
            "include/linux/types.h": "typedef unsigned char u8; typedef unsigned int u32;\n",
            "include/linux/unaligned.h": "/* synthetic pinned helper header */\n",
            "include/linux/compiler_types.h": "#define inline inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))\n",
        }.items():
            self.write(self.source / name, contents)
            self.git_blobs[name] = contents.encode()
        self.generated = self.build_path / "include/generated/autoconf.h"
        self.write(self.generated, "#define CONFIG_SYNTHETIC 1\n")
        self.write(self.build_path / ".config", "CONFIG_SYNTHETIC=y\n")
        self.entry = {"directory": str(self.build_path), "file": str(self.source / "lib/string.c"),
            "arguments": [str(self.compiler), "-O2", "-m32", "-std=gnu11", "-D__KERNEL__",
                "-I", str(self.source / "include"), "-include", str(self.generated),
                "-c", str(self.source / "lib/string.c"), "-o", "lib/string.o"]}
        self.save_build()
        registration = profiles.load_profiles(self.root)["arm-gcc"]
        analysis = copy.deepcopy(registration["analysis"])
        self.yaml = self.root / "models/arm-gcc.yaml"
        self.write(self.yaml, "little_endian: true\nsizeof_int: 4\nsizeof_long: 4\nsizeof_ptr: 4\n")
        self.audit = self.root / "models/analysis-policy-audit.json"
        correctness = {flag.removeprefix("-no"): "false" for flag in analysis_policy.ARITHMETIC_FLAGS}
        correctness[analysis_policy.POINTER_FLAG] = "true"
        parameters = {"eva": {"correctness-parameters": correctness}}
        self.write(self.audit, json.dumps(parameters))
        argv = ["/inert/frama-c", *analysis_policy.analyzer_flags(analysis), "-audit-prepare",
            str(self.audit), str(self.root / "profiles/calibration.c"), "-eva", "-eva-slevel", "10"]
        policy = analysis_policy.validate_actual_model_policy(analysis, argv, parameters)
        self.model = {"profile_id": "arm-gcc", "profile_sha256": profiles._digest(registration),
            "status": "passed", "level": "L1", "kernel_revision": self.revision,
            "analysis": analysis, "compiler": {"path": str(self.compiler), "sha256": sha256(self.compiler),
                "target": registration["compiler_target"], "version": registration["compiler_version"]},
            "build": {"matched_commands": [copy.deepcopy(self.entry)], "source": str(self.source),
                "build_path": str(self.build_path), "build_receipt_sha256": self.build["receipt_sha256"]},
            "fixture_sha256": sha256(self.root / "profiles/calibration.c"),
            "generator": {"path": str(self.root / "tools/generator.py"),
                "sha256": sha256(self.root / "tools/generator.py"),
                "probe_input_hashes": {"probe.h": sha256(self.root / "tools/probe.h")}},
            "machdep": {"path": str(self.yaml), "sha256": sha256(self.yaml),
                "checked_fields": {"sizeof_int": 4, "sizeof_long": 4, "sizeof_ptr": 4, "little_endian": True}},
            "analysis_policy_audit": {"path": str(self.audit), "sha256": sha256(self.audit), "parameters": parameters},
            "validated_model_policy": policy,
            "checks": [{"name": "eva-arithmetic-and-memory-byte-order", "status": "passed",
                "details": {"exit_code": 0, "command": argv}},
                {"name": "analysis-runtime-policy", "status": "passed", "details": copy.deepcopy(policy)}]}
        for patcher in (patch.object(inputs, "run_recorded", side_effect=forbid_execution),
                        patch("subprocess.Popen", side_effect=forbid_execution),
                        patch("subprocess.run", side_effect=self.git_transport)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.binding = self.context()
        self.dependencies = [self.root / frontend_policy.FIXTURE, self.root / frontend_policy.HEADER,
            self.source / "include/linux/types.h", self.source / "include/linux/unaligned.h",
            self.source / "include/linux/compiler_types.h", self.generated]
        self.write(self.output / "kernel-model.o", fixture_elf(self.target["frontend_policy"]))
        self.write(self.output / "kernel-model.log", b"")
        self.write_dependencies()
        self.gate = self.make_gate()

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())

    def save_build(self):
        self.write(self.build_path / "compile_commands.json", json.dumps([self.entry]))
        files = {name: sha256(self.build_path / name) for name in
                 ("compile_commands.json", ".config", "include/generated/autoconf.h")}
        record = {"schema_version": 1, "status": "prepared", "profile_id": "arm-gcc",
            "source": str(self.source), "revision": self.revision, "compiler": str(self.compiler),
            "compiler_sha256": sha256(self.compiler), "files": files}
        self.write(self.build_path / "fragma-build.json", json.dumps(record))
        self.build = inputs.load_build(self.root, "arm-gcc", self.revision)

    def git_transport(self, argv, **kwargs):
        self.assertEqual(argv[:3], ["git", "-C", str(self.kernel)])
        self.git_calls.append(list(argv))
        if argv[3:] == ["rev-parse", "--verify", self.revision + "^{commit}"]:
            return subprocess.CompletedProcess(argv, 0, self.revision + "\n", "")
        if len(argv) == 5 and argv[3] == "show" and argv[4].startswith(self.revision + ":"):
            name = argv[4].split(":", 1)[1]
            if name in self.git_blobs:
                return subprocess.CompletedProcess(argv, 0, self.git_blobs[name], b"")
            return subprocess.CompletedProcess(argv, 1, b"", b"synthetic untracked Git path")
        raise AssertionError("unexpected subprocess, including non-read-only Git: " + repr(argv))

    def context(self, *, target=None, model=None, build=None):
        return calibration.context(self.root, target or self.target, model or self.model,
                                   build or self.build, self.revision)

    def write_dependencies(self):
        escaped = [str(path).replace("\\", "\\\\").replace(" ", "\\ ") for path in self.dependencies]
        self.write(self.output / "model-headers.d", "fragma: " + " ".join(escaped) + "\n")

    def make_gate(self):
        gate = {"argv": calibration.expected_gate_argv(self.binding, self.output),
            "cwd": self.binding["cwd"], "returncode": 0, "timed_out": False,
            "log": str(self.output / "kernel-model.log"),
            "log_sha256": sha256(self.output / "kernel-model.log"),
            "frontend_policy": copy.deepcopy(self.target["frontend_policy"]),
            "original_compile_command": copy.deepcopy(self.entry),
            "fixture_sha256": sha256(self.root / frontend_policy.FIXTURE),
            "inputs": inputs.input_receipts(self.root, self.kernel, self.revision, self.build,
                inputs.dependency_paths(self.output / "model-headers.d", self.build_path))}
        for name, filename in (("object", "kernel-model.o"), ("dependencies", "model-headers.d"),
                               ("diagnostics", "kernel-model.log")):
            gate[name] = calibration.record(self.output / filename)
        return gate

    def validate_gate(self, gate=None, model=None, binding=None):
        return calibration.validate_gate(self.root, self.kernel, binding or self.binding,
            self.build, self.gate if gate is None else gate, self.output,
            target=self.target, model=model or self.model)

    def test_context_binds_real_files_current_registry_model_and_helpers(self):
        before = copy.deepcopy((self.target, self.model, self.build, self.entry))
        observed = self.context()
        self.assertEqual(observed["target_sha256"], calibration.digest(self.target))
        self.assertEqual(observed["model_sha256"], calibration.digest(self.model))
        self.assertEqual(observed["frontend_options"], ["-DFRAGMA_COMMON24_INLINE_POLICY=1"])
        paths = {row["absolute_path"]: row["sha256"] for row in observed["tracked_inputs"]}
        for path in (self.root / CALIBRATION_SOURCE, self.root / frontend_policy.FIXTURE,
                     self.root / "fragma/frontend_policy.py", self.root / "fragma/analysis_policy.py",
                     self.compiler, self.audit, self.yaml, self.build_path / "fragma-build.json"):
            self.assertEqual(paths[str(path)], sha256(path))
        self.assertEqual(integrity.changed_files(observed["tracked_inputs"]), [])
        self.assertEqual(before, (self.target, self.model, self.build, self.entry))

    def test_genuine_fixture_reconstructs_artifacts_and_git_dependencies(self):
        before = copy.deepcopy(self.gate)
        observed = self.validate_gate()
        self.assertEqual(observed["record_sha256"], calibration.digest(self.gate))
        self.assertEqual(observed["object_identity"]["class"], 32)
        self.assertEqual(observed["object_identity"]["byte_order"], "little")
        self.assertEqual({row["origin"] for row in observed["inputs"]}, {"kernel", "kernel-build", "project"})
        self.assertEqual(observed["inputs"], self.gate["inputs"])
        self.assertEqual(before, self.gate)
        self.assertTrue(any(argv[3] == "show" for argv in self.git_calls))

    def test_model_profile_level_revision_and_registration_mismatch_reject(self):
        for field, value in (("profile_id", "m68k-gcc"), ("level", "L0"), ("status", "running"),
                             ("kernel_revision", "f" * 40), ("profile_sha256", "0" * 64)):
            changed = copy.deepcopy(self.model); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.context(model=changed)

    def test_current_registry_drift_rejects_even_when_model_label_stays_passed(self):
        path = self.root / "config/profiles.json"
        data = json.loads(path.read_text())
        next(row for row in data["profiles"] if row["id"] == "arm-gcc")["compiler_version"] = "0.synthetic"
        self.write(path, json.dumps(data))
        with self.assertRaises(ValueError):
            self.context()

    def test_actual_model_policy_is_not_inferred_from_saved_passed_labels(self):
        mutations = [lambda d: d["analysis"].pop("runtime_checks"),
            lambda d: d["validated_model_policy"].update(actual_pointer_formation="false"),
            lambda d: d["analysis_policy_audit"].update(sha256="0" * 64),
            lambda d: d["checks"][0]["details"].update(exit_code=True),
            lambda d: d["checks"][0]["details"]["command"].remove("-warn-invalid-pointer"),
            lambda d: d["checks"].pop()]
        for mutate in mutations:
            changed = copy.deepcopy(self.model); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.context(model=changed)

    def test_changed_audit_bytes_reject_even_with_rehashed_envelope(self):
        raw = json.loads(self.audit.read_text()); raw["eva"]["correctness-parameters"]["-warn-invalid-pointer"] = "false"
        self.write(self.audit, json.dumps(raw))
        changed = copy.deepcopy(self.model); changed["analysis_policy_audit"]["sha256"] = sha256(self.audit)
        with self.assertRaises(ValueError):
            self.context(model=changed)

    def test_source_scope_setting_and_calibration_bytes_reject(self):
        for change in ({"source": "other.h"}, {"functions": list(reversed(calibration.HELPERS))},
                       {"compiler_calibration": None},
                       {"compiler_calibration": {"kind": "other", "source": CALIBRATION_SOURCE}},
                       {"compiler_calibration": {"kind": "common24-fixed22", "source": "../escape.c"}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.context(target={**self.target, **change})
        self.write(self.root / CALIBRATION_SOURCE, b"changed calibration input\n")
        with self.assertRaises(ValueError):
            self.context()

    def test_unknown_or_missing_frontend_policy_cannot_use_context(self):
        for policy in (None, {}, {"schema_version": True, "kind": "common24-inline", "variant": "no-instrument"},
                       {"schema_version": 1, "kind": "common24-inline", "variant": "fallback"}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                self.context(target={**self.target, "frontend_policy": policy})

    def test_model_command_compiler_yaml_and_probe_hashes_reject(self):
        mutations = [lambda d: d["build"].update(matched_commands=[]),
            lambda d: d["compiler"].update(path="/different/compiler"),
            lambda d: d["compiler"].update(sha256="0" * 64),
            lambda d: d["machdep"].update(sha256="0" * 64),
            lambda d: d["generator"]["probe_input_hashes"].update({"probe.h": "0" * 64})]
        for mutate in mutations:
            changed = copy.deepcopy(self.model); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.context(model=changed)

    def test_genuine_build_drift_and_different_supplied_receipt_reject(self):
        changed = copy.deepcopy(self.build); changed["receipt_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.context(build=changed)
        self.write(self.generated, "#define CONFIG_DIFFERENT 1\n")
        with self.assertRaises(ValueError):
            self.context()

    def test_nonmatching_optimization_or_override_in_rebound_genuine_entry_reject(self):
        for extra in ("-O0", "-flto", "-DFRAGMA_COMMON24_INLINE_POLICY=1", "-UBUILD_BUG_ON_MSG"):
            with self.subTest(extra=extra):
                original = copy.deepcopy(self.entry)
                self.entry["arguments"].insert(1, extra); self.save_build()
                changed = copy.deepcopy(self.model); changed["build"]["matched_commands"] = [copy.deepcopy(self.entry)]
                changed["build"]["build_receipt_sha256"] = self.build["receipt_sha256"]
                with self.assertRaises(ValueError):
                    self.context(model=changed)
                self.entry = original; self.save_build()

    def test_changed_helper_source_is_visible_in_reconstructed_binding(self):
        helper = self.root / "fragma/frontend_policy.py"
        self.write(helper, b"changed synthetic helper identity\n")
        current = self.context()
        self.assertFalse(calibration.same(self.binding, current))
        self.assertIn(str(helper), [row["absolute_path"] for row in integrity.changed_files(self.binding["tracked_inputs"])])

    def test_fixture_receipt_metadata_cannot_override_command_or_policy(self):
        mutations = [lambda g: g["argv"].append("-DFRAGMA_COMMON24_INLINE_POLICY=2"),
            lambda g: g.update(cwd=str(self.root)), lambda g: g.update(returncode=True),
            lambda g: g.update(timed_out=True), lambda g: g.update(frontend_policy=None),
            lambda g: g.update(original_compile_command={}),
            lambda g: g.update(fixture_sha256="0" * 64)]
        for mutate in mutations:
            changed = copy.deepcopy(self.gate); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate_gate(changed)

    def test_missing_or_rehashed_mismatched_fixture_artifacts_reject(self):
        for field in ("object", "dependencies", "diagnostics"):
            changed = copy.deepcopy(self.gate); changed.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate_gate(changed)
        for field in ("object", "dependencies", "diagnostics"):
            changed = copy.deepcopy(self.gate); changed[field]["sha256"] = "0" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate_gate(changed)
        (self.output / "kernel-model.o").unlink()
        with self.assertRaises((ValueError, OSError)):
            self.validate_gate()

    def test_rehashed_malformed_or_wrong_policy_elf_reject(self):
        wrong_policy = {**self.target["frontend_policy"], "variant": "patchable-entry-0"}
        for data in (b"not ELF", fixture_elf(wrong_policy),
                     fixture_elf(self.target["frontend_policy"], bits=64),
                     fixture_elf(self.target["frontend_policy"], little_endian=False)):
            self.write(self.output / "kernel-model.o", data); self.gate = self.make_gate()
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.validate_gate()

    def test_rehashed_unexpected_fixture_diagnostic_rejects(self):
        self.write(self.output / "kernel-model.log", "fixture.c:1: warning: unexpected\n")
        self.gate = self.make_gate()
        with self.assertRaises(ValueError):
            self.validate_gate()

    def test_symlinked_artifact_rejects_even_with_identical_bytes_and_hash(self):
        obj = self.output / "kernel-model.o"; saved = self.output / "saved-object"
        obj.rename(saved); obj.symlink_to(saved)
        with self.assertRaises(ValueError):
            self.validate_gate()

    def test_actual_dependency_inventory_cannot_omit_genuine_headers(self):
        self.dependencies.remove(self.source / "include/linux/compiler_types.h")
        self.write_dependencies(); self.gate = self.make_gate()
        with self.assertRaises(ValueError):
            self.validate_gate()

    def test_dependency_metadata_cannot_be_forged_or_omitted(self):
        for mutate in (lambda g: g["inputs"].pop(), lambda g: g["inputs"][0].update(sha256="0" * 64)):
            changed = copy.deepcopy(self.gate); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate_gate(changed)

    def test_changed_consumed_helper_rejects_against_pinned_git_bytes(self):
        self.write(self.source / "include/linux/unaligned.h", "/* different helper bytes */\n")
        with self.assertRaises(ValueError):
            self.validate_gate()

    def test_git_blob_mismatch_or_untracked_header_rejects(self):
        self.git_blobs["include/linux/types.h"] = b"/* mismatched pinned type bytes */\n"
        with self.assertRaises(ValueError):
            self.validate_gate()
        del self.git_blobs["include/linux/types.h"]
        with self.assertRaises(ValueError):
            self.validate_gate()


@unittest.skipUnless(os.environ.get("FRAGMA_COMMON24_CONTEXT_RESULTS") and
                     os.environ.get("FRAGMA_COMMON24_CONTEXT_KERNEL"),
                     "optional explicit current normal3 evidence and kernel Git tree")
class RetainedContextTests(unittest.TestCase):
    """Real builds, models, gate artifacts and Git reads; no target execution."""

    def setUp(self):
        self.base = Path(os.environ["FRAGMA_COMMON24_CONTEXT_RESULTS"]).resolve()
        self.kernel = Path(os.environ["FRAGMA_COMMON24_CONTEXT_KERNEL"]).resolve()
        self.revision, self.targets = configured_targets()
        self.before = {}
        for patcher in (patch.object(inputs, "run_recorded", side_effect=forbid_execution),
                        patch("subprocess.run", side_effect=self.readonly_run),
                        patch("subprocess.Popen", side_effect=self.readonly_popen)):
            patcher.start(); self.addCleanup(patcher.stop)
        self.addCleanup(self.check_unchanged)

    def readonly_command(self, argv):
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[:3], ["git", "-C", str(self.kernel)])
        self.assertTrue(argv[3:] == ["rev-parse", "--verify", self.revision + "^{commit}"] or
                        len(argv) == 5 and argv[3] == "show" and argv[4].startswith(self.revision + ":"))

    def readonly_run(self, argv, **kwargs):
        self.readonly_command(argv)
        return REAL_RUN(argv, **kwargs)

    def readonly_popen(self, argv, **kwargs):
        self.readonly_command(argv)
        return REAL_POPEN(argv, **kwargs)

    def check_unchanged(self):
        self.assertEqual(self.before, {path: sha256(Path(path)) for path in self.before})

    def test_all_three_actual_current_contexts_and_genuine_fixtures(self):
        for target in self.targets:
            with self.subTest(profile=target["profile"]):
                model_path = self.base / ("profile-" + target["profile"]) / "profile.json"
                output = self.base / target["id"]
                result_path = output / "result.json"
                self.before[str(model_path)] = sha256(model_path)
                self.before[str(result_path)] = sha256(result_path)
                model = json.loads(model_path.read_text()); result = json.loads(result_path.read_text())
                build = inputs.load_build(ROOT, target["profile"], self.revision)
                binding = calibration.context(ROOT, target, model, build, self.revision)
                observed = calibration.validate_gate(ROOT, self.kernel, binding, build,
                    result["kernel_model_check"], output, target=target, model=model)
                self.assertEqual(observed["object_identity"], result["validated_frontend_policy"]["fixture_object"])
                self.assertEqual(observed["inputs"], result["kernel_model_check"]["inputs"])
                # The controls' consumer boundary must also accept the actual
                # freshly authenticated gate without creating its output or
                # invoking either negative compiler command.
                from fragma import common24_controls
                controls = common24_controls.context(ROOT, self.kernel, target, model, build,
                    binding, observed, output / "compiler-controls")
                self.assertEqual(controls["positive_gate"], observed)
                self.assertEqual(integrity.changed_files(controls["tracked_inputs"]), [])
                for row in integrity.merge_records(binding["tracked_inputs"], integrity.metadata_records(observed)):
                    self.before[row["absolute_path"]] = row["sha256"]
                self.assertEqual(integrity.changed_files(binding["tracked_inputs"]), [])
                for field in ("object", "dependencies", "diagnostics"):
                    changed = copy.deepcopy(result["kernel_model_check"]); changed[field]["sha256"] = "0" * 64
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        calibration.validate_gate(ROOT, self.kernel, binding, build, changed, output,
                                                  target=target, model=model)


if __name__ == "__main__":
    unittest.main()
