"""UML's delegated kernel headers must never become an implicit host fallback."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fragma.profiles import (ProfileError, UML_HEADER_REVIEW_PATHS, _check_build,
                             _check_uml_prepare_commands, _export_headers,
                             _header_architecture, _uml_compile_flags_match,
                             load_profiles, validate_registration)


ROOT = Path(__file__).resolve().parent.parent


class UMLProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_profiles(ROOT)["um-x86_64-gcc"]
        self.directory = tempfile.TemporaryDirectory(prefix="fragma-uml-profile-")
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)

    def test_profile_is_explicitly_uml_not_an_x86_model_alias(self):
        self.assertEqual(self.profile["architecture"], "um")
        self.assertEqual(self.profile["kernel"]["arch"], "um")
        self.assertEqual(self.profile["kernel"]["subarch"], "x86_64")
        self.assertEqual(self.profile["kernel"]["config_recipe"], ["x86_64_defconfig"])
        self.assertEqual(self.profile["compiler_target"], "x86_64-linux-gnu")
        self.assertEqual(_header_architecture(self.profile), "x86")
        for flag in ("-mcmodel=large", "-m64", "-fno-builtin", "-D__arch_um__"):
            self.assertIn(flag, self.profile["flags"])
        self.assertNotIn("-mno-red-zone", self.profile["flags"])
        self.assertNotIn("-mcmodel=kernel", self.profile["flags"])
        self.assertEqual(set(self.profile["header_arch_review"]["file_hashes"]),
                         UML_HEADER_REVIEW_PATHS)

    def test_unreviewed_or_different_header_routes_fail(self):
        mutations = [
            {"header_arch": None}, {"header_arch": "arm64"},
            {"header_arch_review": None},
            {"header_arch_review": {**self.profile["header_arch_review"], "status": "pending"}},
            {"header_arch_review": {**self.profile["header_arch_review"], "reason": " "}},
            {"header_arch_review": {**self.profile["header_arch_review"], "file_hashes": {}}},
            {"kernel": {**self.profile["kernel"], "subarch": "i386"}},
            {"kernel": {**self.profile["kernel"], "arch": "x86"}},
            {"abi": {**self.profile["abi"], "bits": 32}},
            {"header_type": "asm-generic/posix_types.h"},
            {"generic_bitsperlong": True}, {"extra_uapi_headers": ["posix_types_32.h"]},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ProfileError):
                validate_registration({**self.profile, **mutation})
        ordinary = load_profiles(ROOT)["x86_64-gcc"]
        with self.assertRaisesRegex(ProfileError, "no reviewed port route"):
            validate_registration({**ordinary, "header_arch": "x86"})

    def fake_git(self, command, **kwargs):
        self.assertEqual(command[:3], ["git", "-C", "/not-a-host-header-tree"])
        revision, path = command[-1].split(":", 1)
        self.assertEqual(revision, self.profile["kernel_revision"])
        self.observed.append(path)
        return SimpleNamespace(returncode=0, stdout=self.content(path), stderr=b"")

    @staticmethod
    def content(path):
        return ("/* deterministic pinned fixture: " + path + " */\n").encode()

    def fixture_profile(self):
        result = copy.deepcopy(self.profile)
        result["header_arch_review"]["file_hashes"] = {
            path: hashlib.sha256(self.content(path)).hexdigest()
            for path in UML_HEADER_REVIEW_PATHS}
        self.observed = []
        return result

    def test_export_uses_pinned_delegation_and_retains_selection_evidence(self):
        profile = self.fixture_profile()
        with patch("fragma.profiles.subprocess.run", side_effect=self.fake_git):
            includes, hashes = _export_headers(profile, "/not-a-host-header-tree", self.output)
        self.assertTrue(UML_HEADER_REVIEW_PATHS <= set(self.observed))
        for path in ("arch/x86/include/uapi/asm/bitsperlong.h",
                     "arch/x86/include/uapi/asm/posix_types_64.h",
                     "arch/x86/include/asm/posix_types.h"):
            self.assertIn(path, hashes)
        self.assertNotIn("arch/um/include/uapi/asm/bitsperlong.h", self.observed)
        self.assertNotIn("generated:asm/bitsperlong.h", hashes)
        for path, checksum in profile["header_arch_review"]["file_hashes"].items():
            self.assertEqual(hashes[path], checksum)
            self.assertTrue((includes / "source-evidence" / path).is_file())
        self.assertIn("#include <asm/posix_types_64.h>",
                      (includes / "kernel-types.h").read_text())

    def test_changed_reviewed_source_is_rejected(self):
        profile = self.fixture_profile()
        profile["header_arch_review"]["file_hashes"]["arch/um/Makefile"] = "0" * 64
        with patch("fragma.profiles.subprocess.run", side_effect=self.fake_git):
            with self.assertRaisesRegex(ProfileError, "changed since review"):
                _export_headers(profile, "/not-a-host-header-tree", self.output)

    def test_missing_delegated_header_is_not_replaced_with_generic_or_host(self):
        profile = self.fixture_profile()

        def missing(command, **kwargs):
            if command[-1].endswith(":arch/x86/include/uapi/asm/bitsperlong.h"):
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"missing fixture")
            return self.fake_git(command, **kwargs)

        with patch("fragma.profiles.subprocess.run", side_effect=missing):
            with self.assertRaisesRegex(ProfileError, "Cannot export pinned header"):
                _export_headers(profile, "/not-a-host-header-tree", self.output)

    @staticmethod
    def preparation_receipt():
        return {"commands": [
            {"argv": ["make", "ARCH=um", "SUBARCH=x86_64", "x86_64_defconfig"],
             "returncode": 0},
            {"argv": ["make", "ARCH=um", "SUBARCH=x86_64", "prepare", "lib/string.o"],
             "returncode": 0},
            {"argv": ["python3", "gen_compile_commands.py"], "returncode": 0},
        ]}

    def test_preparation_requires_unique_exact_architecture_selectors(self):
        _check_uml_prepare_commands(self.preparation_receipt())
        for selector in ("ARCH=x86", "SUBARCH=i386", "ARCH=um", "SUBARCH=x86_64",
                         "ARCH:=x86", "SUBARCH+=i386", "ARCH?=um", "ARCH!=echo um"):
            for command in (0, 1):
                receipt = self.preparation_receipt()
                receipt["commands"][command]["argv"].append(selector)
                with self.subTest(selector=selector, command=command):
                    with self.assertRaisesRegex(ProfileError, "unique exact"):
                        _check_uml_prepare_commands(receipt)

    def test_every_preparation_command_requires_typed_zero_exit_status(self):
        for command in range(3):
            for status in (1, -15, None, False, True, "0", 0.0):
                receipt = self.preparation_receipt()
                receipt["commands"][command]["returncode"] = status
                with self.subTest(command=command, status=repr(status)):
                    with self.assertRaisesRegex(ProfileError, "successful exit"):
                        _check_uml_prepare_commands(receipt)
            receipt = self.preparation_receipt()
            del receipt["commands"][command]["returncode"]
            with self.subTest(command=command, status="missing"):
                with self.assertRaisesRegex(ProfileError, "successful exit"):
                    _check_uml_prepare_commands(receipt)

    def test_preparation_rejects_missing_or_malformed_command_records(self):
        for records in (None, [], {}, [None], [{"argv": []}],
                        [{"argv": ["make", 2], "returncode": 0}]):
            with self.subTest(records=records), self.assertRaises(ProfileError):
                _check_uml_prepare_commands({"commands": records})
        for count in (1, 3):
            receipt = self.preparation_receipt()
            receipt["commands"] = [receipt["commands"][0]] * count
            with self.subTest(count=count), self.assertRaises(ProfileError):
                _check_uml_prepare_commands(receipt)

    def test_compile_flags_accept_real_dependency_forwarding_and_kernel_aliases(self):
        args = ["gcc", *self.profile["flags"], "-m64", "-Wp,-MMD,lib/.string.o.d",
                "-Dstrrchr=kernel_strrchr", "-D", "errno=kernel_errno",
                "-U__unrelated__", "-c", "lib/string.c"]
        self.assertTrue(_uml_compile_flags_match(self.profile, args))

    def test_compile_flags_reject_uml_macro_overrides_and_hidden_options(self):
        changes = [
            ["-U__arch_um__"], ["-U", "__arch_um__"],
            ["-D__arch_um__=0"], ["-D", "__arch_um__=0"],
            ["-D__arch_um__"], ["-D__UM_HOST__"], ["-D", "__UM_HOST__=1"],
            ["-Wp,-U__arch_um__"], ["-Wp,-D,__arch_um__=0"],
            ["-Xpreprocessor", "-U__arch_um__"],
            ["-Xpreprocessor", "-D", "-Xpreprocessor", "__arch_um__=0"],
            ["@compiler-options"], ["-Wp,@preprocessor-options"],
            ["-Xpreprocessor", "@preprocessor-options"], ["-Xpreprocessor"],
        ]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(_uml_compile_flags_match(self.profile,
                                                         [*self.profile["flags"], *change]))

    def test_compile_flags_reject_opposing_model_and_position_independent_modes(self):
        for flag in ("-mno-red-zone", "-mcmodel=kernel", "-mcmodel=small", "-fbuiltin",
                     "-fPIE", "-fpie", "-fPIC", "-fpic", "-msse", "-mmmx",
                     "-msse2", "-m3dnow", "-mavx"):
            with self.subTest(flag=flag):
                self.assertFalse(_uml_compile_flags_match(self.profile,
                                                         [*self.profile["flags"], flag]))

    @unittest.skipUnless(os.environ.get("FRAGMA_UM_PROFILE_RESULTS"),
                         "supply current UML configured-profile evidence")
    def test_fresh_configured_evidence_and_build_identity(self):
        path = Path(os.environ["FRAGMA_UM_PROFILE_RESULTS"])
        evidence = json.loads((path / "profile.json").read_text())
        self.assertEqual((evidence["profile_id"], evidence["status"], evidence["level"]),
                         ("um-x86_64-gcc", "passed", "L1"))
        self.assertTrue(all(row["status"] == "passed" for row in evidence["checks"]))
        self.assertEqual(Path(evidence["machdep"]["path"]).name, "um-x86_64-gcc.yaml")
        self.assertEqual(evidence["compiler"]["flags"],
                         self.profile["flags"] + self.profile["common_flags"])
        for source, checksum in self.profile["header_arch_review"]["file_hashes"].items():
            self.assertEqual(evidence["header_hashes"][source], checksum)
        self.assertEqual(evidence["runtime"]["status"], "unavailable")
        for filename, checksum in evidence["build"]["calibration"]["input_hashes"].items():
            self.assertEqual(hashlib.sha256(Path(filename).read_bytes()).hexdigest(), checksum)
        build = ROOT / "build/kernel/um-x86_64-gcc"
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", str(ROOT.parent / "linux")))
        checked = _check_build(self.profile, build, kernel, evidence["compiler"]["path"])
        self.assertEqual(checked["config_sha256"], evidence["build"]["config_sha256"])
        receipt_path, database_path = build / "fragma-build.json", build / "compile_commands.json"
        original_read = Path.read_text
        receipt = json.loads(original_read(receipt_path))
        database = json.loads(original_read(database_path))
        for change in ("missing-subarch", "malformed-command", "duplicate-arch",
                       "duplicate-subarch", "failed-make", "failed-database-command",
                       "x86-code-model", "x86-red-zone", "uml-macro-undefined",
                       "uml-macro-redefined", "pie-override"):
            altered_receipt, altered_database = copy.deepcopy(receipt), copy.deepcopy(database)
            if change == "missing-subarch":
                altered_receipt["commands"][0]["argv"].remove("SUBARCH=x86_64")
            elif change == "malformed-command":
                altered_receipt["commands"][0]["argv"] = []
            elif change in ("duplicate-arch", "duplicate-subarch"):
                altered_receipt["commands"][0]["argv"].append(
                    "ARCH=x86" if change == "duplicate-arch" else "SUBARCH=i386")
            elif change in ("failed-make", "failed-database-command"):
                altered_receipt["commands"][0 if change == "failed-make" else 2]["returncode"] = 1
            else:
                for entry in altered_database:
                    if entry["file"].endswith("/lib/string.c"):
                        args = entry.get("arguments") or shlex.split(entry["command"])
                        if change == "x86-code-model":
                            args = ["-mcmodel=kernel" if arg == "-mcmodel=large" else arg
                                    for arg in args]
                        elif change == "x86-red-zone":
                            args.append("-mno-red-zone")
                        else:
                            args.extend({"uml-macro-undefined": ["-U", "__arch_um__"],
                                         "uml-macro-redefined": ["-D__arch_um__=0"],
                                         "pie-override": ["-fPIE"]}[change])
                        entry["arguments"] = args

            def read_altered(instance, *args, **kwargs):
                if instance == receipt_path:
                    return json.dumps(altered_receipt)
                if instance == database_path:
                    return json.dumps(altered_database)
                return original_read(instance, *args, **kwargs)

            with self.subTest(change=change), patch.object(Path, "read_text", read_altered):
                with self.assertRaises(ProfileError):
                    _check_build(self.profile, build, kernel, evidence["compiler"]["path"])


if __name__ == "__main__":
    unittest.main()
