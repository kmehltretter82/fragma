"""Offline Hexagon header setup gates with synthetic data and mocked processes.

Small authenticated archives replace the exact production PIN only inside each
test. No compiler, network, Git, make recipe or source script is executed.
"""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hexagon_musl_setup", ROOT / "profiles/setup_hexagon_musl.py")
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git_object(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def git_tree(files):
    """Independent fixture encoding, including Git's directory sort suffix."""
    root = {}
    for path, (mode, data) in files.items():
        parts = path.split("/")
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = (mode, data)

    def encode(node):
        payload = bytearray()
        for name, value in sorted(node.items(), key=lambda item: item[0].encode() +
                                  (b"/" if isinstance(item[1], dict) else b"")):
            directory = isinstance(value, dict)
            mode = b"40000" if directory else b"100755" if value[0] & 0o111 else b"100644"
            oid = encode(value) if directory else git_object("blob", value[1])
            payload.extend(mode + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        return git_object("tree", bytes(payload))

    return encode(root)


class HexagonMuslSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fragma-hexagon-headers-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "fixture.tar.gz"
        self.commit = self.root / "fixture.commit"
        self.archive_root = "musl-fixture"
        self.files = {
            "COPYRIGHT": (0o644, b"inert fixture copyright\n"),
            "Makefile": (0o644, b"# inert recipe identity, never executed\n"),
            "a.c": (0o644, b"/* fixture Git directory ordering */\n"),
            "a/value.h": (0o644, b"/* fixture nested value */\n"),
            "include/stdio.h": (0o644, b"/* inert generic stdio header */\n"),
            "include/stddef.h": (0o644, b"/* inert generic stddef header */\n"),
            "include/sys/fixture.h": (0o644, b"/* inert nested public header */\n"),
            "include/alltypes.h.in": (0o644, b"STRUCT fixture_record { int value; };\n"
                                     b"UNION fixture_union { int value; };\n/* unchanged fixture comment */\n"),
            "arch/generic/bits/generic.h": (0o644, b"/* inert generic fallback header */\n"),
            "arch/generic/bits/fixture.h": (0o644, b"/* this generic header is overridden */\n"),
            "arch/hexagon/bits/alltypes.h.in": (0o644, b"TYPEDEF unsigned int fixture_size_t;\n"),
            "arch/hexagon/bits/syscall.h.in": (0o644, b"#define __NR_fixture 0\n"),
            "arch/hexagon/bits/fixture.h": (0o644, b"/* inert architecture header */\n"),
            "tools/install.sh": (0o755, b"# inert executable identity, never run\n"),
            "tools/mkalltypes.sed": (0o644, b"# inert generator identity, never run\n"),
        }
        self.directories = {self.archive_root}
        for name in self.files:
            self.directories.update(self.archive_root + "/" + parent.as_posix()
                                    for parent in PurePosixPath(name).parents if parent.as_posix() != ".")
        self.entries = [(name, tarfile.DIRTYPE, 0o775, b"", "") for name in sorted(self.directories)]
        self.entries += [(self.archive_root + "/" + name, tarfile.REGTYPE,
                          0o775 if mode & 0o111 else 0o664, data, "")
                         for name, (mode, data) in sorted(self.files.items())]
        self.write_archive(self.entries)
        self.tree = git_tree(self.files)
        raw = ("tree " + self.tree + "\nauthor Fixture <fixture@example.invalid> 0 +0000\n"
               "committer Fixture <fixture@example.invalid> 0 +0000\n\nInert fixture source\n").encode()
        self.commit.write_bytes(raw)
        self.pin = {"commit_sha1": git_object("commit", raw), "tree_sha1": self.tree,
                    "archive_sha256": sha256(self.archive), "archive_root": self.archive_root,
                    "file_count": len(self.files), "directory_count": len(self.directories),
                    "file_bytes": sum(len(data) for mode, data in self.files.values())}
        patcher = patch.object(SETUP, "PIN", self.pin)
        self.addCleanup(patcher.stop)
        patcher.start()
        run = patch.object(SETUP.subprocess, "run", side_effect=AssertionError("unmocked source or tool execution"))
        self.addCleanup(run.stop)
        self.run = run.start()
        popen = patch("subprocess.Popen", side_effect=AssertionError("unmocked process launch"))
        self.addCleanup(popen.stop)
        popen.start()

    def write_archive(self, entries):
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as handle:
            for name, kind, mode, data, link in entries:
                member = tarfile.TarInfo(name)
                member.type, member.mode, member.mtime = kind, mode, 0
                member.linkname = link
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                handle.addfile(member, io.BytesIO(data) if member.size else None)

    def repack(self, entries):
        """Keep source commit/tree fixed while exercising inner archive gates."""
        self.write_archive(entries)
        self.pin["archive_sha256"] = sha256(self.archive)

    def extract(self, name="extracted"):
        output = self.root / name
        receipt = SETUP.extract(self.archive, self.commit, output)
        return output, receipt

    def expected_headers(self):
        # Independently encode this tiny fixture's reviewed copy/generation rules.
        headers = {name[len("include/"):]: data for name, (_, data) in self.files.items()
                   if name.startswith("include/") and name.endswith(".h")}
        for prefix in ("arch/generic/bits/", "arch/hexagon/bits/"):
            headers.update({"bits/" + name[len(prefix):]: data for name, (_, data) in self.files.items()
                            if name.startswith(prefix) and name.endswith(".h")})
        headers["bits/alltypes.h"] = (
            b"#if defined(__NEED_fixture_size_t) && !defined(__DEFINED_fixture_size_t)\n"
            b"typedef unsigned int fixture_size_t;\n#define __DEFINED_fixture_size_t\n#endif\n\n"
            b"#if defined(__NEED_struct_fixture_record) && !defined(__DEFINED_struct_fixture_record)\n"
            b"struct fixture_record { int value; };\n#define __DEFINED_struct_fixture_record\n#endif\n\n"
            b"#if defined(__NEED_union_fixture_union) && !defined(__DEFINED_union_fixture_union)\n"
            b"union fixture_union { int value; };\n#define __DEFINED_union_fixture_union\n#endif\n\n"
            b"/* unchanged fixture comment */\n")
        headers["bits/syscall.h"] = b"#define __NR_fixture 0\n#define SYS_fixture 0\n"
        return headers

    def mock_make(self, command, **kwargs):
        """Produce only inert expected files; never execute the supplied recipe."""
        source = Path(kwargs["cwd"])
        output = source.parent
        headers = self.expected_headers()
        for name in ("bits/alltypes.h", "bits/syscall.h"):
            path = source / "obj/include" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(headers[name])
            path.chmod(0o644)
        for name, data in headers.items():
            path = output / "include" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
        # The real child receives umask0022; a mock runs in this test process,
        # whose inherited umask may be more restrictive.
        for tree in (source / "obj", output / "include"):
            for path in (tree, *tree.rglob("*")):
                if path.is_dir():
                    path.chmod(0o755)
        return subprocess.CompletedProcess(command, 0, "inert mocked header installation\n", "")

    def install(self, name="sysroot"):
        extracted, extraction_receipt = self.extract(name + "-input")
        self.run.side_effect = self.mock_make
        output = self.root / name
        receipt = SETUP.install(extracted, output)
        return extracted, extraction_receipt, output, receipt

    def assert_rejected_archive(self, entries, name):
        self.repack(entries)
        output = self.root / name
        with self.assertRaises(SETUP.SetupError):
            SETUP.extract(self.archive, self.commit, output)
        self.assertFalse(output.exists())
        self.run.assert_not_called()

    def test_extract_authenticates_complete_git_tree_and_canonical_modes(self):
        before = {str(path): sha256(path) for path in (self.archive, self.commit)}
        output, receipt = self.extract()
        self.assertEqual(SETUP.verify_extracted(output), receipt)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(sha256(output / "archive.tar.gz"), before[str(self.archive)])
        self.assertEqual((output / "commit.raw").read_bytes(), self.commit.read_bytes())
        self.assertEqual(json.loads((output / "extraction.json").read_text()), receipt)
        self.assertEqual(receipt["source_identity"], self.pin)
        self.assertEqual(receipt["source_tree_sha1"], self.tree)
        self.assertEqual(receipt["output"], str(output))
        self.assertEqual(receipt["source_path"], str(output / "source"))
        actual_files = {path.relative_to(output / "source").as_posix()
                        for path in (output / "source").rglob("*") if path.is_file()}
        self.assertEqual(actual_files, set(self.files))
        for name, (mode, data) in self.files.items():
            path = output / "source" / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            self.assertEqual(receipt["source_manifest"][name],
                             {"kind": "file", "mode": "100755" if mode == 0o755 else "100644",
                              "permissions": f"{mode:04o}", "size": len(data),
                              "sha256": hashlib.sha256(data).hexdigest(),
                              "blob_sha1": git_object("blob", data)})
        for path in (output / "source").rglob("*"):
            if path.is_dir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
        self.assertEqual({str(path): sha256(path) for path in (self.archive, self.commit)}, before)
        self.run.assert_not_called()

    def test_canonical_archive_modes_keep_identical_git_source_identity(self):
        self.repack([(name, kind, 0o755 if mode & 0o111 else 0o644, data, link)
                     for name, kind, mode, data, link in self.entries])
        output, receipt = self.extract()
        self.assertEqual(SETUP.verify_extracted(output), receipt)
        for name, (mode, data) in self.files.items():
            self.assertEqual((output / "source" / name).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((output / "source" / name).stat().st_mode), mode)
        self.run.assert_not_called()

    def test_archive_or_raw_commit_byte_corruption_rejected_before_output(self):
        original_archive, original_commit = self.archive.read_bytes(), self.commit.read_bytes()
        for index, path in enumerate((self.archive, self.commit)):
            self.archive.write_bytes(original_archive)
            self.commit.write_bytes(original_commit)
            path.write_bytes(path.read_bytes() + b"corruption")
            output = self.root / f"corrupted-{index}"
            with self.subTest(path=path.name), self.assertRaises(SETUP.SetupError):
                SETUP.extract(self.archive, self.commit, output)
            self.assertFalse(output.exists())
        self.run.assert_not_called()

    def test_commit_object_tree_must_equal_pinned_source_tree(self):
        raw = self.commit.read_bytes().replace(self.tree.encode(), b"f" * 40, 1)
        self.commit.write_bytes(raw)
        self.pin["commit_sha1"] = git_object("commit", raw)
        with self.assertRaises(SETUP.SetupError):
            self.extract()
        self.assertFalse((self.root / "extracted").exists())
        self.run.assert_not_called()

    def test_modified_blob_with_reauthenticated_archive_fails_git_tree_check(self):
        entries = list(self.entries)
        index = next(i for i, row in enumerate(entries) if row[0].endswith("/a.c"))
        name, kind, mode, data, link = entries[index]
        entries[index] = (name, kind, mode, b"X" + data[1:], link)
        self.assert_rejected_archive(entries, "wrong-blob")

    def test_changed_executable_bit_fails_git_tree_authentication(self):
        entries = [(name, kind, 0o775 if name.endswith("/a.c") else mode, data, link)
                   for name, kind, mode, data, link in self.entries]
        self.assert_rejected_archive(entries, "wrong-git-mode")

    def test_missing_or_extra_source_files_are_rejected(self):
        missing = [row for row in self.entries if not row[0].endswith("/a.c")]
        extra = [*self.entries, (self.archive_root + "/extra.h", tarfile.REGTYPE, 0o664, b"extra\n", "")]
        for index, entries in enumerate((missing, extra)):
            with self.subTest(index=index):
                self.assert_rejected_archive(entries, f"wrong-file-set-{index}")

    def test_duplicate_members_and_incomplete_directory_inventory_are_rejected(self):
        cases = ([*self.entries, self.entries[-1]], [*self.entries, self.entries[0]],
                 [row for row in self.entries if row[0] != self.archive_root + "/a"],
                 [*self.entries, (self.archive_root + "/empty-extra", tarfile.DIRTYPE, 0o775, b"", "")])
        for index, entries in enumerate(cases):
            with self.subTest(index=index):
                self.assert_rejected_archive(entries, f"wrong-directory-set-{index}")

    def test_absolute_parent_aliased_and_wrong_root_paths_are_rejected(self):
        names = ("/absolute.h", "../parent.h", self.archive_root + "/../parent.h",
                 self.archive_root + "//alias.h", self.archive_root + "/./alias.h",
                 self.archive_root + "/dir/../alias.h", "another-root/extra.h")
        for index, name in enumerate(names):
            with self.subTest(name=name):
                self.assert_rejected_archive([*self.entries, (name, tarfile.REGTYPE, 0o664, b"fixture\n", "")],
                                             f"invalid-path-{index}")

    def test_whitespace_and_make_shell_metacharacter_paths_are_rejected(self):
        names = ("space name.h", "tab\tname.h", "line\nname.h", "dollar$name.h", "semi;name.h",
                 "star*name.h", "bracket[name.h", "back`tick.h", "escape\\name.h")
        original_commit = self.commit.read_bytes()
        for index, name in enumerate(names):
            # Authenticate this entirely synthetic renamed tree so an inventory
            # mismatch cannot hide a missing member-name safety check.
            renamed = dict(self.files)
            renamed[name] = renamed.pop("a.c")
            renamed_tree = git_tree(renamed)
            raw = original_commit.replace(self.tree.encode(), renamed_tree.encode(), 1)
            self.commit.write_bytes(raw)
            self.pin.update(commit_sha1=git_object("commit", raw), tree_sha1=renamed_tree)
            entries = [(self.archive_root + "/" + name if path == self.archive_root + "/a.c" else path,
                        kind, mode, data, link) for path, kind, mode, data, link in self.entries]
            with self.subTest(name=name):
                self.assert_rejected_archive(entries, f"unsafe-path-{index}")

    def test_links_devices_fifos_and_unsupported_members_are_rejected(self):
        for index, kind in enumerate((tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                                      tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.CONTTYPE)):
            with self.subTest(kind=kind):
                self.assert_rejected_archive([*self.entries, (self.archive_root + "/unsafe",
                    kind, 0o644, b"", self.archive_root + "/a.c")], f"special-member-{index}")

    def test_nonstandard_file_and_directory_modes_are_rejected(self):
        for index, (kind, mode) in enumerate(((tarfile.REGTYPE, 0o600), (tarfile.REGTYPE, 0o777),
                                            (tarfile.REGTYPE, 0o4644), (tarfile.DIRTYPE, 0o700),
                                            (tarfile.DIRTYPE, 0o1775))):
            with self.subTest(kind=kind, mode=oct(mode)):
                entries = [(name, item_kind, mode if item_kind == kind else item_mode, data, link)
                           for name, item_kind, item_mode, data, link in self.entries]
                self.assert_rejected_archive(entries, f"unsupported-mode-{index}")

    def test_input_and_output_symlink_aliases_are_rejected(self):
        archive_alias, commit_alias = self.root / "archive-alias", self.root / "commit-alias"
        archive_alias.symlink_to(self.archive)
        commit_alias.symlink_to(self.commit)
        for index, (archive, commit) in enumerate(((archive_alias, self.commit), (self.archive, commit_alias))):
            with self.subTest(index=index), self.assertRaises(SETUP.SetupError):
                SETUP.extract(archive, commit, self.root / f"aliased-input-{index}")
        parent_alias = self.root / "parent-alias"
        parent_alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(SETUP.SetupError):
            SETUP.extract(self.archive, self.commit, parent_alias / "new-output")
        dangling = self.root / "dangling-output"
        dangling.symlink_to(self.root / "missing-target")
        with self.assertRaises(SETUP.SetupError):
            SETUP.extract(self.archive, self.commit, dangling)
        self.assertFalse((self.root / "new-output").exists())
        self.assertFalse((self.root / "missing-target").exists())
        self.run.assert_not_called()

    def test_existing_output_and_missing_parent_are_not_modified(self):
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "sentinel"
        sentinel.write_text("preserve user evidence\n")
        with self.assertRaises(SETUP.SetupError):
            SETUP.extract(self.archive, self.commit, output)
        with self.assertRaises(SETUP.SetupError):
            SETUP.extract(self.archive, self.commit, self.root / "missing-parent/output")
        self.assertEqual(sentinel.read_text(), "preserve user evidence\n")
        self.assertEqual(list(output.iterdir()), [sentinel])
        self.assertFalse((self.root / "missing-parent").exists())
        self.run.assert_not_called()

    def test_verify_extracted_rejects_missing_changed_extra_and_mode_drift(self):
        def missing_file(source):
            (source / "a.c").unlink()

        def changed_file(source):
            path = source / "a.c"
            path.write_bytes(b"X" + path.read_bytes()[1:])

        def extra_file(source):
            (source / "unexpected.h").write_bytes(b"inert unexpected data\n")

        def extra_directory(source):
            (source / "unexpected-empty").mkdir()

        def changed_file_mode(source):
            (source / "a.c").chmod(0o755)

        def changed_directory_mode(source):
            (source / "a").chmod(0o700)

        def missing_directory(source):
            (source / "a/value.h").unlink()
            (source / "a").rmdir()

        for index, mutate in enumerate((missing_file, changed_file, extra_file, extra_directory,
                                         changed_file_mode, changed_directory_mode, missing_directory)):
            output, _ = self.extract(f"source-drift-{index}")
            mutate(output / "source")
            with self.subTest(mutation=mutate.__name__), self.assertRaises(SETUP.SetupError):
                SETUP.verify_extracted(output)
        self.run.assert_not_called()

    def test_verify_extracted_rejects_retained_input_and_receipt_drift(self):
        mutations = (("archive.tar.gz", b"not an authenticated archive\n"),
                     ("commit.raw", b"not an authenticated commit\n"),
                     ("extraction.json", b"{}\n"), ("extraction.json", b"[]\n"),
                     ("extraction.json", b"not JSON\n"))
        for index, (name, data) in enumerate(mutations):
            output, _ = self.extract(f"retained-drift-{index}")
            (output / name).write_bytes(data)
            with self.subTest(index=index, name=name), self.assertRaises(SETUP.SetupError):
                SETUP.verify_extracted(output)
        output, _ = self.extract("missing-receipt")
        (output / "extraction.json").unlink()
        with self.assertRaises(SETUP.SetupError):
            SETUP.verify_extracted(output)
        self.run.assert_not_called()

    def test_extraction_receipt_authenticates_identity_and_manifest_fields(self):
        fields = (("source_tree_sha1",), ("source_identity", "commit_sha1"),
                  ("archive", "sha256"), ("archive", "absolute_path"),
                  ("commit_raw", "sha256"), ("provider", "sha256"),
                  ("source_manifest", "a.c", "blob_sha1"),
                  ("source_manifest", "a.c", "mode"), ("source_path",), ("output",))
        for index, parts in enumerate(fields):
            output, receipt = self.extract(f"receipt-identity-{index}")
            changed = copy.deepcopy(receipt)
            target = changed
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = "incorrect-identity"
            (output / "extraction.json").write_text(json.dumps(changed))
            with self.subTest(field=parts), self.assertRaises(SETUP.SetupError):
                SETUP.verify_extracted(output)
        self.run.assert_not_called()

    def test_verify_extracted_rejects_source_and_receipt_symlink_aliases(self):
        output, _ = self.extract("source-file-alias")
        original = output / "source/a.c"
        outside = self.root / "aliased-source.c"
        outside.write_bytes(original.read_bytes())
        original.unlink()
        original.symlink_to(outside)
        with self.assertRaises(SETUP.SetupError):
            SETUP.verify_extracted(output)

        output, _ = self.extract("source-directory-alias")
        original = output / "source/a"
        outside = self.root / "aliased-source-directory"
        original.rename(outside)
        original.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SETUP.SetupError):
            SETUP.verify_extracted(output)

        output, _ = self.extract("receipt-alias")
        original = output / "extraction.json"
        outside = self.root / "aliased-receipt.json"
        original.rename(outside)
        original.symlink_to(outside)
        with self.assertRaises(SETUP.SetupError):
            SETUP.verify_extracted(output)
        self.run.assert_not_called()

    def test_verify_extracted_rejects_aliased_root_without_modifying_evidence(self):
        output, receipt = self.extract()
        alias = self.root / "extraction-alias"
        alias.symlink_to(output, target_is_directory=True)
        with self.assertRaises(SETUP.SetupError):
            SETUP.verify_extracted(alias)
        self.assertEqual(SETUP.verify_extracted(output), receipt)
        self.run.assert_not_called()

    def test_install_reauthenticates_extraction_before_output_or_process(self):
        mutations = (("source/a.c", b"changed source\n"),
                     ("archive.tar.gz", b"changed archive\n"),
                     ("commit.raw", b"changed commit\n"),
                     ("extraction.json", b"{}\n"))
        for index, (name, data) in enumerate(mutations):
            extracted, _ = self.extract(f"bad-install-input-{index}")
            (extracted / name).write_bytes(data)
            output = self.root / f"must-not-install-{index}"
            with self.subTest(name=name), self.assertRaises(SETUP.SetupError):
                SETUP.install(extracted, output)
            self.assertFalse(output.exists())
        self.run.assert_not_called()

    def test_install_rejects_existing_output_missing_parent_and_aliases(self):
        extracted, _ = self.extract()
        existing = self.root / "existing-sysroot"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_bytes(b"preserve existing evidence\n")
        alias = self.root / "extracted-alias"
        alias.symlink_to(extracted, target_is_directory=True)
        parent_alias = self.root / "install-parent-alias"
        parent_alias.symlink_to(self.root, target_is_directory=True)
        dangling = self.root / "dangling-sysroot"
        dangling.symlink_to(self.root / "missing-sysroot")
        pairs = ((extracted, existing), (extracted, self.root / "missing-parent/output"),
                 (alias, self.root / "aliased-input-sysroot"),
                 (extracted, parent_alias / "aliased-parent-sysroot"), (extracted, dangling))
        for source, output in pairs:
            with self.subTest(source=source.name, output=str(output)), self.assertRaises(SETUP.SetupError):
                SETUP.install(source, output)
        self.assertEqual(sentinel.read_bytes(), b"preserve existing evidence\n")
        self.assertEqual(list(existing.iterdir()), [sentinel])
        for name in ("missing-parent", "aliased-input-sysroot", "aliased-parent-sysroot", "missing-sysroot"):
            self.assertFalse((self.root / name).exists())
        self.run.assert_not_called()

    def test_install_uses_one_isolated_explicit_make_and_binds_exact_headers(self):
        with patch.dict("os.environ", {"MAKEFLAGS": "host-flags", "MFLAGS": "host-flags",
                                       "CC": "host-compiler", "CFLAGS": "host-flags",
                                       "SHELL": "host-shell", "CPATH": "host-includes"}):
            extracted, extraction_receipt, output, receipt = self.install()
        self.run.assert_called_once()
        args, kwargs = self.run.call_args
        self.assertEqual(args, (["/usr/bin/make", "--no-builtin-rules", "--no-builtin-variables",
                                 "-f", "Makefile", "ARCH=hexagon", "SHELL=/bin/sh",
                                 "prefix=" + str(output), "install-headers"],))
        self.assertEqual(Path(kwargs["cwd"]), output / "source")
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["umask"], 0o022)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 180)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(SETUP.verify_extracted(extracted), extraction_receipt)
        self.assertEqual(SETUP.verify_sysroot(output), receipt)
        self.assertEqual(json.loads((output / "fragma-sysroot.json").read_text()), receipt)
        self.assertEqual(receipt["source_identity"], self.pin)
        self.assertEqual(receipt["source_manifest"], extraction_receipt["source_manifest"])
        self.assertEqual(receipt["header_sources"]["include/bits/fixture.h"], "arch/hexagon/bits/fixture.h")
        self.assertEqual(receipt["header_sources"]["include/bits/generic.h"], "arch/generic/bits/generic.h")
        self.assertEqual(receipt["header_sources"]["include/bits/alltypes.h"], "obj/include/bits/alltypes.h")
        self.assertEqual(receipt["command"], json.loads((output / "install-command.json").read_text()))
        self.assertEqual(receipt["command_receipt"]["sha256"], sha256(output / "install-command.json"))
        headers = self.expected_headers()
        self.assertEqual({path.relative_to(output / "include").as_posix()
                          for path in (output / "include").rglob("*") if path.is_file()}, set(headers))
        for name, data in headers.items():
            self.assertEqual((output / "include" / name).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((output / "include" / name).stat().st_mode), 0o644)
        for name, (mode, data) in self.files.items():
            self.assertEqual((output / "source" / name).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((output / "source" / name).stat().st_mode), mode)
        for name in ("bits/alltypes.h", "bits/syscall.h"):
            self.assertEqual((output / "source/obj/include" / name).read_bytes(), headers[name])
        self.run.assert_called_once()

    def test_install_rejects_objects_unexpected_files_and_unbound_generated_headers(self):
        def extra_object(output):
            (output / "source/fixture.o").write_bytes(b"inert object-shaped unexpected data\n")

        def unexpected_output(output):
            (output / "unexpected.txt").write_bytes(b"inert unreviewed output\n")

        def extra_header(output):
            (output / "include/extra.h").write_bytes(b"inert unreviewed header\n")

        def missing_header(output):
            (output / "include/stdio.h").unlink()

        def source_changed(output):
            (output / "source/a.c").write_bytes(b"inert changed source\n")

        def generated_changed(output):
            (output / "source/obj/include/bits/alltypes.h").write_bytes(b"inert wrong generated content\n")

        def matching_but_wrong_generated(output):
            for name in ("source/obj/include/bits/syscall.h", "include/bits/syscall.h"):
                (output / name).write_bytes(b"inert same wrong generated content\n")

        def header_mode_changed(output):
            (output / "include/stdio.h").chmod(0o755)

        def installed_symlink(output):
            path = output / "include/stdio.h"
            path.unlink()
            path.symlink_to(output / "source/include/stdio.h")

        mutations = (extra_object, unexpected_output, extra_header, missing_header, source_changed,
                     generated_changed, matching_but_wrong_generated, header_mode_changed, installed_symlink)
        for index, mutate in enumerate(mutations):
            extracted, _ = self.extract(f"invalid-make-input-{index}")
            output = self.root / f"invalid-make-output-{index}"

            def make(command, **kwargs):
                result = self.mock_make(command, **kwargs)
                mutate(Path(kwargs["cwd"]).parent)
                return result

            self.run.reset_mock(side_effect=True)
            self.run.side_effect = make
            with self.subTest(mutation=mutate.__name__), self.assertRaises(SETUP.SetupError):
                SETUP.install(extracted, output)
            self.run.assert_called_once()
            self.assertFalse((output / "fragma-sysroot.json").exists())

    def test_failed_make_does_not_publish_a_successful_sysroot(self):
        extracted, extraction_receipt = self.extract()
        self.run.side_effect = None
        self.run.return_value = subprocess.CompletedProcess([], 2, "inert failure output\n", "inert error\n")
        output = self.root / "failed-sysroot"
        with self.assertRaises(SETUP.SetupError):
            SETUP.install(extracted, output)
        self.run.assert_called_once()
        self.assertFalse((output / "fragma-sysroot.json").exists())
        self.assertEqual(SETUP.verify_extracted(extracted), extraction_receipt)
        with self.assertRaises(SETUP.SetupError):
            SETUP.verify_sysroot(output)
        self.run.assert_called_once()

    def test_timeout_and_launch_error_retain_diagnostics_without_success_receipt(self):
        cases = (subprocess.TimeoutExpired(["inert-fixture"], 180, output=b"partial mock output\n",
                                          stderr=b"mock timeout diagnostic\n"),
                 OSError("inert launch failure"))
        for index, error in enumerate(cases):
            extracted, extraction_receipt = self.extract(f"failed-launch-input-{index}")
            output = self.root / f"failed-launch-{index}"
            self.run.reset_mock()
            self.run.side_effect = error
            with self.subTest(error=type(error).__name__), self.assertRaises(SETUP.SetupError):
                SETUP.install(extracted, output)
            self.run.assert_called_once()
            command = json.loads((output / "install-command.json").read_text())
            self.assertIsNone(command["returncode"])
            self.assertTrue(command["error"])
            self.assertEqual((output / "install.stdout").read_bytes(),
                             b"partial mock output\n" if index == 0 else b"")
            self.assertEqual((output / "install.stderr").read_bytes(),
                             b"mock timeout diagnostic\n" if index == 0 else b"")
            self.assertFalse((output / "fragma-sysroot.json").exists())
            self.assertEqual(SETUP.verify_extracted(extracted), extraction_receipt)
            self.run.assert_called_once()

    def test_verify_sysroot_rejects_source_generated_header_and_receipt_drift(self):
        mutations = (("source/a.c", b"changed source\n"),
                     ("source/obj/include/bits/alltypes.h", b"changed generated header\n"),
                     ("include/bits/alltypes.h", b"changed installed header\n"),
                     ("archive.tar.gz", b"changed archive\n"), ("commit.raw", b"changed commit\n"),
                     ("install.stdout", b"changed command log\n"),
                     ("install.stderr", b"changed command diagnostic\n"),
                     ("install-command.json", b"{}\n"), ("extraction.json", b"{}\n"),
                     ("fragma-sysroot.json", b"{}\n"), ("fragma-sysroot.json", b"[]\n"),
                     ("fragma-sysroot.json", b"not JSON\n"))
        for index, (name, data) in enumerate(mutations):
            _, _, output, _ = self.install(f"verify-drift-{index}")
            (output / name).write_bytes(data)
            self.run.reset_mock()
            with self.subTest(name=name, index=index), self.assertRaises(SETUP.SetupError):
                SETUP.verify_sysroot(output)
            self.run.assert_not_called()

    def test_sysroot_receipt_binds_command_tools_headers_and_source_identity(self):
        fields = (("source_identity", "tree_sha1"),
                  ("generated_manifest", "obj/include/bits/alltypes.h", "sha256"),
                  ("header_manifest", "include/bits/alltypes.h", "sha256"),
                  ("header_sources", "include/bits/fixture.h"),
                  ("command", "environment", "PATH"), ("command", "tools_before", 0, "sha256"),
                  ("command", "cwd"), ("command", "argv", 0),
                  ("command_receipt", "sha256"), ("extraction_receipt", "sha256"),
                  ("provider", "sha256"), ("output",))
        for index, parts in enumerate(fields):
            _, _, output, receipt = self.install(f"sysroot-identity-{index}")
            changed = copy.deepcopy(receipt)
            target = changed
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = "incorrect-identity"
            (output / "fragma-sysroot.json").write_text(json.dumps(changed))
            self.run.reset_mock()
            with self.subTest(field=parts), self.assertRaises(SETUP.SetupError):
                SETUP.verify_sysroot(output)
            self.run.assert_not_called()

    def test_verify_sysroot_rejects_extra_directory_mode_and_symlink_drift(self):
        def extra_directory(output):
            (output / "include/unexpected-empty").mkdir()

        def changed_mode(output):
            (output / "include/stdio.h").chmod(0o755)

        def aliased_header(output):
            path = output / "include/stdio.h"
            path.unlink()
            path.symlink_to(output / "source/include/stdio.h")

        def aliased_receipt(output):
            path = output / "fragma-sysroot.json"
            outside = self.root / "outside-sysroot-receipt.json"
            path.rename(outside)
            path.symlink_to(outside)

        for index, mutate in enumerate((extra_directory, changed_mode, aliased_header, aliased_receipt)):
            _, _, output, _ = self.install(f"verify-inventory-{index}")
            mutate(output)
            self.run.reset_mock()
            with self.subTest(mutation=mutate.__name__), self.assertRaises(SETUP.SetupError):
                SETUP.verify_sysroot(output)
            self.run.assert_not_called()

    def test_cli_dispatches_only_the_explicit_offline_stage(self):
        output = self.root / "cli-output"
        extraction = {"status": "fixture-extracted", "output": str(output),
                      "source_identity": {"file_count": len(self.files)}}
        with patch.object(SETUP, "extract", return_value=extraction) as extract, \
                patch.object(SETUP, "install") as install, redirect_stdout(io.StringIO()) as stdout:
            SETUP.main(["--extract-only", "--archive", str(self.archive), "--commit-raw", str(self.commit),
                        "--output", str(output)])
        extract.assert_called_once_with(self.archive, self.commit, output)
        install.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "fixture-extracted", "output": str(output),
                         "source_files": len(self.files), "headers": 0,
                         "receipt": str(output / "extraction.json")})
        extracted = self.root / "cli-extracted"
        installed = {**extraction, "status": "fixture-installed", "header_manifest": {"include/fixture.h": {}}}
        with patch.object(SETUP, "extract") as extract, \
                patch.object(SETUP, "install", return_value=installed) as install, \
                redirect_stdout(io.StringIO()) as stdout:
            SETUP.main(["--install-headers", "--extracted", str(extracted), "--output", str(output)])
        extract.assert_not_called()
        install.assert_called_once_with(extracted, output)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "fixture-installed", "output": str(output),
                         "source_files": len(self.files), "headers": 1,
                         "receipt": str(output / "fragma-sysroot.json")})
        self.assertFalse(output.exists())
        self.run.assert_not_called()

    def test_cli_rejects_unknown_missing_or_conflicting_stage_options(self):
        output = ["--output", str(self.root / "invalid-cli-output")]
        cases = ([], ["--extract-only"], ["--install-headers"],
                 ["--extract-only", "--install-headers"], ["--unknown-mode"],
                 ["--extract-only", "--archive", str(self.archive)],
                 ["--extract-only", "--archive", str(self.archive), "--commit-raw", str(self.commit),
                  "--extracted", str(self.root / "unwanted")],
                 ["--install-headers", "--extracted", str(self.root / "unused"),
                  "--archive", str(self.archive)],
                 ["--install-headers", "--extracted", str(self.root / "unused"),
                  "--commit-raw", str(self.commit)])
        for args in cases:
            with self.subTest(args=args), patch.object(SETUP, "extract") as extract, \
                    patch.object(SETUP, "install") as install, redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as failure:
                SETUP.main([*args, *output])
            self.assertEqual(failure.exception.code, 2)
            extract.assert_not_called()
            install.assert_not_called()
        self.assertFalse((self.root / "invalid-cli-output").exists())
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
