import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_setup", ROOT / "toolchain/setup_runtime.py")
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)


class RuntimeSetupTests(unittest.TestCase):
    def test_plan_is_read_only_and_keeps_optional_lock_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary) / "new-runtime"
            value = SETUP.plan(prefix)
            self.assertEqual(value["mode"], "plan")
            self.assertEqual(value["lock"]["artifact"]["package"], "qemu-user")
            self.assertFalse(prefix.exists())

    def test_existing_prefix_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = SETUP.plan(Path(temporary))
            with self.assertRaisesRegex(ValueError, "already exists"):
                SETUP.apply(value)

    def test_apply_requires_explicit_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = SETUP.plan(Path(temporary) / "new")
            with self.assertRaisesRegex(ValueError, "downloaded"):
                SETUP.apply(value)

    def test_archive_bytes_and_size_are_both_locked(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "package.deb"
            path.write_bytes(b"fixture")
            record = {"size": 7, "sha256": hashlib.sha256(b"fixture").hexdigest()}
            SETUP.check_archive(path, record)
            for changed in ({**record, "size": 8}, {**record, "sha256": "0" * 64}, {**record, "size": True}):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    SETUP.check_archive(path, changed)

    def test_broad_or_symlink_prefix_is_rejected(self):
        for path in (ROOT, Path.home(), Path("/")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                SETUP.plan(path)
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "link"
            link.symlink_to(Path(temporary) / "missing")
            with self.assertRaises(ValueError):
                SETUP.plan(link)


if __name__ == "__main__":
    unittest.main()
