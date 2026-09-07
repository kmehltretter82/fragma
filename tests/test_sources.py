"""Safety checks for pinned source materialization."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from fragma.sources import SourceError, check_snapshot_files, snapshot


class SourceTests(unittest.TestCase):
    def test_snapshot_checks_consumed_content_and_preserves_checkout(self):
        with tempfile.TemporaryDirectory(prefix="fragma source tests ") as temporary:
            root = Path(temporary)
            tree = root / "repo"
            tree.mkdir()
            subprocess.run(["git", "init", "-q", str(tree)], check=True)
            (tree / "input.h").write_text("#define VALUE 1\n")
            subprocess.run(["git", "-C", str(tree), "add", "input.h"], check=True)
            subprocess.run(["git", "-C", str(tree), "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "commit",
                            "-qm", "fixture"], check=True)
            (tree / "input.h").write_text("#define VALUE 2\n")
            dest = root / "snapshot"
            record = snapshot(tree, "HEAD", dest)
            self.assertEqual((dest / "input.h").read_text(), "#define VALUE 1\n")
            self.assertEqual((tree / "input.h").read_text(), "#define VALUE 2\n")
            self.assertTrue(check_snapshot_files(tree, record["revision"], dest,
                                                 [dest / "input.h"])[0]["passed"])
            (dest / "input.h").write_text("changed\n")
            self.assertFalse(check_snapshot_files(tree, record["revision"], dest,
                                                  [dest / "input.h"])[0]["passed"])
            with self.assertRaises(SourceError):
                snapshot(tree, "HEAD", dest)
            with self.assertRaises(SourceError):
                check_snapshot_files(tree, "HEAD", dest, [tree / "input.h"])


if __name__ == "__main__":
    unittest.main()
