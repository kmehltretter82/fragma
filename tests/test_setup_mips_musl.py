"""Inert unit checks for the offline MIPS musl sysroot provisioner."""
from __future__ import annotations

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import importlib.util


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "setup_mips_musl", ROOT / "profiles/setup_mips_musl.py"
)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


def archive(*members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as output:
        root = tarfile.TarInfo(setup.ARCHIVE_ROOT)
        root.type = tarfile.DIRTYPE
        output.addfile(root)
        for name, kind, data in members:
            row = tarfile.TarInfo(name)
            row.type = kind
            row.size = len(data)
            output.addfile(row, io.BytesIO(data) if data else None)
    return stream.getvalue()


class MipsMuslSetupTests(unittest.TestCase):
    def test_limits_are_exact_and_source_derived(self):
        text = "\n".join(f"#define {name} {value}"
                         for name, value in setup.LIMIT_VALUES.items())
        values = setup.limits_values(text)
        self.assertEqual(values, setup.LIMIT_VALUES)
        overlay = setup.overlay_bytes(values).decode()
        self.assertIn("#include_next <limits.h>", overlay)
        self.assertNotIn("__STDC_HOSTED__", overlay)
        for name, value in values.items():
            self.assertIn(f"#define {name} {value}\n", overlay)

    def test_limits_reject_missing_duplicate_expression_and_drift(self):
        base = "#define PATH_MAX 4096\n#define TTY_NAME_MAX 32\n#define HOST_NAME_MAX 255\n"
        cases = (
            base.replace("#define PATH_MAX 4096\n", ""),
            base + "#define PATH_MAX 4096\n",
            base.replace("PATH_MAX 4096", "PATH_MAX (4096)"),
            base.replace("HOST_NAME_MAX 255", "HOST_NAME_MAX 256"),
        )
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(setup.SetupError):
                    setup.limits_values(text)

    def test_archive_inventory_rejects_traversal_and_links(self):
        traversal = archive((setup.ARCHIVE_ROOT + "/../escape", tarfile.REGTYPE, b"x"))
        with self.assertRaisesRegex(setup.SetupError, "invalid archive path"):
            setup.archive_inventory(traversal)
        linked = archive((setup.ARCHIVE_ROOT + "/link", tarfile.SYMTYPE, b""))
        with self.assertRaisesRegex(setup.SetupError, "links and special"):
            setup.archive_inventory(linked)

    def test_archive_inventory_accepts_regular_bounded_members(self):
        value = archive((setup.ARCHIVE_ROOT + "/COPYRIGHT", tarfile.REGTYPE, b"license"))
        rows = setup.archive_inventory(value)
        self.assertEqual(rows[-1], {
            "path": setup.ARCHIVE_ROOT + "/COPYRIGHT",
            "kind": "file",
            "size": 7,
        })

    def test_setup_refuses_an_existing_output_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "archive.tar.gz"
            archive_path.write_bytes(b"not the pinned archive")
            output = root / "output"
            output.mkdir()
            with self.assertRaises(setup.SetupError):
                setup.setup(archive_path, output)
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
