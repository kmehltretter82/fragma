"""Command-line default paths remain identical to retained snapshot naming."""

from contextlib import redirect_stdout
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma.__main__ import main


ROOT = Path(__file__).resolve().parents[1]
REVISION = "b9b3e33b70b71e516930117e21de3ad2a7723747"


class MainCliTests(unittest.TestCase):
    def test_prepare_uses_the_thirteen_hex_default_snapshot(self):
        profile = {"id": "inert-profile"}
        with patch("fragma.__main__.suite.load_registry",
                   return_value=(REVISION, {}, {})), \
                patch("fragma.__main__.profiles.load_profiles",
                      return_value={profile["id"]: profile}), \
                patch("fragma.__main__.toolchain.prepare_environment",
                      return_value={}), \
                patch("fragma.__main__.build.prepare_build",
                      return_value={"status": "prepared"}) as prepare, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(main(["prepare", "--profile", profile["id"]]), 0)
        self.assertEqual(prepare.call_args.args[1],
                         ROOT / "build/sources/linux-b9b3e33b70b71")

    def test_arm32_cache_command_dispatches_explicit_evidence_inputs(self):
        kernel = ROOT.parent / "linux"
        output = ROOT / "build/test-arm32-cache-cli"
        with patch("fragma.__main__.arm32_cache_mthread.run",
                   return_value={"accepted": True}) as run, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(main([
                "arm32-cache-mthread",
                "--kernel", str(kernel),
                "--output", str(output),
                "--timeout", "37",
            ]), 0)
        run.assert_called_once_with(ROOT, kernel, output, 37)


if __name__ == "__main__":
    unittest.main()
