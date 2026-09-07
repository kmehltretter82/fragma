from pathlib import Path
import tempfile
import unittest

from fragma import rv32_zeropad


def log(*, status: str, case_status: str, failures: str = "") -> str:
    return f"""Boot HART Base ISA          : rv32imafdch
[    0.000000] Linux version 7.3.0-rc2-00001-g0123456789ab (builder) gcc
[    0.000000] Kernel command line: console=ttyS0 test
{failures}[    1.000000]     {case_status} 1 riscv_load_unaligned_zeropad_guard_test
[    1.100000] {status} 1 riscv-load-unaligned-zeropad
[    1.200000] Kernel panic - not syncing: VFS: Unable to mount root fs
"""


class RV32ZeropadTests(unittest.TestCase):
    def test_config_parser_tracks_assignments_and_disabled_symbols(self):
        value = rv32_zeropad.parse_config(
            "CONFIG_32BIT=y\n# CONFIG_64BIT is not set\nCONFIG_NUMBER=17\n"
        )
        self.assertEqual(value, {
            "CONFIG_32BIT": "y", "CONFIG_64BIT": "n", "CONFIG_NUMBER": "17"
        })

    def test_log_parser_preserves_wrong_decimal_and_hex_values(self):
        failures = """[    0.900000] # test: EXPECTATION FAILED at x.c:1
[    0.900000] Expected got == expected, but
[    0.900000]     got == 42405 (0xa5a5)
[    0.900000]     expected == 17459 (0x4433)
[    0.900000] remaining bytes: 2
"""
        value = rv32_zeropad.parse_kunit_log(
            log(status="not ok", case_status="not ok", failures=failures)
        )
        self.assertEqual(value["failures"]["2"], {
            "got": 42405, "got_hex": "0xa5a5",
            "expected": 17459, "expected_hex": "0x4433",
        })
        self.assertEqual(value["suite_status"], "not ok")
        self.assertTrue(value["rootfs_panic_after_test"])

    def test_log_parser_does_not_accept_not_ok_as_ok(self):
        failed = rv32_zeropad.parse_kunit_log(
            log(status="not ok", case_status="not ok")
        )
        passed = rv32_zeropad.parse_kunit_log(log(status="ok", case_status="ok"))
        self.assertEqual(failed["suite_status"], "not ok")
        self.assertEqual(passed["suite_status"], "ok")

    def test_log_parser_rejects_inconsistent_number_spellings(self):
        failures = """[    0.900000] EXPECTATION FAILED
[    0.900000] got == 2 (0x3)
[    0.900000] expected == 1 (0x1)
[    0.900000] remaining bytes: 1
"""
        with self.assertRaisesRegex(rv32_zeropad.RV32ZeropadError, "disagree"):
            rv32_zeropad.parse_kunit_log(
                log(status="not ok", case_status="not ok", failures=failures)
            )

    def test_elf_parser_distinguishes_32_and_64_bit_riscv(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "object"
            header = bytearray(20)
            header[:7] = b"\x7fELF\x01\x01\x01"
            header[18:20] = (243).to_bytes(2, "little")
            path.write_bytes(header)
            self.assertEqual(rv32_zeropad.parse_elf(path), {
                "class_bits": 32, "byte_order": "little", "machine": 243
            })
            header[4] = 2
            path.write_bytes(header)
            self.assertEqual(rv32_zeropad.parse_elf(path)["class_bits"], 64)

    def test_existing_audit_output_is_never_overwritten(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(rv32_zeropad.RV32ZeropadError,
                                        "already exists"):
                rv32_zeropad.audit(root, Path(temporary))


if __name__ == "__main__":
    unittest.main()
