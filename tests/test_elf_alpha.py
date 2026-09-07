"""Alpha ELF metadata boundaries using data only; no object is executed.

The retained positive is read only and remains an old failed calibration
receipt. Container metadata recognition does not upgrade that receipt or prove
instructions, linker behavior, runtime reachability, or architecture support.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from fragma import elf, frontend_policy, inputs
from tests.test_elf import calibration_elf, fixture, header_change, model
from tests.test_elf import section_change, symbol_change


EM_ALPHA = 0x9026
ALPHA_METADATA = (0x80, 0x88)
CALIBRATION_NAME = "fragma_common24_compiler_calibration"
AUXILIARY_NAME = "fragma_alpha_aux_funcx"


def alpha_object(*, other=0, bits=64, little=True, machine=EM_ALPHA):
    """Synthetic bounded object bytes, not Alpha instructions or evidence."""
    data = calibration_elf(bits=bits, little_endian=little, machine=machine)
    return symbol_change(data, 1, 4, other)


def observe(data, *, bits=64, little=True, machine=EM_ALPHA):
    return elf.calibration_object(data, model(bits=bits, little=little),
                                  fixture(bits=bits, little=little, machine=machine))


def forbidden(*args, **kwargs):
    raise AssertionError("compiler/analyzer/native/subprocess transport forbidden")


def expected_metadata(name, other, *, binding="global", section=1):
    return {"name": name, "other": other,
            "meaning": "STO_ALPHA_NOPV" if other == 0x80 else "STO_ALPHA_STD_GPLOAD",
            "binding": binding, "section_index": section, "header_flags": 0}


def auxiliary_object(*, other=0x80, binding="global"):
    """Data-only extra symbol, borrowing space from the bounded test builder."""
    data = calibration_elf(bits=64, machine=EM_ALPHA, arm_unwind=True)
    old_name = b"__aeabi_unwind_cpp_pr0"
    assert len(old_name) == len(AUXILIARY_NAME.encode())
    data = data.replace(old_name, AUXILIARY_NAME.encode())
    # Ordinary nonallocated metadata and an empty relocation table: this
    # synthetic object claims no Alpha/ARM unwind or relocation semantics.
    for field, value in ((1, 1), (2, 0), (6, 0)):
        data = section_change(data, 4, field, value)
    data = section_change(data, 5, 5, 0)
    obj = elf.parse_relocatable(data, model(bits=64))
    strings = obj.section_bytes(2)
    required_name = strings.index(CALIBRATION_NAME.encode())
    auxiliary_name = strings.index(AUXILIARY_NAME.encode())
    auxiliary_index, required_index = (1, 2) if binding == "local" else (2, 1)
    data = section_change(data, 3, 7, 2 if binding == "local" else 1)
    for index, fields in ((required_index, (required_name, 0, 4, 0x12, 0, 1)),
                          (auxiliary_index, (auxiliary_name, 0, 4, 0x02 if binding == "local" else 0x12, other, 1))):
        for field, value in enumerate(fields):
            data = symbol_change(data, index, field, value)
    return data, auxiliary_index


class AlphaELFRejectionTests(unittest.TestCase):
    def setUp(self):
        for patcher in (patch.object(subprocess, "Popen", side_effect=forbidden),
                        patch.object(subprocess, "run", side_effect=forbidden),
                        patch.object(inputs, "run_recorded", side_effect=forbidden)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_unmarked_alpha_object_keeps_existing_container_behavior(self):
        result = observe(alpha_object())
        self.assertEqual(result["machine_observed"], EM_ALPHA)
        self.assertEqual(result["class"], 64)
        self.assertEqual(result["byte_order"], "little")
        self.assertEqual(result["definition"]["size"], 4)
        self.assertEqual(result["undefined_metadata"], [])

    def test_alpha_metadata_never_leaks_to_another_machine(self):
        for machine in (0, 4, 20, 21, 40, 42, 62, 183, 243, 0xffff):
            # The old general container reader can observe an unmarked
            # self-consistent machine. This new exception must be Alpha-only.
            if machine:
                observe(alpha_object(machine=machine), machine=machine)
            for other in ALPHA_METADATA:
                with self.subTest(machine=machine, other=other), self.assertRaises(elf.ELFError):
                    observe(alpha_object(machine=machine, other=other), machine=machine)

    def test_alpha_metadata_requires_elf64_little_endian(self):
        for bits, little in ((32, True), (32, False), (64, False)):
            observe(alpha_object(bits=bits, little=little), bits=bits, little=little)
            for other in ALPHA_METADATA:
                with self.subTest(bits=bits, little=little, other=other), self.assertRaises(elf.ELFError):
                    observe(alpha_object(bits=bits, little=little, other=other), bits=bits, little=little)

    def test_every_other_marked_calibration_value_still_fails(self):
        # Includes visibility mixtures such as 0x81/0x89 and values whose
        # masked bits resemble a known Alpha encoding. No masking is allowed.
        for other in range(1, 256):
            if other in ALPHA_METADATA:
                continue
            with self.subTest(other=other), self.assertRaises(elf.ELFError):
                observe(alpha_object(other=other))

    def test_marked_calibration_is_still_global_function_only(self):
        for other in ALPHA_METADATA:
            for info in (0x02, 0x22, 0x32, 0xA2, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x1f):
                with self.subTest(other=other, info=info), self.assertRaises(elf.ELFError):
                    observe(symbol_change(alpha_object(other=other), 1, 3, info))

    def test_marked_function_must_be_defined_nonempty_and_bounded(self):
        for other in ALPHA_METADATA:
            data = alpha_object(other=other)
            for field, value in ((1, 4), (2, 0), (2, 5), (5, 0), (5, 99),
                                 (5, 0xfff1), (5, 0xfff2), (5, 0xffff)):
                with self.subTest(other=other, field=field, value=value), self.assertRaises(elf.ELFError):
                    observe(symbol_change(data, 1, field, value))
            undefined = symbol_change(symbol_change(data, 1, 2, 0), 1, 5, 0)
            with self.assertRaises(elf.ELFError):
                observe(undefined)

    def test_marked_function_needs_allocated_executable_file_backing(self):
        for other in ALPHA_METADATA:
            for kind, flags in ((8, 6), (1, 0), (1, 2), (1, 4), (1, 7), (1, 0x806)):
                data = section_change(alpha_object(other=other), 1, 1, kind)
                with self.subTest(other=other, kind=kind, flags=flags), self.assertRaises(elf.ELFError):
                    observe(section_change(data, 1, 2, flags))

    def test_metadata_does_not_bypass_header_or_fixture_bindings(self):
        for other in ALPHA_METADATA:
            data = alpha_object(other=other)
            for changed in (data[:-1], data[:63], header_change(data, 0, 2),
                            header_change(data, 3, 1), header_change(data, 5, len(data))):
                with self.subTest(other=other), self.assertRaises(elf.ELFError):
                    observe(changed)
            for wrong in (fixture(bits=64, machine=62), fixture(bits=32, machine=EM_ALPHA),
                          fixture(bits=64, little=False, machine=EM_ALPHA)):
                with self.assertRaises(elf.ELFError):
                    elf.calibration_object(data, model(bits=64), wrong)

    def test_alpha_marked_functions_require_exact_zero_header_flags(self):
        for other in ALPHA_METADATA:
            for flags in (1, 2, 0x100, 0xffffffff):
                with self.subTest(other=other, flags=flags), self.assertRaises(elf.ELFError):
                    observe(header_change(alpha_object(other=other), 6, flags))

    def test_exact_known_metadata_on_required_function_is_preserved(self):
        for other in ALPHA_METADATA:
            with self.subTest(other=other):
                result = observe(alpha_object(other=other))
                self.assertEqual(result["alpha_symbol_metadata"], [expected_metadata(CALIBRATION_NAME, other)])
                self.assertEqual(result["definition"]["name"], CALIBRATION_NAME)
                self.assertEqual(result["definition"]["size"], 4)
                self.assertEqual(result["undefined_metadata"], [])

    def test_defined_auxiliary_local_and_global_function_metadata_is_preserved(self):
        for binding in ("local", "global"):
            for other in ALPHA_METADATA:
                with self.subTest(binding=binding, other=other):
                    data, _ = auxiliary_object(other=other, binding=binding)
                    result = observe(data)
                    self.assertEqual(result["alpha_symbol_metadata"],
                                     [expected_metadata(AUXILIARY_NAME, other, binding=binding)])

    def test_auxiliary_metadata_does_not_admit_weak_or_nonfunction_symbols(self):
        for other in ALPHA_METADATA:
            data, index = auxiliary_object(other=other)
            for info in (0x22, 0x32, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x1f):
                with self.subTest(other=other, info=info), self.assertRaises(elf.ELFError):
                    observe(symbol_change(data, index, 3, info))
            for field, value in ((0, 0), (2, 0), (2, 5), (5, 4), (5, 0xfff1), (5, 0xffff)):
                with self.subTest(other=other, field=field, value=value), self.assertRaises(elf.ELFError):
                    observe(symbol_change(data, index, field, value))
            undefined = symbol_change(symbol_change(data, index, 2, 0), index, 5, 0)
            with self.assertRaises(elf.ELFError):
                observe(undefined)

    def test_auxiliary_mixed_unknown_values_and_invalid_local_order_fail(self):
        data, index = auxiliary_object()
        for other in (4, 8, 0x08, 0x40, 0x81, 0x82, 0x83, 0x89, 0x8a, 0x90, 0xff):
            with self.subTest(other=other), self.assertRaises(elf.ELFError):
                observe(symbol_change(data, index, 4, other))
        local, _ = auxiliary_object(binding="local")
        with self.assertRaises(elf.ELFError):
            observe(section_change(local, 3, 7, 1))

    def test_unmarked_or_nonalpha_observations_have_no_added_metadata(self):
        for machine in (EM_ALPHA, 62, 183, 243):
            self.assertNotIn("alpha_symbol_metadata", observe(alpha_object(machine=machine), machine=machine))
        for visibility in range(4):
            data, _ = auxiliary_object(other=visibility)
            self.assertNotIn("alpha_symbol_metadata", observe(data))

    def test_retained_alpha_positive_is_read_only_not_receipt_acceptance(self):
        root = Path(__file__).resolve().parents[1]
        directory = Path(os.environ.get("FRAGMA_COMMON24_ALPHA_ELF_EVIDENCE",
            root / "build/common24-wave3-compiler-work/initial-1/common.unaligned24.alpha"))
        if not directory.is_dir():
            self.skipTest("set FRAGMA_COMMON24_ALPHA_ELF_EVIDENCE to retained Alpha initial-1 evidence")
        receipt_path = directory / "compiler-calibration/receipt.json"
        before = receipt_path.read_bytes()
        self.assertEqual(hashlib.sha256(before).hexdigest(),
                         "54ef24655088eb10ea0994da1d86207968ecca755d1262ff113b2d666eae2ae9")
        saved = json.loads(before)
        self.assertEqual(saved["status"], "error")
        self.assertEqual(saved["error"], {"type": "ELFError", "message": "invalid ELF symbol type/binding/order"})
        self.assertIsNone(saved["positive_object"])
        genuine_path = directory / "kernel-model-check.json"
        self.assertEqual(hashlib.sha256(genuine_path.read_bytes()).hexdigest(),
                         "8be0b0bfa4eefad26dfb5a6ca42e3962de235846a8354d2da8cc23e725598b07")
        genuine = json.loads(genuine_path.read_text())
        fixture_bytes = (directory / "kernel-model.o").read_bytes()
        self.assertEqual(hashlib.sha256(fixture_bytes).hexdigest(), genuine["object"]["sha256"])
        fixture_observation = frontend_policy.fixture_object(fixture_bytes, saved["target"], saved["model"])
        positive = (directory / "compiler-calibration/positive.o").read_bytes()
        self.assertEqual(hashlib.sha256(positive).hexdigest(),
                         "8f290657b9e3703c179e5cd301c5a02521db354afb762dbdaa9c14d052a28c89")
        result = elf.calibration_object(positive, saved["model"], fixture_observation)
        self.assertEqual(result["alpha_symbol_metadata"], [expected_metadata(CALIBRATION_NAME, 0x80)])
        self.assertEqual(result["section_count"], 22)
        self.assertEqual(result["symbol_count"], 15)
        self.assertEqual(result["definition"]["size"], 4)
        self.assertEqual(result["undefined_metadata"], [])
        self.assertEqual(receipt_path.read_bytes(), before)

    def test_six_retained_nonalpha_object_observations_are_unchanged(self):
        root = Path(__file__).resolve().parents[1]
        directory = Path(os.environ.get("FRAGMA_COMMON24_ALPHA_LEGACY_EVIDENCE",
            root / "results/common24-six-reviewed-20260906"))
        if not directory.is_dir():
            self.skipTest("set FRAGMA_COMMON24_ALPHA_LEGACY_EVIDENCE to retained six-profile evidence")
        # Recheck object bytes/observations only. The old enclosing receipts
        # deliberately become stale when the shared ELF implementation changes.
        for suffix in ("arm", "powerpc32", "m68k", "arm64", "riscv64", "sh"):
            with self.subTest(suffix=suffix):
                receipt_path = directory / ("common.unaligned24." + suffix) / "compiler-calibration/receipt.json"
                before = receipt_path.read_bytes()
                saved = json.loads(before)

                def bytes_from(record):
                    data = Path(record["absolute_path"]).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
                    return data

                gate_object = next(row for row in saved["gate"]["artifacts"]
                                   if Path(row["absolute_path"]).name == "kernel-model.o")
                genuine = frontend_policy.fixture_object(bytes_from(gate_object), saved["target"], saved["model"])
                self.assertEqual(genuine, saved["gate"]["object_identity"])
                positive = next(row for row in saved["artifacts"]
                                if Path(row["absolute_path"]).name == "positive.o")
                actual = elf.calibration_object(bytes_from(positive), saved["model"], genuine)
                self.assertEqual(actual, saved["positive_object"])
                self.assertNotIn("alpha_symbol_metadata", actual)
                self.assertEqual(receipt_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
