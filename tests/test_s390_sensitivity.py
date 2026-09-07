"""Benign valid-input s390 witness and fail-closed local receipt regressions."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from fragma import analysis_policy, inputs, s390_sensitivity as native


ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "config").is_dir():
    ROOT = Path.cwd()


class S390SensitivityTests(unittest.TestCase):
    def setUp(self):
        self.revision, self.target = native.scope(ROOT)
        self.mapping = native.read_json(ROOT / native.MAPPING)
        self.source = (ROOT / native.HARNESS).read_text()
        self.generated, self.rows = native.render_adapter(self.source, self.target, self.mapping)

    def events(self):
        return [{"kind": "begin", "entry": native.ENTRY}, native.LAYOUT_STATE,
                *[{"kind": "property", "name": row["name"], "observed": row["expected"],
                   "expected": row["expected"]} for row in self.rows], native.STATE,
                {"kind": "normal-return", "entry": native.ENTRY}]

    def stream(self, events=None):
        return "\n".join(json.dumps(event) for event in (self.events() if events is None else events)) + "\n"

    def test_exact_scope_and_two_original_assertion_locations(self):
        self.assertEqual(self.target["functions"], ["__get_unaligned_be24"])
        self.assertEqual([row["line"] for row in self.rows], [152, 153])
        self.assertEqual([row["expected"] for row in self.rows], [True, False])
        self.assertEqual(native.INSERTION.sub("", self.generated), self.source)
        result = native.validate_events(self.stream(), self.rows, 0, "")
        self.assertTrue(all(row["reached"] is True for row in result))
        self.assertEqual([row["observed"] for row in result], [True, False])

    def test_scope_requires_explicit_rte_before_eva(self):
        self.assertEqual(self.target["analysis_pipeline"], {"kind": "rte-eva"})
        model = {"analysis": {"wp_model": "Typed", "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS),
                              "runtime_checks": {"pointer_formation": "object-or-null"}}}
        bound = native.native.analysis_binding(model, [self.target])
        pipeline = bound["pipelines"][0]["pipeline"]
        self.assertEqual(pipeline["kind"], "rte-eva")
        self.assertEqual(pipeline["rte_functions"], [native.HELPER, native.ENTRY])
        self.assertIs(pipeline["rte_use_eva_results"], False)
        manifest_path = ROOT / "config/s390-targets.json"
        original = native.read_json
        manifest = original(manifest_path)
        for declaration in (None, {"kind": "eva"}, {"kind": "rte-eva", "reuse_results": True}):
            altered = copy.deepcopy(manifest)
            target = next(row for row in altered["targets"] if row["id"] == native.TARGET)
            if declaration is None:
                target.pop("analysis_pipeline")
            else:
                target["analysis_pipeline"] = declaration
            with self.subTest(declaration=declaration), \
                    patch.object(native, "read_json", lambda path: altered if Path(path) == manifest_path else original(path)), \
                    self.assertRaises(native.S390Error):
                native.scope(ROOT)

    def test_model_validation_does_not_upgrade_legacy_pointer_policy(self):
        for runtime in (None, {}, {"pointer_formation": False}, {"pointer_formation": "disabled"}):
            analysis = {"wp_model": "Typed", "arithmetic_flags": list(analysis_policy.ARITHMETIC_FLAGS)}
            if runtime is not None:
                analysis["runtime_checks"] = runtime
            with self.subTest(runtime=runtime), self.assertRaisesRegex(ValueError, "runtime-check policy"):
                native.check_model({"analysis": analysis}, {}, self.revision)

    def test_changed_source_or_predicate_needs_review(self):
        for source in (self.source + "\n", self.source.replace("0x12, 0x34, 0x56", "0x12, 0x34, 0x55")):
            with self.assertRaises(native.S390Error):
                native.render_adapter(source, self.target, self.mapping)
        altered = copy.deepcopy(self.mapping)
        altered["properties"][-1]["expected"] = 0
        with self.assertRaises(native.S390Error):
            native.render_adapter(self.source, self.target, altered)
        altered = copy.deepcopy(self.mapping)
        altered["properties"][-1]["acsl"] = "value != 0x123456"
        with self.assertRaises(native.S390Error):
            native.render_adapter(self.source, self.target, altered)

    def test_rehashed_new_input_is_still_outside_bounded_entry(self):
        source = self.source.replace("0x12, 0x34, 0x56", "0x12, 0x34, 0x55")
        mapping = {**self.mapping, "harness_sha256": hashlib.sha256(source.encode()).hexdigest()}
        with self.assertRaisesRegex(native.S390Error, "three-byte"):
            native.render_adapter(source, self.target, mapping)

    def test_stream_requires_complete_ordered_reached_state(self):
        for mutate in (
                lambda rows: rows.pop(),
                lambda rows: rows.reverse(),
                lambda rows: rows.append(rows[-1]),
                lambda rows: rows[1].update(bytes=[4, 3, 2, 1]),
                lambda rows: rows[4].update(bytes=[18, 52, 85]),
                lambda rows: rows[4].update(value=1193046.0),
                lambda rows: rows[2].update(observed=1),
                lambda rows: rows[3].update(observed=True),
                lambda rows: rows[1].update(bits=True)):
            events = copy.deepcopy(self.events())
            mutate(events)
            with self.assertRaises(native.S390Error):
                native.validate_events(self.stream(events), self.rows, 0, "")
        for returncode, stderr in ((False, ""), (1, ""), (-11, ""), (0, "unexpected error")):
            with self.assertRaises(native.S390Error):
                native.validate_events(self.stream(), self.rows, returncode, stderr)

    def test_json_duplicate_keys_and_nonfinite_numbers_fail(self):
        for stream in (self.stream().replace('"bits": 64', '"bits": 64, "bits": 64'),
                       self.stream().replace('"bits": 64', '"bits": NaN')):
            with self.assertRaises(ValueError):
                native.validate_events(stream, self.rows, 0, "")

    def test_static_elf_identity_requires_actual_machine_and_encoding(self):
        with tempfile.TemporaryDirectory(prefix="fragma-s390-elf-") as directory:
            path = Path(directory) / "not-elf"
            path.write_bytes(b"not an executable")
            with self.assertRaises(native.S390Error):
                native.elf_identity(path, machine=22, byte_order="big")
            header = bytes([127, 69, 76, 70, 2, 2, 1]) + bytes(9)
            header += struct.pack(">HHIQQQIHHHHHH", 2, 22, 1, 0x1000, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            header += struct.pack(">IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, 120, 120, 0x1000)
            path.write_bytes(header)
            self.assertEqual(native.elf_identity(path, machine=22, byte_order="big")["machine"], 22)
            with self.assertRaises(native.S390Error):
                native.elf_identity(path, machine=62, byte_order="little")
            path.write_bytes(header[:64] + struct.pack(">I", 3) + header[68:])
            with self.assertRaises(native.S390Error):
                native.elf_identity(path, machine=22, byte_order="big")
            for offset, replacement in ((20, bytes(4)), (24, bytes(8)),
                                        (68, struct.pack(">I", 4)),
                                        (96, struct.pack(">Q", 121))):
                path.write_bytes(header[:offset] + replacement + header[offset + len(replacement):])
                with self.subTest(offset=offset), self.assertRaises(native.S390Error):
                    native.elf_identity(path, machine=22, byte_order="big")

    def test_immutable_gate_keeps_revision_and_discards_only_checkout_observations(self):
        gate = {"passed": True, "source": {"path": "header.h", "kind": "git-blob",
                "revision": "a" * 40, "sha256": "b" * 64, "checkout_head": "c" * 40}}
        changed = copy.deepcopy(gate)
        changed["source"]["checkout_head"] = "d" * 40
        self.assertTrue(native.same(native.immutable_gate(gate), native.immutable_gate(changed)))
        for field in ("path", "kind", "revision", "sha256"):
            changed = copy.deepcopy(gate)
            changed["source"][field] = "contradictory"
            self.assertFalse(native.same(native.immutable_gate(gate), native.immutable_gate(changed)))

    @unittest.skipUnless(os.environ.get("FRAGMA_S390_NATIVE_RESULTS"),
                         "supply a current independent s390 runtime receipt")
    def test_current_receipt_and_contradictory_metadata_mutations(self):
        path = Path(os.environ["FRAGMA_S390_NATIVE_RESULTS"]).resolve() / "receipt.json"
        evidence = native.read_json(path)
        model = native.read_json(evidence["profile_receipt"]["path"])
        build = inputs.load_build(ROOT, "s390x-gcc", self.revision)
        kernel = Path(os.environ.get("FRAGMA_KERNEL_TREE", str(ROOT.parent / "linux")))

        def validate():
            return native.validate_native_receipt(ROOT, kernel, self.target, self.revision, model, build, path)

        accepted = validate()
        self.assertEqual(accepted["status"], "passed")
        self.assertEqual(accepted["runtime"]["cpu"], "max")
        self.assertEqual(accepted["runtime"]["requested_cpu"], "z13")
        self.assertFalse(accepted["properties"][-1]["observed"])
        self.assertTrue(accepted["properties"][-1]["reached"])
        self.assertEqual(accepted["analysis_policy"], native.native.analysis_binding(model, [self.target]))
        self.assertIn(str(Path(analysis_policy.__file__).resolve()), [row["absolute_path"] for row in accepted["tracked_files"]])
        raw_header = (path.parent / "elf-header.stdout").read_text()
        native.check_readelf(raw_header, evidence["elf"])
        for before, after in (("IBM S/390", "Other machine"),
                              ("0x" + format(evidence["elf"]["entry"], "x"), "0x0"),
                              ("R E", "RW "), ("0x0930e8", "0x0930e7")):
            self.assertIn(before, raw_header)
            with self.assertRaises(native.S390Error):
                native.check_readelf(raw_header.replace(before, after), evidence["elf"])
        mutations = [
            lambda row: row.update(corroborated=1),
            lambda row: row.update(target_sha256="0" * 64),
            lambda row: row.update(kernel_inputs=[]),
            lambda row: row.update(model_inputs=[]),
            lambda row: row.update(backend_inputs=[]),
            lambda row: row.update(hosted_inputs=[]),
            lambda row: row.update(link_inputs=[]),
            lambda row: row["bindings"].pop(),
            lambda row: row["artifact_hashes"].pop(next(iter(row["artifact_hashes"]))),
            lambda row: row["commands"][-1]["argv"].__setitem__(2, "z14"),
            lambda row: row["commands"][-1].update(returncode=False),
            lambda row: row["commands"][-1].update(timed_out=True),
            lambda row: row["commands"][-1].update(cwd="/tmp"),
            lambda row: row["source_gate_before_compile"].update(passed=1),
            lambda row: row["source_gate_before_compile"]["source"].update(revision="0" * 40),
            lambda row: row["source_gate"]["source"].update(revision="0" * 40),
            lambda row: row["source_gate"]["source"].update(path="different.h"),
            lambda row: row["source_gate"]["source"].update(kind="working-copy"),
            lambda row: row["properties"][-1].update(observed=True),
            lambda row: row["state"].update(value=1193046.0),
            lambda row: row["runtime"].update(cpu="z14"),
            lambda row: row["trace_evidence"].update(helper_call_confirmed=False),
            lambda row: row["trace_evidence"]["symbols"][native.HELPER].update(address=0),
            lambda row: row["model"]["analysis"].pop("runtime_checks"),
            lambda row: row["model"]["analysis"]["runtime_checks"].update(pointer_formation="disabled"),
            lambda row: row.pop("analysis_policy"),
            lambda row: row["analysis_policy"].update(schema_version=True),
            lambda row: row["analysis_policy"]["pipelines"][0]["pipeline"].update(kind="eva"),
            lambda row: row["analysis_policy"]["pipelines"][0]["pipeline"].update(rte_use_eva_results=True),
            lambda row: row.update(bindings=[item for item in row["bindings"] if item["path"] != str(Path(analysis_policy.__file__).resolve())]),
            lambda row: next(item for item in row["bindings"] if item["path"] == str(Path(analysis_policy.__file__).resolve())).update(sha256="0" * 64),
        ]
        original_read = Path.read_text
        for index, mutate in enumerate(mutations):
            altered = copy.deepcopy(evidence)
            mutate(altered)

            def read_altered(instance, *args, **kwargs):
                return json.dumps(altered) if instance == path else original_read(instance, *args, **kwargs)

            with self.subTest(mutation=index), patch.object(Path, "read_text", read_altered):
                with self.assertRaises(native.S390Error):
                    validate()


if __name__ == "__main__":
    unittest.main()
