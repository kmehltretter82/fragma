"""Closed selector and byte-bound actual frontend regression checks."""

import copy
from pathlib import Path
import shlex
import struct
import tempfile
import unittest

from fragma import frontend_policy as frontend
from fragma.sources import SourceError, sha256


def fixture_elf(policy, *, bits=32, little_endian=True):
    """Data-only synthetic ET_REL; no emitted code is executed."""
    endian, is64 = ("<" if little_endian else ">"), bits == 64
    inline = ("inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) "
              + frontend.VARIANTS[policy["variant"]][1]).encode() + b"\0"
    names = (b"fragma_common24_effective_inline", b"fragma_common24_expected_inline")
    strings = b"\0" + names[0] + b"\0" + names[1] + b"\0"
    header_size, section_size, symbol_size = (64, 64, 24) if is64 else (52, 40, 16)
    data = bytearray(header_size)
    rodata_offset = len(data)
    data.extend(inline * 2)
    strings_offset = len(data)
    data.extend(strings)
    data.extend(b"\0" * (-len(data) % (8 if is64 else 4)))
    symbols_offset = len(data)
    data.extend(bytes(symbol_size))
    for index, name_offset in enumerate((1, len(names[0]) + 2)):
        values = (name_offset, 0x11, 0, 1, index * len(inline), len(inline)) if is64 else (
            name_offset, index * len(inline), len(inline), 0x11, 0, 1)
        data.extend(struct.pack(endian + ("IBBHQQ" if is64 else "IIIBBH"), *values))
    sections_offset = len(data)
    sections = [(0,) * 10,
        (0, 1, 2, 0, rodata_offset, len(inline) * 2, 0, 0, 1, 0),
        (0, 3, 0, 0, strings_offset, len(strings), 0, 0, 1, 0),
        (0, 2, 0, 0, symbols_offset, symbol_size * 3, 2, 1, 8 if is64 else 4, symbol_size)]
    for section in sections:
        data.extend(struct.pack(endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII"), *section))
    ident = b"\x7fELF" + bytes((2 if is64 else 1, 1 if little_endian else 2, 1)) + bytes(9)
    machine = (62 if little_endian else 21) if is64 else (40 if little_endian else 20)
    values = (1, machine, 1, 0, 0, sections_offset, 0, header_size, 0, 0, section_size, 4, 2)
    data[:header_size] = ident + struct.pack(endian + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH"), *values)
    return bytes(data)


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "results/test"
        (self.output / "tmp").mkdir(parents=True)
        self.policy = {"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument"}
        self.target = {"frontend_policy": self.policy, "input_mode": "standalone",
                       "source": "include/linux/unaligned.h", "harness": frontend.HARNESS,
                       "kernel_model_check": frontend.FIXTURE}
        self.build = self.root / "build/kernel/example"
        self.build.mkdir(parents=True)
        self.entry = {"file": str(self.root / "source/lib/string.c"), "directory": str(self.build),
                      "arguments": ["/compiler", "-std=gnu11", "-D__KERNEL__", "-c",
                                    str(self.root / "source/lib/string.c"), "-o", "string.o"]}
        self.model = {"compiler": {"path": "/compiler"}, "analysis": {"compiler_flags": ["-std=gnu11"]},
                      "machdep": {"checked_fields": {"sizeof_ptr": 4, "little_endian": True}},
                      "build": {"source": str(self.root / "source"), "matched_commands": [self.entry]}}
        self.write(self.root / frontend.HEADER, "/* policy header */\n")
        self.write(self.root / frontend.STRATEGY, '/*@ strategy sample: \\prover("qed"); */\n')
        self.write(self.root / "fragma/frontend_policy.py", "# test helper identity\n")
        self.write(self.root / "fragma/elf.py", "# test ELF helper identity\n")
        self.write(self.root / frontend.FIXTURE, '#include <linux/types.h>\n#include <linux/unaligned.h>\n')
        raw = []
        for name in frontend.FUNCTIONS:
            signature = ("u32 " + name + "(const u8 *p) { return p[0]; }" if name.startswith("__get_")
                         else "void " + name + "(const u32 val, u8 *p) { *p = val; }")
            raw.append("/*@ ensures sample_contract: 1 == 1; */\nstatic inline " + signature)
        for name in frontend.WITNESSES:
            raw.append("/*@ ensures sample_roundtrip: \\result == val; */\n"
                       + "u32 " + name + "(u32 val) { /*@ assert sample_assert: val == val; */ return val; }")
        self.raw = "typedef unsigned char u8;\ntypedef unsigned int u32;\n" + "\n".join(raw) + "\n"
        self.write(self.root / frontend.HARNESS, self.raw)
        self.stream = self.output / "tmp/unaligned24.verified.c12.i34.pp"
        self.header = self.record(self.root / frontend.HEADER)
        self.strategy = self.record(self.root / frontend.STRATEGY)
        self.fixture_source = self.record(self.root / frontend.FIXTURE)
        self.source = self.record(self.root / frontend.HARNESS)
        self.write(self.output / "model-headers.d", "fragma: " + str(self.root / frontend.HEADER)
                   + " " + str(self.root / frontend.FIXTURE) + "\n")
        self.write(self.output / "kernel-model.log", "")
        self.refresh()

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def record(self, path):
        return {"absolute_path": str(path), "sha256": sha256(path)}

    def command(self, argv):
        return {"argv": argv, "cwd": str(self.build), "returncode": 0, "timed_out": False}

    def refresh(self):
        flag = frontend.cpp_arguments(self.target)
        fields = self.model["machdep"]["checked_fields"]
        (self.output / "kernel-model.o").write_bytes(fixture_elf(self.policy,
            bits=fields["sizeof_ptr"] * 8, little_endian=fields["little_endian"]))
        cpp = ["/compiler", "-std=gnu11", "-nostdinc", "-D__KERNEL__", *flag, "-E", "-C"]
        self.prepared = {"frama_cpp_command": shlex.join(cpp), "cwd": str(self.build),
            "frama_input": str(self.root / frontend.HARNESS), "path": str(self.output / "input.i"),
            "inputs": [self.source, self.header, self.strategy], "preprocess": self.command([
                *cpp[:-2], "-D__FRAMAC__", "-E", "-C", "-MD", "-MF", str(self.output / "headers.d"),
                "-MT", "fragma", str(self.root / frontend.HARNESS)])}
        self.fixture = {**self.command(["/compiler", "-std=gnu11", "-D__KERNEL__", *flag,
            "-Werror", "-MD", "-MF", str(self.output / "model-headers.d"), "-MT", "fragma", "-c",
            str(self.root / frontend.FIXTURE), "-o", str(self.output / "kernel-model.o")]),
            "original_compile_command": copy.deepcopy(self.entry), "frontend_policy": copy.deepcopy(self.policy),
            "fixture_sha256": sha256(self.root / frontend.FIXTURE), "inputs": [self.header, self.fixture_source],
            "object": self.record(self.output / "kernel-model.o"),
            "dependencies": self.record(self.output / "model-headers.d"),
            "diagnostics": self.record(self.output / "kernel-model.log"),
            "log": str(self.output / "kernel-model.log"), "log_sha256": sha256(self.output / "kernel-model.log")}
        self.actual = self.command(["/frama-c", "-cpp-command", shlex.join(cpp),
            "-cpp-extra-args=-std=gnu11", "-cpp-frama-c-compliant", "-pp-annot", "-keep-temp-files",
            str(self.root / frontend.HARNESS), "-wp", "-then", "-report"])
        attr = frontend.VARIANTS[self.policy["variant"]][1]
        text = self.raw.replace("static inline ", "static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) " + attr + " ")
        self.write(self.stream, (self.root / frontend.STRATEGY).read_text() + text)
        self.retain_stream()

    def retain_stream(self):
        row = {"path": str(self.stream.relative_to(self.output)), **self.record(self.stream)}
        self.audit = {"inputs": [self.source, self.header, self.strategy], "retained_preprocessing": [row],
                      "parsed_streams": [{"source": frontend.HARNESS, **row}]}

    def validate(self, **kwargs):
        return frontend.validate_actual(self.root, self.target, self.model, self.prepared,
                                        self.fixture, self.actual, self.audit, **kwargs)

    def evidence(self):
        saved = self.validate()
        records = [*self.prepared["inputs"], *self.fixture["inputs"], *self.audit["inputs"],
                   self.fixture["object"], self.fixture["dependencies"], self.fixture["diagnostics"],
                   *self.audit["parsed_streams"]]
        unique = {row["absolute_path"]: {"absolute_path": row["absolute_path"], "sha256": row["sha256"]}
                  for row in records}
        helper = self.record(self.root / "fragma/frontend_policy.py")
        elf_helper = self.record(self.root / "fragma/elf.py")
        shared = {helper["absolute_path"]: helper["sha256"], elf_helper["absolute_path"]: elf_helper["sha256"]}
        hashes = {name: sha256(self.root / name) for name in
                  (frontend.HARNESS, frontend.FIXTURE, frontend.HEADER, frontend.STRATEGY, "fragma/frontend_policy.py", "fragma/elf.py")}
        evidence = {"validated_frontend_policy": saved, "input": self.prepared,
                    "kernel_model_check": self.fixture, "analysis_command": self.actual,
                    "analyzer_audit": self.audit, "integrity_inputs": list(unique.values()),
                    "validated_review": {"review_context": {"preprocessing": {"frontend_policy": copy.deepcopy(self.policy)},
                                                           "file_hashes": hashes}}}
        return evidence, shared

    def test_both_explicit_variants_observe_actual_prefixes(self):
        for variant in frontend.VARIANTS:
            self.policy["variant"] = variant
            self.refresh()
            result = self.validate()
            self.assertEqual(result["status"], "checked")
            self.assertEqual(len(result["functions"]), 4)
            self.assertEqual(result["policy"], self.policy)

    def test_no_legacy_default_or_new_envelope(self):
        self.assertIsNone(frontend.identity({"harness": "legacy.c"}))
        self.assertEqual(frontend.add_cpp_arguments(["gcc"], {"harness": "legacy.c"}), ["gcc"])
        self.assertIsNone(frontend.observation(self.root, {}, {}, {}, {}))
        with self.assertRaises(SourceError):
            frontend.observation(self.root, {}, {}, {"validated_frontend_policy": {}}, {})
        del self.target["frontend_policy"]
        with self.assertRaisesRegex(SourceError, "explicit"):
            frontend.identity(self.target)

    def test_closed_schema_and_no_macro_injection(self):
        for bad in (None, {}, True, {**self.policy, "schema_version": True},
                    {**self.policy, "schema_version": 1.0}, {**self.policy, "variant": 1},
                    {**self.policy, "variant": "unknown"}, {**self.policy, "flags": ["-U__KERNEL__"]}):
            with self.subTest(bad=bad), self.assertRaises(SourceError):
                frontend.identity({**self.target, "frontend_policy": bad})
        for args in (["gcc", "-D", frontend.MACRO + "=1"], ["gcc", "-U" + frontend.MACRO],
                     ["gcc", "-D" + frontend.MACRO + "=2"]):
            with self.subTest(args=args), self.assertRaises(SourceError):
                frontend.add_cpp_arguments(args, self.target)

    def test_each_actual_command_rejects_selector_mismatch(self):
        for label in ("dependency", "fixture", "analyzer"):
            for extra in (["-D" + frontend.MACRO + "=2"], ["-U", frontend.MACRO]):
                self.refresh()
                if label == "analyzer":
                    self.actual["argv"][2] += " " + shlex.join(extra)
                else:
                    record = self.fixture if label == "fixture" else self.prepared["preprocess"]
                    record["argv"] += extra
                with self.subTest(label=label, extra=extra), self.assertRaises(SourceError):
                    self.validate()

    def test_matching_rewritten_prepared_and_actual_cpp_is_not_enough(self):
        self.prepared["frama_cpp_command"] += " -Dinline="
        self.actual["argv"][2] = self.prepared["frama_cpp_command"]
        with self.assertRaisesRegex(SourceError, "explicit profile"):
            self.validate()

    def test_actual_extra_args_cannot_override_policy(self):
        for extra in (["-cpp-extra-args", "-Dinline="], ["-cpp-extra-args=-U__KERNEL__"],
                      ["-cpp-extra-args=-std=gnu11"], ["-no-pp-annot"], ["-no-cpp-frama-c-compliant"],
                      ["-no-keep-temp-files"], ["-keep-temp-files=false"], ["-pp-annot=false"]):
            self.refresh()
            self.actual["argv"] += extra
            with self.subTest(extra=extra), self.assertRaises(SourceError):
                self.validate()

    def test_rehashed_acsl_contract_strategy_assertion_and_witness_changes_fail(self):
        changes = (("sample_contract: 1 == 1", "sample_contract: 1 == 2"),
                   ('\\prover("qed")', '\\prover("z3")'),
                   ("sample_assert: val == val", "sample_assert: val == 0"),
                   ("return val;", "return 0;"),
                   ("u32 fragma_roundtrip_be24", "static u32 fragma_roundtrip_be24"))
        for before, after in changes:
            self.refresh()
            self.write(self.stream, self.stream.read_text().replace(before, after, 1))
            self.retain_stream()
            with self.subTest(before=before), self.assertRaises((SourceError, ValueError)):
                self.validate()

    def test_missing_and_reordered_annotations_fail(self):
        strategy = (self.root / frontend.STRATEGY).read_text()
        for mode in ("missing", "reordered"):
            self.refresh()
            body = self.stream.read_text().removeprefix(strategy)
            self.write(self.stream, body if mode == "missing" else body + strategy)
            self.retain_stream()
            with self.subTest(mode=mode), self.assertRaisesRegex(SourceError, "ACSL"):
                self.validate()

    def test_annotation_tokens_preserve_literals_boundaries_and_order(self):
        source = '/*@ strategy sample: \\prover("a b"); */'
        self.assertEqual(frontend.annotation_tokens(source), frontend.annotation_tokens(
            '/*@\n strategy sample : \\prover ( "a b" ) ;\n*/'))
        self.assertNotEqual(frontend.annotation_tokens(source), frontend.annotation_tokens(source.replace('a b', 'ab')))
        self.assertNotEqual(frontend.annotation_tokens('/*@ assert x: a b; */'),
                            frontend.annotation_tokens('/*@ assert x: ab; */'))
        self.assertNotEqual(frontend.annotation_tokens('/*@ assert x: a == b; */'),
                            frontend.annotation_tokens('/*@ assert x: a = = b; */'))
        self.assertEqual(frontend.annotation_tokens('const char *s = "/*@ not an annotation */";'), [])

    def test_rehashed_stream_still_checks_attribute_and_body(self):
        for old, new in (("__no_instrument_function__", "patchable_function_entry(0,0)"),
                         ("__attribute__((__gnu_inline__))", ""), ("p[0]", "p[1]")):
            self.refresh()
            self.write(self.stream, self.stream.read_text().replace(old, new))
            self.retain_stream()
            with self.subTest(old=old), self.assertRaises(SourceError):
                self.validate()

    def test_missing_or_duplicate_stream_and_changed_bytes(self):
        self.audit["parsed_streams"] *= 2
        with self.assertRaises(SourceError):
            self.validate()
        self.refresh()
        self.write(self.stream, self.stream.read_text() + "\n")
        with self.assertRaisesRegex(SourceError, "changed"):
            self.validate()

    def test_genuine_fixture_must_match_model_command_and_outputs(self):
        for mutation in (lambda: self.fixture["argv"].append("-Dinline="),
                         lambda: self.fixture["original_compile_command"]["arguments"].append("-m64"),
                         lambda: self.fixture.pop("object"),
                         lambda: self.fixture["inputs"].pop(),
                         lambda: self.fixture.update(returncode=True)):
            self.refresh()
            mutation()
            with self.assertRaises(SourceError):
                self.validate()

    def test_artifact_reader_handles_binary_and_cannot_skip_hashes(self):
        seen = []
        def read(path, expected, *, binary=False):
            seen.append((path, binary))
            return Path(path).read_bytes() if binary else Path(path).read_text()
        self.validate(read=read)
        self.assertIn((str(self.output / "kernel-model.o"), True), seen)
        with self.assertRaisesRegex(SourceError, "bound artifact bytes"):
            self.validate(read=lambda *args, **kwargs: b"unrelated")

    def test_exact_raw_and_expanded_typedef_inventory(self):
        for location in ("raw", "expanded"):
            for before, after in (("unsigned char u8", "signed char u8"),
                                  ("unsigned int u32", "unsigned long u32"),
                                  ("typedef unsigned char u8;", ""),
                                  ("typedef unsigned char u8;", "typedef unsigned char u8; typedef unsigned char u8;"),
                                  ("typedef unsigned int u32;", "typedef enum { test_value } u32;")):
                self.write(self.root / frontend.HARNESS, self.raw)
                self.source = self.record(self.root / frontend.HARNESS)
                self.refresh()
                path = self.root / frontend.HARNESS if location == "raw" else self.stream
                self.write(path, path.read_text().replace(before, after))
                if location == "raw":
                    self.source["sha256"] = sha256(path)
                else:
                    self.retain_stream()
                with self.subTest(location=location, after=after), self.assertRaisesRegex(SourceError, "typedef"):
                    self.validate()

    def test_fixture_source_and_diagnostics_cross_bindings(self):
        for mutation in (lambda: self.fixture.update(fixture_sha256="a" * 64),
                         lambda: self.fixture["inputs"].append(copy.deepcopy(self.fixture_source)),
                         lambda: self.fixture["diagnostics"].update(sha256="a" * 64),
                         lambda: self.audit["inputs"].remove(self.source),
                         lambda: self.audit["inputs"].remove(self.strategy)):
            self.refresh()
            mutation()
            with self.assertRaises(SourceError):
                self.validate()

    def test_elf_container_and_metadata_all_class_endian_variants(self):
        for bits in (32, 64):
            for little in (True, False):
                for variant in frontend.VARIANTS:
                    policy = {**self.policy, "variant": variant}
                    target = {**self.target, "frontend_policy": policy}
                    model = {"machdep": {"checked_fields": {"sizeof_ptr": bits // 8, "little_endian": little}}}
                    observed = frontend.fixture_object(fixture_elf(policy, bits=bits, little_endian=little), target, model)
                    self.assertEqual(observed["class"], bits)
                    self.assertEqual(observed["byte_order"], "little" if little else "big")
                    self.assertEqual(set(observed["inline_metadata"]),
                                     {"fragma_common24_effective_inline", "fragma_common24_expected_inline"})

    def test_rejects_invalid_elf_container_and_missing_wrong_metadata(self):
        valid = fixture_elf(self.policy)
        wrong_type = bytearray(valid)
        struct.pack_into("<H", wrong_type, 16, 2)
        wrong_bounds = bytearray(valid)
        struct.pack_into("<I", wrong_bounds, 32, len(valid) + 1)
        for data in (b"\x7fELF", valid[:51], valid[:-1], bytes(wrong_type), bytes(wrong_bounds),
                     fixture_elf(self.policy, bits=64), fixture_elf(self.policy, little_endian=False),
                     valid.replace(b"fragma_common24_effective_inline", b"fragma_common24_wrongname_inline"),
                     valid.replace(b"__no_instrument_function__", b"__invalid_instrumentation__")):
            with self.subTest(length=len(data)), self.assertRaises(SourceError):
                frontend.fixture_object(data, self.target, self.model)

    def test_elf_model_enums_and_widths_are_strict(self):
        for fields in (None, [], {}, {"sizeof_ptr": True, "little_endian": True},
                       {"sizeof_ptr": 4.0, "little_endian": True},
                       {"sizeof_ptr": 4, "little_endian": 1}, {"sizeof_ptr": 16, "little_endian": False}):
            with self.subTest(fields=fields), self.assertRaises(SourceError):
                frontend.fixture_object(fixture_elf(self.policy), self.target, {"machdep": {"checked_fields": fields}})

    def test_saved_observation_requires_consistent_combined_inventory(self):
        evidence, shared = self.evidence()
        self.assertEqual(frontend.observation(self.root, self.target, self.model, evidence, shared)["status"], "checked")
        for position in range(len(evidence["integrity_inputs"])):
            changed = copy.deepcopy(evidence)
            changed["integrity_inputs"].pop(position)
            with self.subTest(position=position), self.assertRaises(SourceError):
                frontend.observation(self.root, self.target, self.model, changed, shared)
        changed = copy.deepcopy(evidence)
        changed["integrity_inputs"].append({"absolute_path": next(iter(shared)), "sha256": "a" * 64})
        with self.assertRaisesRegex(SourceError, "conflicting"):
            frontend.observation(self.root, self.target, self.model, changed, shared)
        changed = copy.deepcopy(evidence)
        changed["kernel_model_check"]["fixture_sha256"] = "a" * 64
        with self.assertRaises(SourceError):
            frontend.observation(self.root, self.target, self.model, changed, shared)

    def test_review_binds_all_frontend_files(self):
        evidence, shared = self.evidence()
        for name in (frontend.HARNESS, frontend.FIXTURE, frontend.HEADER, frontend.STRATEGY,
                     "fragma/frontend_policy.py", "fragma/elf.py"):
            changed = copy.deepcopy(evidence)
            changed["validated_review"]["review_context"]["file_hashes"][name] = "a" * 64
            with self.subTest(name=name), self.assertRaises(SourceError):
                frontend.observation(self.root, self.target, self.model, changed, shared)

    def test_factored_elf_implementation_is_a_required_bound_input(self):
        self.assertIn("fragma/elf.py", frontend.required_files(self.target))
        self.assertEqual(frontend.required_files({}), [])
        evidence, shared = self.evidence()
        shared.pop(str(self.root / "fragma/elf.py"))
        with self.assertRaisesRegex(SourceError, "implementation"):
            frontend.observation(self.root, self.target, self.model, evidence, shared)

    def test_fixture_saved_and_review_policy_values_remain_json_typed(self):
        evidence, shared = self.evidence()
        for value in (True, 1.0):
            for location in ("fixture", "saved", "review"):
                changed = copy.deepcopy(evidence)
                policy = (changed["kernel_model_check"]["frontend_policy"] if location == "fixture" else
                          changed["validated_frontend_policy"]["policy"] if location == "saved" else
                          changed["validated_review"]["review_context"]["preprocessing"]["frontend_policy"])
                policy["schema_version"] = value
                with self.subTest(location=location, value=value), self.assertRaises(SourceError):
                    frontend.observation(self.root, self.target, self.model, changed, shared)

    def test_physical_stream_binding_is_not_logical_replay_identity(self):
        first = self.validate()
        second = copy.deepcopy(first)
        second["parsed_stream"]["absolute_path"] = "/another/temporary.pp"
        second["parsed_stream"]["sha256"] = "a" * 64
        self.assertEqual(frontend.logical_observation(first), frontend.logical_observation(second))
        second["policy"]["variant"] = "patchable-entry-0"
        self.assertNotEqual(frontend.logical_observation(first), frontend.logical_observation(second))


if __name__ == "__main__":
    unittest.main()
