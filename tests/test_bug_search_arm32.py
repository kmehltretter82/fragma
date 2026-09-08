"""Fail-closed checks for the frozen analyzer-first ARM32 campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from fragma.analysis_policy import pipeline_identity
from fragma.provenance import check_target, extract_function, tokenize


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config/bug-search-arm32.json"
TARGETS = ROOT / "config/bug-search-arm32-targets.json"
RECENT = ROOT / "config/bug-search-arm32-recent.json"
RECENT_TARGETS = ROOT / "config/bug-search-arm32-recent-targets.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class ARM32BugSearchFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(MANIFEST.read_text())

    def test_campaign_is_arm32_and_is_now_a_calibration_result(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["campaign_id"], "arm32-string-first-20260907")
        self.assertEqual(self.data["status"],
                         "calibration-run-no-confirmed-findings")
        self.assertEqual(self.data["architecture"], "arm")
        self.assertEqual(self.data["profile"], "arm-gcc")
        self.assertEqual(self.data["configuration"]["recipe"], "multi_v7_defconfig")
        self.assertEqual(self.data["configuration"]["bits"], 32)
        self.assertIn("no detailed function-body review", self.data["selection_review"])
        self.assertEqual(self.data["execution"]["confirmed_bugs"], 0)
        self.assertEqual(self.data["execution"]["classification"],
                         "frontend-and-driver-calibration")

    def test_frozen_candidates_and_selection_rule_are_exact(self):
        self.assertEqual(
            [(row["name"], row["object_size"]) for row in self.data["candidates"]],
            [
                ("sized_strscpy", 336),
                ("memchr_inv", 276),
                ("strstr", 176),
                ("strncasecmp", 164),
                ("strnstr", 144),
                ("strsep", 108),
                ("memcmp", 100),
                ("strncmp", 88),
            ],
        )
        selection = self.data["selection"]
        self.assertEqual(selection["kind"], "compiled-object-global-text-size")
        self.assertEqual(selection["excluded_existing_targets"], ["strnchr", "strlcat"])
        self.assertEqual(selection["ranking"], "descending compiled symbol size")
        self.assertEqual(selection["limit"], 8)

    def test_discovery_policy_does_not_relabel_rv32_or_failed_proofs(self):
        policy = self.data["discovery_policy"]
        self.assertIs(policy["analyzer_first"], True)
        self.assertIs(policy["unchanged_source_required"], True)
        self.assertIs(policy["failed_proof_is_only_a_lead"], True)
        self.assertIs(policy["concrete_original_source_witness_required"], True)
        self.assertIs(policy["same_input_fix_ab_required"], True)
        self.assertEqual(policy["rv32_zeropad_classification"],
                         "review-found-confirmed")

    def test_tracked_selection_inputs_match(self):
        for relative in ("config/profiles.json", "config/architectures.json"):
            self.assertEqual(sha256(ROOT / relative),
                             self.data["input_hashes"][relative])

    def test_retained_arm_object_reproduces_frozen_ranking(self):
        object_path = ROOT / self.data["selection"]["object"]
        source_path = ROOT / self.data["source"]["exported_path"]
        nm = shutil.which("arm-linux-gnueabi-nm")
        if not object_path.is_file() or not source_path.is_file() or not nm:
            self.skipTest("retained ARM32 object/source or target nm is unavailable")

        self.assertEqual(sha256(source_path), self.data["source"]["sha256"])
        for relative, expected in self.data["input_hashes"].items():
            path = ROOT / relative
            if path.is_file():
                self.assertEqual(sha256(path), expected, relative)

        process = subprocess.run(
            [nm, "-S", "--size-sort", "--defined-only", str(object_path)],
            check=True,
            text=True,
            capture_output=True,
        )
        excluded = set(self.data["selection"]["excluded_existing_targets"])
        rows = []
        for line in process.stdout.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[2] == "T" and fields[3] not in excluded:
                rows.append({
                    "name": fields[3],
                    "object_address": f"0x{fields[0]}",
                    "object_size": int(fields[1], 16),
                })
        selected = list(reversed(rows[-self.data["selection"]["limit"]:]))
        self.assertEqual(selected, self.data["candidates"])


class ARM32BugSearchTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.targets = json.loads(TARGETS.read_text())["targets"]

    def test_frozen_candidates_have_one_closed_analyzer_target_each(self):
        frozen = json.loads(MANIFEST.read_text())
        self.assertEqual([target["functions"][0] for target in self.targets],
                         [row["name"] for row in frozen["candidates"]])
        self.assertEqual(len(self.targets), 8)
        for target in self.targets:
            with self.subTest(target=target["id"]):
                self.assertEqual(target["suite"], "bug-search-arm32")
                self.assertEqual(target["profile"], "arm-gcc")
                self.assertEqual(target["analysis_pipeline"], {"kind": "rte-eva"})
                self.assertIs(target["eva_auto_builtins"], False)
                self.assertEqual(target["eva_builtins"], ["memcpy:Frama_C_memcpy"])
                self.assertIn("arm32_unknown_bytes", target["analysis_functions"])
                self.assertEqual(pipeline_identity(target)["rte_functions"],
                    [*target["analysis_functions"], target["entry"]])
                self.assertEqual(target["search_classification"],
                                 "calibration-only-no-confirmed-bug")

    def test_reached_kernel_and_modeled_helpers_are_not_hidden(self):
        closures = {
            "sized_strscpy": {"load_unaligned_zeropad", "has_zero",
                               "create_zero_mask", "find_zero", "fls"},
            "memchr_inv": {"check_bytes8"},
            "strstr": {"strlen", "memcmp"},
            "strncasecmp": {"__tolower"},
            "strnstr": {"strlen", "memcmp"},
            "strsep": {"strpbrk", "fragma_arm32_strchr_model"},
            "memcmp": set(),
            "strncmp": set(),
        }
        for target in self.targets:
            function = target["functions"][0]
            with self.subTest(function=function):
                self.assertTrue(closures[function] <= set(target["analysis_functions"]))

    def test_memchr_inv_domain_reaches_the_large_buffer_path(self):
        source = (ROOT / "harness/arm32_search.c").read_text()
        tokens = extract_function(source, "fragma_arm32_memchr_inv").tokens
        body = " ".join(tokens)
        self.assertRegex(body, r"input \[ 40 \]")
        self.assertIn("Frama_C_interval ( 0 , 40 )", body)
        self.assertRegex(source, r"assert arm32_memchr_inv_domain:\s*\n\s*count <= 40")

    def test_assembly_dependencies_are_explicit_and_target_scoped(self):
        assumptions = {item["id"] for item in
            json.loads((ROOT / "config/assumptions.json").read_text())["assumptions"]}
        by_name = {target["functions"][0]: target for target in self.targets}
        self.assertIn("arm32-search-unaligned-load", assumptions)
        self.assertIn("arm32-search-strchr", assumptions)
        self.assertIn("arm32-search-unaligned-load",
                      by_name["sized_strscpy"]["assumptions"])
        self.assertIn("arm32-search-strchr", by_name["strsep"]["assumptions"])
        for name, target in by_name.items():
            if name != "sized_strscpy":
                self.assertNotIn("arm32-search-unaligned-load", target["assumptions"])
            if name != "strsep":
                self.assertNotIn("arm32-search-strchr", target["assumptions"])

    def test_shadow_header_changes_only_the_assembly_loader_when_kernel_is_available(self):
        kernel = ROOT.parent / "linux"
        if not (kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        revision = json.loads(MANIFEST.read_text())["kernel_revision"]
        process = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(kernel), "show",
             revision + ":arch/arm/include/asm/word-at-a-time.h"],
            check=True, text=True, capture_output=True,
        )
        original = process.stdout
        shadow = (ROOT / "harness/arm32-override/asm/word-at-a-time.h").read_text()
        for name in ("has_zero", "create_zero_mask", "find_zero"):
            with self.subTest(function=name):
                self.assertEqual(extract_function(original, name).tokens,
                                 extract_function(shadow, name).tokens)
        self.assertNotEqual(extract_function(original, "load_unaligned_zeropad").tokens,
                            extract_function(shadow, "load_unaligned_zeropad").tokens)
        self.assertIn("does not model exception", shadow)
        self.assertIn("page crossing", shadow)


class ARM32RecentRiskFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(RECENT.read_text())

    def test_recent_risk_campaign_replaces_strings_as_primary_search(self):
        self.assertEqual(self.data["campaign_id"], "arm32-recent-risk-20260907")
        self.assertEqual(self.data["status"],
                         "active-first-fragma-found-bug-confirmed")
        self.assertIn("Primary ARM32 bug-search", self.data["purpose"])
        self.assertIs(self.data["selection"]["body_review_before_freeze"], False)
        self.assertEqual(self.data["selection"]["limit"], 8)

    def test_frozen_recent_candidates_are_exact_and_non_string(self):
        self.assertEqual([item["name"] for item in self.data["candidates"]], [
            "__sync_icache_dcache",
            "build_insn",
            "module_frob_arch_sections",
            "get_module_plt",
            "pcibios_align_resource",
            "arch_uprobe_copy_ixol",
            "dma_cache_maint_page",
            "__map_sg_chunk",
        ])
        self.assertTrue(all(item["source"].startswith("arch/arm/")
                            for item in self.data["candidates"]))
        self.assertTrue(all("string" not in item["name"]
                            for item in self.data["candidates"]))

    def test_candidate_sources_and_function_tokens_match_pinned_git(self):
        kernel = ROOT.parent / "linux"
        if not (kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        revision = self.data["kernel_revision"]
        cache = {}
        for item in self.data["candidates"]:
            path = item["source"]
            if path not in cache:
                process = subprocess.run(
                    ["git", "--no-optional-locks", "-C", str(kernel), "show",
                     revision + ":" + path],
                    check=True, capture_output=True,
                )
                cache[path] = process.stdout
            source = cache[path]
            with self.subTest(function=item["name"]):
                self.assertEqual(hashlib.sha256(source).hexdigest(),
                                 item["source_sha256"])
                function = extract_function(source.decode(), item["name"])
                self.assertEqual(len(function.tokens), item["function_tokens"])
                payload = json.dumps(function.tokens, ensure_ascii=True,
                                     separators=(",", ":")).encode()
                self.assertEqual(hashlib.sha256(payload).hexdigest(),
                                 item["function_token_sha256"])

    def test_every_candidate_has_recent_trigger_and_analysis_lane(self):
        for item in self.data["candidates"]:
            with self.subTest(function=item["name"]):
                self.assertRegex(item["trigger_commit"], r"^[0-9a-f]{40}$")
                self.assertGreaterEqual(item["trigger_date"], "2025-08-09")
                self.assertIn(item["analysis_lane"], {
                    "eva-rte", "eva-rte-then-functional", "mthread-plus-eva"
                })
                self.assertGreater(item["function_tokens"], 0)

    def test_first_result_remains_a_narrow_no_finding(self):
        result = self.data["execution"]["pcibios_align_resource"]
        self.assertEqual(result["full_translation_unit"]["status"],
                         "model-or-contract-gap")
        sliced = result["source_identical_slice"]
        self.assertEqual(sliced["status"], "calibration-passed")
        self.assertEqual(sliced["classification"], "verified-no-finding")
        self.assertEqual(sliced["properties"],
                         {"valid": 20, "unknown": 0, "invalid": 0})
        self.assertIn("not a functional or whole-TU proof", sliced["scope"])

    def test_campaign_reports_one_confirmed_analyzer_first_bug(self):
        self.assertEqual(self.data["confirmed_bugs"], 1)
        module = self.data["execution"]["module_frob_arch_sections"]
        self.assertEqual(module["source_identical_general"]["classification"],
                         "fragma-found-confirmed")
        self.assertEqual(
            self.data["execution"]["arch_uprobe_copy_ixol"]["new_bug_count"],
            0,
        )
        self.assertIn("dma_cache_maint_page()", self.data["next_step"])
        self.assertIn("__map_sg_chunk()", self.data["next_step"])

    def test_exposed_sibling_is_not_eligible_for_strict_discovery_label(self):
        by_name = {item["name"]: item for item in self.data["candidates"]}
        self.assertIn("not eligible for the strict fragma-found label",
                      by_name["get_module_plt"]["eligibility_note"])

    def test_retained_build_receipt_and_objects_match_when_available(self):
        retained = self.data["retained_build"]
        receipt = ROOT / retained["receipt"]
        if not receipt.is_file():
            self.skipTest("retained ARM32 recent-risk build unavailable")
        self.assertEqual(sha256(receipt), retained["receipt_sha256"])
        build = json.loads(receipt.read_text())
        self.assertEqual(build["build_id"], retained["id"])
        self.assertEqual(build["files"][".config"],
                         retained["configuration_sha256"])
        for relative, expected in retained["object_sha256"].items():
            self.assertEqual(build["files"][relative], expected, relative)

    def test_module_analysis_build_receipt_matches_when_available(self):
        retained = self.data["retained_analysis_build"]
        receipt = ROOT / retained["receipt"]
        if not receipt.is_file():
            self.skipTest("retained ARM32 module-analysis build unavailable")
        self.assertEqual(sha256(receipt), retained["receipt_sha256"])
        build = json.loads(receipt.read_text())
        self.assertEqual(build["build_id"], retained["id"])
        self.assertEqual(build["files"][".config"],
                         retained["configuration_sha256"])
        for relative, expected in retained["object_sha256"].items():
            self.assertEqual(build["files"][relative], expected, relative)


class ARM32RecentRiskSliceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.campaign = json.loads(RECENT.read_text())
        cls.target = json.loads(RECENT_TARGETS.read_text())["targets"][0]
        cls.kernel = ROOT.parent / "linux"

    def git_source(self, relative: str) -> str:
        process = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(self.kernel), "show",
             self.campaign["kernel_revision"] + ":" + relative],
            check=True, text=True, capture_output=True,
        )
        return process.stdout

    def test_target_is_a_source_identical_bounded_arm32_slice(self):
        self.assertEqual(self.target["functions"], ["pcibios_align_resource"])
        self.assertEqual(self.target["profile"], "arm-gcc")
        self.assertEqual(self.target["build_id"], "arm-gcc-recent-v2")
        self.assertEqual(self.target["input_mode"], "standalone")
        self.assertEqual(self.target["provenance"], {"mode": "functions"})
        self.assertEqual(self.target["analysis_pipeline"], {"kind": "rte-eva"})
        self.assertIs(self.target["eva_auto_builtins"], False)
        self.assertEqual(self.target["search_classification"],
                         "verified-no-finding-bounded-rte")

    def test_candidate_definition_matches_the_pinned_git_blob(self):
        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        result = check_target(self.target, self.kernel,
                              self.campaign["kernel_revision"], ROOT)
        self.assertTrue(result["passed"], result["errors"])
        function = result["functions"][0]
        self.assertEqual(function["source_token_sha256"],
                         "dfa41dbf6ffc59538c599a006fa963573c06fa052512dc7ac654833a45120b26")
        self.assertTrue(function["declaration_prefix_equal"])

    def test_minimal_resource_and_callback_declarations_are_source_derived(self):
        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        ioport = self.git_source("include/linux/ioport.h")
        pci = self.git_source("include/linux/pci.h")
        model = (ROOT / "harness/arm32_recent_pci_model.h").read_text()

        def one(pattern: str, text: str) -> tuple[str, ...]:
            matches = re.findall(pattern, text, flags=re.S)
            self.assertEqual(len(matches), 1, pattern)
            return tokenize(matches[0])

        resource = r"struct resource\s*\{.*?\n\};"
        self.assertEqual(one(resource, ioport), one(resource, model))
        callback = r"resource_size_t\s*\(\*align_resource\)\s*\([^;]+;"
        self.assertEqual(one(callback, pci), one(callback, model))
        default = r"resource_size_t\s+pci_align_resource\s*\([^;]+;"
        self.assertEqual(one(default, pci), one(default, model))
        lookup = r"struct pci_host_bridge\s*\*pci_find_host_bridge\s*\([^;]+;"
        self.assertEqual(one(lookup, pci), one(lookup, model))
        pci_dev = pci[pci.index("struct pci_dev {"):]
        model_dev = model[model.index("struct pci_dev {"):]
        bus_field = r"struct pci_bus\s*\*bus\s*;"
        self.assertEqual(tokenize(re.search(bus_field, pci_dev).group()),
                         tokenize(re.search(bus_field, model_dev).group()))

        for name, value in (("IORESOURCE_IO", "0x00000100"),
                            ("IORESOURCE_MEM", "0x00000200")):
            actual = re.search(rf"#define\s+{name}\s+(0x[0-9a-fA-F]+)", ioport)
            modeled = re.search(rf"#define\s+{name}\s+(0x[0-9a-fA-F]+)", model)
            self.assertIsNotNone(actual)
            self.assertIsNotNone(modeled)
            self.assertEqual(actual.group(1), value)
            self.assertEqual(modeled.group(1), value)

    def test_configured_resource_size_is_32_bits(self):
        receipt = ROOT / self.campaign["retained_build"]["receipt"]
        if not receipt.is_file():
            self.skipTest("retained ARM32 recent-risk build unavailable")
        build = json.loads(receipt.read_text())
        config = Path(build["output"]) / ".config"
        self.assertNotRegex(config.read_text(),
                            r"(?m)^CONFIG_PHYS_ADDR_T_64BIT=y$")
        model = (ROOT / "harness/arm32_recent_pci_model.h").read_text()
        self.assertIn("typedef unsigned int resource_size_t;", model)

    def test_retained_final_result_matches_manifest_when_available(self):
        run = self.campaign["execution"]["pcibios_align_resource"][
            "source_identical_slice"]
        output = ROOT / run["output"]
        if not output.is_dir():
            self.skipTest("retained local analyzer result unavailable")
        result = output / "search.arm32.recent.pcibios_align_resource/result.json"
        analysis = output / "search.arm32.recent.pcibios_align_resource/analysis.log"
        self.assertEqual(sha256(output / "summary.json"), run["summary_sha256"])
        self.assertEqual(sha256(result), run["result_sha256"])
        self.assertEqual(sha256(analysis), run["analysis_log_sha256"])
        parsed = json.loads(result.read_text())
        self.assertEqual(parsed["status"], "calibration-passed")
        self.assertEqual(parsed["warnings"], [])
        self.assertEqual(parsed["evaluation"]["counts"]["properties"],
                         {"valid": 20})


class ARM32RecentModuleFrobFindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.campaign = json.loads(RECENT.read_text())
        cls.targets = {
            target["id"]: target
            for target in json.loads(RECENT_TARGETS.read_text())["targets"]
        }
        cls.general = cls.targets[
            "search.arm32.recent.module_frob_arch_sections"]
        cls.witness = cls.targets[
            "search.arm32.recent.module_frob_arch_sections.oob_witness"]
        cls.execution = cls.campaign["execution"]["module_frob_arch_sections"]
        cls.kernel = ROOT.parent / "linux"

    def test_targets_retain_source_identity_and_honest_classification(self):
        self.assertEqual(self.general["build_id"],
                         "arm-gcc-recent-2g-analysis-v2")
        self.assertEqual(self.general["search_classification"],
                         "fragma-found-confirmed")
        self.assertEqual(self.witness["search_classification"],
                         "concrete-invalid-pointer-confirmed-by-qemu")
        self.assertEqual(self.general["analysis_pipeline"], {"kind": "rte-eva"})
        self.assertEqual(self.general["provenance"], {"mode": "functions"})
        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        for target in (self.general, self.witness):
            with self.subTest(target=target["id"]):
                result = check_target(target, self.kernel,
                                      self.campaign["kernel_revision"], ROOT)
                self.assertTrue(result["passed"], result["errors"])
                self.assertEqual(
                    result["functions"][0]["source_token_sha256"],
                    "de47a9730cb8f64c06774efa24e7d5b4efcd69ad067f0cefcac50814033a6f1c",
                )

    def test_general_analyzer_lead_matches_retained_result_when_available(self):
        run = self.execution["source_identical_general"]
        output = ROOT / run["output"]
        if not output.is_dir():
            self.skipTest("retained module-frob analyzer result unavailable")
        target_dir = output / self.general["id"]
        result_path = target_dir / "result.json"
        log_path = target_dir / "analysis.log"
        self.assertEqual(sha256(output / "summary.json"), run["summary_sha256"])
        self.assertEqual(sha256(result_path), run["result_sha256"])
        self.assertEqual(sha256(log_path), run["analysis_log_sha256"])
        result = json.loads(result_path.read_text())
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["evaluation"]["counts"]["properties"],
                         {"valid": 81, "unknown": 2})
        issues = [item for item in result["evaluation"]["issues"]
                  if item["kind"] == "unknown"]
        self.assertEqual([(item["line"], item["kind"]) for item in issues],
                         [(51, "unknown"), (57, "unknown")])
        self.assertIn("object_pointer", issues[0]["property"])
        self.assertIn("dstsec->sh_flags", issues[1]["property"])
        self.assertEqual(result["kernel_model_check"]["returncode"], 0)
        self.assertEqual(result["kernel_model_check"]["log_sha256"],
                         hashlib.sha256(b"").hexdigest())

    def test_concrete_witness_stops_at_invalid_pointer_when_available(self):
        run = self.execution["concrete_analyzer_witness"]
        output = ROOT / run["output"]
        if not output.is_dir():
            self.skipTest("retained module-frob witness result unavailable")
        target_dir = output / self.witness["id"]
        result_path = target_dir / "result.json"
        log_path = target_dir / "analysis.log"
        self.assertEqual(sha256(output / "summary.json"), run["summary_sha256"])
        self.assertEqual(sha256(result_path), run["result_sha256"])
        self.assertEqual(sha256(log_path), run["analysis_log_sha256"])
        result = json.loads(result_path.read_text())
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["evaluation"]["counts"]["properties"],
                         {"valid": 34, "unreachable": 47})
        log = log_path.read_text()
        self.assertIn("got status invalid (stopping propagation)", log)
        self.assertIn("line 51", log)

    def test_qemu_original_fixed_ab_matches_retained_logs_when_available(self):
        run = self.execution["qemu_ab"]
        before = ROOT / run["before_log"]
        after = ROOT / run["after_log"]
        if not before.is_file() or not after.is_file():
            self.skipTest("retained ARM32 QEMU A/B logs unavailable")
        self.assertEqual(sha256(before), run["before_log_sha256"])
        self.assertEqual(sha256(after), run["after_log_sha256"])
        before_text = before.read_text(errors="replace")
        after_text = after.read_text(errors="replace")
        self.assertIn("Unable to handle kernel paging request", before_text)
        self.assertIn("module_frob_arch_sections+0x160/0x2b8", before_text)
        self.assertIn("FRAGMA: malformed result=-1 errno=8", after_text)
        self.assertIn("FRAGMA: witness completed without kernel panic", after_text)

    def test_patch_handoff_is_signed_attributed_and_repro_is_ignored(self):
        current = self.execution["current_upstream"]
        patch = ROOT / current["patch"]
        self.assertEqual(sha256(patch), current["patch_sha256"])
        text = patch.read_text()
        self.assertIn("To: Luis Chamberlain", text)
        self.assertIn("Cc: Aaron Tomlin", text)
        self.assertIn("Russell King <linux@armlinux.org.uk>", text)
        self.assertIn("Fixes: c298be74492b", text)
        self.assertIn("Fixes: 7d485f647c1f", text)
        self.assertIn("Cc: stable@vger.kernel.org", text)
        self.assertIn("Assisted-by: LLM\n", text)
        self.assertIn("Signed-off-by: Karl Mehltretter <kmehltretter@gmail.com>",
                      text)
        self.assertIn("PA-RISC A/B testing used QEMU 10.2.1", text)
        self.assertIn("base-commit: " + current["base_commit"], text)
        self.assertTrue((ROOT / "arm/arm32-module-sh-info/REPORT.txt").is_file())
        self.assertTrue((ROOT / "results/arm32-module-sh-info-20260908/SUMMARY.md").is_file())
        ignore = (ROOT / ".gitignore").read_text()
        self.assertIn("/repro/arm32-module-sh-info/", ignore)

    def test_patch_applies_to_local_kernel_when_available(self):
        if not (self.kernel / ".git").exists():
            self.skipTest("local kernel tree unavailable")
        patch = ROOT / self.execution["current_upstream"]["patch"]
        process = subprocess.run(
            ["git", "-C", str(self.kernel), "apply", "--check", str(patch)],
            text=True, capture_output=True,
        )
        self.assertEqual(process.returncode, 0, process.stderr)


class ARM32RecentBPFBuildInsnTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.campaign = json.loads(RECENT.read_text())
        cls.targets = {
            target["id"]: target
            for target in json.loads(RECENT_TARGETS.read_text())["targets"]
        }
        cls.target = cls.targets["search.arm32.recent.build_insn"]
        cls.execution = cls.campaign["execution"]["build_insn"]
        cls.kernel = ROOT.parent / "linux"

    def test_target_is_source_identical_and_keeps_partial_classification(self):
        self.assertEqual(self.target["source"], "arch/arm/net/bpf_jit_32.c")
        self.assertEqual(self.target["analysis_pipeline"], {"kind": "rte-eva"})
        self.assertEqual(self.target["provenance"], {"mode": "functions"})
        self.assertEqual(self.target["search_classification"],
                         "partial-no-reachable-direct-rte-lead")
        self.assertEqual(self.execution["classification"], "partial-no-finding")
        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        result = check_target(self.target, self.kernel,
                              self.campaign["kernel_revision"], ROOT)
        self.assertTrue(result["passed"], result["errors"])
        function = result["functions"][0]
        self.assertEqual(function["source_token_sha256"],
                         "49454fa5f56c2c4d80dcb579384cbaa438f8fcda8f72b9c95a95fd446d5f9aa1")
        self.assertEqual(function["source_declaration_prefix"], ["static", "int"])
        self.assertEqual(function["harness_declaration_prefix"], ["int"])

    def test_analysis_assumptions_are_reviewed_narrow_and_non_recursive(self):
        ledger = {
            item["id"]: item
            for item in json.loads((ROOT / "config/assumptions.json").read_text())[
                "assumptions"]
        }
        driver = ledger["arm32-recent-bpf-build-insn-driver"]
        frontend = ledger["arm32-recent-bpf-build-insn-frontend"]
        dependencies = ledger["arm32-recent-bpf-build-insn-dependencies"]
        self.assertEqual(driver["files"],
                         ["harness/arm32_recent_bpf_build_insn_driver.c"])
        self.assertNotIn("config/bug-search-arm32-recent.json", driver["files"])
        self.assertEqual(driver["review_status"], "reviewed")
        self.assertEqual(frontend["review_status"], "reviewed")
        self.assertEqual(dependencies["review_status"], "reviewed-assumption")
        self.assertIn("no generated-A32 value", dependencies["scope"])

    def test_compact_slice_and_runtime_harness_compile_for_arm32(self):
        compiler = shutil.which("arm-linux-gnueabi-gcc")
        if not compiler:
            self.skipTest("ARM32 cross-compiler unavailable")
        syntax = subprocess.run([
            compiler, "-std=gnu11", "-march=armv7-a", "-mabi=aapcs-linux",
            "-msoft-float", "-mfpu=vfp", "-mlittle-endian",
            "-funsigned-char", "-fshort-wchar", "-fno-strict-overflow",
            "-fno-strict-aliasing", "-ffreestanding", "-Werror",
            "-Wno-attributes", "-fsyntax-only",
            str(ROOT / "harness/arm32_recent_bpf_build_insn_slice.c"),
            str(ROOT / "harness/arm32_recent_bpf_build_insn_driver.c"),
        ], text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        with tempfile.TemporaryDirectory() as directory:
            runtime = subprocess.run([
                compiler, "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                "-o", str(Path(directory) / "init"),
                str(ROOT / "harness/arm32_bpf_jit_semantics.c"),
            ], text=True, capture_output=True)
            self.assertEqual(runtime.returncode, 0, runtime.stderr)

    def test_final_analyzer_result_is_exact_and_fail_closed_when_available(self):
        run = self.execution["source_identical_direct_pass"]
        output = ROOT / run["output"]
        if not output.is_dir():
            self.skipTest("retained BPF analyzer result unavailable")
        target_dir = output / self.target["id"]
        result_path = target_dir / "result.json"
        self.assertEqual(sha256(output / "summary.json"), run["summary_sha256"])
        self.assertEqual(sha256(result_path), run["result_sha256"])
        self.assertEqual(sha256(target_dir / "analysis.log"),
                         run["analysis_log_sha256"])
        result = json.loads(result_path.read_text())
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["evaluation"]["counts"]["properties"],
                         {"valid": 197, "unreachable": 3})
        self.assertEqual(len(result["evaluation"][
            "selected_property_duplicate_groups"]), 12)
        self.assertEqual(result["evaluation"]["selected_property_ambiguities"], [])
        issues = result["evaluation"]["issues"]
        self.assertEqual(len(issues), 3)
        self.assertTrue(all(item["line"] == 122 and
                            item["property_status"] == "Dead"
                            for item in issues))

    def test_qemu_semantic_result_is_tracked_and_artifacts_match_when_available(self):
        run = self.execution["qemu_semantic_matrix"]
        result_log = ROOT / run["tracked_result_log"]
        self.assertEqual(sha256(result_log), run["tracked_result_log_sha256"])
        text = result_log.read_text()
        self.assertEqual(text.count("FRAGMA_BPF: PASS"), 88)
        self.assertIn("FRAGMA_BPF: SUMMARY pass=88 fail=0", text)
        self.assertNotRegex(text, r"FRAGMA_BPF: (?:MISMATCH|LOAD_FAIL|RUN_FAIL)")
        for path_field, hash_field in (
                ("source", "source_sha256"),
                ("binary", "binary_sha256"),
                ("initramfs", "initramfs_sha256"),
                ("configuration", "configuration_sha256"),
                ("zimage", "zimage_sha256"),
                ("full_log", "full_log_sha256")):
            path = ROOT / run[path_field]
            if path.is_file():
                with self.subTest(path=path_field):
                    self.assertEqual(sha256(path), run[hash_field])

    def test_qemu_configuration_forces_jit_when_available(self):
        config = ROOT / self.execution["qemu_semantic_matrix"]["configuration"]
        if not config.is_file():
            self.skipTest("retained QEMU kernel configuration unavailable")
        text = config.read_text()
        for symbol in ("CONFIG_BPF=y", "CONFIG_BPF_SYSCALL=y",
                       "CONFIG_BPF_JIT=y", "CONFIG_BPF_JIT_ALWAYS_ON=y"):
            self.assertRegex(text, rf"(?m)^{re.escape(symbol)}$")


class ARM32RecentUprobeCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.campaign = json.loads(RECENT.read_text())
        cls.targets = {
            target["id"]: target
            for target in json.loads(RECENT_TARGETS.read_text())["targets"]
        }
        cls.target = cls.targets[
            "search.arm32.recent.arch_uprobe_copy_ixol"]
        cls.control = cls.targets[
            "search.arm32.recent.arch_uprobe_copy_ixol.cross_page_control"]
        cls.execution = cls.campaign["execution"]["arch_uprobe_copy_ixol"]
        cls.kernel = ROOT.parent / "linux"

    def git_source(self, relative: str) -> str:
        process = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(self.kernel), "show",
             self.campaign["kernel_revision"] + ":" + relative],
            check=True, text=True, capture_output=True,
        )
        return process.stdout

    def test_targets_are_source_gated_and_classified_fail_closed(self):
        self.assertEqual(self.target["analysis_pipeline"], {"kind": "rte-eva"})
        self.assertEqual(self.target["analysis_functions"],
                         ["arch_uprobe_copy_ixol", "memcpy"])
        self.assertEqual(self.target["provenance"], {"mode": "functions"})
        self.assertEqual(self.target["search_classification"],
                         "verified-no-finding-bounded-rte")
        self.assertNotIn("eva_builtins", self.target)
        self.assertEqual(self.control["expected_invalid"],
                         ["arm32_uprobe_copy_destination_valid"])
        self.assertEqual(self.control["search_classification"],
                         "model-sensitivity-not-kernel-defect")
        self.assertIn("not a kernel-defect claim",
                      self.control["calibration_scope"])

        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        for target in (self.target, self.control):
            with self.subTest(target=target["id"]):
                result = check_target(target, self.kernel,
                                      self.campaign["kernel_revision"], ROOT)
                self.assertTrue(result["passed"], result["errors"])
                function = result["functions"][0]
                self.assertEqual(function["source_token_sha256"],
                                 "e3c5f3ace201c05fa6fe4f4e18426746805b77000f563297faae5193b1cb8ea7")
                self.assertTrue(function["declaration_prefix_equal"])

    def test_dependency_model_analyzes_each_byte_and_is_explicitly_narrow(self):
        ledger = {
            item["id"]: item
            for item in json.loads((ROOT / "config/assumptions.json").read_text())[
                "assumptions"]
        }
        self.assertEqual(ledger["arm32-recent-uprobe-driver"]["review_status"],
                         "reviewed")
        self.assertEqual(
            ledger["arm32-recent-uprobe-sensitivity-driver"]["review_status"],
            "reviewed",
        )
        dependencies = ledger["arm32-recent-uprobe-dependencies"]
        self.assertEqual(dependencies["review_status"], "reviewed-assumption")
        self.assertIn("bounded C byte loop", dependencies["scope"])
        self.assertIn("No highmem implementation", dependencies["scope"])
        driver = (ROOT / "harness/arm32_recent_uprobe_slice_driver.c").read_text()
        self.assertRegex(driver, r"for \(index = 0; index < len; index\+\+\)")
        self.assertIn("arm32_uprobe_copy_destination_valid", driver)

    def test_in_tree_callers_fit_the_analyzed_slot_domain(self):
        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        arch = self.git_source("arch/arm/include/asm/uprobes.h")
        generic = self.git_source("kernel/events/uprobes.c")
        self.assertRegex(arch, r"#define\s+UPROBE_XOL_SLOT_BYTES\s+64\b")
        self.assertRegex(arch, r"#define\s+UPROBE_SWBP_INSN_SIZE\s+4\b")
        self.assertRegex(arch, r"unsigned long\s+ixol\[2\]")
        self.assertIn("#define UINSNS_PER_PAGE", generic)
        self.assertIn("(PAGE_SIZE/UPROBE_XOL_SLOT_BYTES)", generic)
        self.assertIn("slot_nr < UINSNS_PER_PAGE", generic)
        self.assertIn("slot_nr * UPROBE_XOL_SLOT_BYTES", generic)
        self.assertRegex(
            generic,
            r"arch_uprobe_copy_ixol\(area->page, 0, insns, insns_size\);",
        )
        self.assertRegex(
            generic,
            r"arch_uprobe_copy_ixol\(area->page, utask->xol_vaddr,\s*"
            r"&uprobe->arch\.ixol, sizeof\(uprobe->arch\.ixol\)\);",
        )
        receipt = ROOT / self.campaign["retained_build"]["receipt"]
        if receipt.is_file():
            build = json.loads(receipt.read_text())
            config = Path(build["output"]) / ".config"
            self.assertRegex(config.read_text(),
                             r"(?m)^CONFIG_PAGE_SIZE_4KB=y$")
        domain = self.execution["source_identical_bounded_pass"]["caller_domain"]
        self.assertEqual(domain, {
            "slot_bytes": 64,
            "slots_per_4k_page": 64,
            "trampoline_copy_bytes": 4,
            "instruction_copy_bytes": 8,
            "result": ("Both in-tree callers fit within every allocated XOL "
                       "slot; the analyzed domain is broader and permits any "
                       "length from zero through 64 bytes in any of the 64 "
                       "slots."),
        })

    def test_slice_compiles_as_arm32_gnu_c(self):
        compiler = shutil.which("arm-linux-gnueabi-gcc")
        if not compiler:
            self.skipTest("ARM32 cross-compiler unavailable")
        process = subprocess.run([
            compiler, "-std=gnu11", "-march=armv7-a", "-mabi=aapcs-linux",
            "-msoft-float", "-mfpu=vfp", "-mlittle-endian",
            "-funsigned-char", "-fshort-wchar", "-fno-strict-overflow",
            "-fno-strict-aliasing", "-ffreestanding", "-Wall", "-Wextra",
            "-Werror", "-Wno-attributes", "-fsyntax-only",
            str(ROOT / "harness/arm32_recent_uprobe_slice.c"),
            str(ROOT / "harness/arm32_recent_uprobe_slice_driver.c"),
        ], text=True, capture_output=True)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_retained_raw_and_bounded_results_match(self):
        raw = self.execution["full_translation_unit"]
        raw_output = ROOT / raw["last_output"]
        if raw_output.is_dir():
            raw_target = raw_output / self.target["id"]
            self.assertEqual(sha256(raw_output / "summary.json"),
                             raw["summary_sha256"])
            self.assertEqual(sha256(raw_target / "result.json"),
                             raw["result_sha256"])
            self.assertEqual(sha256(raw_target / "analysis.log"),
                             raw["analysis_log_sha256"])
            parsed = json.loads((raw_target / "result.json").read_text())
            self.assertEqual(parsed["status"], "tool-error")
            self.assertTrue(parsed["provenance"]["passed"])
            log = (raw_target / "analysis.log").read_text()
            self.assertIn("include/linux/nodemask.h", log)
            self.assertIn("__auto_type", log)

        bounded = self.execution["source_identical_bounded_pass"]
        output = ROOT / bounded["output"]
        if not output.is_dir():
            self.skipTest("retained uprobe bounded result unavailable")
        target_dir = output / self.target["id"]
        self.assertEqual(sha256(output / "summary.json"),
                         bounded["summary_sha256"])
        self.assertEqual(sha256(target_dir / "result.json"),
                         bounded["result_sha256"])
        self.assertEqual(sha256(target_dir / "analysis.log"),
                         bounded["analysis_log_sha256"])
        self.assertEqual(sha256(target_dir / "properties.tsv"),
                         bounded["properties_tsv_sha256"])
        result = json.loads((target_dir / "result.json").read_text())
        self.assertEqual(result["status"], "calibration-passed")
        self.assertTrue(result["accepted"])
        self.assertEqual(result["evaluation"]["counts"]["properties"],
                         {"valid": 13})
        self.assertEqual(
            [(warning["plugin"], warning["message"])
             for warning in result["warnings"]],
            [("kernel", "using size of 'void'"),
             ("kernel", "using size of 'void'")],
        )
        regression = self.execution["regression"]
        log = ROOT / regression["log"]
        if log.is_file():
            self.assertEqual(sha256(log), regression["log_sha256"])
            text = log.read_text()
            self.assertIn("Ran 1100 tests", text)
            self.assertIn("OK (skipped=20)", text)

    def test_cross_page_control_retains_the_exact_alarm(self):
        run = self.execution["cross_page_sensitivity"]
        output = ROOT / run["output"]
        if not output.is_dir():
            self.skipTest("retained uprobe sensitivity result unavailable")
        target_dir = output / self.control["id"]
        self.assertEqual(sha256(output / "summary.json"),
                         run["summary_sha256"])
        self.assertEqual(sha256(target_dir / "result.json"),
                         run["result_sha256"])
        self.assertEqual(sha256(target_dir / "analysis.log"),
                         run["analysis_log_sha256"])
        self.assertEqual(sha256(target_dir / "properties.tsv"),
                         run["properties_tsv_sha256"])
        result = json.loads((target_dir / "result.json").read_text())
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["evaluation"]["counts"]["properties"],
                         {"valid": 10, "unknown": 1})
        log = (target_dir / "analysis.log").read_text()
        self.assertIn(
            "assertion 'arm32_uprobe_copy_destination_valid' got status invalid",
            log,
        )


class ARM32RecentDmaCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.campaign = json.loads(RECENT.read_text())
        cls.targets = {
            target["id"]: target
            for target in json.loads(RECENT_TARGETS.read_text())["targets"]
        }
        cls.target = cls.targets[
            "search.arm32.recent.dma_cache_maint_page"]
        cls.witness = cls.targets[
            "search.arm32.recent.dma_cache_maint_page.low_to_high_witness"]
        cls.execution = cls.campaign["execution"]["dma_cache_maint_page"]
        cls.kernel = ROOT.parent / "linux"

    def test_targets_are_source_gated_and_keep_the_lead_unconfirmed(self):
        self.assertEqual(self.target["analysis_pipeline"], {"kind": "rte-eva"})
        self.assertEqual(self.target["search_classification"],
                         "analyzer-first-source-gated-pending")
        self.assertEqual(self.witness["expected_invalid"],
                         ["arm32_dma_cache_direct_mapping_stays_lowmem"])
        self.assertEqual(self.witness["search_classification"],
                         "functional-boundary-witness-pending")
        self.assertEqual(self.execution["new_bug_count"], 0)
        self.assertEqual(self.execution["classification"],
                         "analyzer-lead-unconfirmed")

        if not (self.kernel / ".git").exists():
            self.skipTest("local pinned kernel tree unavailable")
        for target in (self.target, self.witness):
            with self.subTest(target=target["id"]):
                result = check_target(target, self.kernel,
                                      self.campaign["kernel_revision"], ROOT)
                self.assertTrue(result["passed"], result["errors"])
                function = result["functions"][0]
                self.assertEqual(
                    function["source_token_sha256"],
                    "a9acf3c17369800887680a1aac5a8cd7c8ea9bb6293ac72bfd7fba804d7dfda1",
                )

    def test_boundary_driver_uses_a_nonreducing_check_and_branch_controls(self):
        source = (ROOT / "harness/arm32_recent_dma_cache_boundary_driver.c").read_text()
        self.assertIn("/*@ check arm32_dma_cache_direct_mapping_stays_lowmem:",
                      source)
        self.assertIn("FRAGMA_DMA_HIGHMEM_START - 64", source)
        self.assertIn("size_t size = 128", source)
        for name in (
            "arm32_dma_cache_boundary_witness_reached",
            "arm32_dma_cache_high_nonaliasing_control",
            "arm32_dma_cache_high_aliasing_mapped_control",
            "arm32_dma_cache_high_aliasing_unmapped_control",
        ):
            self.assertIn(name, source)

    def test_retained_runs_bind_the_exact_reached_invalid_check(self):
        broad = self.execution["source_identical_bounded_pass"]
        broad_output = ROOT / broad["output"]
        witness = self.execution["low_to_high_boundary_lead"]
        witness_output = ROOT / witness["output"]
        if not broad_output.is_dir() or not witness_output.is_dir():
            self.skipTest("retained DMA cache results unavailable")

        broad_dir = broad_output / self.target["id"]
        self.assertEqual(sha256(broad_output / "summary.json"),
                         broad["summary_sha256"])
        self.assertEqual(sha256(broad_dir / "result.json"),
                         broad["result_sha256"])
        self.assertEqual(sha256(broad_dir / "analysis.log"),
                         broad["analysis_log_sha256"])
        self.assertEqual(sha256(broad_dir / "properties.tsv"),
                         broad["properties_tsv_sha256"])
        broad_result = json.loads((broad_dir / "result.json").read_text())
        self.assertEqual(broad_result["evaluation"]["counts"]["properties"],
                         {"valid": 13})

        witness_dir = witness_output / self.witness["id"]
        self.assertEqual(sha256(witness_output / "summary.json"),
                         witness["summary_sha256"])
        self.assertEqual(sha256(witness_dir / "result.json"),
                         witness["result_sha256"])
        self.assertEqual(sha256(witness_dir / "analysis.log"),
                         witness["analysis_log_sha256"])
        self.assertEqual(sha256(witness_dir / "properties.tsv"),
                         witness["properties_tsv_sha256"])
        result = json.loads((witness_dir / "result.json").read_text())
        self.assertEqual(result["status"], "calibration-passed")
        self.assertEqual(result["evaluation"]["confirmed_invalid_properties"],
                         ["arm32_dma_cache_direct_mapping_stays_lowmem"])
        checks = result["evaluation"]["eva_invalid_checks"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["classification"],
                         "eva-reached-invalid-nonreducing-check")
        self.assertFalse(checks[0]["kernel_defect_evidence"])


if __name__ == "__main__":
    unittest.main()
