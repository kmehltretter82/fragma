"""Fail-closed checks for the ARM32 cache-ordering Mthread pilot."""

from pathlib import Path
import hashlib
import json
import tempfile
import unittest

from fragma import arm32_cache_mthread, provenance


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Arm32CacheMthreadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = arm32_cache_mthread.load_manifest(ROOT)
        cls.fixture = ROOT / cls.manifest["model"]["fixture"]
        kernel = cls.manifest["kernel"]
        cls.source = ROOT / kernel["source_root"] / kernel["source"]

    def test_manifest_is_a_known_fix_calibration_not_a_new_finding(self):
        self.assertEqual(
            self.manifest["classification"],
            "known-fix-detection-calibration-no-new-bug",
        )
        current, negative = self.manifest["cases"]
        self.assertTrue(current["current_source_candidate"])
        self.assertEqual(
            current["expected_assertions"],
            {"arm32_cache_publish_after_local_flush": "valid"},
        )
        self.assertFalse(negative["current_source_candidate"])
        self.assertEqual(
            negative["expected_assertions"],
            {"arm32_cache_publish_after_local_flush": "invalid"},
        )

    def test_candidate_is_token_identical_to_the_pinned_snapshot(self):
        name = self.manifest["kernel"]["function"]
        source = provenance.extract_function(self.source.read_text(), name)
        fixture = provenance.extract_function(self.fixture.read_text(), name)
        self.assertEqual(source.tokens, fixture.tokens)
        self.assertEqual(source.declaration_prefix, fixture.declaration_prefix)
        self.assertEqual(
            provenance.token_hash(source.tokens),
            self.manifest["kernel"]["function_token_sha256"],
        )

    def test_current_candidate_orders_test_flush_then_publication(self):
        function = provenance.extract_function(
            self.source.read_text(), self.manifest["kernel"]["function"])
        positions = [function.tokens.index(name) for name in (
            "test_bit", "__flush_dcache_folio", "set_bit")]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("test_and_set_bit", function.tokens)

    def test_negative_adapter_does_not_modify_the_candidate(self):
        text = self.fixture.read_text()
        candidate = provenance.extract_function(
            text, self.manifest["kernel"]["function"])
        helper = provenance.extract_function(text, "test_bit")
        self.assertNotIn("FRAGMA_ARM32_CACHE_EARLY_SET_NEGATIVE",
                         candidate.tokens)
        self.assertIn("FRAGMA_ARM32_CACHE_EARLY_SET_NEGATIVE", helper.tokens)

    def test_cache_flush_event_is_not_serialized_by_the_bit_mutex(self):
        flush = provenance.extract_function(
            self.fixture.read_text(), "__flush_dcache_folio")
        self.assertNotIn("Frama_C_mutex_lock", flush.tokens)
        self.assertNotIn("Frama_C_mutex_unlock", flush.tokens)
        self.assertIn("Frama_C_thread_id", flush.tokens)

    def test_sequential_target_retains_narrow_no_finding_scope(self):
        targets = json.loads(
            (ROOT / "config/bug-search-arm32-recent-targets.json").read_text())[
                "targets"]
        target = next(item for item in targets if item["id"] ==
                      "search.arm32.recent.__sync_icache_dcache")
        self.assertEqual(target["functions"], ["__sync_icache_dcache"])
        self.assertEqual(target["analysis_pipeline"], {"kind": "rte-eva"})
        self.assertEqual(
            target["search_classification"],
            "sequential-no-finding-known-fix-mthread-sensitive",
        )
        self.assertEqual(target["claims"], [])

    def test_retained_result_records_a_sensitive_ab_when_available(self):
        campaign = json.loads(
            (ROOT / "config/bug-search-arm32-recent.json").read_text())
        run = campaign.get("execution", {}).get(
            "__sync_icache_dcache", {}).get("mthread_eva_ab", {})
        output = ROOT / run.get("output", "missing")
        if not output.is_dir():
            self.skipTest("retained cache Mthread result unavailable")
        self.assertEqual(sha256(output / "summary.json"),
                         run["summary_sha256"])
        self.assertEqual(sha256(output / "SUMMARY.md"),
                         run["summary_markdown_sha256"])
        self.assertEqual(
            sha256(output / "cases/current_source/report.tsv"),
            run["current_report_sha256"],
        )
        self.assertEqual(
            sha256(output / "cases/early_publication_negative/report.tsv"),
            run["negative_report_sha256"],
        )
        result = json.loads((output / "summary.json").read_text())
        self.assertTrue(result["accepted"])
        self.assertEqual(result["known_fix_detection_count"], 1)
        self.assertEqual(result["new_bug_count"], 0)
        self.assertEqual(result["cases"][0]["assertions"],
                         {"arm32_cache_publish_after_local_flush": "valid"})
        self.assertEqual(result["cases"][1]["assertions"],
                         {"arm32_cache_publish_after_local_flush": "invalid"})

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                    arm32_cache_mthread.Arm32CacheMthreadError,
                    "already exists"):
                arm32_cache_mthread.run(ROOT, ROOT, Path(directory))


if __name__ == "__main__":
    unittest.main()
