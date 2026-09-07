"""Fail-closed checks for the frozen analyzer-first ARM32 campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config/bug-search-arm32.json"


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

    def test_campaign_is_arm32_and_explicitly_not_an_analyzer_result_yet(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["campaign_id"], "arm32-string-first-20260907")
        self.assertEqual(self.data["status"], "candidates-frozen-analyzer-not-run")
        self.assertEqual(self.data["architecture"], "arm")
        self.assertEqual(self.data["profile"], "arm-gcc")
        self.assertEqual(self.data["configuration"]["recipe"], "multi_v7_defconfig")
        self.assertEqual(self.data["configuration"]["bits"], 32)
        self.assertIn("no detailed function-body review", self.data["selection_review"])

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


if __name__ == "__main__":
    unittest.main()
