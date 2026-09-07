"""Registered generic profile variants keep explicit scope and fail closed."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from fragma import frontend_policy, provenance, suite


ROOT = Path(__file__).resolve().parents[1]


class CommonByteRegistryTests(unittest.TestCase):
    def test_profile_variants_share_source_but_not_an_inferred_policy(self):
        _, targets, ledger = suite.load_registry(ROOT)
        expected = {"arm": ("arm-gcc", "no-instrument"),
                    "powerpc32": ("powerpc32-gcc", "patchable-entry-0"),
                    "m68k": ("m68k-gcc", "no-instrument")}
        for suffix, (profile, variant) in expected.items():
            target = targets["common.unaligned24." + suffix]
            with self.subTest(profile=profile):
                self.assertEqual(target["profile"], profile)
                self.assertEqual(target["harness"], frontend_policy.HARNESS)
                self.assertEqual(target["kernel_model_check"], frontend_policy.FIXTURE)
                self.assertEqual(target["wp_strategy_file"], frontend_policy.STRATEGY)
                self.assertEqual(frontend_policy.identity(target)["variant"], variant)
                self.assertEqual(target["functions"], list(frontend_policy.FUNCTIONS))
                self.assertEqual(len(target["analysis_functions"]), 6)
                self.assertEqual(len(target["required_properties"]), 12)
                for name in target["assumptions"]:
                    self.assertTrue(ledger[name]["kernel_files"])

    def test_new_variants_do_not_inflate_unique_kernel_function_count(self):
        _, targets, _ = suite.load_registry(ROOT)
        def functions(selected):
            return {(target["source"], name) for target in selected if target["role"] == "proof"
                    for name in target["functions"]}
        old = [target for name, target in targets.items() if not name.startswith("common.unaligned24.")]
        self.assertEqual(functions(targets.values()), functions(old))
        self.assertTrue(all(not name.startswith("fragma_") for _, name in functions(targets.values())))

    def test_source_blocks_exist_and_genuine_functions_stay_source_exact(self):
        revision, targets, _ = suite.load_registry(ROOT)
        # Read-only git-blob comparison. It does not compile or run kernel code.
        kernel = ROOT.parent / "linux"
        if not (kernel / ".git").exists():
            self.skipTest("pinned kernel source is not available")
        for suffix in ("arm", "powerpc32", "m68k"):
            target = targets["common.unaligned24." + suffix]
            gate = provenance.check_target(target, kernel, revision, ROOT)
            self.assertTrue(gate["passed"], gate["errors"])
            self.assertEqual(len(gate["functions"]), 4)

    def load_changed(self, mutate):
        def read(path):
            data = json.loads(path.read_text())
            for target in data.get("targets", []):
                if target["id"] == "common.unaligned24.arm":
                    mutate(target)
            return data
        with patch.object(suite, "read_json", side_effect=read), \
                patch("subprocess.Popen", side_effect=AssertionError("registry must not execute tools")):
            return suite.load_registry(ROOT)

    def test_bad_frontend_settings_reject_at_registry_before_execution(self):
        for value in (None, {}, {"schema_version": True, "kind": "common24-inline", "variant": "no-instrument"},
                      {"schema_version": 1, "kind": "common24-inline", "variant": "host-default"},
                      {"schema_version": 1, "kind": "common24-inline", "variant": "no-instrument", "flags": []}):
            with self.subTest(value=value), self.assertRaisesRegex(suite.SuiteError, "frontend policy"):
                self.load_changed(lambda target: target.update(frontend_policy=value))

    def test_missing_selector_cannot_hide_behind_path_aliases(self):
        for path in ("common/annotated/unaligned24.verified.c",
                     "common/annotated/./unaligned24.verified.c",
                     "common/annotated/../annotated/unaligned24.verified.c"):
            def mutate(target):
                target.pop("frontend_policy")
                target["harness"] = path
                target["kernel_model_check"] = "common/annotated/./kernel-model-check.c"
            with self.subTest(path=path), self.assertRaisesRegex(suite.SuiteError, "explicit policy"):
                self.load_changed(mutate)


if __name__ == "__main__":
    unittest.main()
