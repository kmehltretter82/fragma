# Nine calibration renewals, 2026-09-07

All nine selected Eva specification-sensitivity targets now pass the normal
runner under the current shared provider identity. Both batches completed with
exit 0. Sources, drivers, contracts, models, assumptions and retained native
receipts were not changed. These are bounded valid-input calibration cases,
not nine new kernel proofs or evidence of a Linux kernel defect.

## Completed evidence

| Batch | Completed UTC | L1 checks | Selected positive properties Valid | Deliberate negative assertions |
| --- | --- | ---: | ---: | ---: |
| [s390 byte order](../results/calibrations-clang-renewed-s390-20260907/summary.json) | 02:19:52.077050 | 18 | 16 | 1 |
| [Eight string cases](../results/calibrations-clang-renewed-strings-20260907/summary.json) | 02:20:28.960162 | 20 | 39 | 8 |
| Total | | 38 | 55 | 9 |

The string cases cover truncation, no room to copy, full copy, first match,
conversion to NUL, early NUL, zero count and count cutoff. The s390 case checks
one concrete BE24 decode. Positive observations precede one deliberately false
assertion per entry. None of the actual calls violates its selected API domain.

All nine negative rows retain the raw analyzer status `Invalid or unreachable`.
That label alone does not establish reachability. The normal runner independently
revalidates the explicit [string native-9 receipt](../build/string-sensitivity/native-9/receipt.json)
and [s390 native-5 receipt](../build/s390-sensitivity/native-5/receipt.json), including
their source/model/build identities, generated adapters, complete retained
artifacts and reached false observations. No historical native provider was
rerun, and no analyzer label was rewritten. The selected calibration outcomes
are `calibration-passed`, with `verified=false` and no kernel correctness claim.

All 789 raw warnings remain visible: 787 across the string batches and two in
s390. These targets have no scoped warning-review envelope; passing their
existing calibration policy is not a new blanket warning waiver. The string
byte-copy implementation remains an explicit trusted dependency. Unselected
whole-translation-unit rows are not additional accepted properties.

Independent read-only audit reconstructs the raw TSV rows, warnings, actual
analysis policy/audit, source/dependency gates, assumptions, native envelopes
and acceptance decisions. All nine result objects equal their summary entries.
The native envelopes match the current validators exactly; their combined
474-file closure is unchanged. The calibration audit rehashes 1,556 unique
recorded inputs and snapshots all 300 retained result files before and after
readback, with zero drift. These are execution-tool audit results, not a saved
audit JSON, a new solver replay or a tamper-resistant attestation.

Normal profile validation includes the separate benign x86 model-calibration
runtime fixture. No historical native fault, trap or out-of-bounds harness was
executed. No installation, new kernel build, production change or full project
test run was performed. The latest separate regression remains the recorded
[891-test pass](../results/tests-hexagon-gnu-model-20260906.json).

## Exact normal-run commands

These commands were run from the project root in the ordinary sandbox. The
per-analyzer wall cap does not bound the entire batch or setup. Output directories
were absent before invocation; choose new directories for any future run.
Exact analyzer argv, preprocessing and input hashes are in the normal receipts.

```sh
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  FRAGMA_TOOLCHAIN_PREFIX=/home/karl/linux-work/fragma/toolchain/verified-prefix \
  /usr/bin/python3 -B -m fragma run --kernel /home/karl/linux-work/linux \
  --timeout 1 --wall-timeout 600 --jobs 2 --provers alt-ergo,z3 \
  --target calibration.s390.byte-order.eva \
  --native-evidence /home/karl/linux-work/fragma/build/s390-sensitivity/native-5/receipt.json \
  --output /home/karl/linux-work/fragma/results/calibrations-clang-renewed-s390-20260907

env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  FRAGMA_TOOLCHAIN_PREFIX=/home/karl/linux-work/fragma/toolchain/verified-prefix \
  /usr/bin/python3 -B -m fragma run --kernel /home/karl/linux-work/linux \
  --timeout 1 --wall-timeout 600 --jobs 2 --provers alt-ergo,z3 \
  --target calibration.string.truncation.eva \
  --target calibration.string.no_copy_room.eva \
  --target calibration.string.full_copy.eva \
  --target calibration.string.first_match.eva \
  --target calibration.string.nul_conversion.eva \
  --target calibration.string.early_nul.eva \
  --target calibration.string.zero_count.eva \
  --target calibration.string.count_cutoff.eva \
  --native-evidence /home/karl/linux-work/fragma/build/string-sensitivity/native-9/receipt.json \
  --output /home/karl/linux-work/fragma/results/calibrations-clang-renewed-strings-20260907
```

## Current coverage and limits

The [new coverage matrix](../results/coverage-calibrations-clang-renewed-20260907/coverage.md)
has 25 accepted-current targets: 16 proof variants and nine calibrations.
There are no accepted-stale targets. Six legacy nonpasses remain unchanged:
three inconsistent, two unsupported and one incomplete. Eighteen of 24 distinct
kernel functions have a current accepted proof variant; calibration renewals
do not add functions or caller coverage. The
[generation command and independent audit](../build/calibration-clang-renewal-audit-20260907/README.md)
retain all twelve completed summaries and the same ten standalone model paths.

The [s390 seven-helper scope renewal](../s390/L2-RENEWAL-20260907.md) separately
checks the existing pilot's four mandatory targets across two authentic
completed summaries. Neither this calibration note nor the coverage generator
awards general architecture support. Full-suite renewal remains open for the
six legacy cases; relocation, callers, eleven other architecture baselines and
Hexagon alignment/integration also remain unfinished.

```text
7afccfc966880748c529c0e9489b700eeff4c69beebdb6100f9bb6acb50d9e4c  s390 summary.json
d47a0b3ecc8eba3ae74b58ae92651a7062c325a7362f845ca71d7cf26f7348c7  strings summary.json
72489743032adaa50e9f199837a4353499ed0172372d12b95f8260177155a38a  string native-9/receipt.json
70e6f6832f189533d412692ec1b9a0f58436910ad18fdc11e67e695bc9e0b6df  s390 native-5/receipt.json
```
