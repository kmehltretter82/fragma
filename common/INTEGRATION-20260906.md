# Registered common24 integration — 2026-09-06

The normal runner now produces complete ordinary proof inventories for the shared
24-bit helpers on ARM32, PowerPC32 and m68k. This is an integration milestone,
not an L2 baseline: all three targets remain `unsupported`, `accepted: false`,
with pending assumptions and unreviewed diagnostics. The suite correctly exits 1.

## Actual run and independent readback

The [three-target summary](../results/common24-integration-20260906/SUMMARY.md)
records a run from 07:54:28 to 08:03:35 UTC, using pinned kernel revision
`b9b3e33b70b71e516930117e21de3ad2a7723747` and the locked local toolchain.
All three fresh configured models passed their 18 checks (54 in total).

| Profile | Inline policy | Ordinary goals | Selected properties | Smoke checks | Warnings | Analyzer seconds |
| --- | --- | --- | --- | --- | --- | --- |
| ARM32 | `no-instrument` | 94 valid | 82 Valid | 12 inconclusive | 5 | 177.856 |
| PowerPC32 | `patchable-entry-0` | 94 valid | 82 Valid | 12 inconclusive | 6 | 177.691 |
| m68k | `no-instrument` | 94 valid | 82 Valid | 12 inconclusive | 5 | 177.597 |

All analyzer processes returned 0 without a wall timeout. The
[independent audit](../build/common24-integration-audit-20260906/REPORT.md)
reparsed the raw reports, reconstructed frontend and coverage readback, and
checked 1,021 unique recorded input hashes without drift. The actual compiler
fixtures, preprocessing commands, six C functions, two typedefs and ordered
24 ACSL blocks match their checked identities.

The exact inventory includes all 16 intermediate assertions, 12 functional
postconditions, 12 memory-access guards, 12 pointer-formation guards, four shift
guards and four direct-call preconditions, with complete dependency closure.
The full original input domains remain: arbitrary valid three-byte reader ranges
and full `u32` writer/witness values. These three profile variants do not add
distinct kernel functions; the two round-trip witnesses are project code.

Summary SHA-256:
`4fcaa96ed5296873b6dfd7223bad0a2098041fc6e838649a22cc86df368af114`.
Independent audit SHA-256:
`206eba1e8b5c7cac9615542300088a06d52e14d24b5811406b2709549a37e92d`.

## Tests, calibration freshness and coverage

The [evidence-backed test run](../results/tests-common24-integration-final-20260906.log)
passed all 456 tests, with no skips, in 63.360 seconds. Its SHA-256 is
`446671a344a0a94b2d8e959400b325cc1482a2a5fdb9394ffee334eb951cfb7b`.
The retained earlier integration log failed three native freshness checks;
fresh [string and s390 receipts](../build/native-refresh-readback-20260906/READBACK.md)
resolved those stale bindings without weakening validation. Those nine valid-input
runtime cases belong to the existing string/s390 calibrations, not to these
three new architecture variants.

The [new coverage matrix](../results/coverage-common24-integration-20260906/coverage.md)
explicitly includes the old 22-target suite, this three-target run and all ten
configured standalone profile receipts. It retains all 21 architectures and
24 distinct kernel functions. There are 18 functions with a dated reported
accepted variant, but zero currently accepted variants: shared-input changes
stale the older approvals, while the three new results are current but unaccepted.
That distinction is evidence freshness, not a finding that the kernel regressed.
All 2,818 coverage-generation input hashes and 327 retained artifact rows were
rechecked without mismatch. New unaccepted targets also passed the separate
raw-artifact audit above; coverage does not require successful-only artifacts
merely to list an unsuccessful result.

## Reproduce and next acceptance work

Use a new output directory with the already prepared builds:

```sh
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" \
  python3 -m fragma run --kernel /home/karl/linux-work/linux \
  --target common.unaligned24.arm --target common.unaligned24.powerpc32 \
  --target common.unaligned24.m68k --output results/common24-new \
  --timeout 1 --wall-timeout 600 --jobs 2
```

No package installation or compiled-object execution is part of this command.
The checked proof strategy has separate child budgets. Retained evidence can be
audited read-only with the dated audit script while its frozen inputs still match.

The no-skip test run explicitly supplied the retained evidence directories below.
Historical analyzer artifacts are read as historical test data, not silently
accepted as current proof receipts:

```sh
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" \
  FRAGMA_POINTER_AUDIT_RESULTS="$PWD/build/pointer-formation-review" \
  FRAGMA_POINTER_BUILTIN_RESULTS="$PWD/results/pointer-policy-non-s390-20260906" \
  FRAGMA_REPLAY_PROJECT="$PWD" \
  FRAGMA_STRING_NATIVE_RESULTS="$PWD/build/string-sensitivity/native-9" \
  FRAGMA_S390_NATIVE_RESULTS="$PWD/build/s390-sensitivity/native-5" \
  FRAGMA_RISCV_PROOF_RESULTS="$PWD/build/riscv-verified/proof-work/all-fields-5" \
  FRAGMA_UM_PROFILE_RESULTS="$PWD/build/profile-checks/pointer-policy-final-20260906/um-x86_64-gcc" \
  FRAGMA_ARM64_CPUID_RESULTS="$PWD/results/pointer-policy-final-ci-20260906/suite/arm64.cpuid" \
  FRAGMA_STRING_SENSITIVITY_RESULTS="$PWD/build/string-sensitivity/baseline-3" \
  python3 -m unittest discover -s tests -q
```

Remaining acceptance requirements:

1. Finish the target-local type/frontend assumption and diagnostic reviews,
   binding the exact source, model, commands and checker implementations.
   The [scoped review draft](../build/common24-review-draft-20260906/REVIEW.md)
   maps all 5/6/5 warnings and both pending assumptions to the actual operations;
   it is not an approval or a substitute for the remaining calibration gates.
2. Integrate and independently validate the existing fixed-input compiler
   sensitivity checks under current inputs. The staged 22 observations and
   22 rejected expectations per profile are compiler-only evidence, not native
   execution, an ACSL interpreter or L3.
   A [tested orchestration draft](../build/common-byte-calibration-integration-draft/PLAN.md)
   now records exact compile-only commands, required artifacts and input drift;
   it deliberately cannot issue calibration acceptance until its listed
   object-definition, environment, review and production-integration gates close.
3. Regenerate reviewed proof/calibration evidence, then refresh the affected
   full suite and coverage. Full replay currently rejects these pending-review
   receipts with `assumption approvals are incomplete`; no replay success is claimed.

Smoke timeouts do not prove consistency. No claim covers kernel callers,
instrumentation, generated instructions, traps, assembly, MMIO or concurrency.
The other architecture L2 baselines and remaining PLAN.md milestones stay open.
