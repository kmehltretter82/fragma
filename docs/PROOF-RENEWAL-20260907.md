# Seven proof-target renewals, 2026-09-07

Later status: registering `mips32el-clang` changed the central toolchain-lock
and review-context identity. This document remains exact evidence for its run,
but its proof acceptance is dated until post-registration replay.

All seven selected non-common WP targets now pass the normal runner under the
current shared provider identity. Three separately authorized batches completed
with exit 0, retaining their original sources, contracts, reviews and full input
domains. This renews conditional proof acceptance, not the entire suite or an
architecture support level. No Linux kernel defect is established.

## Completed evidence

| Batch and retained summary | Completed UTC | L1 checks | Ordinary goals | Selected Valid properties |
| --- | --- | ---: | ---: | ---: |
| [ARM64/RISC-V scalars](../results/noncommon-clang-renewed-scalars-20260907/summary.json) | 01:45:40.885842 | 36 | 125 | 129 |
| [s390 helpers](../results/noncommon-clang-renewed-s390-20260907/summary.json) | 01:47:33.807686 | 18 | 183 | 158 |
| [Verified strings](../results/noncommon-clang-renewed-strings-20260907/summary.json) | 01:42:02.872561 | 20 | 110 | 44 |
| Total | | 74 | 418 | 331 |

The exact seven target IDs are `arm64.cpuid`, `riscv.base-encoders`,
`s390.unaligned24`, `s390.unaligned48`, `s390.tod_to_ns`,
`string.verified.strnchr` and `string.verified.strlcat`. Each actual analyzer
command returns 0 without a timeout; all ordinary goals and selected properties
pass their existing gates. The recorded budgets remain one second per prover
attempt, 600 seconds per analyzer and two jobs. Exact analyzer argv, working directories,
logs, parsed input streams and input identities remain in the per-target raw
receipts linked through those summaries. Earlier failed or dated results are
not overwritten or substituted.

There are 47 inconclusive smoke observations. Two additional `strlcat` smoke
rows retain their raw `inconsistent` outcome and their existing, narrowly scoped
unreachable-branch reviews; they were not relabeled as successful consistency
checks. The 177 raw warning records are preserved. Thirty-two selected-scope
warnings match existing reviews, not a blanket waiver of all warnings or support
for alignment-sensitive operations. No review or assumption was rewritten for
this renewal.

Independent retained-evidence readback checks 2,031 file hashes without drift,
including the actual normal-run inputs and reports. This is an execution-tool
readback result, not a separately saved audit JSON or a new solver replay.
The latest separate [891-test regression](../results/tests-hexagon-gnu-model-20260906.json)
was not rerun by this proof renewal.

Normal model checks were performed, including the separately recorded benign
x86 host calibration fixture. No historical native string/s390 fault, trap or
out-of-bounds harness was rerun, and no native provider receipt was supplied to
these three WP batches. No installation, source/configuration/toolchain change
or new kernel build was part of the proof renewal.

## Current coverage and remaining scope

The [new explicit coverage matrix](../results/coverage-common-and-noncommon-clang-renewed-20260907/coverage.md)
retains all ten completed summaries: the prior seven inputs plus these three,
with the same ten standalone model paths. Its
[exact command and independent readback](../build/common-and-noncommon-clang-coverage-audit-20260907/README.md)
verify 4,654 generation-input hashes, 1,330 artifact references (1,270 unique
paths), 47 raw target receipts, 26 dated model receipts and all four Markdown
tables. All 40 prior target observations and 32 prior model observations remain
unchanged. No result discovery or success-only selection was used.

The matrix has 16 current accepted proof variants, nine stale accepted Eva
calibrations and six legacy nonpasses. Eighteen of 24 distinct kernel functions
have a current accepted variant; six lack one. Repeated profile variants and
project round trips do not add distinct kernel functions. All ten profiles
configured at this dated renewal had current latest-dated L1: the 26 dated model observations
comprise 13 current and 13 stale observations, alongside ten current undated
standalone observations. Eleven additional profile rows remain planned.

The renewed s390 WP groups prove the seven pilot helpers, but its byte-order
Eva calibration remains stale. Therefore its full
[historical scoped L2 decision](../s390/PILOT-20260906.md) is still dated, not
newly awarded here. The [nine common24 scoped L2 baselines](../common/L2-CLANG-RENEWAL-20260907.md)
remain freshly renewed. These are ten named architecture baselines when dated
s390 is included, not ten newly completed whole-profile suites or L3 support.

ARM64 cpuid acceptance remains runtime-safety-only; functional contracts and
caller proofs are separate work. The seven RISC-V encoder proofs still need
their separate calibration/scope decision before an encoder L2 claim. String
proofs remain conditional on their contracts and trusted external interfaces;
the eight string Eva calibrations have not been renewed. The ninth stale Eva
calibration is s390 byte order. All six legacy nonpasses remain visible, even
where another contract variant for the same function now passes.

Full-suite renewal remains open for these calibrations and legacy outcomes,
alongside relocation, kernel callers, broader architecture/ABI coverage and the
blocked Hexagon integration work. The
[interrupted common24 attempts](../common/RENEWAL-SOCKET-FAILURE-20260907.md)
remain preserved outside completed matrix history because their summaries are
incomplete. The failed first coverage audit also remains preserved unchanged.
