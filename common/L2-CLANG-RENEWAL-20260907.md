# Common24 scoped L2 renewal — nine GCC profiles, 2026-09-07

Later status: registering `mips32el-clang` changed the central toolchain-lock
and review-context identity. This document remains exact evidence for its run,
but its scoped L2 acceptance is dated until post-registration replay.

The same four explicit-byte Linux helpers again meet the scoped [L2 criteria](../PLAN.md)
under all nine common24 profiles. This decision follows fresh normal proof
execution, independent retained-evidence/replay audit and the corrected explicit
coverage audit at Linux `b9b3e33b70b71e516930117e21de3ad2a7723747`.
The renewal follows shared build/profile/toolchain changes for Clang support;
these nine proof profiles still use their original GCC compilers, not Clang.

Scope review: Codex AI assistant, with independent proof-evidence and coverage
audits by separate AI agents; not a human approval. The existing
[first-wave](REVIEW-20260906.md), [wave-two](REVIEW-WAVE2-20260906.md) and
[wave-three](REVIEW-WAVE3-20260906.md) reviews remain unchanged. Their inputs,
assumptions, full domains, compiler identities, machine-description bytes and
actual preprocessing commands still match. New runs, not review rehashing,
restore current acceptance. No audit or generated coverage cell itself awards L2.

## Exact scope and completed batches

The kernel functions are `__get_unaligned_be24`, `__get_unaligned_le24`,
`__put_unaligned_be24` and `__put_unaligned_le24` in `include/linux/unaligned.h`.
The two `fragma_roundtrip_*24` witnesses are project code. Thirty-six checked
helper/profile pairs still represent only four distinct kernel functions.
Getters require three readable bytes; writers require three writable bytes and
accept every `u32`. Witnesses recover the input modulo 2^24. No extra alignment,
storage extent or value restriction was introduced.

All six analyzed bodies, both typedefs, 24 ordered ACSL blocks and 16
intermediate assertions remain present per profile. The actual frontend retains
`no-instrument` on eight profiles and PowerPC32's `patchable-entry-0` policy.
Hardware x86/UML keep their genuine `-Os` compiler commands; the other seven
profiles keep `-O2`. Exact source-derived compiler assertion identities and
Alpha's narrowly supported ELF metadata remain checked.

| Fresh normal batch | Profiles | Completed UTC | L1 checks / ordinary goals / selected properties |
| --- | --- | --- | --- |
| [Wave 1](../results/common24-clang-renewed-socket-enabled-wave1-20260907/SUMMARY.md) | `arm-gcc`, `powerpc32-gcc`, `m68k-gcc` | 00:19:41.052197 | 54 / 282 / 246 |
| [Wave 2](../results/common24-clang-renewed-socket-enabled-wave2-20260907/SUMMARY.md) | `arm64-gcc`, `riscv64-gcc`, `sh-gcc` | 00:19:41.472929 | 54 / 282 / 246 |
| [Wave 3](../results/common24-clang-renewed-socket-enabled-wave3-20260907/SUMMARY.md) | `alpha-gcc`, `x86_64-gcc`, `um-x86_64-gcc` | 00:19:41.400977 | 56 / 282 / 246 |

Each batch exits 0 with three accepted targets. They are separate profile
batches, not equivalent repeat runs or second-location replay. The
[new launcher](../build/common24-clang-renewal-socket-enabled-20260907/run_batch.py)
retains the original exact target selection, clean environment, one-second
solver timeout, 600-second analyzer wall limit, two jobs and 2,400-second outer
limit. Local Why3 socket access was separately authorized; no package was
installed and the launcher does not change sandbox permissions.

The total is 164 passing L1 checks, 846 valid ordinary goals and 738 Valid
selected properties: exactly 94 ordinary goals and 82 selected properties per
profile. Every selected memory-access, pointer-formation, shift and direct-call
obligation passes with complete unconditional dependency closure. No required
dependency, trusted proof dependency or missing report entry is waived. The
analysis tools and explicitly reviewed model assumptions remain trusted;
assumption records retain `implementation_proved: false`.

All 46 actual warnings retain individual scoped reviews. All 108 smoke outcomes
remain inconclusive; `reviewed_smoke` is empty and no consistency theorem follows.
Nine genuine-header fixtures, 225 core compiler/preprocessor commands and 18
wrong-type/inline controls total 252 compiler observations. All 198 wrong fixed
expectations have their intended sole errors and produce no object. Positive
preprocessing supplies each profile's 22 assertion identities; negative
diagnostics do not choose their own expectations.

## Proof audit and runtime boundary

The [independent proof audit](../build/common24-clang-renewal-socket-enabled-audit-20260907/audit-1.json)
exits 0 and finishes at 00:21:28.623256 UTC. All three full replay views are
comparable and accepted. It rechecks 5,155 unique hashes, including 3,927 retained
run files, with zero drift; a subsequent independent hash readback also matches
every path. It verifies the wrapper/child PID, start-time, executable, command,
session and intent records, terminal reaping, and 16 immutable original-attempt
references. Its 2,985 bounded Git revision/blob reads all succeed. No compiler,
analyzer or native program is rerun by the audit. Production revalidators are
reused alongside independent inventory checks, not presented as a second proof
engine or a hermetic descendant-process attestation.

The normal hardware-x86 model check separately builds/runs the existing benign
`profiles/calibration.c` fixture under its recorded `-O2` model context. This is
not execution of the genuine `-Os` common24 object, UML execution or L3 evidence.
No common24 object or historical fault/trap/out-of-bounds harness is executed.
The latest [891-test regression](../results/tests-hexagon-gnu-model-20260906.log)
remains a separate passing observation; this renewal does not claim a new
regression-test run.

## Preserved failures and current coverage

The [original socket-denied attempts](RENEWAL-SOCKET-FAILURE-20260907.md)
remain unchanged: three wrapper failures with child return code `-9` and
`KeyboardInterrupt`, after Why3 IPC errors and first-target analyzer timeouts.
Their inner suite summaries still say `running` without a completion time.
They are excluded from completed matrix history because they are incomplete,
not because they failed. The coverage audit separately binds all three failed
attempts, six started-analysis logs and retry chronology; no terminal summary
or accepted proof was manufactured for them.

The [current matrix](../results/coverage-common24-clang-renewed-socket-enabled-20260907/coverage.md)
retains seven explicit completed summaries and ten standalone model receipts.
Across 31 target IDs it reports nine accepted-current, 16 accepted-stale and six
legacy nonpasses. Four of 24 distinct kernel functions have current accepted
variants; 18 have latest-reported accepted variants including dated evidence,
and 20 lack current acceptance. Calibration and project witnesses do not add
kernel functions or establish kernel-caller coverage.

[Coverage audit 1](../build/common24-clang-coverage-socket-enabled-audit-20260907/audit-1.json)
is preserved as a failure. It incorrectly required every historical acceptance
to remain revalidatable under the current context. The
[narrow successor correction](../build/common24-clang-coverage-socket-enabled-audit-20260907/AUDIT-CORRECTION.md)
requires exactly nine old common24 observations to retain
`unavailable-or-mismatched` / `current context/gate differs`, with exactly the
changed `fragma/build.py`, `fragma/profiles.py` and `fragma/toolchain.py` bindings.
Those history entries remain stale with `current_accepted` and
`current_verified` false. The exception cannot excuse a new failed proof.

[Coverage audit 2](../build/common24-clang-coverage-socket-enabled-audit-20260907/audit-2.json)
passes at 00:29:25.717407 UTC: 4,500 generation inputs, 1,218 artifact references
(1,161 unique paths), all four Markdown tables, and no discrepancies or drift.
A separate post-readback combines its initial inputs, matrix generation inputs
and standalone-index inputs: 5,447 records deduplicate to 5,027 paths, all
matching their SHA-256 values. That count is an additional execution-tool
readback, not a field or separate saved sidecar in audit 2.

Ten standalone models remain current L1; the nine new suites also supply current
dated model observations. Older dated s390 model/proof evidence remains stale.
Together these nine fresh scoped L2 baselines and the
[dated seven-helper s390 pilot](../s390/PILOT-20260906.md) name ten architecture
baselines; [eleven families](../profiles/NEXT-WAVE.md) still lack one. Generated
architecture-level cells remain `not-assessed`.

Full-suite renewal stays open. Six legacy nonpasses, remaining older suites,
second-location replay, kernel callers, broader ABI/endian/configuration variants,
instrumentation, assembly, traps, MMIO, concurrency and L3 remain outside this
renewal. This work neither registers Hexagon nor claims a new Hexagon
extended-alignment diagnostic or L1 result. No genuine Linux kernel defect has
been confirmed by these proof-renewal results.

## Recorded identities

```text
53949e31e7e7f7287345daaa73ca99f6dd2a25ddd0f477788cf9d09a7ac394b7  retry launcher
008d5dce65d15118bf5b2a2995a76be31332dfd9ea1d0331c5f66632faa86104  proof audit script
769791c4c7ea1ee1b0d22da794fadc1d70f014256525f73e29eeeebc3c3eafe3  proof audit-1.json
25195c56868dd218b825e901319fd9f68a2a9b9393b6b0406283eea4c7a0ab11  coverage.json
4a0654649d48d54c32aac202eba5e4a56a553fbd49ff2f6c2dc7877ee2edfafe  coverage.md
70d11d106d2b8ca9a6f4d6ba8102f202d016efc4b684cdd72c49ec372443f6ec  preserved coverage audit-1.json
fad7b9d719ae74c7f22ba79fddc1fc1003b1f02eb305f6f6a667cc56d975d6fa  passing coverage audit-2.json
```

These are local file identities, not tamper-resistant attestations. All earlier
review documents, proof records, incomplete attempts and failed audit receipts
remain preserved.
