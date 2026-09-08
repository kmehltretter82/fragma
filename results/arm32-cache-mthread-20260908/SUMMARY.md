# ARM32 `__sync_icache_dcache()` checkpoint — 2026-09-08

Classification: `known-fix-detection-calibration-no-new-bug`.

This is the fourth candidate to enter the recent-risk ARM32 search funnel and
the first production-function Mthread + Eva pilot in that funnel. It is not a
new Linux bug report. The candidate's April 2026 trigger commit had already
fixed an early `PG_dcache_clean` publication race. The pilot detects a
mutation-equivalent version of that old ordering defect and accepts the fixed
ordering in the pinned source.

## Source and configured-build identity

The current `__sync_icache_dcache()` named declarator and body are copied
token-for-token from `arch/arm/mm/flush.c` at
`b9b3e33b70b71e516930117e21de3ad2a7723747`:

- function tokens: 136;
- function token SHA-256:
  `d9fdc83818a53012672cf8cbc372fc74db4d1956a4dd42143c49293d7dc49438`;
- source-file SHA-256:
  `8642de64dfcadfc0cd911192a12fde073972238ebda24ffd0d8b9a9bb7d87b81`;
- configured ARM32 `flush.o` SHA-256:
  `b5bb4ea5b7b1965b70e058efd5176c4626acbb1d9f4d326ad6550006a53b8306`.

Four attempts to analyze the exact configured translation unit stopped before
the candidate in unrelated transitive-header constructs. The failures are
retained locally under `build/arm32-recent-search-20260908/cache-raw-tu-*`.
Temporary diagnostic header adapters were removed. A mechanically extracted
source-gated slice then completed a sequential RTE/Eva pass with nine selected
valid properties, no unresolved/invalid properties and no warnings. This only
checks direct sequential C runtime safety over the modeled input domain.

| Sequential artifact | SHA-256 |
| --- | --- |
| Run summary | `63c43811a515bea398126c2eb51dd872b5b406ee2a9512fc1dc5125ada177e23` |
| Target result | `aa348fd02a8e9f5d110d577959b704ba24c01b1e13dd9b33181d7f838f4024c6` |
| Analyzer log | `1c03285e8a4154e24985e6c5cbca24bfed90bc388a7332590c5e98b2f1059d73` |
| Property report | `a670db0b36a40988e30d0799264c63e773ed218f66ff1b3dfb2a246e99fae7bd` |

Local output:
`build/arm32-recent-search-20260908/cache-slice-final-2`.

## Mthread + Eva ordering A/B

Two modeled callers invoke the unchanged candidate. The property at the
modeled `set_bit()` boundary requires that the same caller has completed its
modeled data-cache flush before publishing the clean bit. Per-thread ghost
state records that event. An abstract Mthread mutex gives indivisible access
to the one modeled page-flag word; it is not held across the candidate's
test/flush/set sequence, and the flush event itself does not take that mutex.

| Case | Property | Final flag-word protection | Result |
| --- | --- | --- | --- |
| Current source (`test_bit`; flush; `set_bit`) | valid | protected by `arm32-cache-bit` | pass |
| Early-publication negative control | invalid | unavailable after invalid-path stop | pass |

The negative macro changes only the modeled `test_bit()` helper, leaving the
source-gated candidate function unchanged. It publishes before the candidate
flush, corresponding to the ordering defect fixed by commit
`75f9a484e817adea211c73f89ed938a2b2f90953`. Eva stops propagation at the
deliberately invalid property, so Mthread has no final shared-object protection
row for that control; the runner requires this exact outcome and separately
requires mutex initialization, a completed analysis fixpoint, and no reported
unprotected race or unsupported primitive.

The calibrated provider binary SHA-256 is
`815c916df2361e7af5a18125c97b37665e4eed91e76daa185d571706563e7ef2`.
The Mthread fixture SHA-256 is
`e35cf9a984b40ac29ca420ebbeed6c5a88bf6d012bf0aeef06fc4dc7fdd74a24`.

| Mthread artifact | SHA-256 |
| --- | --- |
| Run summary | `eb16ce295a46d09ad1ab265ed83a78d110625dd0fdd499274b37e612ba2588ec` |
| Generated compact summary | `5aec22be99e30d2d5a3189149cdead7a30f939ebf25010fc5e35c4c8affc3f8f` |
| Current-source property report | `78628172cad10e791118084031aaf4a8002290738b298c562a51e7b4d6f17978` |
| Early-publication property report | `559c7749601ca25a50ced61f3b68562f4003ec0c7c89f5caa3895ffeb9b5b9e5` |

Local output:
`build/arm32-recent-search-20260908/cache-mthread-runner-9`.

Reproduction command:

```sh
python3 -m fragma arm32-cache-mthread \
  --kernel /home/karl/linux-work/linux \
  --output /new/evidence/directory
```

The accepted property does not model the ARM bitop implementation, barrier
strength, LKMM/weak-memory behavior, cache-maintenance assembly or hardware
effects, concurrent dirty-bit clearing, folio lifetime, interrupts, progress,
or arbitrary callers. Those exclusions prevent this useful sensitivity test
from being mislabeled a proof of cache coherency.

New bugs found by this checkpoint: **0**. The next untouched target is the
January 2026 ARM uprobes `arch_uprobe_copy_ixol()` change, followed by the two
DMA/scatter-gather candidates.

Regression: `python3 -m unittest discover -s tests -v` passed 1,094 tests with
20 skips. The local log SHA-256 is
`65ed45790e38e232b9eb1b40d8e7cf6ed1aa81e311bd33f7bb1aa2881954a781`.
