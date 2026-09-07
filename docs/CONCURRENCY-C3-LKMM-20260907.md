# C3 Linux LKMM/herd7 capability baseline — 2026-09-07

Status: **accepted as a semantic capability calibration; 92/92 checks pass;
zero production-kernel properties and zero defects are claimed**.

The current result is
[`results/concurrency-c3-lkmm-20260907-05`](../results/concurrency-c3-lkmm-20260907-05/SUMMARY.md).
This renewal changes only the recorded CLI identity after adding the IPC
refcount command; the four semantic outcomes are unchanged.
It establishes that the exact local `herd7` executable can run the exact model
from the pinned Linux snapshot and distinguish canonical weak outcomes from
their ordered counterparts. It is the prerequisite for source-linked C3 work,
not by itself a verification of kernel production code.

## Pinned execution chain

| Input | Accepted identity |
| --- | --- |
| Linux source | `b9b3e33b70b71e516930117e21de3ad2a7723747`, tree `054b6818c409ab20ae89b1031a1a7c358f673d87` |
| Kernel model | Snapshot-owned `linux-kernel.{cat,bell,cfg,def}` and `lock.cat`, each SHA-256 checked |
| Provider | `/usr/bin/herd7`, `7.58, Rev: exported`, SHA-256 `f398c4ba11ee87226e104efc77e64873cf775292e16b90e1e71015962969060b` |
| Generic CAT library | `stdlib.cat`, `cross.cat`, and `cos-opt.cat` from herdtools7 tag 7.58, commit `1ca343e16a2038e406d1ac674e7e3a1b722b36c7` |
| Library license | Upstream CeCILL-B text retained in `third_party/herdtools7-7.58/LICENSE.txt` |

Linux's own README requires herdtools7 7.58 or newer and recommends the exact
version for compatibility with this model. Fragma pins 7.58 exactly rather than
claiming compatibility with a later untested provider.

The Ubuntu package's compiled-in library directory is
`/sbuild-nonexistent/share/herdtools7/herd`, so an otherwise normal invocation
cannot locate `stdlib.cat`. The project vendors only the three small generic
helpers needed by this model and invokes herd with an authenticated absolute
`-set-libdir`. The Linux model itself remains supplied by and executed from the
pinned kernel snapshot. No system file was changed and no installation was
performed.

## Detecting semantic pairs

| Pair | Weakened control | Ordered calibration | Result |
| --- | --- | --- | --- |
| Message passing | `WRITE_ONCE` + `READ_ONCE`: 4 states, 1 bad witness, `Sometimes` | `smp_store_release` + `smp_load_acquire`: 3 states, 0 bad witnesses, `Never` | Detects the missing release/acquire ordering |
| Store buffering | `WRITE_ONCE` + `READ_ONCE`: 4 states, 1 bad witness, `Sometimes` | `smp_mb`: 3 states, 0 bad witnesses, `Never` | Detects the missing full barriers |

The condition is identical within each A/B pair. Every test file, parsed test
name, disposition, state count, state inventory, witness count, condition,
observation and herd hash is checked. Truncation, extra output, contradictory
witness counts, duplicate states and mismatched test names are rejected. A
successful process exit alone cannot pass the gate.

The first retained development attempt,
`results/concurrency-c3-lkmm-20260907-01`, is a failed 74/92 result: all herd
commands exited zero, but the initial parser rejected the provider's second
terminal newline and therefore accepted no semantic result. The correction
permits exactly one or two terminal newlines while continuing to reject other
trailing text. The later `-02` pass became stale when the source-linked runner
was added; `-03` is the current standalone renewal.

## What this accepts

This result accepts three capabilities:

1. The pinned provider/model/library chain executes reproducibly.
2. LKMM outcomes are not substituted with Mthread's ordinary interleavings.
3. The selected `READ_ONCE`, `WRITE_ONCE`, release/acquire and `smp_mb`
   primitives produce independently detecting outcomes.

It accepts no production function, compiler lowering, architecture
implementation, lock-free functional behavior, lifetime argument or progress
claim. The source-linked trace pilot supplies one separate, narrower production
property. Atomic read-modify-write operations still need their own calibration.

## Reproduce

From the repository root:

```text
python3 -m fragma concurrency-c3-lkmm \
  --output results/concurrency-c3-lkmm-NEW
```

The command never overwrites an existing directory. It retains provider
inventory, exact argv and working directory, stdout/stderr, per-case parsed
results, manifest snapshot, input identities and raw-artifact hashes. It does
not run `klitmus7`, generate/load a module, touch the running kernel, install a
package or invoke `sudo`.
