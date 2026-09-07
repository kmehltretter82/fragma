# C3 LL/SC progress capability audit — 2026-09-07

Status: accepted as a fail-closed capability evaluation of six existing IPC
implementation profiles. It accepts **zero** new kernel progress properties and
promotes **zero** LL/SC mappings. C3 remains incomplete.

The accepted evidence is
[`results/concurrency-c3-llsc-progress-20260907-04`](../results/concurrency-c3-llsc-progress-20260907-04/SUMMARY.md).
All 505 checks pass. The receipt binds 18 direct inputs, retains 27 raw audit
artifacts, and independently revalidates all 77 inputs and 331 raw artifacts of
the fresh
[`concurrency-c3-ipc-refcount-20260907-10`](../results/concurrency-c3-ipc-refcount-20260907-10/SUMMARY.md)
base. A separate readback of the accepted LL/SC receipt found no mismatch across
its 45 direct input and retained-artifact records.

This is a useful negative result. The existing bounded strong-CAS source model
does not automatically establish machine-level progress on implementations that
may repeatedly lose an exclusive reservation. The audit therefore completes the
current-evidence admission decision without converting absence of a guarantee
into a proof.

## Why no LL/SC profile is promoted

The pinned kernel revision is
`b9b3e33b70b71e516930117e21de3ad2a7723747`, tree
`054b6818c409ab20ae89b1031a1a7c358f673d87`. Its exact
`Documentation/atomic_t.txt` bytes are checked before using the forward-progress
discussion. That discussion expects simple compare/exchange loops not to starve,
but explicitly explains why the expectation does not simply transfer to LL/SC:
even control flow can disturb a reservation. It also warns that native CAS alone
does not imply forward progress.

The audit checks source order and freshly disassembles the complete configured
`ipc/util.o` for each profile:

| Profile | Checked retry implementation | Decision |
| --- | --- | --- |
| arm64 | runtime LSE `cas` alternative plus `ldxr`/`stxr` loop | not promoted |
| riscv64 | runtime Zacas `amocas.w` alternative plus `lr.w`/`sc.w` loop | not promoted |
| ARM32 | `ldrex`/`strexeq` loop | not promoted |
| PowerPC32 | `lwarx`/`stwcx.` loop | not promoted |
| SuperH | `movli.l`/`movco.l` loop | not promoted |
| Alpha | `ldl_l`/`stl_c` loop through a cold subsection trampoline | not promoted |

ARM64 and RISC-V are mixed profiles: a native-CAS subpath cannot promote the
whole configured object while a runtime-selectable LL/SC alternative remains.
The other four selected objects directly contain LL/SC retries. None of the six
profile records supplies a finite architecture-backed store-conditional failure
bound. Alpha is intentionally checked with full-object disassembly because its
failed-`stl_c` edge branches outside the reported function extent to a compiler
subsection trampoline and then back into `ipc_rcu_getref()`.

## Detecting diagnostic and control

A project-owned diagnostic enumerates a deliberately hypothetical premise:
each of one through four source CAS calls may encounter zero, one or two failed
store-conditionals before completing. This gives

```text
3^1 + 3^2 + 3^3 + 3^4 = 120 finite schedules
```

The maximum witness has four source CAS calls, eight failed
store-conditionals, and twelve total store-conditional attempts. Every schedule
is finite only because the two-failure limit was inserted as a premise. The
manifest permanently marks this diagnostic ineligible for kernel verification,
and explicitly states that no selected CPU, emulator, compiler output or kernel
configuration establishes that premise.

The paired unbounded control repeatedly loses the reservation without changing
the refcount or expected value. It returns to the same state after one retry, so
the audit detects a one-state nontermination cycle. This prevents a finite test
bound from being mistaken for unbounded progress evidence.

## Accepted and excluded claims

Accepted:

- all six existing LL/SC-bearing IPC profiles received a source and emitted-
  control-flow capability assessment;
- their current admission decision is `not_promoted`;
- the artificial finite diagnostic and unbounded-failure control have their
  exact expected outcomes; and
- the complete upstream IPC receipt and all of its retained identities are
  fresh at the time of this audit.

Not accepted:

- any new kernel correctness or progress property;
- any new progress implementation mapping beyond the already accepted native
  x86-64, s390x and UML x86-64 single-instruction paths;
- an LL/SC failure bound, scheduler fairness, wait-freedom, general lock-free
  progress, interrupt/NMI progress, RCU progress or whole-kernel liveness; or
- a Linux bug. The checked production code is not classified as defective.

The audit uses pinned kernel source, configured object files, GNU disassemblers
and a small exhaustive finite-state diagnostic. It is complementary to the
Mthread+Eva capability work; it is not a new Mthread model or a claim that
Mthread supplies architecture memory-order or reservation-progress semantics.

## Failed-first evidence and review notes

Run `-01` is retained as a failed gate. It passed 484/486 checks, but the new
manifest initially named the wrong kernel tree object and the supplied IPC base
correctly reported `fragma/__main__.py` stale after the CLI was extended. Those
were evidence-construction failures, not kernel failures. The tree pin was
corrected and the complete nine-profile IPC pilot was rerun as `-10`; weakening
the base readback rule was not used as a shortcut. Run `-02` then passed 486/486,
but final evidence review found that each live object identity was recorded
without comparing it to the object accepted by the base. Run `-03` adds
twelve object hash/size comparisons and seven exact base-semantic gates, passing
505/505. Final run `-04` directly binds the two reused process/artifact helper
modules in addition to their upstream-receipt identities; it also passes 505/505
and is current. The conclusion did not change.

Ten focused tests cover exact profile inventory, source/document identities,
finite and cyclic outcomes, promotion rejection, fresh full-object disassembly,
path traversal, result-directory symlinks, output non-overwrite, timeout typing
and zero-promotion summary wording. The full project run passes
[1,000 tests](../results/tests-concurrency-c3-llsc-final-20260907.log),
with 20 existing conditional skips.

No package was installed, no `sudo` command was used, no module was loaded and
no running kernel was modified or exercised.

Reproduce from the prepared local snapshot and objects with:

```text
python3 -m fragma concurrency-c3-ipc-refcount \
  --output results/concurrency-c3-ipc-refcount-NEW --timeout 180
python3 -m fragma concurrency-c3-llsc-progress \
  --ipc-result results/concurrency-c3-ipc-refcount-NEW \
  --output results/concurrency-c3-llsc-progress-NEW --timeout 180
```

## Next progress work

Promotion now requires evidence that is specific to each possible runtime path,
not another finite loop cutoff. Plausible next steps are to split native-CAS and
LL/SC runtime alternatives where configuration and CPU selection permit it,
bind relevant architecture guarantees or reviewed kernel backoff mechanisms,
and add detecting controls for every adopted premise. Separately, C3 still needs
broader lockless functional/lifetime protocols, mappings outside the current
nine-profile IPC set and ultimately explicit RCU grace-period/reclamation work.
