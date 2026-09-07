# C3 module-statistics atomic/RMW pilot — 2026-09-07

Status: accepted for one narrow production atomicity property; C3 remains
incomplete.

The current standalone evidence is
[`results/concurrency-c3-module-stats-20260907-04`](../results/concurrency-c3-module-stats-20260907-04/SUMMARY.md).
It passes all 162 gates, accepts one source-linked kernel property, and includes
two additional return-value ordering calibrations. It found no new Linux defect:
the selected source uses `atomic_inc()` correctly.

The preceding `-01` run passed the same semantic gates but described the global
counter as process-wide in one manifest argument. Run `-02` corrected that scope
wording to kernel-wide. The current `-03` run additionally includes the pinned
kernel `scripts/config` executable in its top-level input inventory; it was
already hash-checked by the earlier runs. No source, model, build or outcome
changed across these provenance-only renewals. Run `-04` renews only the CLI
identity after adding the IPC refcount command.

## Accepted property

On the pinned kernel revision and configured SMP x86-64 build, start
`failed_load_modules` at zero, select exactly two completed concurrent calls to
`mod_stat_bump_invalid()`, and exclude any third update. Each selected call
executes:

```c
atomic_inc(&failed_load_modules);
```

The final value cannot be one. Both increments contribute, so the selected
counter is two. This is a no-lost-update property for one `atomic_t`, not a claim
that an unsynchronized debugfs read must observe a particular instantaneous
value.

The production source is
`kernel/module/stats.c`. Its own documentation says all statistics counters are
incremental, explains that atomics avoid delays and deadlocks, and describes
module-load races that can reach these failure counters. The sole C callsite is
on `load_module()`'s allocated-module cleanup path in `kernel/module/main.c`.
The runner also checks both module-loading syscall entry paths and verifies that
the relevant list lock is released before `add_unformed_module()` returns.

Within the statistics translation unit, `failed_load_modules` is a static,
implicitly zero-initialized `atomic_t`. There is exactly one increment, one
snapshot read and one debugfs exposure, with no reset, decrement, exchange,
direct assignment or deallocation. Those facts are content-hashed and checked
again on every run.

## Atomicity A/B model

Both LKMM cases ask for the identical bad condition
`exists ([counter]=1)` after two threads attempt one increment each.

| Case | Operations | Distinct states | Bad/good witnesses | Result |
| --- | --- | ---: | ---: | --- |
| Source abstraction | two `atomic_inc(counter)` RMWs | 1 | 0/2 | `Never` |
| Weakened control | split `READ_ONCE` + `WRITE_ONCE` updates | 2 | 2/2 | `Sometimes` |

The negative is permanently ineligible for verification acceptance. It proves
that the condition is observable when the indivisible RMW assumption is removed.
The witness totals describe executions, not unique final states; this is why the
positive has one state but two negative witnesses, and the control has two states
but four total witnesses. The strict parser and a regression test preserve that
distinction.

The source-to-model abstraction keeps only the selected counter operation from
each completed function call. The independent `invalid_mod_bytes` update and
the rest of module cleanup do not write `failed_load_modules` and cannot alter
the selected RMW atomicity question.

## Independent return-ordering calibration

A second pair tests an atomic property not used to inflate the source claim.
Both threads perform an increment-return operation and then read the other
counter. The condition asks whether both later reads can return zero.

| Case | Increment operation | Distinct states | Bad/good witnesses | Result |
| --- | --- | ---: | ---: | --- |
| Ordered | `atomic_inc_return()` | 3 | 0/3 | `Never` |
| Weakened | `atomic_inc_return_relaxed()` | 4 | 1/3 | `Sometimes` |

This independently checks that the pinned provider honors the LKMM distinction
between the `MB` and `ONCE` definitions. It is a semantic calibration, not a
second production-code property.

## Contract, model and object gates

The run first repeats the separate canonical LKMM baseline. It then pins and
checks all of the following:

- Linux's `atomic_t` documentation identifies these as inter-CPU RMW operations,
  states that no intermediate state is lost or visible, and distinguishes
  no-return relaxed operations from fully ordered return operations.
- `linux-kernel.def` maps `atomic_inc()` to one `NORETURN` atomic operation and
  distinguishes `atomic_inc_return()` (`MB`) from its relaxed (`ONCE`) variant.
- `linux-kernel.cat` contains the RMW atomicity axiom
  `empty rmw & (fre ; coe)`.
- the instrumented generic API routes `atomic_inc()` through `raw_atomic_inc()`
  to the architecture implementation;
- the pinned x86 implementation uses `LOCK_PREFIX "incl"` with a memory
  operand and compiler memory clobber;
- a dedicated `x86_64_defconfig` build explicitly enables `DEBUG_FS`,
  `MODULE_DEBUG` and `MODULE_STATS`, leaves KCSAN disabled, and compiles
  `kernel/module/stats.o` with GCC 15.2.0;
- the exact ELF64 x86-64 object has SHA-256
  `e472812193fd94f57f7ec01ac2c9d3e5912fda29db80eed4214c165e07c690c2`;
  its local `.bss` symbols bind the four-byte selected counter and the separate
  eight-byte byte counter;
- selected disassembly contains the independent `lock add` for byte accounting,
  followed by `lock incl` at the relocation corresponding to
  `failed_load_modules`.

The final kernel configuration hash is
`c3153142bfe223bfa819e84f75aa0fe7e7fbbee64494a56877742c1d0e701a86`.
Raw commands, stdout/stderr, model results, source/model facts, identities and
artifact hashes are retained in the evidence directory.

## Boundaries and next work

Not accepted: arbitrary initial values near wraparound, a concurrent third
update, freshness of an arbitrary debugfs snapshot, ordering between
`failed_load_modules` and `invalid_mod_bytes`, allocation or cleanup behavior,
module-loader correctness, runtime frequency, progress, fairness, lock freedom,
wait freedom, or whole-kernel race freedom.

The source-linked implementation mapping is x86-64 only. LKMM and the generic
atomic API are architecture-independent contracts, but another architecture is
not promoted by that fact alone; it needs its own source/macro/compiler/object
evidence. The subsequent
[System V IPC refcount pilot](CONCURRENCY-C3-REFCOUNT-20260907.md) supplies one
bounded lifetime-sensitive functional case. C3 still needs any separately
justified progress property, broader lockless protocols and implementation
mappings beyond x86-64. C4 RCU remains separate.

Reproduce with:

```text
python3 -m fragma concurrency-c3-module-stats \
  --output results/concurrency-c3-module-stats-NEW --timeout 180
```

This runs static model checking and an out-of-tree object build. It does not
load a module, modify the running kernel, install a package, or use `sudo`.
