# C3 System V IPC refcount lifetime pilot — 2026-09-07

Status: accepted for one narrow production lifetime decision; C3 remains
incomplete.

The current standalone evidence is
[`results/concurrency-c3-ipc-refcount-20260907-02`](../results/concurrency-c3-ipc-refcount-20260907-02/SUMMARY.md).
It passes all 157 gates and accepts one source-linked kernel property. It found
no new Linux defect: the selected IPC code uses the refcount API correctly.

The preceding `-01` run passed the same model, source, build and outcome gates.
Run `-02` renews the receipt after changing the property wording from a generic
“report” to the precise observable actions: schedule destruction and return a
successful get. No semantic claim changed.

## Accepted property

The pinned `ipc/util.h` contract says that its reference-counted objects start
at one, that a put reducing the count to zero schedules RCU destruction, and
that the caller must guarantee locking. Under that prerequisite, select exactly
one `ipc_rcu_putref()` and one concurrent `ipc_rcu_getref()` operating on the
same initially-one `kern_ipc_perm::refcount`, with no third update.

The two operations cannot both:

- make the final-put decision and schedule `call_rcu()`; and
- return a successful get from `refcount_inc_not_zero()`.

There are only two valid linearizations. If the get wins, it changes 1 to 2 and
the put observes 2, leaving 1 without scheduling destruction. If the put wins,
it changes 1 to 0 and the get cannot increment zero. The property assumes the
caller's lock/RCU discipline keeps `ptr` and its refcount storage valid while
the get is attempted. It does not prove that prerequisite.

## Functional A/B model

Both LKMM cases ask for the identical bad condition:

```text
exists (0:released=1 /\ 1:acquired=1)
```

| Case | Get operation | Distinct states | Bad/good witnesses | Result |
| --- | --- | ---: | ---: | --- |
| Source abstraction | relaxed compare/exchange 1 to 2 | 2 | 0/2 | `Never` |
| Unsafe control | unconditional relaxed increment | 2 | 1/1 | `Sometimes` |

The negative remains permanently ineligible for verification acceptance. Its
bad witness is the deliberate resurrection sequence: the put changes 1 to 0
and decides to destroy, then the unconditional increment changes 0 back to 1.
This demonstrates that the query detects the lifetime failure excluded by the
real get-unless-zero operation.

`refcount_inc_not_zero()` begins with `refcount_read()` and retries
`atomic_try_cmpxchg_relaxed()`. LKMM does not directly spell the try-CAS helper,
so the positive uses `atomic_cmpxchg_relaxed(refs, 1, 2)`. That is exact for this
bounded outcome: there is one initial reference and only one competing
decrement. If the first CAS succeeds, the get wins. If it fails, the decrement
has already installed zero; the source loop reads that zero and stops rather
than retrying. Saturation and any other count are outside the property.

The put side retains the source implementation's
`atomic_fetch_sub_release(1, refs)` and records `released=1` only when the old
value is one. The successful source path also executes
`smp_acquire__after_ctrl_dep()`. That ordering matters for later destruction
work but cannot change this same-refcount mutual-success question; no
cross-object ordering claim is inferred from its omission.

## Source and configured implementation gates

The source gate pins and rechecks:

- `ipc/util.c`'s one-line get and its final-put test before `call_rcu()`;
- `ipc/util.h`'s initial-count, destruction and caller-locking contract;
- the full `refcount_inc_not_zero()` chain through its zero test and relaxed
  try-CAS loop;
- the full `refcount_dec_and_test()` chain through release fetch-sub, exact
  1-to-0 test and acquire-after-control operation;
- the kernel refcount ordering documentation;
- the instrumented atomic API, generic fallback, x86 atomic/cmpxchg macros and
  LKMM RMW atomicity axiom;
- the System V IPC Kconfig/Makefile selection and an actual configured object.

A dedicated `x86_64_defconfig` build has `CONFIG_SMP=y`, `CONFIG_SYSVIPC=y`,
`CONFIG_TREE_RCU=y`, `CONFIG_PREEMPT_RCU=y`, GCC 15.2.0 and KCSAN disabled. It
compiles the real `ipc/util.o`, not a project wrapper. The exact ELF64 x86-64
object has SHA-256
`00b7dfa8b08c8d76546e13cc8adb5e5102480225c444902ea46aa6c993525d6d`.
Its two global function symbols are pinned, and selected disassembly shows:

- `ipc_rcu_getref()`: zero test followed by `lock cmpxchg` and its success
  result; and
- `ipc_rcu_putref()`: `lock xadd`, comparison with one, and the `call_rcu`
  relocation on the successful final-put branch.

The final kernel configuration hash is
`c1d909f833602f5d8fb7fba52322c1f411c44fe4e41a44b52ac5d897e3f3033e`.
Raw commands, stdout/stderr, model results, source/model facts, identities and
artifact hashes are retained in the local evidence directory.

## Boundaries and next work

Not accepted: an unstabilized or already reclaimed pointer, callback execution,
RCU grace periods, allocator reuse, ABA, `SLAB_TYPESAFE_BY_RCU`, arbitrary
initial counts, a third update, saturation/overflow/underflow, warning paths,
whole-IPC or whole-RCU correctness, whole-kernel race freedom, or any progress,
fairness, retry-bound, lock-free or wait-free guarantee.

The implementation mapping is x86-64 only. The architecture-independent
refcount contract and LKMM result do not activate another architecture without
its source/macro/compiler/object evidence. C3 still needs any separately
justified progress property, implementation mappings beyond x86-64 and broader
lockless protocol coverage. C4 remains responsible for explicit RCU grace
period and reclamation reasoning.

Reproduce with:

```text
python3 -m fragma concurrency-c3-ipc-refcount \
  --output results/concurrency-c3-ipc-refcount-NEW --timeout 180
```

This performs static model checking and an out-of-tree object build. It does
not execute code in the running kernel, load a module, install a package or use
`sudo`.
