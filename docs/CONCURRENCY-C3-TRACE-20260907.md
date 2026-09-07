# C3 trace tgid-map release/acquire pilot — 2026-09-07

Status: **accepted for one source-linked kernel ordering property on one
configured SMP x86-64 profile; 135/135 checks pass**.

The retained result is
[`results/concurrency-c3-trace-20260907-04`](../results/concurrency-c3-trace-20260907-04/SUMMARY.md).
This is evidence that bounded production-code weak-memory checking is now
usable. It confirms correct synchronization in the selected source; it is not a
new kernel bug.

The preceding `results/concurrency-c3-trace-20260907-01` also passed, but a
subsequent no-semantics-change cleanup altered a hashed test input. Later
receipts renewed parser and CLI identities; current run `-04` records the new
IPC refcount command. Source, model, build and outcomes are unchanged, and the
older compact records remain history rather than silently being treated as
fresh.

## Accepted property

In pinned `kernel/trace/trace_sched_switch.c`, a successful
`trace_alloc_tgid_map()` assigns `tgid_map_max`, allocates the array and
publishes its non-NULL pointer with `smp_store_release(&tgid_map, map)`.
`trace_find_tgid_ptr()` reads that pointer with `smp_load_acquire()` and, only
when it is non-NULL, compares `pid` with the plain `tgid_map_max` payload.

The accepted claim is exactly:

> On the configured SMP x86-64 profile, if the consumer observes the pointer
> published by that successful release, its following guarded max access cannot
> observe the static pre-publication zero.

It does not claim that allocation succeeds, that every pid is valid, that map
elements are correct, or that the whole tracing subsystem is safe.

## Source-to-model correspondence

| Role | Production source | Litmus abstraction |
| --- | --- | --- |
| Payload initialization | `tgid_map_max = init_pid_ns.pid_max` | `*tgid_map_max = 1` |
| Pointer publication | `smp_store_release(&tgid_map, map)` | `smp_store_release(tgid_map, 1)` |
| Pointer observation | `smp_load_acquire(&tgid_map)` | `r0 = smp_load_acquire(tgid_map)` |
| Guarded payload read | short-circuit `!map || pid > tgid_map_max` | `if (r0) r1 = *tgid_map_max` |

Both source objects are translation-unit-local statics and therefore initially
zero. `PID_MAX_DEFAULT` is pinned as a positive value, so abstract `1` means
“the assigned value” rather than its actual magnitude. A successful non-NULL
allocation is similarly abstracted as `1`. The condition asks only for
published pointer plus stale maximum; allocation internals and array contents
cannot change that two-location ordering question.

The guard is load-bearing. An early draft read the payload unconditionally and
LKMM correctly emitted `Flag data-race`, because that draft added executions in
which a NULL publication read was followed by an unsynchronized max read. The
final model preserves C short-circuiting: the positive has no race flag, while
the deliberately weakened control still does.

## A/B result

| Case | States | Bad witnesses | LKMM flags | Observation |
| --- | ---: | ---: | --- | --- |
| Exact release/acquire pair | 2 | 0 | none | `Never` |
| Release/acquire replaced by once accesses | 3 | 1 | `data-race` | `Sometimes` |

Both cases retain the condition
`exists (1:r0=1 /\ 1:r1=0)`. The negative is permanently ineligible for
verification acceptance. The run first executes the separate 92-check canonical
LKMM baseline, which itself accepts zero kernel properties.

## Caller, lifetime and implementation gates

The runner checks the whole pinned C snapshot for the allocator token. There is
one definition and one callsite. The call is in the `RECORD_TGID` arm of
`set_tracer_flag()`, whose corresponding arm asserts `event_mutex` ownership;
the allocator returns immediately on later calls after publication. Within the
translation unit, `tgid_map_max` has one explicit assignment and `tgid_map` has
no later NULL assignment or `kfree`/`kvfree`/`vfree`. A future replacement or
reclamation change invalidates source hashes and the lifetime argument.

The configured build uses unmodified `x86_64_defconfig` with `CONFIG_SMP=y`,
`CONFIG_TRACING=y`, `CONFIG_CONTEXT_SWITCH_TRACER=y`, GCC 15.2.0 and an exact
ELF64 x86-64 object. Its compile command includes `-D__KERNEL__`, `-m64`,
`-march=x86-64`, `-O2` and `-fno-allow-store-data-races`. Local ELF symbols pin
the two eight-byte `.bss` objects. The selected disassembly shows:

- producer: load positive `init_pid_ns.pid_max`, store `tgid_map_max`, allocate,
  then store `tgid_map`;
- inlined consumer: load `tgid_map`, test it, then load `tgid_map_max`.

The source gates also pin Linux's release/acquire contract, generic API routing,
x86 compiler-barrier plus once-access definitions, and volatile scalar
`READ_ONCE`/`WRITE_ONCE`. Object inspection confirms this selected compilation;
it is not an independent proof of the x86 ISA, arbitrary compiler releases, or
other kernel architectures.

## Boundaries and next work

Not accepted: map-element contents, allocation arithmetic, broader tracing
behavior, architecture profiles other than this SMP x86-64 build, future
reclamation, lock-free progress, fairness, wait freedom, or whole-subsystem race
freedom. The subsequent
[module-statistics atomic/RMW pilot](CONCURRENCY-C3-ATOMIC-20260907.md) supplies
the first source-linked atomic property, and the later
[System V IPC refcount pilot](CONCURRENCY-C3-REFCOUNT-20260907.md) supplies one
bounded lifetime-sensitive functional case. C3 still requires any separately
justified progress claim, broader lockless protocols and per-architecture
configured implementation evidence. C4 RCU remains separate.

Reproduce with:

```text
python3 -m fragma concurrency-c3-trace \
  --output results/concurrency-c3-trace-NEW --timeout 180
```

This performs static model checking and an out-of-tree object build only. It
does not generate or load a kernel module, execute a running-kernel test,
install anything or use `sudo`.
