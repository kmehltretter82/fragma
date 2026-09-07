# C2 Linux `DO_ONCE_SLEEPABLE` mutex pilot

Status: **one narrowly scoped kernel shared-access property accepted and
renewed on 2026-09-07; the separate IRQ/SMP slice was accepted later, while
functional exactly-once behavior remains outside both properties**.

This is the first result in this project that connects the calibrated Frama-C
33 Mthread+Eva mutex abstraction to token-identical Linux kernel function
bodies. It does not turn Mthread into a Linux Kernel Memory Model backend and
does not establish whole-API or whole-kernel concurrency safety.

## Accepted property

For the pinned kernel revision `b9b3e33b70b71e516930117e21de3ad2a7723747`
and prepared `x86_64-gcc` profile, two correctly paired process-context
slow-path callers access the shared `done` flag in
`__do_once_sleepable_start()` and `__do_once_sleepable_done()` only while the
same abstracted Linux `once_mutex` is held.

The profile is deliberately small:

- `CONFIG_SMP=n`, so inter-CPU behavior is outside the claim;
- `CONFIG_PREEMPTION=y` and `CONFIG_PREEMPT_LAZY=y`, with task interleavings
  overapproximated by Mthread's independently analyzed entries;
- `CONFIG_DEBUG_MUTEXES=n` and `CONFIG_DEBUG_LOCK_ALLOC=n`, selecting the
  ordinary `mutex_lock()`/`mutex_unlock()` implementation paths; and
- IRQ, softirq and NMI callers are excluded because the Linux mutex contract
  forbids these locks in interrupt context.

The shared flag, lock, static-key placeholder and module placeholder have
static lifetime in the harness. No allocation, free or external owner is
present in the accepted object-lifetime scope.

## Source and model connection

The [C2 declaration](../config/concurrency-c2.json) pins hashes for
`lib/once.c`, `include/linux/once.h`, `include/linux/mutex.h`,
`kernel/locking/mutex.c`, the mutex design documentation, the prepared kernel
configuration and its build receipt. Before analysis, the runner compares the
comment/whitespace-insensitive C token streams of both selected function
bodies in [the model input](../concurrency/c2/once_sleepable.c) with the real
`lib/once.c` bodies. Both match exactly.

The real `DO_ONCE_SLEEPABLE` macro is checked to preserve the ordered
start/callback/done pairing. The configured `lib/once.o` target is built through
Kbuild and checked as a 64-bit little-endian x86-64 ELF object; its saved command
must name the pinned source and `/usr/bin/gcc` with `-m64`.

The mutex adapter maps a successful lock and matching same-task unlock to one
Mthread abstract mutex. This is accepted only for the selected shared-access
protection property: Linux documents exclusive single-task ownership, and the
abstract entries admit arbitrary interference between the two modeled task
callers. The Linux atomic owner implementation is reviewed and configured-built,
not proved. Blocking, scheduling points, fairness, ordering and progress are
not inferred from the adapter.

`static_branch_disable()` is represented by a monitored event while the model
always permits another slow-path attempt. For the selected property this is an
overapproximation: the real key can suppress attempts, while each additional
modeled attempt still traverses the mutex-protected `done` check. No static-key
state, patching or ordering claim is accepted.

## Positive/negative evidence

The current [63-check A/B result](../results/concurrency-c2-20260907-08/SUMMARY.md)
passes:

| Run | Local assertions | Final `done` classification | Acceptance role |
|---|---|---|---|
| `linux_mutex_positive` | four Valid | protected by `linux-once-mutex` | only verification candidate |
| `lock_elided_negative` | publish-before-unlock Valid; true-path invariant Unknown | unprotected | mandatory rejecting control |

The positive run proves that the abstract lock identifier is valid on each
modeled operation, that a successful start path observes `done == false`, and
that done is set before unlock. Mthread's final fixpoint classifies both
cross-entry read/write pairs as protected by the same mutex and reports no
manual-synchronization gap.

The negative run compiles the same kernel bodies but selects an explicitly
labelled event-only, non-excluding adapter. It is never eligible for acceptance.
Mthread then classifies all shared `done` accesses as unprotected, requests
manual synchronization and changes the true-path assertion from Valid to
Unknown. Acceptance requires both the positive result and this sensitivity
control.

The post-change repository regression run passes
[all 928 tests](../results/tests-concurrency-c2-irq-20260907.log), with 20 existing
environment/evidence-dependent skips.

The machine-readable `pilot-audit.json` beside the summary directly retains the
30 input identities plus source-token digests, configured-object identity,
parsed assertions, final protection classifications, all checks and hashes for
the raw local artifacts. Commands are covered by those artifact hashes. Bulk
stdout, CSV and build output remain local by repository policy.

Reproduce into a fresh directory with:

```sh
python3 -m fragma concurrency-c2 \
  --output results/concurrency-c2-NEW
```

Existing outputs are refused. This command performs no installation and needs
no `sudo`.

## Explicitly unproved

This pilot does **not** accept:

- end-to-end exactly-once callback execution or callback state/side effects;
- the static-key fast path or `static_branch_disable()` implementation;
- actual subsystem call sites beyond the checked macro pairing contract;
- IRQ, softirq, NMI, SMP or inter-CPU behavior;
- weak-memory, atomic, barrier, RCU or lock-free semantics;
- deadlock freedom, fairness, progress, termination or a post-join final state;
  or
- correctness of the Linux mutex implementation from its atomic fields.

The earlier attempt to assert a global callback-entry count remained Unknown
because the current Mthread/Eva integration loses the needed relational state
across the conditionally lock-retaining function return. That observation is
why the accepted claim is access protection, not functional exactly-once
execution.

## Subsequent C2 work

The separate [OMAP HDQ hard-IRQ/spinlock pilot](CONCURRENCY-C2-IRQ-20260907.md)
now checks local IRQ exclusion independently from remote-CPU spinlock exclusion,
with mask-elided and lock-elided controls. Together the two pilots complete the
limited C2 checklist, without transferring this UP mutex result to SMP or IRQ
callers. Functional exactly-once work is still unproved. C3 weak-memory/atomic
work and C4 RCU/lifetime work remain separate open gates.
