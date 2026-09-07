# Concurrency verification workstream

Requested: 2026-09-07, after the current bounded kernel-source review.
Status: C0 capability calibration, C1 evidence/scope infrastructure and two
narrow C2 properties accepted on 2026-09-07: the UP/process-context mutex slice
and the ARM SMP process/hard-IRQ spinlock slice. The limited C2 pilot milestone
is complete. C3 now has a pinned four-case LKMM baseline and one source-linked
SMP x86-64 release/acquire property. A second four-case pilot adds one
source-linked module-statistics atomicity property plus an independent atomic
return-ordering calibration on SMP x86-64. Lock-free lifetime/progress, other
architecture mappings and C4 remain open.
See the [C0 evidence record](CONCURRENCY-C0-20260907.md) and
[C1 evidence record](CONCURRENCY-C1-20260907.md), followed by the
[C2 mutex pilot](CONCURRENCY-C2-20260907.md) and
[C2 IRQ pilot](CONCURRENCY-C2-IRQ-20260907.md). The C3 evidence is split into
the [LKMM capability baseline](CONCURRENCY-C3-LKMM-20260907.md) and the
[trace tgid-map source pilot](CONCURRENCY-C3-TRACE-20260907.md), followed by the
[module-statistics atomic/RMW pilot](CONCURRENCY-C3-ATOMIC-20260907.md).
Parent goal: [execute PLAN.md](../PLAN.md). This work does not replace the
remaining sequential-suite, architecture or coverage requirements.

## Starting boundary

The accepted [string contracts](../annotated/verification-notes.md) establish
sequential properties under explicit assumptions. Architecture calibration of
integer widths, layout and byte order does not establish multiprocessor memory
ordering. Parallel solver jobs do not model parallel execution of kernel code.

Frama-C's [Mthread documentation](https://www.frama-c.com/fc-plugins/mthread.html)
describes thread interactions, shared memory and mutex-based race analysis,
with threading-library models and limitations for lock-free algorithms. Its
[release history](https://www.frama-c.com/html/changelog.html) records integration
into Eva, interrupt-handler support and version-dependent invocation changes.
These upstream capabilities are motivation, not proof that the project's locked
provider can model Linux synchronization correctly.

Work begins with capability evidence and grows to kernel-specific semantics.
A successful narrow pilot must not erase the later weak-memory/RCU requirements.

## C0 — Establish the actual tool and semantic capabilities

- [x] Inspect the locked production provider's version, source, documentation,
  available Mthread features and bundled threading models. Keep the private
  Hexagon candidate out of this baseline unless separately accepted.
- [x] Record the exact execution/memory model: thread discovery, shared writes,
  synchronization, object lifetime, interrupts, atomic operations and unsupported
  constructs. Separate upstream claims from locally verified capabilities.
- [x] Add small project-owned, non-kernel calibration models for thread creation,
  joining, protected shared state, interference and interrupt exclusion. Include
  both valid invariants and deliberately false assertions with independently
  justified expected outcomes. No fault-triggering kernel tests are required.
- [x] Preserve raw diagnostics and distinguish an identified false property,
  a possible alarm, an unknown result, unsupported semantics and a tool error.
  A missing warning or successful parse is not a successful negative control.

Acceptance: a pinned, repeatable capability report states which properties the
actual provider checks and exposes every modeling assumption. If a required
feature is absent, record the evidence and implement or integrate a suitable
backend; do not relabel a sequential run as concurrency verification.

C0 decision: accepted for capability characterization only. The pinned
[nine-case result](../results/concurrency-c0-20260907-08/SUMMARY.md) matches every
expected result class. `pthread_join()` completion, automatically registered
handler lock initialization, unsupported pthread operations, weak-memory
atomics/barriers, Linux synchronization and RCU remain explicit gaps. C1 is the
next acceptance gate.

## C1 — Integrate explicit concurrency models and evidence gates

- [x] Extend target and result schemas with threading-model identity,
  synchronization model, memory-order assumptions, shared-object ownership,
  external interference, interrupt/preemption context and property scope.
- [x] Represent synchronization with justified behavior, never empty lock,
  barrier or RCU stubs used to claim concurrent correctness. Any abstraction
  must include all behaviors relevant to the stated property, with a reviewed
  argument explaining why it is conservative.
- [x] Add runner support, retained command/input evidence, regression checks
  and stale-result invalidation. Changed threading models invalidate dependent
  concurrent results without retroactively upgrading sequential evidence.
- [x] Give support dimensions separate statuses: sequential, mutex-protected
  concurrency, interrupts, weak-memory atomics, RCU and lock-free algorithms.
  Unknown required dimensions prevent acceptance of that target/property.

Acceptance: missing or changed model dependencies are detected; unsupported
primitives cannot disappear silently; each accepted result names its exact
concurrent property and assumptions. Data-race freedom is not automatically
functional correctness, deadlock freedom, termination or lifetime safety.

C1 decision: accepted for infrastructure only. The current
[C1 audit](../results/concurrency-c1-20260907-04/SUMMARY.md) re-parses all nine C0
cases with current dependencies and explicit scope metadata. A
[stale-model control](../results/concurrency-c1-stale-control-20260907-05/SUMMARY.md)
rejects exactly the pthread-dependent cases after their recorded model identity
changes. All nine records remain calibrations, all verification flags are false,
and the kernel-concurrency acceptance count is zero. C2 is the next gate.

## C2 — Validate limited Linux synchronization and interrupt integration

- [x] Select a small, documented kernel API scope after C0, preserving source
  provenance, build configuration and real caller contracts. State excluded
  call paths rather than treating them as verified.
- [x] Model the selected mutex/spinlock operations, ownership and scheduling
  effects against their actual configured implementations. Distinguish local
  interrupt exclusion, preemption exclusion and inter-CPU mutual exclusion.
- [x] Check shared accesses and object lifetime across the selected callers and
  callees; a local helper proof cannot establish its caller's synchronization.
- [x] Validate interrupt-handler interference separately, including the limits
  of modeled interrupt classes and nesting. Publish unsupported contexts.
- [x] Compare the model with independent source review and benign calibration
  models. Preserve remaining alarms and assumptions in the accepted scope.

Acceptance: at least one precisely scoped kernel concurrency case has reviewed
primitive models, checked callers, calibrated analysis and reproducible evidence.
This is a pilot milestone, not whole-subsystem or all-kernel support.

C2 mutex-slice decision: the
[current 63-check A/B pilot](../results/concurrency-c2-20260907-07/SUMMARY.md)
accepts one kernel property: shared `done` accesses in token-identical
`__do_once_sleepable_start()`/`done()` bodies are protected by the same mutex
for two correctly paired process-context callers under the pinned
`CONFIG_SMP=n`, preemptible x86_64 profile. The lock-elided negative exposes the
accesses as unprotected and downgrades the selected branch invariant. Functional
exactly-once behavior, static keys, real subsystem callbacks, IRQ/NMI and SMP are
not accepted; see the [scope record](CONCURRENCY-C2-20260907.md).

C2 IRQ-slice decision: the
[current 125-check four-way A/B pilot](../results/concurrency-c2-irq-20260907-03/SUMMARY.md)
accepts one further kernel property. Selected accesses in token-identical
`hdq_reset_irqstatus()` and the locked update in `hdq_isr()` carry the same
`hdq-spinlock` under a pinned SMP ARM OMAP profile. The same-CPU case separately
models the local hard-IRQ mask; the remote-CPU case relies only on the shared
spinlock. Mask-elided and spin-elided controls expose their respective missing
protection. The handler's post-unlock status read remains explicitly unprotected
on a remote CPU and is outside the accepted property, not classified as a bug.
Frama-C's automatic-handler initialization gap, recurrence, nesting, other IRQ
classes, weak memory and lifetime remain unsupported. This completes the
limited C2 pilot acceptance checklist, not general kernel concurrency support;
see the [IRQ scope record](CONCURRENCY-C2-IRQ-20260907.md).

## C3 — Add weak-memory, atomics and lock-free reasoning

- [x] Evaluate the [Linux Kernel Memory Model and herd7](https://docs.kernel.org/dev-tools/lkmm/readme.html)
  as a complementary backend for small, source-linked ordering models. Pin both
  the model and compatible tool version, and document abstraction limits.
- [x] Distinguish ordinary interleavings from weak-memory outcomes for selected
  `READ_ONCE`/`WRITE_ONCE`, acquire/release and full-barrier cases. The two
  canonical A/B pairs detect `Sometimes` to `Never` transitions under the exact
  pinned model/provider.
- [x] Record one reviewed argument connecting a model to production kernel
  source and required compiler/architecture evidence. The trace tgid-map pilot
  binds exact statements, caller/lifetime facts, x86 macro definitions and a
  configured SMP x86-64 object to a detecting release/acquire A/B pair.
- [x] Add independent atomic read-modify-write calibration and at least one
  source-linked atomic/RMW property. Parsing an atomic builtin does not establish
  its ordering rules. The module-statistics pilot checks `atomic_inc()` against
  a lost-update control, separately distinguishes ordered and relaxed
  increment-return operations, and pins the configured x86 `lock incl` lowering.
- [ ] Extend implementation evidence beyond the first configured SMP x86-64
  mapping. ABI matching alone is insufficient; each activated architecture
  needs source/macro/compiler evidence appropriate to its claimed property.
- [ ] For lock-free algorithms, state and check the intended functional and
  lifetime properties, and separately any claimed progress guarantee. A
  mutex-oriented race analysis cannot supply these claims implicitly.

Acceptance: the supported ordering/atomic cases have independent semantic
calibrations, explicit source-to-model links and retained results. Unmodeled
ordering, progress or architecture guarantees remain outstanding requirements.

C3 partial decision: the
[92-check capability baseline](../results/concurrency-c3-lkmm-20260907-04/SUMMARY.md)
accepts four semantic calibrations and zero production properties. The separate
[135-check trace pilot](../results/concurrency-c3-trace-20260907-03/SUMMARY.md)
accepts one production ordering property: after `trace_find_tgid_ptr()` observes
the `tgid_map` pointer published by a successful `trace_alloc_tgid_map()` release,
its guarded max read cannot see the old zero on the configured SMP x86-64
profile. Removing release/acquire makes the outcome `Sometimes` and exposes
`Flag data-race`. The subsequent
[162-check atomic/RMW pilot](../results/concurrency-c3-module-stats-20260907-03/SUMMARY.md)
accepts one production no-lost-update property for two selected concurrent
`failed_load_modules` increments. Its split once-access control permits the lost
update, while a separate ordered/relaxed return-value pair calibrates ordering.
Both source pilots verify correct selected code; neither found a new defect or
completes C3. Lifetime-sensitive lock-free behavior, progress and other
architecture mappings remain open.

## C4 — Extend to RCU and maintain honest combined coverage

- [ ] Model selected RCU publication, read-side protection, removal, grace
  periods and reclamation rules, including their configuration/context limits.
- [ ] Check lifetime across caller boundaries, reference ownership and delayed
  reclamation. Do not substitute a no-op grace period or assume objects remain
  live without a source-supported argument.
- [ ] Integrate concurrency coverage with the existing source/profile/property
  matrix without conflating static proofs, model checks and dynamic observations.
- [ ] Assess complementary [KCSAN](https://cdn.kernel.org/doc/html/latest/dev-tools/kcsan.html)
  race evidence and [lockdep](https://cdn.kernel.org/doc/html/latest/locking/lockdep-design.html)
  locking evidence. Any future runtime validation is separately scoped and
  authorized; neither tool's clean run is a blanket concurrency proof.
- [ ] Maintain regression examples, assumptions and update procedures for every
  supported synchronization family. Keep remaining families and contexts visible.

Acceptance: the declared RCU and combined concurrency scopes are source-linked,
reproducible and independently reviewed, with property-specific limitations.
The broader workstream remains incomplete while any promised capability lacks
its required model or validation evidence.

## Execution order and reporting

The bounded static review and limited C0-C2 pilot are complete. Continue C3
from its accepted LKMM baseline, release/acquire pilot and atomic/RMW pilot:
a lifetime-sensitive lock-free case and additional architecture mappings come
next, followed by C4 RCU/lifetime/combined coverage.
Broader interrupt and functional-protocol extensions remain visible backlog and
need not wait for every architecture port or all sequential proofs.
No system installation, running-kernel modification or new backend execution is
authorized merely by this planning document.

Report implemented capabilities, validated kernel scopes and remaining work
separately. Do not convert an analyzer alarm into a confirmed kernel bug without
source-supported validation, or count project calibration examples as kernel
functions or discovered kernel defects.
