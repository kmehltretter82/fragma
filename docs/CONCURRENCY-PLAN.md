# Concurrency verification workstream

Requested: 2026-09-07, after the current bounded kernel-source review.
Status: C0 capability calibration accepted on 2026-09-07; C1-C4 remain open and
no concurrent-kernel target is accepted. See the
[C0 evidence record](CONCURRENCY-C0-20260907.md).
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
[nine-case result](../results/concurrency-c0-20260907-04/SUMMARY.md) matches every
expected result class. `pthread_join()` completion, automatically registered
handler lock initialization, unsupported pthread operations, weak-memory
atomics/barriers, Linux synchronization and RCU remain explicit gaps. C1 is the
next acceptance gate.

## C1 — Integrate explicit concurrency models and evidence gates

- [ ] Extend target and result schemas with threading-model identity,
  synchronization model, memory-order assumptions, shared-object ownership,
  external interference, interrupt/preemption context and property scope.
- [ ] Represent synchronization with justified behavior, never empty lock,
  barrier or RCU stubs used to claim concurrent correctness. Any abstraction
  must include all behaviors relevant to the stated property, with a reviewed
  argument explaining why it is conservative.
- [ ] Add runner support, retained command/input evidence, regression checks
  and stale-result invalidation. Changed threading models invalidate dependent
  concurrent results without retroactively upgrading sequential evidence.
- [ ] Give support dimensions separate statuses: sequential, mutex-protected
  concurrency, interrupts, weak-memory atomics, RCU and lock-free algorithms.
  Unknown required dimensions prevent acceptance of that target/property.

Acceptance: missing or changed model dependencies are detected; unsupported
primitives cannot disappear silently; each accepted result names its exact
concurrent property and assumptions. Data-race freedom is not automatically
functional correctness, deadlock freedom, termination or lifetime safety.

## C2 — Validate limited Linux synchronization and interrupt integration

- [ ] Select a small, documented kernel API scope after C0, preserving source
  provenance, build configuration and real caller contracts. State excluded
  call paths rather than treating them as verified.
- [ ] Model the selected mutex/spinlock operations, ownership and scheduling
  effects against their actual configured implementations. Distinguish local
  interrupt exclusion, preemption exclusion and inter-CPU mutual exclusion.
- [ ] Check shared accesses and object lifetime across the selected callers and
  callees; a local helper proof cannot establish its caller's synchronization.
- [ ] Validate interrupt-handler interference separately, including the limits
  of modeled interrupt classes and nesting. Publish unsupported contexts.
- [ ] Compare the model with independent source review and benign calibration
  models. Preserve remaining alarms and assumptions in the accepted scope.

Acceptance: at least one precisely scoped kernel concurrency case has reviewed
primitive models, checked callers, calibrated analysis and reproducible evidence.
This is a pilot milestone, not whole-subsystem or all-kernel support.

## C3 — Add weak-memory, atomics and lock-free reasoning

- [ ] Evaluate the [Linux Kernel Memory Model and herd7](https://docs.kernel.org/dev-tools/lkmm/readme.html)
  as a complementary backend for small, source-linked ordering models. Pin both
  the model and compatible tool version, and document abstraction limits.
- [ ] Distinguish ordinary interleavings from weak-memory outcomes. Validate
  the exact selected READ_ONCE/WRITE_ONCE, acquire/release, barrier and atomic
  operations; parsing an atomic builtin does not establish its ordering rules.
- [ ] Record the argument connecting each model to the kernel source and its
  required compiler/architecture guarantees. ABI matching alone is insufficient.
- [ ] For lock-free algorithms, state and check the intended functional and
  lifetime properties, and separately any claimed progress guarantee. A
  mutex-oriented race analysis cannot supply these claims implicitly.

Acceptance: the supported ordering/atomic cases have independent semantic
calibrations, explicit source-to-model links and retained results. Unmodeled
ordering, progress or architecture guarantees remain outstanding requirements.

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

The bounded static review and C0 capability calibration are complete. Continue
with C1; later concurrent model work need not wait for every architecture port
or all sequential proofs.
No system installation, running-kernel modification or new backend execution is
authorized merely by this planning document.

Report implemented capabilities, validated kernel scopes and remaining work
separately. Do not convert an analyzer alarm into a confirmed kernel bug without
source-supported validation, or count project calibration examples as kernel
functions or discovered kernel defects.
