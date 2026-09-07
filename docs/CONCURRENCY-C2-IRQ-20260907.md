# C2 OMAP HDQ hard-IRQ/spinlock pilot

Status: **one narrowly scoped process/hard-IRQ critical-access property accepted
on 2026-09-07; the limited C2 pilot milestone is complete, while broader IRQ,
weak-memory and RCU support remains open**.

This is the separate interrupt/SMP slice required after the UP mutex pilot. It
connects Frama-C 33 Mthread+Eva lockset analysis to two token-identical functions
from `drivers/w1/masters/omap_hdq.c`. It is not a proof that the driver, its
status protocol, or Linux interrupt handling is race-free.

## Accepted property

At pinned Linux revision `b9b3e33b70b71e516930117e21de3ad2a7723747`, for one
post-initialization process/handler pair:

- the selected reads and write in the exact `hdq_reset_irqstatus()` critical
  section carry the abstracted `hdq-spinlock`;
- the read/write update inside the exact `hdq_isr()` critical section carries
  the same lock;
- a same-CPU handler entry is additionally classified under a CPU-local IRQ
  gate; and
- a remote-CPU handler cannot share that local gate and therefore relies on
  `hdq-spinlock` for the selected cross-CPU accesses.

This is a site-based access-protection result. It deliberately does not claim
whole-object data-race freedom. In particular, the status read in `hdq_isr()`
after `spin_unlock_irqrestore()` remains visible: Mthread classifies it under
the CPU gate for the same-CPU case and as unprotected for the remote-CPU case.
That observation is outside the accepted property and is **not classified as a
confirmed kernel bug**. The wait predicates, logging expansion, status/wakeup
protocol and MMIO behavior need separate reasoning before such a conclusion.

## Real source, caller and build binding

The [declaration](../config/concurrency-c2-irq.json) pins the source snapshot,
driver, Kconfig/Makefile, spinlock/IRQ/preemption implementation files, model,
provider, compiler and expectations. The runner checks that:

- [the fixture](../concurrency/c2/omap_hdq_irq.c) contains token-identical
  `hdq_reset_irqstatus()` and `hdq_isr()` bodies: 57 and 93 C tokens;
- `omap_hdq_probe()` orders `devm_kzalloc()`, `spin_lock_init()`,
  `devm_request_irq(..., hdq_isr, ...)` and `omap_hdq_break()`; the latter calls
  the selected reset helper;
- `spin_lock_irqsave()` reaches the configured SMP raw-spin API, whose reviewed
  order is local IRQ save, preemption disable and spin acquisition, with the
  reverse release/restore operations on unlock;
- the configured ARMv6+ IRQ-save path contains `cpsid i` with memory/condition
  code clobbers; and
- Kbuild compiles the real `omap_hdq.o` with the pinned
  `/usr/bin/arm-linux-gnueabi-gcc-15` identity.

The runner regenerates `omap2plus_defconfig` in the dedicated ignored
`build/kernel/arm-omap2plus-c2` directory. Required selections include
`CONFIG_ARM=y`, `CONFIG_ARCH_OMAP2PLUS=y`, `CONFIG_SMP=y`,
`CONFIG_PREEMPT_VOLUNTARY=y`, `CONFIG_PREEMPT_RT=n`, `CONFIG_W1=m` and
`CONFIG_HDQ_MASTER_OMAP=m`. The resulting config hash is pinned. The compiled
object is ELF32, little-endian ARM (`e_machine=40`) with SHA-256
`614d6375651117c9cde07438b1ccfb3c97b5bf3fb0835722ea16364fefc3dcbe`.

## Handler-entry model and its boundary

Frama-C 33's automatic `-mt-interrupt-handlers` entries are created from the
initial state at the beginning of `main`. C0's
`interrupt_registered_exclusion_gap` control demonstrates that a mutex
initialized later in `main` is consequently possibly uninitialized in such a
handler. The OMAP source instead initializes `hdq_spinlock` before registering
`hdq_isr`.

The pilot therefore uses a post-initialization pthread-created Mthread entry as
a hard-IRQ entry adapter. Both abstract locks are initialized before entry
creation, matching the reviewed probe order. The wrapper calls the exact handler
once. One reached invocation is sufficient only for this access-site lockset
property because every invocation reaches the same selected sites through the
same locks. Handler recurrence, changed state across deliveries, liveness and
functional protocol behavior are not inferred.

For the same-CPU case, one abstract `cpu0-local-irq` mutex is held by the process
only over the `local_irq_save` interval and by the handler wrapper for its whole
invocation. For the remote-CPU case the handler does not take that CPU0 gate.
The data spinlock is a separate abstract mutex in both contexts. Neither model
is an empty synchronization stub.

## Four-way A/B evidence

The current [125-check result](../results/concurrency-c2-irq-20260907-04/SUMMARY.md)
passes all source, compiler, config, object, provider, assertion, access-site and
negative-control gates:

| Run | Acceptance role | Selected critical accesses | Diagnostic boundary |
|---|---|---|---|
| `same_cpu_positive` | candidate | CPU-local IRQ gate plus `hdq-spinlock` | post-unlock read has CPU gate |
| `same_cpu_mask_elided_negative` | local-mask control only | data accesses retain `hdq-spinlock` | both process marker writes become unprotected |
| `remote_cpu_positive` | candidate | process and handler share `hdq-spinlock` | post-unlock handler read is unprotected |
| `remote_cpu_spin_elided_negative` | spinlock control only | selected process/handler sites have no common lock | both cross-thread directions are unprotected |

Every abstract lock/unlock result assertion is Valid. The retained
`c2_irq_same_cpu_no_overlap_boundary` assertion is Unknown in both same-CPU
runs because Mthread merges the process marker's intermediate protected values.
It is not an accepted assertion; the gate consumes the final per-access lockset
records instead. This precision limitation remains visible rather than being
replaced by an assumed assertion.

The result pins 35 direct input identities and 32 raw artifacts. The renewed
[C0 result](../results/concurrency-c0-20260907-09/SUMMARY.md),
[C1 audit](../results/concurrency-c1-20260907-05/SUMMARY.md),
[C1 staleness control](../results/concurrency-c1-stale-control-20260907-06/SUMMARY.md)
and [mutex C2 result](../results/concurrency-c2-20260907-08/SUMMARY.md) bind the
current CLI identity. The full repository run passes
[928 tests](../results/tests-concurrency-c2-irq-20260907.log), with 20 explicit
environment/evidence-dependent skips.

Reproduce into a new evidence directory:

```sh
python3 -m fragma concurrency-c2-irq \
  --output results/concurrency-c2-irq-NEW
```

The command refuses an existing output, performs no installation and invokes
neither `sudo` nor a running kernel.

## Unsupported contexts and next concurrency gates

No claim is made for automatic post-probe handler registration, multiple or
nested deliveries, IRQ priorities, softirq, threaded IRQ, FIQ/NMI,
`PREEMPT_RT`, affinity migration, CPU hotplug, nested driver locks or teardown
lifetime. The real devm-managed object/IRQ lifetime is reviewed only enough to
bind probe ordering; it is not analyzed through removal.

Mthread supplies interleavings and access locksets, not LKMM or ARM weak-memory
semantics. Atomic/spin implementation details, acquire/release guarantees,
compiler barriers, fairness, deadlock, progress and termination remain outside
this result. C3 must add source-linked weak-memory/atomic reasoning; C4 must add
RCU/lifetime and honest combined coverage. Those open gates prevent any claim
of general Linux concurrency support.
