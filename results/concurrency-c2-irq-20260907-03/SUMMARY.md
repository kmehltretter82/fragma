# OMAP HDQ C2 hard-IRQ/spinlock pilot

Overall C2 IRQ gate: **PASS**

Accepted kernel concurrency properties: **1**

The accepted property covers only the selected accesses inside the
token-identical `hdq_reset_irqstatus()` critical section and the locked
update in `hdq_isr()`, under one post-initialization process/handler pair.

| Run | Role | Critical accesses carry `hdq-spinlock` | Unlocked handler read | Gate |
|---|---|---|---|---|
| `same_cpu_positive` | candidate | yes | cpu0-local-irq | PASS |
| `same_cpu_mask_elided_negative` | negative: linux_local_irq_mask | yes | cpu0-local-irq | PASS |
| `remote_cpu_positive` | candidate | yes | unprotected | PASS |
| `remote_cpu_spin_elided_negative` | negative: linux_hdq_spinlock | no | unprotected | PASS |

Evidence checks: **125/125 passed**.

The same-CPU no-overlap assertion is deliberately retained as `Unknown`;
acceptance uses Mthread's per-access locksets, not that functional assertion.
The mask-elided control exposes the model marker, and the remote-CPU
spin-elided control removes the common lock from all selected accesses.

The unlocked `hdq_isr()` status read is protected by the CPU gate only in
the same-CPU case and remains unprotected in the remote-CPU case. It is a
preserved source observation outside the accepted property, not a confirmed
kernel defect. Logging, wait predicates, MMIO and the status protocol are
not modeled.

Unsupported: automatic handler registration after probe-time initialization,
handler recurrence/nesting/priorities, softirq, threaded IRQ, FIQ/NMI,
PREEMPT_RT, affinity migration, CPU hotplug, teardown lifetime, LKMM/ARM
weak memory, atomics, RCU, deadlock, progress and whole-driver race freedom.

The ARM object/config build, commands, raw analyzer output, report CSVs,
source/model identities and per-case decisions are retained beside this file.
No package installation or privileged command is performed.
