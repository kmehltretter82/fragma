# Linux `DO_ONCE_SLEEPABLE` C2 mutex pilot

Overall C2 pilot gate: **PASS**

Accepted kernel concurrency properties: **1**

This accepts only mutex protection of the shared `done` accesses in the
token-identical sleepable-once helper bodies, for two correctly paired
process-context callers in the pinned UP/preemptible x86_64 profile.

| Run | Assertions | `done` protection | Role | Gate |
|---|---|---|---|---|
| `linux_mutex_positive` | c2_mutex_lock_succeeds=valid, c2_mutex_unlock_succeeds=valid, c2_start_true_path_done_false=valid, c2_done_published_before_unlock=valid | protected | candidate | PASS |
| `lock_elided_negative` | c2_start_true_path_done_false=unknown, c2_done_published_before_unlock=valid | unprotected | required negative | PASS |

Evidence checks: **63/63 passed**.

Not accepted: end-to-end exactly-once callback execution, callback data,
static-key behavior, real subsystem call sites, IRQ/NMI/SMP, weak memory,
atomics, RCU, lock-free behavior, deadlock freedom, progress, termination
or post-join state. The lock-elided adapter is used only as a negative
control and can never be a verification candidate.

Raw analyzer/build output, report CSVs, commands, input identities and
artifact hashes are retained beside this summary.
