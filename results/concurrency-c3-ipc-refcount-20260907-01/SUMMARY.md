# System V IPC refcount C3 lifetime pilot

Overall source-linked gate: **PASS**

Accepted kernel lifetime properties: **1**
LKMM functional cases: **2**

| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |
|---|---|---|---:|---:|---|
| `refcount_put_get_positive` | verification_candidate | Never | 0/2 | 2 | PASS |
| `unconditional_resurrection_negative` | required_unsafe_control | Sometimes | 1/1 | 2 | PASS |

Evidence checks: **157/157 passed**.

Starting with the IPC contract's sole reference, the selected final put
and get-unless-zero cannot both decide that destruction should be scheduled
and that a reference was acquired. LKMM reports the mutual-success outcome
`Never` (0/2 witnesses). The unsafe unconditional-increment control can
resurrect zero and reports `Sometimes` (1/1).

The gate pins the IPC helper and locking contract, refcount implementation,
LKMM RMW axiom, configured x86-64 object, both function symbols, and its
`lock cmpxchg`/`lock xadd` lowering. The caller-locking prerequisite is an
assumption. Callback execution and RCU grace periods are not modeled.

No allocator reuse, arbitrary refcount population, progress, other
architecture, whole-IPC, whole-RCU, or whole-kernel property is accepted.
No runtime kernel was used; nothing was installed and no privileged
operation was performed.
