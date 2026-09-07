# System V IPC refcount C3 lifetime pilot

Overall source-linked gate: **PASS**

Accepted kernel lifetime properties: **1**
Checked architecture mappings: **4**
LKMM functional cases: **2**

| Architecture profile | Kernel ARCH | Object | Gate |
|---|---|---|---|
| `x86_64-ipc-refcount-c3` | `x86_64` | ELF64, machine 62 | PASS |
| `arm64-ipc-refcount-c3` | `arm64` | ELF64, machine 183 | PASS |
| `riscv64-ipc-refcount-c3` | `riscv` | ELF64, machine 243 | PASS |
| `s390x-ipc-refcount-c3` | `s390` | ELF64, machine 22 | PASS |

| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |
|---|---|---|---:|---:|---|
| `refcount_put_get_positive` | verification_candidate | Never | 0/2 | 2 | PASS |
| `unconditional_resurrection_negative` | required_unsafe_control | Sometimes | 1/1 | 2 | PASS |

Evidence checks: **396/396 passed**.

Starting with the IPC contract's sole reference, the selected final put
and get-unless-zero cannot both decide that destruction should be scheduled
and that a reference was acquired. LKMM reports the mutual-success outcome
`Never` (0/2 witnesses). The unsafe unconditional-increment control can
resurrect zero and reports `Sometimes` (1/1).

The gate pins the IPC helper and locking contract, refcount implementation,
LKMM RMW axiom, and configured x86-64, arm64, riscv64, and s390x
objects. Each mapping pins both function symbols and target disassembly,
including alternative atomic paths where the architecture emits them.
The caller-locking prerequisite is assumed. Callback execution and RCU
grace periods are not modeled.

No allocator reuse, arbitrary refcount population, progress, unlisted
architecture, whole-IPC, whole-RCU, or whole-kernel property is accepted.
No runtime kernel was used; nothing was installed and no privileged
operation was performed.
