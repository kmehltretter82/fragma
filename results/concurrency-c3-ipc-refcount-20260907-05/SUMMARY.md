# System V IPC refcount C3 lifetime pilot

Overall source-linked gate: **PASS**

Accepted kernel lifetime properties: **1**
Checked architecture mappings: **8**
LKMM functional cases: **2**

| Architecture profile | Kernel ARCH | Scope | Object | Gate |
|---|---|---|---|---|
| `x86_64-ipc-refcount-c3` | `x86_64` | `smp-multicpu` | ELF64, machine 62 | PASS |
| `arm64-ipc-refcount-c3` | `arm64` | `smp-multicpu` | ELF64, machine 183 | PASS |
| `riscv64-ipc-refcount-c3` | `riscv` | `smp-multicpu` | ELF64, machine 243 | PASS |
| `s390x-ipc-refcount-c3` | `s390` | `smp-multicpu` | ELF64, machine 22 | PASS |
| `arm32-ipc-refcount-c3` | `arm` | `smp-multicpu` | ELF32, machine 40 | PASS |
| `powerpc32-smp-ipc-refcount-c3` | `powerpc` | `smp-multicpu` | ELF32, machine 20 | PASS |
| `sh-smp-ipc-refcount-c3` | `sh` | `smp-multicpu` | ELF32, machine 42 | PASS |
| `alpha-smp-ipc-refcount-c3` | `alpha` | `smp-multicpu` | ELF64, machine 36902 | PASS |

| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |
|---|---|---|---:|---:|---|
| `refcount_put_get_positive` | verification_candidate | Never | 0/2 | 2 | PASS |
| `unconditional_resurrection_negative` | required_unsafe_control | Sometimes | 1/1 | 2 | PASS |

Evidence checks: **738/738 passed**.

Starting with the IPC contract's sole reference, the selected final put
and get-unless-zero cannot both decide that destruction should be scheduled
and that a reference was acquired. LKMM reports the mutual-success outcome
`Never` (0/2 witnesses). The unsafe unconditional-increment control can
resurrect zero and reports `Sometimes` (1/1).

The gate pins the IPC helper and locking contract, refcount implementation,
LKMM RMW axiom, and eight configured SMP profiles: x86-64, arm64,
riscv64, s390x, ARM32, PowerPC32, SuperH, and Alpha.
Each mapping pins both function symbols and target disassembly,
including alternative atomic paths where the architecture emits them.
The caller-locking prerequisite is assumed. Callback execution and RCU
grace periods are not modeled.

No allocator reuse, arbitrary refcount population, progress, unlisted
architecture, whole-IPC, whole-RCU, or whole-kernel property is accepted.
No runtime kernel was used; nothing was installed and no privileged
operation was performed.
