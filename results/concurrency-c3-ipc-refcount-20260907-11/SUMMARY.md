# System V IPC refcount C3 lifetime and bounded-progress pilot

Overall source-linked gate: **PASS**

Accepted kernel properties: **2**
Accepted lifetime properties: **1**
Accepted bounded-progress properties: **1**
Checked architecture mappings: **10**
Progress implementation mappings: **3**
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
| `loongarch64-clang-ipc-refcount-c3` | `loongarch` | `smp-multicpu` | ELF64, machine 258 | PASS |
| `um-x86_64-smp-ipc-refcount-c3` | `um (SUBARCH=x86_64)` | `smp-multicpu` | ELF64, machine 62 | PASS |

| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |
|---|---|---|---:|---:|---|
| `refcount_put_get_positive` | verification_candidate | Never | 0/2 | 2 | PASS |
| `unconditional_resurrection_negative` | required_unsafe_control | Sometimes | 1/1 | 2 | PASS |

| Progress case | Role | Finite schedules | Nontermination | Max CAS attempts | Gate |
|---|---|---:|---:|---:|---|
| `bounded_quiescent_strong_cas` | verification_candidate | 340 | 0 | 4 | PASS |
| `stale_expected_negative` | required_stale_expected_control | 340 | 117 | 4 | PASS |
| `spurious_failure_negative` | required_spurious_failure_control | — | cycle/1 | — | PASS |
| `unbounded_interference_negative` | required_unbounded_interference_control | — | cycle/2 | — | PASS |

Evidence checks: **937/937 passed**.

Starting with the IPC contract's sole reference, the selected final put
and get-unless-zero cannot both decide that destruction should be scheduled
and that a reference was acquired. LKMM reports the mutual-success outcome
`Never` (0/2 witnesses). The unsafe unconditional-increment control can
resurrect zero and reports `Sometimes` (1/1).

A separate finite-state check enumerates 340 bounded interference
schedules for the source retry loop. With strong compare/exchange
mismatch updating the expected value, every schedule terminates in at
most four CAS attempts. A stale-expected variant has 117 quiescent
nonterminating schedules; spurious failure and unbounded interference
separately expose one-state and two-state cycles.

The gate pins the IPC helper and locking contract, refcount implementation,
LKMM RMW axiom, and ten configured SMP profiles: x86-64, arm64,
riscv64, s390x, ARM32, PowerPC32, SuperH, Alpha, LoongArch64, and
UML x86-64.
Each mapping pins both function symbols and target disassembly,
including alternative atomic paths where the architecture emits them.
The bounded progress mapping is limited to native x86-64, s390x, and
UML x86-64 objects with checked single-instruction CAS retry paths.
The caller-locking prerequisite is assumed. Callback execution and RCU
grace periods are not modeled.

No allocator reuse, arbitrary refcount population, unbounded progress,
wait-freedom, LL/SC liveness, unlisted architecture, whole-IPC, whole-RCU,
or whole-kernel property is accepted.
No runtime kernel was used; nothing was installed and no privileged
operation was performed.
