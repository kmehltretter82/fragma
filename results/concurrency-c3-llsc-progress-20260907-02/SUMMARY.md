# C3 LL/SC progress capability audit

Overall evidence gate: **PASS**

Assessed LL/SC profiles: **6**
New kernel progress properties: **0**
Promoted LL/SC mappings: **0**
Detecting controls: **1**

| Profile | Implementation | Decision | Gate |
|---|---|---|---|
| `arm64-ipc-refcount-c3` | `runtime_dual_native_cas_llsc` | not_promoted | PASS |
| `riscv64-ipc-refcount-c3` | `runtime_dual_native_cas_llsc` | not_promoted | PASS |
| `arm32-ipc-refcount-c3` | `llsc_only_selected_object` | not_promoted | PASS |
| `powerpc32-smp-ipc-refcount-c3` | `llsc_only_selected_object` | not_promoted | PASS |
| `sh-smp-ipc-refcount-c3` | `llsc_only_selected_object` | not_promoted | PASS |
| `alpha-smp-ipc-refcount-c3` | `llsc_only_selected_object_with_trampoline` | not_promoted | PASS |

Evidence checks: **486/486 passed**.

The kernel's pinned atomic documentation says that simple compare/exchange
loops are expected to progress, but explicitly warns that this does not
automatically transfer to LL/SC implementations. A failed comparison branch
can itself invalidate a reservation; unbounded conditional-store failure
therefore remains a one-state retry cycle in the detecting control.

The diagnostic enumerates 120 finite
failure schedules under a hypothetical at-most-two-failures-per-CAS premise.
That artificial premise gives a maximum of 12 conditional-store
attempts across four source CAS calls, but no selected profile establishes
the premise. The diagnostic is permanently ineligible as kernel verification.

ARM64 and RISC-V contain runtime-selectable native-CAS and LL/SC paths.
ARM32, PowerPC32, SuperH and Alpha expose direct LL/SC retry paths; Alpha's
cold retry edge is checked through its emitted subsection trampoline.
No profile is promoted merely because its lifetime mapping passes.

No scheduler fairness, wait-freedom, unbounded lock-free progress, RCU
progress, interrupt/NMI progress or whole-kernel liveness is accepted.
No package was installed and no privileged or running-kernel action occurred.
