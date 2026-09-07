# Concurrency C1 evidence and scope gate

Overall C1 infrastructure gate: **FAIL**

A PASS means the C0 observations were re-parsed, their dependencies are
current, and every calibration carries explicit scope/context/model metadata.
It does not accept a concurrent Linux kernel target.

Accepted kernel concurrency targets: **0**

| Support dimension | Status | Scope |
|---|---|---|
| `sequential` | **calibrated** | Eva value properties inside the project-owned entry points, with Mthread enabled and the recorded options. |
| `mutex_protected_concurrency` | **calibrated** | Mthread abstract mutex ownership and interference in project-owned pthread fixtures. |
| `interrupts` | **partial** | Automatic handler discovery and shared-write interference from the initial main state. |
| `weak_memory_atomics` | **unsupported** | No accepted C11 or Linux weak-memory atomic/barrier semantics. |
| `rcu` | **unsupported** | No accepted RCU publication, grace-period or reclamation semantics. |
| `lock_free_algorithms` | **unsupported** | No accepted lock-free functional, lifetime or progress reasoning. |

| Calibration | Evidence | Stale dependencies | Verification | Blocking support |
|---|---|---|---|---|
| `isolated` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, pthread_create=calibrated |
| `mutex` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, mutex_protected_concurrency=calibrated, pthread_create=calibrated, mthread_abstract_mutex=calibrated |
| `interference` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, pthread_create=calibrated |
| `join` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, pthread_create=calibrated, pthread_join=unsupported |
| `false_assertion` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, pthread_create=calibrated |
| `interrupt_unprotected` | accepted | none | not accepted | sequential=calibrated, interrupts=partial, interrupt_registration=partial |
| `interrupt_exclusion_synthetic` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, mutex_protected_concurrency=calibrated, pthread_create=calibrated, mthread_abstract_mutex=calibrated |
| `interrupt_registered_exclusion_gap` | accepted | none | not accepted | sequential=calibrated, mutex_protected_concurrency=calibrated, interrupts=partial, mthread_abstract_mutex=calibrated, interrupt_registration=partial |
| `unsupported_pthread` | rejected | toolchain/verified-prefix/opam/fragma/share/frama-c/share/mt/mthread_pthread.c | not accepted | sequential=calibrated, pthread_barrier_wait=unsupported |

All current targets are project-owned capability calibrations. Calibrated,
partial, unsupported, or not-assessed dimensions block verification claims;
only an explicitly `supported` required dimension/primitive can clear that
future gate. Model/source/runner drift invalidates the dependent evidence.
