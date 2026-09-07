# Module-statistics C3 atomic/RMW pilot

Overall source-linked gate: **PASS**

Accepted kernel atomicity properties: **1**
LKMM atomic/RMW cases: **4**

| Case | Role | Outcome | Witnesses +/− | Distinct states | Gate |
|---|---|---|---:|---:|---|
| `atomic_inc_positive` | verification_candidate | Never | 0/2 | 1 | PASS |
| `split_once_negative` | required_weakened_control | Sometimes | 2/2 | 2 | PASS |
| `atomic_return_mb_positive` | ordered_calibration | Never | 0/3 | 3 | PASS |
| `atomic_return_relaxed_negative` | weakened_calibration | Sometimes | 1/3 | 4 | PASS |

Evidence checks: **162/162 passed**.

The accepted source claim is deliberately small: from zero, two selected
concurrent `atomic_inc(&failed_load_modules)` operations cannot finish at
one. LKMM reports the lost-update condition `Never` (0/2 witnesses); the
split once-access control reports `Sometimes` (2/2). Witness totals count
executions and are intentionally distinct from the number of final states.

A supplemental ordering pair reports `Never` for fully ordered
`atomic_inc_return()` and `Sometimes` for its relaxed variant. The source
gate pins the counter inventory, caller path, atomic_t contract, LKMM RMW
axiom, configured object, local symbols, and x86 `lock incl` lowering.

No arbitrary debugfs snapshot, cross-object ordering, counter-overflow case,
other architecture, progress, module-loader correctness, or whole-kernel
race-freedom property is accepted. No runtime kernel or module was used;
nothing was installed and no privileged operation was performed.
