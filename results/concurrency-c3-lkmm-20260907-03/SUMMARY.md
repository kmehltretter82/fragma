# Linux LKMM/herd7 C3 capability calibration

Overall calibration: **PASS**

Semantic calibrations accepted: **4**
Production kernel properties accepted: **0**

| Case | Role | Condition outcome | Witnesses +/− | States | Gate |
|---|---|---|---:|---:|---|
| `mp_once_once` | weakened_control | Sometimes | 1/3 | 4 | PASS |
| `mp_release_acquire` | ordered_calibration | Never | 0/3 | 3 | PASS |
| `sb_once_once` | weakened_control | Sometimes | 1/3 | 4 | PASS |
| `sb_full_barrier` | ordered_calibration | Never | 0/3 | 3 | PASS |

Evidence checks: **92/92 passed**.

The two weakened READ_ONCE/WRITE_ONCE controls permit their bad outcome;
the matching release/acquire and full-barrier tests forbid it. This pins
a working architecture-independent LKMM route and proves the runner can
distinguish weak-memory outcomes from ordinary interleavings.

This is not yet a production-code proof or a kernel bug result. Source-to-
litmus correspondence, compiler/architecture lowering, lifetime, functional
lock-free behavior, and progress remain separate C3 gates. No klitmus7
module, running-kernel action, installation, or privileged command was used.

Raw stdout/stderr, exact argv and working directories, manifest snapshot,
input identities, parsed decisions, and artifact hashes are retained beside
this summary.
