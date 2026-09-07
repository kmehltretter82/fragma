# Mthread + Eva C0 capability baseline

Overall calibration: **PASS**

A PASS means every valid, invalid, unknown, race, and unsupported control
matched its pinned expectation. It does not mean every fixture is safe.

Provider: Frama-C 33.0 (Arsenic)
Provider binary SHA-256: `815c916df2361e7af5a18125c97b37665e4eed91e76daa185d571706563e7ef2`

| Case | Interpretation | Assertions | Unprotected R/W | Unprotected W/W | Exit | Gate |
|---|---|---|---:|---:|---:|---|
| `isolated` | valid_calibration | isolated_arithmetic=valid | no | no | 0 | PASS |
| `mutex` | valid_calibration | mutex_worker_owned=valid, mutex_main_owned=valid | no | no | 0 | PASS |
| `interference` | possible_race | interference_worker_range=valid, interference_main_range=valid | yes | no | 0 | PASS |
| `join` | model_gap | join_completion_model_gap=unknown | yes | no | 0 | PASS |
| `false_assertion` | false_property | deliberate_false=invalid | no | no | 0 | PASS |
| `interrupt_unprotected` | possible_race | interrupt_range=valid | yes | no | 0 | PASS |
| `interrupt_exclusion_synthetic` | valid_synthetic_exclusion | synthetic_interrupt_worker_owned=valid, synthetic_interrupt_main_owned=valid | no | no | 0 | PASS |
| `interrupt_registered_exclusion_gap` | model_gap | interrupt_handler_owned=unknown, interrupt_main_owned=unknown | yes | no | 0 | PASS |
| `unsupported_pthread` | unsupported | none | no | no | 1 | PASS |

Raw stdout, stderr, report CSV files, commands, manifest snapshot, and
SHA-256 identities are retained beside this summary.
