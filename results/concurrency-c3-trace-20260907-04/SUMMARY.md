# Trace tgid-map C3 release/acquire pilot

Overall source-linked gate: **PASS**

Accepted kernel ordering properties: **1**

| Case | Role | Outcome | LKMM flags | Bad witnesses | Gate |
|---|---|---|---|---:|---|
| `release_acquire_positive` | verification_candidate | Never | none | 0 | PASS |
| `once_once_negative` | required_weakened_control | Sometimes | data-race | 1 | PASS |

Evidence checks: **135/135 passed**.

The accepted property is narrow: after the acquire observes the pointer
published by the successful release, the guarded `tgid_map_max` read cannot
see its static pre-publication zero. The release/acquire model is `Never`
with no LKMM flag; replacing only those primitives yields `Sometimes`, one
bad witness, and `Flag data-race`.

The gate binds this model to exact source statements, the sole allocator
callsite, static lifetime, kernel barrier contracts, x86 macro definitions,
a configured SMP x86-64 compile, local ELF symbols, and instruction order.
It does not verify array contents, bounds, allocation, all tracing behavior,
other architectures, progress, or any future replacement/reclamation design.

No module was generated or loaded; no runtime kernel, package installation,
or privileged operation was used.
