# Concurrency C1 identity, scope and evidence gates

Status: **C1 infrastructure accepted and renewed on 2026-09-07; zero Linux
concurrency targets are accepted by C1 itself. Two narrow C2 and three narrow
C3 properties were accepted later; C3 remains incomplete and C4 is open**.

C1 turns the C0 capability observations into explicitly scoped, dependency-bound
records. It prevents a successful calibration from silently becoming a claim
about Linux locks, interrupts, weak memory, RCU or lock-free code.

## Schemas and command

The [model registry](../config/concurrency-models.json) names the exact Frama-C
33 Mthread+Eva provider, execution abstraction, model-file groups, six support
dimensions and five primitive models. Every primitive contains its observed
semantics, a conservative-use argument, limitations, and an explicit rule that
an empty stub is not allowed.

The [target registry](../config/concurrency-scopes.json) gives each of the nine
C0 cases:

- model identity and dependency groups;
- property kind, exact claim and excluded claims;
- synchronization model and justification;
- memory-order assumptions;
- ordinary-thread, interrupt and preemption context;
- shared-object ownership and external interference; and
- required support dimensions/primitives, evidence kind and kernel scope.

The new command rechecks a complete local C0 result and writes a new result
without modifying it:

```sh
python3 -m fragma concurrency-c1 \
  --c0-result results/concurrency-c0-20260907-09 \
  --output results/concurrency-c1-NEW
```

Existing outputs are never overwritten. No installation or `sudo` is involved.

## Accepted current result

The final [C0 result](../results/concurrency-c0-20260907-09/SUMMARY.md) pins the
current C0 runner, CLI, tests, source fixtures, provider binary, bundled models,
implementation sources, options and tool lock. C1 then re-parses every report
CSV and stdout/stderr diagnostic, recomputes every expected outcome, checks each
argv/environment/exit status, compares the per-case result with the terminal C0
summary, and hashes 47 raw C0 artifacts.

The [C1 result](../results/concurrency-c1-20260907-05/SUMMARY.md) passes all 82
checks. Its [machine-readable audit](../results/concurrency-c1-20260907-05/pilot-audit.json)
records 25 current C0 inputs, target-specific dependency digests, four C1
implementation/schema identities, all raw-artifact hashes, support blockers and
the complete scope metadata. All nine capability calibrations are accepted as
evidence; all nine remain **not accepted as verification**, and the accepted
kernel-concurrency count is exactly zero.

## Support matrix

| Dimension | Status | Meaning |
|---|---|---|
| Sequential | calibrated | Small Eva properties behave as expected with Mthread enabled; this is not arbitrary-kernel support. |
| Mutex-protected concurrency | calibrated | The abstract Mthread mutex works in synthetic fixtures; it is not connected to Linux mutex/spinlock implementations. |
| Interrupts | partial | Handler discovery/interference works, but initialization, nesting, IRQ classes and Linux masking remain gaps. |
| Weak-memory atomics | unsupported | No C11/LKMM atomic, acquire/release or barrier claim is accepted. |
| RCU | unsupported | Publication, grace periods and reclamation are not modeled. |
| Lock-free algorithms | unsupported | Functional, lifetime and progress properties are not modeled. |

The primitive table separately keeps `pthread_join` and
`pthread_barrier_wait` unsupported, automatic interrupt registration partial,
and abstract create/mutex behavior calibrated only. The acceptance function
requires every dimension and primitive of a future verification target to be
explicitly `supported`; `calibrated`, `partial`, `unsupported` and
`not_assessed` all block verification.

## Stale-evidence negative control

For the negative run only, the C0 receipt's recorded SHA-256 identity of
`mthread_pthread.c` was temporarily replaced with a false value; the
provider/model files themselves were not modified, and the current receipt was
restored and hash-checked immediately afterward. The resulting
[negative-control summary](../results/concurrency-c1-stale-control-20260907-06/SUMMARY.md)
is a required **FAIL**:

- the overall input-freshness gate detects exactly that model dependency;
- all seven pthread-dependent cases are rejected as stale; and
- the two builtins-only interrupt cases retain current calibration evidence.

This demonstrates dependency-specific invalidation instead of globally
rewriting old observations or upgrading unaffected sequential evidence. Unit
controls also verify that unknown/not-assessed support blocks verification and
that the unsupported join primitive remains an explicit blocker. The later
[981-test project run](../results/tests-concurrency-c3-refcount-20260907.log) passes with
20 pre-existing conditional skips.

## C1 boundary and next work

C1 completes evidence plumbing, not kernel semantics. It provides no justification
for replacing Linux synchronization with the abstract Mthread mutex, and its
schemas cannot make an unsound model conservative by declaration alone. C2 must
select a very small configured Linux API/caller scope, derive models from the
actual implementation, review lock/IRQ/preemption and lifetime behavior, add
benign and negative controls, and only then change the relevant statuses to
`supported` for precisely stated properties. Weak-memory atomics and RCU remain
separate C3/C4 gates.

Subsequent work completed two such bounded connections in the
[C2 `DO_ONCE_SLEEPABLE` mutex pilot](CONCURRENCY-C2-20260907.md) and
[C2 OMAP HDQ IRQ pilot](CONCURRENCY-C2-IRQ-20260907.md). Those later results
accept two access-protection properties in their own C2 scopes; they do not
alter or upgrade any of the nine C1 calibration records.
