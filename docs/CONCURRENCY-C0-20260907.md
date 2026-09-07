# Mthread + Eva C0 capability record

Status: **C0 accepted and renewed on 2026-09-07; C1 and two narrow C2
properties were subsequently accepted; general kernel concurrency remains open**.
See the [C1 record](CONCURRENCY-C1-20260907.md) and
[C2 mutex record](CONCURRENCY-C2-20260907.md), followed by the
[C2 IRQ record](CONCURRENCY-C2-IRQ-20260907.md).

This milestone establishes what the project's locked Frama-C provider actually
does on small, project-owned concurrent models. It does not establish that Linux
mutexes, spinlocks, IRQ masking, atomics, barriers, RCU, object reclamation, or
the Linux Kernel Memory Model are soundly modeled.

## Provider and replay

- Frama-C `33.0 (Arsenic)`.
- Provider binary SHA-256:
  `815c916df2361e7af5a18125c97b37665e4eed91e76daa185d571706563e7ef2`.
- Mthread identifies itself as `Experimental tools for multi-threaded programs`.
- The manifest binds the provider, bundled Mthread C models, selected Mthread
  implementation sources, all nine fixtures, common options, and exact expected
  outcomes: [config/concurrency-c0.json](../config/concurrency-c0.json).
- Reproduce without installing anything:

  ```sh
  python3 -m fragma concurrency-c0 \
    --output results/concurrency-c0-NEW
  ```

The runner refuses an existing output path. It retains version/help inventory,
argv, stdout, stderr, Frama-C report CSV, parsed results, and SHA-256 identities
locally. The compact accepted result is
[results/concurrency-c0-20260907-09/SUMMARY.md](../results/concurrency-c0-20260907-09/SUMMARY.md).
This renewal changes only the recorded CLI identity after adding the IPC
refcount command; all nine capability outcomes are unchanged.

## Empirically established behavior

Mthread and Eva analyze each discovered entry point as an abstract thread and
iterate shared-write interference to a fixpoint. The bundled pthread model can
create a thread and maps its mutex operations to Mthread's abstract mutex
operations. In this calibration:

- isolated worker arithmetic is `valid` in one iteration;
- both mutex-protected critical-section assertions are `valid`, and both writes
  are reported as protected by the same abstract mutex;
- deliberately unprotected shared reads/writes are reported as an unprotected
  read/write race, while both bounded value assertions remain `valid` after
  interference;
- a deliberately false worker-local assertion is `invalid`, demonstrating that
  process exit zero and successful parsing are not treated as property success;
- the automatic interrupt-handler option creates a distinct interrupt entry
  point and exposes its unprotected interference with main;
- a synthetic thread created after an abstract exclusion lock is initialized
  has two `valid` protected critical-section assertions; and
- an unsupported `pthread_barrier_wait()` aborts the plugin with exit 1 and an
  explicit warning that continuing would probably be unsound.

Mthread's final write/write section can be `none` when the same zone is also
read: such accesses appear in the broader read/write section. Therefore the
runner preserves both final sections and checks the `unprotected` qualifier; it
does not infer “no competing writes” from an empty write/write section.

## Model gaps exposed by C0

The bundled `pthread_join()` model returns a nondeterministic status but does
not wait for, synchronize with, or import completion from the target thread.
Accordingly, the post-join completion assertion is `unknown` and the shared
access is unprotected. This model cannot justify lifetime or ownership claims
that depend on a real join.

Automatic interrupt handlers begin from the initial main state. A lock
initialized later inside `main()` may therefore be uninitialized in the
handler's abstract starting state. The registered-handler exclusion case keeps
both assertions `unknown` and reports the lock-lifecycle access; the successful
synthetic exclusion case must not be used to hide this initialization gap.

The inspected provider/model sources do not supply Linux or C11 weak-memory
semantics for atomics, acquire/release operations, compiler/CPU barriers, RCU,
or lock-free reclamation. Mthread's mutex-oriented interleaving and race model
is not an LKMM proof. Likewise, its abstract mutex is not yet a justified model
of `spin_lock()`, `local_irq_disable()`, preemption control, or any configured
kernel implementation.

The pthread fixtures' Frama-C report CSVs contain 32 `Considered valid` rows
from bundled/model contracts (the builtins-only interrupt fixture contains
none). These are trusted or builtin specification statuses, not independently
proved obligations. They stay counted in the raw result rather than being
presented as 32 additional program proofs.

The provider source also documents limitations/no-op behavior in other pthread
operations and asymmetric priority handling. C0 has not converted those paths
into supported semantics; any target using them must fail a later capability
gate or add a reviewed conservative model and new controls.

## C0 outcome and next gate

All nine expected classes pass: valid property, invalid property, unknown
property, protected access, possible unprotected race, automatic interrupt
registration, lock-initialization gap, unsupported primitive, and tool exit.
Focused concurrency runner/parser tests pass; the combined project run is
[928 passing tests](../results/tests-concurrency-c2-irq-20260907.log), with 20
pre-existing conditional skips.

This meets C0 because the actual provider and its limitations are now pinned,
exercised, and distinguished in evidence. It awards no Linux concurrency target.
The subsequent C1 milestone adds the required identities, stale-evidence gates
and scope fields without upgrading these calibrations. The later C2 mutex and
IRQ pilots accept two independently gated access-protection properties. They do
not upgrade C0's automatic-handler mechanism or establish general interrupt,
weak-memory or RCU support.
