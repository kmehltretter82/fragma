# fragma — Frama-C on the Linux kernel

Verification and calibration rig for selected Linux kernel C functions.
Frama-C/ACSL checks conditional correctness claims; deliberately wrong contracts
and altered control examples test whether the verification setup detects them.
This is not a whole-kernel proof. One Linux RV32 wrong-result defect has now been
dynamically reproduced and has a send-ready fix; it has not yet been emailed or
acknowledged upstream.

The public repository contains the authored runner, specifications, tests,
plans, compact result summaries, and experimental provider patches. Downloaded
toolchains, kernel snapshots, prepared builds, binaries, caches, and bulk run
evidence remain local and are reproducible from the recorded inputs. Links to
excluded bulk artifacts therefore describe local evidence rather than files
shipped in Git. Licensing remains governed by the notices on individual files;
no blanket repository license has been assigned.

Original string baseline source tree: `~/linux-work/linux` @ `b9b3e33b70b71`
(7.2-rc6), `lib/string.c`. The RV32 finding records its separate v7.3-rc2 and
linux-next identities in its handoff.

Development roadmap: [PLAN.md](PLAN.md) covers model validation, reproducible
regression checks, stronger contracts, and staged coverage expansion, including
s390 first and eventual support for every architecture in the pinned kernel tree.

Current implementation and fresh evidence: [PROGRESS.md](PROGRESS.md).
The [RV32 guard-page A/B result](riscv/rv32-zeropad/README.md) demonstrates that
`load_unaligned_zeropad()` returns bytes from the preceding word at a page
boundary before the fix and passes all three cases after it. The minimal patch
is strict-checkpatch clean, applies to mainline and linux-next, has RV32/RV64
build controls, and passed a mail dry-run. It is send-ready, not sent.
The [Mthread + Eva C0 record](docs/CONCURRENCY-C0-20260907.md) pins nine
capability controls and their valid, invalid, unknown, race and unsupported
outcomes. The [C1 evidence gate](docs/CONCURRENCY-C1-20260907.md) adds explicit
model, property, context, ownership and freshness identities, including a
dependency-specific stale control. The first
[C2 Linux mutex pilot](docs/CONCURRENCY-C2-20260907.md) now accepts one narrow
kernel property: the shared `done` accesses in token-identical
`DO_ONCE_SLEEPABLE` helper bodies are protected for paired process-context
callers on the pinned UP x86_64 profile. Its lock-elided A/B control exposes the
same accesses as unprotected. The separate
[C2 OMAP HDQ IRQ pilot](docs/CONCURRENCY-C2-IRQ-20260907.md) accepts one
site-based process/hard-IRQ property on a configured SMP ARM profile: selected
critical accesses share `hdq-spinlock`, with independent same-CPU mask-elided
and remote-CPU spin-elided controls. The handler's unlocked status read remains
visible and outside the accepted claim. The new
[C3 LKMM baseline](docs/CONCURRENCY-C3-LKMM-20260907.md) pins herd7 7.58, the
kernel model and four detecting weak/ordered calibrations. The separate
[trace tgid-map pilot](docs/CONCURRENCY-C3-TRACE-20260907.md) accepts one narrow
source-linked release/acquire ordering property on configured SMP x86-64; its
once-access negative permits the stale-payload outcome and reports a data race.
The new [module-statistics atomic/RMW pilot](docs/CONCURRENCY-C3-ATOMIC-20260907.md)
passes 162/162 gates and accepts a second C3 production property: two selected
concurrent `atomic_inc()` operations on `failed_load_modules` cannot collapse to
one. Its split once-access control permits the lost update, and an independent
pair distinguishes fully ordered from relaxed increment-return operations. The
[System V IPC refcount pilot](docs/CONCURRENCY-C3-REFCOUNT-20260907.md) then
passes 822/822 gates and accepts one lifetime-sensitive functional property:
from the sole reference, `ipc_rcu_putref()` cannot schedule destruction while a
concurrent, locking-stabilized `ipc_rcu_getref()` also succeeds. Its unsafe
unconditional-increment control exposes a zero-refcount resurrection witness.
Real `ipc/util.o` source/compiler/symbol/disassembly mappings pass for x86-64,
arm64, riscv64, big-endian s390x, ARMv7, big-endian PowerPC32, SuperH, Alpha
and UML x86-64, including emitted alternative atomic paths and UML's explicit
`ARCH`/`SUBARCH` header route. All nine selected configurations are SMP; the
UP-only exploratory m68k object is not promoted into this claim.
These checks confirm bounded production weak-memory/atomic reasoning, not a new
defect or general concurrency support. Progress, remaining architecture mappings,
broader lockless protocols, IRQ/NMI classes and explicit RCU grace-period
reasoning remain open.
The [renewed s390x pilot](s390/L2-RENEWAL-20260907.md) establishes scoped L2 support
for seven C helpers. The [freshly renewed common24 baselines](common/L2-CLANG-RENEWAL-20260907.md)
cover four helpers on ARM32, PowerPC32, m68k, ARM64, RISC-V64, SH, Alpha,
hardware x86-64 and UML x86-64. These are named function
sets under specific profiles; broader architecture support remains open.
The [seven-target proof renewal](docs/PROOF-RENEWAL-20260907.md) now also restores
current ARM64 scalar, RISC-V encoder, s390 and string WP acceptance. The
[nine-calibration renewal](docs/CALIBRATION-RENEWAL-20260907.md) restores the
eight string cases and s390's mandatory byte-order case. S390's existing
seven-helper L2 scope is separately rechecked, not expanded.
The results and reproduction notes below describe the original experiments;
they are not the acceptance baseline for the new runner and checked profiles.

The new entry point is `python3 -m fragma` (`list`, `preflight`, `snapshot`,
`prepare`, `run`, `compare`, `coverage`, `concurrency-c0`, `concurrency-c1`,
`concurrency-c2`, `concurrency-c2-irq`, `concurrency-c3-lkmm`,
`concurrency-c3-trace`, `concurrency-c3-module-stats`,
`concurrency-c3-ipc-refcount`,
`rv32-zeropad-audit`). See
[toolchain setup](docs/toolchain.md) and
[architecture profiles](profiles/README.md). Verification never installs
packages. No `sudo` installation is needed on the current machine for the
ten configured architecture profiles, including s390x and UML x86-64.
See [result semantics](docs/results.md) and [explicit-evidence coverage](docs/coverage.md)
for the distinction between historical, current, incomplete and calibrated results.
The [maintenance guide](docs/maintenance.md) covers adding targets, scoped reviews,
pin updates and `python3 ci/check.py` for local core/extended/all regression runs.
The [shared byte-helper harness](common/README.md) uses explicit profile-local
policies and compiler controls. Its nine registered variants now have current
accepted evidence and audited replay: 846 ordinary goals, 738 selected properties
and 252 compiler observations, with 5,155 audit hashes unchanged. The
[wave-three record](common/WAVE3-20260906.md) preserves the initial failures,
exact Alpha metadata and genuine `-Os` corrections, and scoped review renewal.
The [Hexagon LLVM build milestone](profiles/LLVM-BUILD-20260906.md) passes
genuine preparation and `lib/string.o`, without model activation or target
execution. The new [target-aware Clang interfaces](profiles/CLANG-INTERFACE-20260906.md)
preserve GCC behavior, with 182 freshly rerun existing-model checks. The subsequent
[Hexagon header milestone](profiles/HEXAGON-HEADER-PROVISION-20260906.md)
authenticates and provisions 217 workspace-local headers. The new
[generator adapter](profiles/HEXAGON-GENERATOR-ADAPTER-20260906.md) is extended by
[source-derived layout calibration](profiles/HEXAGON-LAYOUT-20260906.md): 100
actual compiler queries, all twelve GNU alignment fields, correct Clang dialect
selection, and Frama-C agreement on 28 layout values with three rejection
controls. The dated September 6 [891-test pass](results/tests-hexagon-gnu-model-20260906.log)
is shared-project evidence, not a new private-provider regression run.
Four extended-alignment contradictions still block activation; Hexagon remains
unconfigured, with L1 and production integration open.
The [private alignment candidate](build/framac-alignment-provider-20260907/CANDIDATE-BUILD-20260907.md)
now builds and passes six early/core-parser checks, preserving the initial
failed attempts. Its [fresh private context run](build/framac-alignment-provider-20260907/PRIVATE-CONTEXT-20260907.md)
has 33 constant agreements, 21 corresponding rejections and one category
mismatch across 55 pairs. Fourteen additional controls expose declaration,
VLA and typed-arithmetic gaps. The [fresh declaration successor](build/framac-alignment-provider-20260907/CANDIDATE-DECLARATION-20260907.md)
now builds and correctly rejects the four missing-definition controls, keeping
the reverse-order cases and 55-pair outcomes unchanged. The later
[candidate-5 handoff](build/framac-alignment-provider-20260907/CANDIDATE-VLA-ARITHMETIC-20260907.md)
preserves candidate 4's VLA regression and fixes its saved-bound initializer:
basic double/int witnesses match `[8,8,4]`/`[4,4,4]`, while the 55-pair summary
remains 33/21/1. Its 44-case raw batch records 156 executed queries, 66 skips,
eleven exit-zero and 33 exit-one initial results per analyzer mode, and 22
successful reparses. Three expanded AST-check failures recover; cast/constant-
expression, static type-query and three valid-but-unsupported VLA cases remain.
Patch 009 is unbuilt. Hexagon implementation is parked for the user's priority:
actual bounded Linux kernel correctness review. No profile or accepted count
changes; these are private tool/model observations and are unrelated to the
separately confirmed RV32 finding.
The [current coverage matrix](results/coverage-calibrations-clang-renewed-20260907/coverage.md)
retains all 31 targets: 16 current proofs, nine current accepted Eva calibrations
and six legacy nonpasses. No accepted-stale targets remain. Eighteen of 24
distinct kernel functions have current
accepted variants; six still lack one. The seven newly renewed proof targets
pass 74 L1 checks, 418 ordinary goals and 331 selected properties, with 2,031
independently checked hashes unchanged. Full-suite renewal remains open.
The [socket-denied attempts](common/RENEWAL-SOCKET-FAILURE-20260907.md) remain
failed and incomplete; the retry needed approved local solver IPC, not `sudo`.
The new [L2 record](common/L2-CLANG-RENEWAL-20260907.md) also preserves the failed
first coverage audit and distinguishes unavailable old-context validation from
the nine current common24 proofs. The new combined matrix preserves those
histories and adds the seven renewed non-common proofs and nine renewed
calibrations. This restores existing acceptance, not a new architecture or L3.
See the [configured-profile queue](common/NEXT-PROFILES.md) and
[remaining architecture prerequisites](profiles/NEXT-WAVE.md) for subsequent work.

## Layout

    toolchain/install.sh      sudo-free Frama-C 33 + Alt-Ergo + GMP via opam/~.local
                              (cvc5, z3 added to ~/.local/bin by hand)
    kbuild/                   x86_64 tinyconfig O= build (source tree untouched)
    compile_commands.json     kernel's real flags for lib/string.c
    annotated/
      string.acsl.c           lib/string.c + ACSL in COMMENTS ONLY (see gate)
      specs.h                 assumed contracts for extern strlen/memcpy +
                              fragma_unreachable stub (models BUG()/trap)
      compat.h                asm_inline -> asm front-end shim
      override/asm/           doctored string_64.h (C23 auto), bug.h (ud2 elided)
      check-unmodified.sh     GATE: proves string.acsl.c == tree lib/string.c
                              after comment stripping (all ACSL is in comments)
      gen-db.py               builds annotated/compile_commands.json + shims
      gen-variants.sh         derives string.eva.c / string.fault.c
    harness/
      naive_cex.c             EVA driver: naive strlcat postcond -> status INVALID
      eacsl_cex.c             E-ACSL: runtime ABORT on the naive claim
      eacsl_fault_cex.c       E-ACSL: runtime OOB when BUG_ON is removed
    run-wp.sh                 uniform WP driver (FRAGMA_FILE= picks the variant)

## Results

* `strnchr`   : **39/39** goals proved (memory safety + full functional + term.)
* `strlcat`   : **39/40** — the 1 open goal is `naive_no_truncation`, a
                DELIBERATELY WRONG spec (the classic "return value == resulting
                length" misreading). It is the counterexample demo, not a bug.
* Counterexample, three independent forms, on the REAL kernel body:
  - WP: the naive goal fails only on the truncation path (triage: spec wrong).
  - EVA: `strlcat("ab","cdef",5)` -> naive postcondition status **invalid**,
         exact final state buf="abcd", return 6.
  - E-ACSL: instrumented binary **aborts** on the naive assertion at runtime.
* Fault injection (`string.fault.c`, BUG_ON removed): WP collapses 39->21/34,
  memcpy's dst_ok/no_overlap preconditions become unprovable; E-ACSL witness
  aborts on the out-of-bounds store. => the BUG_ON guard is load-bearing.

## The string calibration is not a reportable bug

Everything here is by construction: a planted wrong spec on decades-hardened
code, and a guard *we* removed. The value delivered is a validated rig, not a
finding. `lib/string.c` was the control target precisely because it is clean.

## Reproduce

    ./annotated/check-unmodified.sh          # gate: comments-only diff
    python3 annotated/gen-db.py && annotated/gen-variants.sh && python3 annotated/gen-db.py
    ./run-wp.sh strnchr                      # 39/39
    ./run-wp.sh strlcat                      # 39/40 (naive fails by design)
    FRAGMA_FILE=annotated/string.fault.c ./run-wp.sh strlcat   # collapse
    # EVA / E-ACSL counterexamples: see harness/*.c headers for exact cmds

## Gotchas defeated (Frama-C 33 vs kernel headers)

`__typeof_unqual__`, `asm_inline`, GNU `, ## arg` comma-deletion (needs
`-std=gnu11`, NOT Frama-C's `-std=c11`), `u128`/`__int128` + `__signed__`,
C23 `auto`, `__builtin_unreachable` (no model -> falls through -> poisons
downstream proofs; mapped to a noreturn `ensures \false` stub), volatile asm
in BUG() (havoc-all can't satisfy `assigns` even on dead paths -> ud2 elided
in the header override). WP typed-model quirk: a moving pointer loses its
same-object relation unless you add a `\base_addr` loop invariant.
