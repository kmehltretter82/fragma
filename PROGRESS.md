# Implementation progress

Updated 2026-09-07. [PLAN.md](PLAN.md) remains in progress. Model calibration,
individual proofs and named architecture baselines are not whole-suite or
all-architecture completion.

The requested bounded Linux review has produced one dynamically confirmed RV32
wrong-result defect. A project-only guard-page KUnit test fails on all three
page-end offsets before the fix and passes after it under a byte-identical
configuration. The [A/B handoff](riscv/rv32-zeropad/README.md) contains the
minimal send-ready patch, replay script and review/test notes; the
[evidence audit](results/rv32-zeropad-mail-ready-20260907/SUMMARY.md) binds source, logs,
images, configs, tool versions, patch identity, mainline/linux-next applicability,
RV32/RV64 build controls, strict checkpatch, maintainers and mail dry-run. It has
been sent manually by the user; upstream review or acknowledgement is not yet
recorded. The project will not invoke email commands on this host. No `sudo` or
package installation was used.

The preserved [MIPS32el machine-model checkpoint](profiles/MIPS32EL-MACHDEP-20260907.md)
has advanced to a registered
[MT7621 production profile](profiles/MIPS32EL-MT7621-L1-20260907.md). Its normal
no-override workflow selects a hash-locked SMP/CPS seed, builds genuine pinned
kernel `lib/string.c`, and passes all 19 L1 gates with an ELF32 little-endian
O32/MIPS32r2 object. The other ten profiles were freshly
[renewed](results/l1-mips-registration-renewal-20260907/SUMMARY.md), so the
configured model layer is now 11 profiles and 201/201 passing checks. The
[MIPS32el common24 L2 run](common/L2-MIPS32EL-20260907.md) now adds one current
scoped proof target: 94/94 ordinary goals and 82/82 selected properties pass.
Target execution, kernel callers, big-endian and 64-bit variants remain open.

The additive lock entry leaves all 18 preceding tool records unchanged, and
normal preflight passes the resulting 19-tool lock. Existing L2/proof receipts
remain exact at their preceding identity but are dated for the post-registration
project until their analyses are replayed; no L2 count is inferred from L1.

The concurrency continuation has completed C0 capability characterization,
C1 evidence/scope infrastructure and the limited C2 pilot milestone. The
[nine-case Mthread + Eva record](docs/CONCURRENCY-C0-20260907.md) passes its
valid, invalid, unknown, protected, race, interrupt and unsupported controls.
The [C1 audit](docs/CONCURRENCY-C1-20260907.md) re-parses all raw outcomes, binds
model/property/context/ownership identities and exposes six separate support
dimensions. Its current 82 checks pass; nine calibrations are current, while
all C1 verification flags and its kernel acceptance count remain zero. A
targeted stale-model control rejects the seven pthread-dependent cases while
preserving the two unaffected builtins-only cases. The
[C2 `DO_ONCE_SLEEPABLE` A/B pilot](docs/CONCURRENCY-C2-20260907.md) passes 63/63
checks and accepts one separate kernel property: mutex protection of the shared
`done` accesses for paired process-context callers on the pinned UP x86_64
profile. The lock-elided control exposes the same accesses as unprotected.
The separate
[C2 OMAP HDQ hard-IRQ/spinlock pilot](docs/CONCURRENCY-C2-IRQ-20260907.md)
passes 125/125 checks and accepts one further site-based kernel property on a
configured SMP ARM profile. Selected process/handler critical accesses carry
the same spinlock; independent mask-elided and remote-CPU spin-elided controls
expose the two protection dimensions. The handler's remote-CPU post-unlock read
remains explicitly unprotected and outside the accepted property, not declared
a kernel bug. This completes the limited C2 checklist. Functional protocols,
broader IRQ/NMI contexts and C4 RCU remain open. C3 has now delivered a
[92-check LKMM capability baseline](docs/CONCURRENCY-C3-LKMM-20260907.md): four
kernel-owned weak/ordered calibrations pass under pinned herd7 7.58, while its
production acceptance count remains zero. The separate
[trace tgid-map source pilot](docs/CONCURRENCY-C3-TRACE-20260907.md) passes
135/135 checks and accepts one bounded production ordering property on a
configured SMP x86-64 profile. Its release/acquire case forbids a stale max
value without an LKMM flag; its once-access negative permits one bad witness
and reports `data-race`. This verifies correct selected code, not a new defect.
The subsequent
[module-statistics atomic/RMW pilot](docs/CONCURRENCY-C3-ATOMIC-20260907.md)
passes 162/162 checks and accepts one bounded no-lost-update property: two
selected concurrent `failed_load_modules` increments cannot finish at one. Its
split once-access control permits the lost update; a separate pair distinguishes
fully ordered and relaxed increment-return operations. This also verifies
correct selected code rather than finding a defect. The subsequent
[System V IPC refcount lifetime/progress pilot](docs/CONCURRENCY-C3-REFCOUNT-20260907.md)
passes 1036/1036 checks and accepts two separately bounded properties. The
lifetime property says that, from an initial sole reference, the
locking-stabilized final put cannot schedule RCU destruction while the
concurrent get-unless-zero also succeeds. Its unsafe unconditional-increment
control permits the zero-refcount resurrection outcome. The finite-state
progress property checks all 340 declared interference schedules and establishes
termination within four strong-CAS attempts after at most three observations
and quiescence. Its stale-expected, spurious-failure and unbounded-interference
controls expose the omitted behaviors.
The same real `ipc/util.o` mapping now passes on eleven configured SMP builds:
x86-64, arm64, riscv64, big-endian s390x, ARMv7, big-endian PowerPC32, SuperH
and Alpha, LoongArch64, little-endian MIPS32r2 and UML x86-64. LoongArch64 and
MIPS use pinned Clang/LLVM 21.1.8 target routes and produce genuine ELF64
machine-258 and ELF32 machine-8 objects, respectively. The UML
profile separately binds `ARCH=um`,
`SUBARCH=x86_64`, an SMP config mutation, its x86-header route and its own
object. Native atomic paths, emitted alternatives, ELF32/ELF64 symbols and build
diagnostics are checked per architecture. The lifetime mapping covers all eleven;
the progress implementation mapping is limited to the checked native/UML x86-64
`CMPXCHG` and s390x `CS` paths and makes no LL/SC-liveness claim. The subsequent
[LL/SC capability audit](docs/CONCURRENCY-C3-LLSC-PROGRESS-20260907.md) passes
609/609 checks after revalidating the fresh 1036-check IPC base. It checks pinned
documentation, source and complete-object retry paths for ARM64, RISC-V, ARM32,
PowerPC32, SuperH, Alpha, LoongArch64 and MIPS32r2, but promotes zero properties
and zero mappings. LoongArch's AMO final decrement does not establish progress
for its LL/SC get retry; MIPS directly retries LL/SC in both selected paths.
Its 120-schedule finite diagnostic is explicitly hypothetical; an unbounded
conditional-store-failure control detects a one-state retry cycle. This is a
completed admission evaluation, not LL/SC progress verification or a new bug.
The [LoongArch mapping handoff](docs/CONCURRENCY-C3-LOONGARCH-20260907.md)
records its exact Clang/LLVM/configuration/object boundary and the remaining
general machine-model work.
The [MIPS mapping handoff](docs/CONCURRENCY-C3-MIPS-20260907.md) records the
distinct O32/MIPS32r2 route and keeps general, big-endian and 64-bit support
outside the accepted mapping.
The available m68k profile is UP only and was deliberately not promoted into
the SMP claim. Unbounded progress, architecture-backed LL/SC liveness, broader
lockless lifetime behavior and remaining architecture mappings keep C3
incomplete. Further Hexagon work remains parked; these
additions do not activate a general Frama-C LoongArch machine profile or change
the main 25-target suite acceptance counts.

The IPC CLI addition was followed by current-input renewal of the C0 result,
C1 audit and dependency-specific stale control, both C2 pilots, the C3 LKMM
baseline, trace pilot and atomic pilot. Their respective current directories end
in `c0-...-09`, `c1-...-05`, `c1-stale-control-...-06`, `c2-...-08`,
`c2-irq-...-04`, `c3-lkmm-...-05`, `c3-trace-...-04` and
`c3-module-stats-...-04`; every positive gate passes, and the stale control
rejects exactly seven pthread-dependent cases while preserving the two
builtins-only cases. A direct readback finds no input identity drift in those
positive receipts, the preceding `c3-ipc-refcount-...-03` lifetime pilot or the
current `c3-ipc-refcount-...-13` receipt. The accepted eight-profile predecessor
is `c3-ipc-refcount-...-06`; run `-07` added the ninth UML mapping, `-08` added
bounded x86 progress, `-09` added the separately checked s390 `CS` path, and
`-10` renews all 848 gates after the LL/SC CLI addition. Run `-11` adds the
distinct LLVM LoongArch64 mapping and reruns the full ten-profile base, passing
937/937 with 85 inputs and 363 retained artifacts. Run `-12` adds MIPS32r2 and
passes 1036/1036, but its generated prose retains the old ten-profile count;
current run `-13` fixes that renderer with a regression and passes 1036/1036
across 91 inputs and 395 retained artifacts. LL/SC audit run `-01`
failed closed at 484/486 because of a wrong tree pin and the correctly stale
base CLI identity; run `-02` uses the corrected pin and fresh `-10` base and
passes 486/486; final review then found that the live object identity was only
recorded rather than compared with the base receipt. Run `-03` adds all twelve
object hash/size gates plus seven exact base-semantic gates and passes 505/505.
Run `-04` adds direct identities for both reused helper modules and retains the
same 505/505 result. Run `-05` revalidates the enlarged base, assesses the
seventh LoongArch LL/SC get path and passes 556/556 with zero promotion. Run
`-06` adds MIPS and passes 609/609 but omits it from one generated explanatory
paragraph; current `-07` fixes and regression-tests that prose and passes the
same 609/609 with 22 inputs, 35 artifacts and zero promotion.
The earlier IPC run `-04` is retained as a 736/738 failed matcher attempt caused
only by PowerPC objdump whitespace, and IPC run `-05` is superseded because
final readback caught its stale four-profile exclusion sentence.

The earlier [1,015-test checkpoint](results/tests-mips-rv32-checkpoint-20260907.log)
remains preserved. The current
[full regression](results/tests-mips32el-mt7621-l1-20260907/SUMMARY.md) passes
1,025 tests after MT7621 profile registration, with 20 conditional skips. The
IPC/refcount module has 23 focused tests, including exact profile inventory,
ELF32/Alpha symbol parsing, diagnostic classification, native atomic-disassembly
requirements, exhaustive progress outcomes and fail-closed scope controls.
Eleven focused tests cover the LL/SC inventory, finite/cyclic diagnostics, source
identities, fresh full-object disassembly and promotion/path/output hardening.

The [audited private VLA/arithmetic successor](build/framac-alignment-provider-20260907/CANDIDATE-VLA-ARITHMETIC-20260907.md)
now retains candidate 5 and candidate 4's preceding regression separately.
Candidate 5 builds, passes six early/core-runtime checks and fixes the saved-bound
initializer: the basic double/int VLA witnesses match Clang at `[8,8,4]` and
`[4,4,4]`. The 55-pair matrix is unchanged at 33 constant agreements, 21 named
rejection correspondences and one compound mismatch. The unchanged 14-control
batch has six exit-zero and eight exit-one results for each tool.
The expanded 44-case batch completes at 05:45:27 UTC with 156 executed queries,
66 explicit skips, eleven exit-zero and 33 exit-one initial outcomes per analyzer
mode, and 22 successful reparses. Three previous AST-check failures recover;
this is raw collection, not 44 semantic passes. Candidate 4's 150-executed,
72-skipped followup and VLA failures remain preserved. Cast/parser, integer-
constant-expression, static type-query and three valid-but-unsupported VLA
controls remain open. Patch 009 is unapplied and unbuilt. The dated 891-test
pass was not rerun as private-provider regression validation. Independent
readback verifies 364 rows and 179 preprocessing closures without drift.

The preceding [private declaration correction](build/framac-alignment-provider-20260907/CANDIDATE-DECLARATION-20260907.md)
built in a fresh source tree, passed six private runtime checks and reran
the 55-pair matrix plus all 14 extra controls, completing at 04:50:33 UTC.
The four forward missing-definition controls now reject with the intended
diagnostic; reverse-order outcomes are unchanged. The fixed matrix remains
33 constant agreements, 21 corresponding rejections and one compound-category
mismatch, with no input drift. Candidate 3 differs from candidate 2 only by a
nine-line pre-merge source-presence guard. At that candidate-3 milestone the
double-VLA mismatch and typed GNU arithmetic remained open and their separate
proposals were unbuilt; the successor above records their later bounded progress.
No profile, existing proof, installed provider or accepted-count change occurs.

The preceding [private Hexagon context continuation](build/framac-alignment-provider-20260907/PRIVATE-CONTEXT-20260907.md)
now completes a fresh 55-pair run at 04:26:08 UTC: all 33 successful constant
witnesses agree, 21 rejection categories correspond and one compound-category
mismatch remains. All nine offline parser tests pass. The first private run's
four unresolved local witnesses are preserved; a new exact parser handles their
multiline attribute spelling without changing provider/source/fixture bytes.
A separate 14-case compile/parse-only diagnostic confirms four missing-definition
acceptance errors, double-VLA alignment 4 versus compiler 8, and unsupported
typed GNU arithmetic. The extra run's exit zero denotes raw collection only.
Independent retained-output audits find no drift. No target program, proof,
kernel build, installation or production activation was run. Hexagon remains
unconfigured, with full semantics, L1, L2 and integration open; current accepted
target/function/architecture counts are unchanged. No kernel defect arose from
that private provider work; the later RV32 finding is separate.

The [nine-calibration renewal](docs/CALIBRATION-RENEWAL-20260907.md) now passes
both normal batches, completing at 02:20:28 UTC on September 7. All 38 model
checks and 55 positive selected properties pass. Nine intentionally false
assertions retain their raw `Invalid or unreachable` labels and are corroborated
by independently revalidated retained native evidence, not new native runs.
All 789 warnings remain explicit. Read-only audit checks 1,556 recorded inputs
and 300 retained files without drift. This restores current acceptance for all
25 previously accepted targets; six legacy nonpasses remain unresolved.
The [s390 seven-helper L2 renewal](s390/L2-RENEWAL-20260907.md) separately verifies
its four mandatory targets across two authentic completed summaries, without
extending its contracts, runtime scope or architecture coverage.

The [seven-target WP renewal](docs/PROOF-RENEWAL-20260907.md) now passes all three
normal ARM64/RISC-V, s390 and string batches, completing at 01:47:33 UTC on
September 7. All 74 L1 checks, 418 ordinary goals and 331 selected properties
pass under unchanged sources, contracts and reviews. Independent retained
readback checks 2,031 hashes without drift. Forty-seven smoke outcomes remain
inconclusive; two additional string smoke outcomes retain their existing
unreachable-branch reviews. The 177 raw warnings and 32 reviewed selected-scope
warnings remain explicit. This WP batch alone does not renew the separate Eva
calibrations, full-suite acceptance or an architecture level.

The [approved common24 retry](common/L2-CLANG-RENEWAL-20260907.md) has completed:
all nine normal proof targets pass under the current shared provider identity.
The three batches finished at 00:19:41 UTC with 164 model checks, 846 valid
ordinary goals, 738 Valid selected properties and 252 compiler observations.
Independent full proof/replay readback verifies 5,155 file hashes without drift;
all 46 warnings retain their scoped reviews and all 108 smoke outcomes remain
inconclusive. The four helper bodies, full domains and existing reviews are
unchanged. This renews nine scoped L2 baselines, not the entire suite.

The first [current-identity common24 renewal attempts](common/RENEWAL-SOCKET-FAILURE-20260907.md)
passed all nine model validations (164/164 checks), but Why3's local Unix-socket
connections were denied inside the execution sandbox. Three analyses timed out;
the three batches were then stopped through their cleanup handlers at 00:01:02
UTC on September 7, preserving failed invocation receipts and incomplete suite
summaries with no input drift. No proof from those attempts was accepted. The
successful retry above used separately approved local solver IPC permission,
not a package installation. The original failures remain unchanged and outside
completed matrix history because their suite summaries are incomplete. They
are not evidence of a kernel defect.

The new [Hexagon context diagnostic](profiles/HEXAGON-CONTEXT-20260907.md)
finished at 01:09:51 UTC on September 7 with all 55 pairs and 112 direct queries
retained, no input drift, and terminal exit 1. The unchanged receipt records
24 constant mismatches, 13 corresponding rejections, six acceptance/rejection
mismatches, five agreements and seven unresolved observations; two of the six
mismatches are unexpected analyzer acceptance of negative controls. Raw logs
show member expression-alignment differences already at 16 bytes, two diagnostic
format misses, four genuine local-static-initializer rejections and one compound
compiler rejection. Those four local cases do not measure analyzer alignment.
Independent readback checks 112 command records, 55 comparisons and 5,012 unique
paths without drift; it does not change the receipt's unresolved classification.
The 112 queries comprise two version checks, 55 textual-IR compilations and 55
Frama-C parses, excluding their explicit preprocessing descendants. No target
program, WP/Eva proof or kernel build was run; no installation or production
change was made. Hexagon remains unregistered and ineligible for integration/L1;
these tool/model observations are not confirmed Linux kernel defects.
The [private unmodified Frama-C build baseline](build/framac-alignment-provider-20260907/README.md)
and five early version/resource-path checks now pass as preparation for further
work. They do not validate private plugin loading/C parsing or change alignment
semantics; the integration gate remains closed.
The [patched private candidate](build/framac-alignment-provider-20260907/CANDIDATE-BUILD-20260907.md)
now builds and passes five early path/version checks plus one core-only C parse,
completing at 03:35:24 UTC. Its three patches change nine files and 39 hunks in
an exact archive-derived source tree. A module-shadowing compile error and a
runtime-recorder newline expectation error are preserved as failed attempts;
fresh successors pass with terminal process groups and no input drift.
Independent build readback checks 37,487 unique regular paths without drift.
The inert parse uses legacy x86_64 and disables plugin autoloading; it does not
validate opt-in Hexagon alignment or plugin loading. Active pragma pack/align
is explicitly rejected pending full semantics, and typed arithmetic,
redeclaration and consumer gaps remain open. The
[next context controls](build/framac-alignment-provider-20260907/CONTEXT-NEXT.md)
retain all 55 unchanged pairs and additional policy/local/VLA checks. The
subsequent private context continuation above confirms the double-VLA risk and
exercises the opt-in YAML, which differs from the unchanged generator candidate
by exactly one policy field. It is still not activated in the normal profile
pipeline. The unmodified baseline and installed provider remain unchanged;
no architecture or proof is added, and that provider work produced no kernel
finding.

The preceding [Hexagon layout calibration](profiles/HEXAGON-LAYOUT-20260906.md)
corrects the scalar-only `max_align_t` representation and executable-path/dialect
confusion. The generator derives the complete struct from authenticated source
and measures all twelve GNU alignment fields instead of leaving them unsupported
or copying C values. Its fresh 100-query result preserves all four alignment
contradictions. Actual Frama-C parsing now matches all 28 compiler layout values
and rejects all three wrong representations without unrelated warnings/errors.
The first failed analyzer run is retained. All
[891 regression tests](results/tests-hexagon-gnu-model-20260906.log) pass in
86.183 seconds, without skips. Independent retained compiler/analyzer readback
checks 4,069 unique file hashes without drift.
No profile, existing proof, tool lock or system package was changed.

The preceding [Hexagon generator adapter](profiles/HEXAGON-GENERATOR-ADAPTER-20260906.md)
extracts a complete candidate using all 84 actual compiler queries, with no
warnings or unrelated errors. Explicit macro absence, preprocessing commands,
freestanding return and a duplicate fallback type declaration are handled.
The adapter detects four emitted-object alignment contradictions and correctly
returns nonzero: Hexagon integration/L1 remains closed. All
[802 regression tests](results/tests-hexagon-adapter-20260906.log) pass in
84.536 seconds, without skips. Independent retained readback checks all commands,
31 objects and 3,757 bound paths without drift. No target program, analyzer or kernel build was
run, and no installation or existing proof/profile change was made in this step.

The preceding [Hexagon header milestone](profiles/HEXAGON-HEADER-PROVISION-20260906.md)
authenticates all 2,658 source files against the exact Git tree and provisions
217 target headers offline in a private workspace directory. Independent
reconstruction matches all 461,704 installed header bytes. All
[720 regression tests](results/tests-hexagon-headers-20260906.log) pass in
85.011 seconds, without skips. Two actual compile/preprocess-only diagnostics
confirm musl-first ordering and the kernel's short-wchar type; they retain the
missing `__WORDSIZE` warning, upstream command/sanity-probe warnings and genuine
wide-character-limit mismatch. Hexagon remains unconfigured, with no L1 or
proof promotion. No system packages were installed and no target object executed.

The preceding [target-aware Clang interfaces](profiles/CLANG-INTERFACE-20260906.md)
bind exact compiler family, target/CPU arguments, executable and builtin-resource
identities, with genuine-TU flag matching. Existing GCC commands are preserved.
All [690 regression tests](results/tests-clang-model-interface-20260906.log)
pass in 75.666 seconds without skips; that dated 18-tool preflight has no issues.
The [fresh ten-model renewal](build/profile-checks/clang-interface-20260906/index.json)
passes all 182 L1 checks with unchanged machine bytes and compiler flags.
Independent audit verifies 133 logged command/log comparisons, all 771 renewal
inputs and 284 retained files, without drift. The real Clang metadata check binds
297 builtin-header files, not a target libc or generated Hexagon model.

The earlier [genuine Hexagon source research](profiles/HEXAGON-HEADERS-20260906.md)
retains the original recipe/tag observations. The new authenticated source and
header receipts extend that evidence rather than rewriting it. The normal
profile generator gate remains closed pending the newly observed alignment and
representation work, production integration and genuine-kernel calibration.
The standalone adapter resolves the earlier probe/transport issues, and the
layout continuation resolves representation and dialect/GNU-field calibration.
No word size or missing model value is invented.

The [pre-MIPS coverage matrix](results/coverage-calibrations-clang-renewed-20260907/coverage.md)
has 25 accepted targets at its exact identity: 16 proofs and nine Eva
calibrations. Six legacy nonpasses are preserved, and eighteen of 24 distinct
functions had accepted variants. The additive lock extension changes the
current project identity, so those proof receipts remain dated until replay;
the 11-profile L1 renewal does not silently renew L2. Its
[independent readback](build/calibration-clang-renewal-audit-20260907/README.md)
checks 4,983 generation inputs, 1,545 artifact references (1,478 unique paths),
56 raw target receipts, 28 dated model receipts and all four Markdown tables,
with no discrepancies or drift at that identity. The separate post-registration
renewal now supplies current L1 for all eleven configured profiles.
The preceding common24-only [coverage audit 2](build/common24-clang-coverage-socket-enabled-audit-20260907/audit-2.json)
retains its 4,500-input/1,218-reference check and separate 5,027-path post-readback.
The [failed first coverage audit](build/common24-clang-coverage-socket-enabled-audit-20260907/audit-1.json)
is preserved. Its [narrow correction](build/common24-clang-coverage-socket-enabled-audit-20260907/AUDIT-CORRECTION.md)
keeps nine old common24 observations' current-context validation unavailable
under the changed build/profile/toolchain providers, with current acceptance
false. Only the new proof receipts restore current acceptance.

The earlier [Hexagon LLVM compiler-build milestone](profiles/LLVM-BUILD-20260906.md)
passed genuine `olddefconfig`, `prepare` and `lib/string.o` using explicit LLVM
21.1.8/v68. Its audit checked 760 canonical pinned sources, 434 retained artifacts
and 1,496 run hashes without drift. Its then-passing 647 tests and build-only
coverage remain dated records. No Hexagon object was executed or model activated.

The preceding [wave-three continuation](common/WAVE3-20260906.md) added Alpha,
hardware x86-64 and UML x86-64 to the common24 suite. The registry then contained
31 targets and still 24 distinct kernel functions. Narrow Alpha ELF metadata
recognition and genuine `-Os` support preserve source bodies, full domains,
compiler flags and all mismatch controls. Original six review contexts were
explicitly renewed; the new three have separate scoped assumptions.

At that identity, all [610 regression tests](results/tests-common24-nine-reviewed-20260906.log)
passed in 71.158 seconds with no skips. The [dated nine-profile L2 renewal](common/L2-WAVE3-20260906.md)
passed three normal batches: 164 model checks, 846 ordinary goals, 738 selected
properties and 252 common24 fixture/compiler commands. Independent readback
accepted each batch's full retained-evidence replay and checked 5,114 unique
hashes, including 3,927 retained files, without drift at that identity. All 108 smoke outcomes
remain inconclusive; no consistency theorem follows.

The [coverage matrix at that identity](results/coverage-common24-nine-reviewed-20260906/coverage.md)
retained all 31 targets and 21 architecture families, then with nine current
acceptances and four of 24 distinct kernel functions represented. Its earlier
audit checked 3,715 input hashes and 1,056 artifact references without drift.
The new matrix above supersedes those freshness counts, not the retained results.
The nine profile variants do not add distinct functions.

Together with the [renewed seven-helper s390 pilot](s390/L2-RENEWAL-20260907.md),
ten architecture families have dated named L2 baselines. The fresh MIPS32el
scope is the eleventh documented baseline, leaving ten without one.
The nine common24 scopes and s390's complete four-target pilot gates were
renewed at the preceding identity and now await post-registration replay.
Arbitrary functions on those architectures are not covered. The
[remaining architecture prerequisites](profiles/NEXT-WAVE.md) cover missing GCC
tools, explicit LLVM bring-up and Nios II's pre-GCC-15 requirement.
No sudo or installation is needed for the eleven configured profiles.

Hardware x86's dated model checks include its separate benign native calibration
under the recorded `-O2` context. No common24 compiler object is executed;
these are not helper runtime checks under the genuine `-Os` kernel command,
UML execution or L3 evidence. The retained
[string](build/string-sensitivity/native-9/receipt.json) and
[s390](build/s390-sensitivity/native-5/receipt.json) native receipts continue
to pass read-only regression checks. No historical fault/trap/OOB harness is run.

The [initial wave-three run](results/common24-wave3-initial-20260906/SUMMARY.md)
and [six stale-review test failures](results/tests-common24-wave3-pending-20260906.log)
remain unchanged. Explicit review and fresh runs resolved those then-current gates;
no failed or stale receipt was rehashed into approval. The
[first-wave](common/L2-20260906.md) and [six-profile](common/L2-WAVE2-20260906.md)
L2 records, with their then-passing 556 and 580 tests, remain dated evidence.

## What this project does

Fragma applies Frama-C to selected Linux kernel C helpers. ACSL annotations
describe their input requirements and intended behavior; WP checks generated
proof obligations, while separate calibration cases test whether deliberately
wrong expectations are detected. Source gates connect annotated copies to a
pinned kernel revision. This is function-level, conditional verification, not
a proof of the whole kernel or automatic verification of every caller.

## Delivered evidence and remaining work

| Area | Delivered result (dated where linked) | Still required |
| --- | --- | --- |
| Source identity | Token-based whole-TU/function gates, pinned source snapshot and consumed-header checks; dated relocated string experiment. | Register and rerun remaining historical examples; automate path-bound review relocation. |
| Toolchain | Actual 19-tool preflight passes; target-aware Clang identities; exact MIPS32el and Hexagon routes, with Hexagon still build-only. | Resolve Hexagon extended alignment; other tools, broader relocated setup and CVC5/WP compatibility investigation. |
| Runner | Twenty-five targets passed at the preceding identity; one new MIPS32el proof target passes at the post-registration identity. Registry has 32 targets and old histories are preserved. | Replay the preceding 25 targets, renew and resolve six legacy nonpasses, automate relocation and expand the profile matrix. |
| Architecture models | Eleven profiles pass 201/201 current L1 checks. MT7621 MIPS32el has a genuine O32/MIPS32r2 SMP/CPS build and one scoped common24 L2 result; the preceding ten models were rerun under the additive lock. | Resolve Hexagon extended alignment; ten families still lack L1 and ten lack a documented L2 baseline, then add callers/runtime and broader ABI/endian/configuration variants. |
| Stronger strings | Dated conditional WP proofs: `strnchr` 48/48 and `strlcat` 62/62 ordinary goals, all 44 selected dependencies valid; eight Eva calibrations with retained native evidence revalidated read-only. | Replay at the post-registration identity; external implementations and kernel callers remain outside these proofs. |
| s390 pilot | Dated seven-helper scoped L2: 183 ordinary goals, 158 WP properties, three project round trips and mandatory byte-order calibration. All four target gates and retained native evidence were rechecked. | Replay at the post-registration identity; broaden trap models and verify kernel callers; whole-pilot L3 remains open. |
| Common byte helpers | Dated nine-GCC-profile scoped L2 plus one current MIPS32el target. MIPS passes 19 model checks, 94 ordinary goals, 82 properties and all 27 compiler/control commands. | Replay the nine GCC targets at the post-registration identity; remaining architectures, kernel callers and runtime corroboration. |
| RISC-V encoders | Dated source/model/proof gates for seven helpers and five project witnesses: 119 ordinary goals, 119 dependencies and 47 postconditions. | Replay at the post-registration identity; helper-specific calibration, kernel callers and a documented encoder L2 scope. |
| ARM64 scalar extraction | Dated runtime-safety gates for two cpuid helpers: six ordinary goals and ten selected dependencies with genuine-header checks. | Replay at the post-registration identity; add functional contracts/calibration and verify kernel callers. |
| Kernel bug search | RV32 `load_unaligned_zeropad()` is a review-found defect, dynamically reproduced in QEMU; identical-config A/B passes after a two-line fix and the user sent it manually. The recent-risk ARM32 batch is frozen, and its first source-identical canary (`pcibios_align_resource()`) passes bounded RTE/Eva with 20 valid properties and no warnings or surviving leads. | Analyze the remaining seven recent ARM32 candidates, starting with strict analyzer-first `module_frob_arch_sections()`; add functional/WP passes for survivors. Count only analyzer-first, concretely reproduced violations as Fragma-found. Track RV32 upstream review separately. |
| Concurrency | C0/C1 infrastructure, limited C2 mutex/IRQ pilots, a 92-check LKMM baseline, a 135-check release/acquire pilot, a 162-check atomic/RMW pilot and a 1036-check IPC refcount lifetime/progress pilot are accepted. Six narrow kernel concurrency properties now exist: two access-protection claims, trace tgid-map publication ordering, module-statistics no-lost-update atomicity, IPC final-put/get-unless-zero exclusion with eleven checked SMP mappings, and bounded-quiescent strong-CAS retry progress with native/UML x86-64 and s390x mappings. A separate 609-check audit evaluates all eight existing LL/SC-bearing profiles and promotes none. | C3 architecture-backed unbounded/LL/SC progress, broader lockless lifetime behavior and remaining architecture mappings; then C4 RCU. Broader IRQ classes, functional protocols and the preserved unlocked HDQ accesses remain open. |

The registry's 24 distinct kernel functions reach the plan's initial numerical
range, not its proof/coverage acceptance. The pre-MIPS report had 18 functions
with accepted-current variants and 18 with latest-reported accepted variants.
Six functions lacked both a current and a dated accepted variant there; a fresh
post-registration coverage report remains to be generated.
Six nonpassing target variants are a
different count because some variants repeat functions with stronger accepted
contracts. The 62 kernel-function rows, 12 calibration rows and 26 project-witness
rows do not increase the distinct kernel-function inventory.

The eleven configured profiles are `x86_64-gcc`, `arm64-gcc`, `riscv64-gcc`,
`s390x-gcc`, `arm-gcc`, `powerpc32-gcc`, `alpha-gcc`, `m68k-gcc`,
`sh-gcc`, `um-x86_64-gcc` and `mips32el-clang`. Fresh standalone receipts pass
201/201 L1 gates across all eleven. The older 28 suite-model observations retain
their own historical freshness classifications. Ten additional registry profile
rows are planned without models, not configured profiles.
The generated architecture-level cells remain `not-assessed`; the separate
s390/common24 documents supply the scoped L2 decisions.

L1/L2 do not establish arbitrary C/ABI support, assembly, MMIO, concurrency,
compatibility userspace layouts or whole-profile L3. The explicit pointer policy
is checked against actual analyzer audits and bound in reviews. MPI still has
an unresolved pointer-formation obligation and dependent partial properties;
multibyte alignment is also open. Neither is reported as a kernel defect or
hidden behind successful common24/string/s390 results.

## Dated full-suite baseline evidence

- [All 22 final target outcomes](results/pointer-policy-final-ci-20260906/suite/SUMMARY.md)
  and [CI commands/status](results/pointer-policy-final-ci-20260906/ci.json):
  16 accepted, six unaccepted, all 2,518 merged tracked inputs unchanged.
- [Coverage at the earlier input identity](results/coverage-pointer-policy-final-20260906/coverage.md):
  18/24 kernel functions with accepted-current variants; all 21 architectures
  and ten eligible L1 model observations remain visible. All 2,713 generation
  input hashes and 327 retained artifact entries passed independent checks.
- [Explicit pointer-policy review](docs/pointer-policy-review.md),
  [final ten-model refresh](build/profile-checks/pointer-policy-final-20260906/index.json),
  [then-current string native receipt](build/string-sensitivity/native-8/receipt.json)
  and [then-current s390 native receipt](build/s390-sensitivity/native-4/receipt.json).
  These two native receipts are now stale and preserved, not rehashed into approval.
- [s390 L2 scope decision](s390/PILOT-20260906.md),
  [exact evidence audit](results/pointer-policy-final-ci-20260906/pilot-audit.json)
  and [17 passing audit tests](results/pointer-policy-final-ci-20260906/pilot-audit-tests.log).
- [382 evidence-backed tests, no skips](results/tests-pointer-policy-final-20260906.log).
  Historical raw artifacts are tested as historical observations, not promoted
  into new current acceptance.
- [Builtin-audit serialization review](build/pointer-formation-review/builtin-audit-review.md):
  exact Frama-C category spelling corrected without changing commands, silently
  enabling automatic builtins or retroactively accepting the eight retained
  tool-errors. Fresh canary and full-suite runs pass.
- [Next common-helper compiler stage](build/common-byte-port-work/HANDOFF.md):
  ARM32, PowerPC32 and m68k pass 18 compiler-only commands, including intended
  type/macro rejections. Original four helper bodies/contracts, two witnesses
  and checked strategies are preserved. That compiler stage alone establishes
  neither per-profile proof nor new L2.

## Historical and supporting evidence

The following are retained dated experiments and source reviews. Their original
counts and status statements describe those runs; none certifies later inputs.
Bound reviews are preserved rather than rewritten.

- [Toolchain setup and limitations](docs/toolchain.md),
  [clean setup receipt](toolchain/verified-prefix/setup-report.json), and
  [clean environment preflight](toolchain/verified-prefix/clean-environment-report.json).
- [Architecture model documentation](profiles/README.md),
  [capability inventory](build/profile-checks/wave2-capabilities.json), and
  `build/profile-checks/*/profile.json` for individual dated results.
- [UML-specific model scope and evidence](profiles/UML.md): 17 configured checks
  pass, including independent rejection of wrong widths and byte order.
- [Optional local runtime tools](docs/runtime-tools.md): the pinned QEMU package
  is extracted locally and its file hashes pass. Runtime calibration integration
  remains separate; no support level follows from emulator availability alone.
- [Stronger string contracts and reviewed assumptions](annotated/verification-notes.md)
  and [native-preprocessing equivalence evidence](build/string-verified/native-review/equivalence.json).
- [s390 targets and open obligations](s390/TARGETS.md).
- [All 22 registered cases, fresh baseline](results/all-registered-baseline-20260906/SUMMARY.md):
  five proof groups and eight calibrations accepted; nine cases remain unresolved.
  The [baseline triage](docs/baseline-20260906.md) explains the separate causes.
- [Generated coverage](results/coverage-all-registered-20260906/coverage.md) and
  [reporting policy](docs/coverage.md): all 21 architecture profiles and 24 distinct
  kernel functions remain visible. Later runner edits correctly stale the dated
  baseline; coverage generation does not grant new proof or architecture claims.
- [Updated all-case integration](results/all-registered-integrated-2-20260906/SUMMARY.md)
  and [updated coverage](results/coverage-integrated-2-20260906/coverage.md):
  all 22 targets have final outcomes, 15 were accepted by then-current policy, and no
  input drift was detected. Six proof groups account for 16 of the 24 distinct
  kernel functions; eight functions have no accepted variant. Seven unsuccessful
  target variants remain visible, including duplicate historical string cases.
- [s390 native receipt](build/s390-sensitivity/native-2/receipt.json) and
  [runtime scope](harness/S390-NATIVE-SENSITIVITY.md): both assertions reached,
  correct decode true, deliberate false claim false, normal exit and actual
  big-endian layout. Exact helper instructions and pinned return backend are
  bound to the execution trace. Requested z13 and executed max are not conflated.
- [s390 pilot acceptance checklist](build/s390-pilot/acceptance-work/CHECKLIST.md):
  current-policy checks pass, but explicit pointer-formation evidence remains
  required. The checklist awards no architecture level.
- [RISC-V encoder contracts and evidence](riscv/ENCODERS.md): all original
  domains are retained; the two timed-out strategy experiments remain historical.
- [ARM64 scalar review](arm64/CPUID.md) and
  [fresh integrated run](results/arm64-cpuid-integrated-20260906/SUMMARY.md):
  both real source bodies and attributed signatures are checked; all six
  ordinary goals and ten selected properties pass. No functional or caller
  claim is added by reviewing the scalar model and exact warnings.
- [Post-ARM64 explicit coverage](results/coverage-arm64-cpuid-20260906/coverage.md):
  24 unique kernel functions, 18 with latest reported accepted variants, but
  only two accepted-current under this report's explicit input set. The 15
  older accepted target variants are correctly stale after the registry edit.
- [Post-CI explicit coverage](results/coverage-ci-core-20260906/coverage.md):
  the refreshed core/calibration run plus ARM64 result now supply 12
  accepted-current target variants, including four distinct kernel functions.
  Four older proof groups remain stale and six target variants unaccepted.
  The union of latest reported accepted kernel variants remains 18 of 24.
- [Completed staged pointer audit](build/pointer-formation-review/REVIEW.md):
  exact verified-prefix replay, unchanged source/contracts/domains/strategies,
  and all new guards closed. The mixed-tool first string trial and interrupted
  first s390 records remain preserved and do not authorize acceptance.
- [Original naive calibration integration review](build/legacy-string-review/INTEGRATION.md):
  12 WP support obligations close formerly Unknown positive preconditions in
  the same EVA project; the reached negative has separately revalidated native
  evidence. Typed lineage/report integration and the original broad-domain
  trap-model problem remain open; no suite approval is inferred.
- [Initial integrated native-preprocessing run](results/core-native-preprocessing-20260906/SUMMARY.md):
  incomplete. Its older string contracts are not the new verified variants.
- [Integrated stronger strings](results/verified-strings-integrated-20260906/SUMMARY.md)
  and [independent clean-toolchain replay](results/verified-strings-clean-toolchain-20260906/SUMMARY.md):
  both pass their selected proof, source, model, dependency, and scoped-review gates.
- [Independent clean run A](results/replay-strings-a-20260906/SUMMARY.md),
  [run B](results/replay-strings-b-20260906/SUMMARY.md), and their
  [stable replay comparison](results/replay-strings-a-versus-b-20260906.json):
  matching inputs, recorded execution limits and complete outcomes; distinct
  accepted executions. Both used the stripped environment and same clean tools.
  See [comparison policy and limits](docs/replay.md).
- [Relocated clean-run handoff](build/relocation-review/handoff-20260906/RESULTS.md)
  and [independent replay recheck](results/relocation-replay-recheck-20260906.json):
  two new-project runs each pass 106 ordinary goals, 41 selected properties and
  all 19 configured x86 model checks. Source/build are newly generated at the
  relocated path; the same clean toolchain prefix is explicitly selected.
  Fresh path/build review was necessary. Old/new-workspace identity remains
  changed; only the two runs within the new workspace satisfy same-input replay.
  The full evidence remains at the recorded `/tmp` location, with small handoff
  mirrors preserved here. Automatic no-manual-path-edit relocation stays open.
- [Integrated s390 TOD proof](results/s390-tod-integrated-20260906/SUMMARY.md):
  passes on the checked z13 model, without changing the source body or contract.
- [Integrated s390 24-bit group and TOD replay](results/s390-24-tod-integrated-20260906/SUMMARY.md):
  both targets pass all integrated gates. All 85 ordinary goals and 75 selected
  dependency rows are valid; round-trip and helper dependencies close together.
  The 24-bit proof takes approximately 299 seconds with five-second solver
  attempts. Smoke timeouts remain inconclusive about overall consistency.
- [Integrated all-seven s390 helper proofs](results/s390-all-proofs-integrated-20260906/SUMMARY.md):
  all three groups pass with the clean toolchain, including the 48-bit round trip
  and every selected dependency. Runtime calibration remains separate.
- [Integrated string specification calibration](results/string-sensitivity-integrated-2-20260906/SUMMARY.md)
  and [native execution scope](harness/NATIVE-STRING-SENSITIVITY.md): all eight
  cases pass their calibration gates, with no additional verified-function claim.
  The first integration attempt is retained as a report-parser failure. Frama-C
  omits source columns in TSV output, so distinct unselected callsites can have
  identical exported identities. These occurrences are retained and flagged;
  selected-property ambiguity still fails closed.

These are dated, input-hashed run records, not a cache certifying later source
or runner changes. Repeat the gates after any relevant input changes.

## Running the current implementation

List targets and check the locked installed tools without installing anything:

```sh
python3 -m fragma list
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" python3 -m fragma preflight
python3 -m unittest discover -s tests -v
```

To reproduce the dated pre-MIPS coverage matrix, use the
[recorded twelve-summary/ten-model command](build/calibration-clang-renewal-audit-20260907/README.md#exact-generation-command).
Its direct tool invocation completed with exit 0; the matrix's generation inputs
and raw artifact projections were independently read back. No separate wrapper
or invocation receipt was created for this coverage command.
It supplies the earlier 22-target CI summary, three dated common24 summaries,
all three completed socket-enabled retry summaries, three fresh non-common WP
summaries, the two fresh calibration summaries and ten explicit standalone model
paths. The incomplete socket-denied attempts remain separately recorded,
not completed matrix inputs. Choose a new output directory; existing results
are not overwritten. The latest separate
[891-test command record](results/tests-hexagon-gnu-model-20260906.json)
retains the exact argv, stdin and environment for that evidence-backed test run.

The [local CI entry point](ci/check.py) runs all unit tests before the real
core/calibration, extended, or all-suite selection. See the
[maintenance guide](docs/maintenance.md) for commands, explicit native receipts,
scope and baseline-review steps. The dated all-mode refresh supplied both
then-current native receipts and retained all 22 targets. It reports seven proof and
nine calibration acceptances, six legacy nonpasses, no driver drift and exit 1.
CI does not execute native witnesses or update baselines; it revalidates the
explicitly supplied observations. Its tests also cover contradictory success
records, missing targets, limits, input drift, argv/path handling, direct-child
timeout and interruption. The earlier
[first core run](results/ci-core-20260906/ci.json),
[second core run](results/ci-core-complete-evidence-20260906/ci.json) and
[331-test evidence run](results/tests-with-evidence-20260906.log) remain historical.

With the already prepared kernel builds, request fresh runs in new directories:

```sh
python3 -m fragma run --target string.verified.strnchr --target string.verified.strlcat
python3 -m fragma run --profile s390x-gcc --suite extended
python3 -m fragma run --target s390.unaligned24 --timeout 1 --wall-timeout 600
python3 -m fragma run --target calibration.string.truncation.eva \
  --native-evidence "$PWD/build/string-sensitivity/native-9/receipt.json"
```

Use `python3 -m fragma list` to check the current suite membership before a
filtered run. The runner writes `results/<run>/summary.json`, `SUMMARY.md`, and
per-target evidence. Incomplete proofs or unmet reviews return failure; this is
intentional. Existing result directories are never overwritten. Sources are
pinned to `b9b3e33b70b71e516930117e21de3ad2a7723747`; the external checkout's
different HEAD is not silently treated as the proved source.

`--timeout` limits individual prover attempts; `--wall-timeout` separately caps
each analyzer process, including its tactic search. These limits and job count
are recorded explicitly. The wall cap does not cover setup/profile checks or
the entire multi-target suite. Keep a generous analyzer cap when using many
short solver attempts; reaching a cap remains an incomplete run, never success.

For a new source/build location, use `python3 -m fragma snapshot --help` and
`python3 -m fragma prepare --help`; prepare each selected profile before running
its suite. Kernel sources are read-only inputs, with generated files in separate
build directories. Frama-C performs native ACSL preprocessing using the target
compiler; the runner retains its audit and actual parsed streams.

## Do I need sudo?

Not on the current machine for the active profiles. The required tools,
including herd7 7.58, are already available, and the isolated toolchain was
installed inside this project. The distro herd7 library path is invalid, so the
three exact generic CAT helpers are vendored and selected explicitly; no system
installation or modification is needed.
The current read-only preflight passes all 19 locked tools with zero issues; the
[additive lock review](docs/TOOLCHAIN-LOCK-MIPS32EL-20260907.md) records the
identity change. The preceding
[18-tool receipt](results/preflight-clang-model-interface-20260906.json) remains
dated evidence.
The verification commands do not install or upgrade packages. A sandbox that
blocks Why3's local Unix socket needs execution permission, not `sudo` or another
package installation.

Other architecture ports can require additional cross-compilers. Missing tools
are listed as prerequisites; none is installed automatically. A fresh machine
also needs the native build dependencies listed in [the setup guide](docs/toolchain.md).
No blanket system-package command is required for continuing the current work.

## Next acceptance milestones

The bounded review, RV32 A/B handoff, limited C2 pilot, C3 LKMM baseline,
source-linked release/acquire pilot, atomic/RMW pilot and IPC refcount
lifetime/bounded-progress pilot are complete at their narrow boundaries. The
eight-profile LL/SC admission evaluation is also complete, with zero promotion.
The scoped MIPS32el L2 proof is now complete. The ARM32 Fragma-first campaign
has frozen its recent-risk batch and completed one bounded canary with no
finding; seven candidates plus functional follow-up remain. Immediate work is
the rest of that configured ARM32 campaign, followed by post-registration proof
replay, tracking the manually sent RV32 patch, and further C3 protocol or
architecture-backed progress work.
Mappings for architectures outside the refcount pilot's eleven-profile set,
interrupt classes and functional protocols remain explicit extensions
rather than inherited claims. The later
milestones are still open backlog; Hexagon stays
parked unless its workstream is resumed explicitly.

1. Track review of the manually sent RV32 patch. This project must not invoke
   email commands on this host; treat “sent” and “maintainer accepted” as
   separate states.
2. Execute the [Fragma-first bug-search protocol](docs/BUG-SEARCH-PLAN.md) on
   only the configured 32-bit ARMv7 `arm-gcc` profile. Freeze a mechanical
   5–10-function candidate list before detailed body review, run unchanged-source
   Eva/RTE first, add independently sourced WP properties, and concretely A/B
   every confirmed violation. An alarm or failed proof is only a lead.
3. Continue with C3 from the [concurrency plan](docs/CONCURRENCY-PLAN.md): broaden
   lockless functional protocols and establish, where supportable, path-specific
   unbounded or LL/SC progress premises that survive the new fail-closed audit.
   Extend the release/acquire and module-statistics mappings beyond
   their configured SMP x86-64 cases, and extend the refcount map beyond its
   configured x86-64, arm64, riscv64, s390x, ARM32, PowerPC32, SuperH, Alpha,
   LoongArch64, MIPS32r2 and UML x86-64 cases. Do not treat Mthread
   interleavings as weak-memory
   evidence and do not install tools automatically.
4. Replay the 25 previously accepted targets at the post-registration identity,
   then renew and resolve the six legacy nonpasses across all 32 targets, and
   extend inventory/source gates to remaining examples.
   Keep the earlier 22-target results identifiable as dated evidence.
5. Replay the current-policy suite with the clean toolchain and at a second location;
   separate stable input identity from timing and temporary filenames.
6. When architecture implementation resumes, continue the
   [remaining-architecture queue](profiles/NEXT-WAVE.md): resolve Hexagon's
   remaining cast/constant-expression, static type-query, VLA allocation and
   wider extended-alignment gaps, preserving the audited declaration and
   saved-bound corrections and completing
   its broader policy/redeclaration regressions,
   then integrate the standalone adapter and authenticated headers. Open the
   Clang model route only after complete generator/calibration checks. Alpha ELF and
   genuine x86/UML `-Os` support were delivered in
   [wave three](common/L2-WAVE3-20260906.md); their four-helper proof scopes have
   a [pre-MIPS renewal](common/L2-CLANG-RENEWAL-20260907.md) that now needs replay.
   Approvals do not transfer to a new architecture.
7. Expand the curated function collection and run eligible generic helpers across
   checked profiles. [Ten architectures](profiles/NEXT-WAVE.md) still need
   configured L1 evidence and ten need documented L2 baselines. The renewed s390
   and common24 scopes do not complete broader trap, runtime, ABI-variant
   or caller coverage; no new architecture is supplied by calibration renewal.
