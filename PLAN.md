# fragma improvement plan

Status: implementation in progress; no full-suite or all-architecture completion claimed.
Prepared: 2026-09-05.
Progress updated: 2026-09-07. See [PROGRESS.md](PROGRESS.md) for current evidence,
commands, and limitations. Checked boxes describe individual delivered tasks;
each phase's acceptance criteria still apply independently.

The requested bounded Linux kernel review has produced one dynamically
reproduced RV32 wrong-result defect. Its [A/B handoff](riscv/rv32-zeropad/README.md)
contains a send-ready, strict-checkpatch-clean fix and exact test/review evidence;
the patch has not been emailed or acknowledged upstream. Further Hexagon
implementation remains parked, and its private diagnostics did not produce this
kernel finding or add accepted proofs/profiles.

The next user-requested workstream is concurrency support. C0 capability
characterization and C1 evidence/scope infrastructure are now accepted; C2-C4
remain open. See the [C0 record](docs/CONCURRENCY-C0-20260907.md),
[C1 record](docs/CONCURRENCY-C1-20260907.md), and
[staged concurrency plan](docs/CONCURRENCY-PLAN.md). Existing sequential proofs
do not gain concurrent guarantees.

The common runner, source gates, locked local toolchain, and 21-architecture
registry now exist. Ten configured profiles, including s390x and UML x86-64,
pass all 182 configured model checks with the explicit pointer-formation policy.
No sudo installation is needed to continue the current work.

The [nine-calibration renewal](docs/CALIBRATION-RENEWAL-20260907.md) now passes
both normal Eva batches: 38 model checks, 55 positive selected properties and
nine deliberately false assertions corroborated by revalidated retained native
evidence. Raw analyzer labels and all 789 warnings remain unchanged. Independent
readback checks 1,556 recorded inputs and 300 retained files without drift.
The [s390 seven-helper L2 scope](s390/L2-RENEWAL-20260907.md) is separately renewed
from its three current WP groups and mandatory byte-order calibration.

The [seven-target WP renewal](docs/PROOF-RENEWAL-20260907.md) restores current
proof acceptance for the existing ARM64 scalar, RISC-V encoder, s390 and string
targets: 74 L1 checks, 418 ordinary goals and 331 selected Valid properties.
Independent retained readback checks 2,031 file hashes without drift. The
[current coverage matrix](results/coverage-calibrations-clang-renewed-20260907/coverage.md)
now records 25 accepted-current targets: 16 proofs and nine Eva calibrations,
with no accepted-stale targets. Six legacy nonpasses remain. Eighteen of 24
kernel functions have current accepted variants; six lack one. This is not
full-suite renewal, a new architecture or an L3 award.

The [nine-profile common24 renewal](common/L2-CLANG-RENEWAL-20260907.md)
now restores current scoped L2 acceptance for the same four byte helpers under
nine GCC profiles. Three separately authorized normal batches pass 164 model
checks, 846 ordinary goals, 738 selected properties and 252 compiler observations.
Independent proof/replay audit rechecks 5,155 file hashes without drift; all
108 smoke checks remain inconclusive. Its nine current four-helper scopes are
included in the combined matrix above.
The [interrupted socket-denied attempts](common/RENEWAL-SOCKET-FAILURE-20260907.md)
and failed first coverage audit remain preserved, not converted into successes.
This completes the nine-common24 renewal subtask, not full-suite renewal.

The new [Hexagon context diagnostic](profiles/HEXAGON-CONTEXT-20260907.md)
completes 55 actual compiler/analyzer pairs with 112 direct queries and no input
drift. Its preserved exit-1 result records 24 constant mismatches, 13 corresponding
rejections, six acceptance/rejection mismatches, five agreements and seven
unresolved observations. Two negative controls are unexpectedly accepted by the
analyzer; even 16-byte member expression alignment differs. Independent retained
readback checks 5,012 unique paths without drift. This completes only the scoped
diagnostic: alignment resolution, integration and Hexagon L1 remain open.
The [private unmodified Frama-C baseline](build/framac-alignment-provider-20260907/README.md)
also builds and passes five early version/resource-path queries. This is build
preparation, not private C/plugin validation or an alignment-semantics fix.
The subsequent [patched private candidate](build/framac-alignment-provider-20260907/CANDIDATE-BUILD-20260907.md)
now builds and passes five path/version checks plus one legacy core-only C parse.
The first compile failure and a runtime-recorder newline error are preserved;
fresh successors pass with no input drift. Independent build readback checks
37,487 unique regular paths. The subsequent
[private context continuation](build/framac-alignment-provider-20260907/PRIVATE-CONTEXT-20260907.md)
now reruns all 55 unchanged pairs: 33 constant agreements, 21 corresponding
rejection categories and one compound-category mismatch, with no input drift.
Nine offline parser tests pass. A separate 14-case run confirms four missing-
definition acceptance errors, double-VLA alignment 4 versus compiler 8, and
unsupported typed GNU arithmetic. Full semantics, plugin validation and
production integration remain open; no support is awarded.

The preceding [private declaration correction](build/framac-alignment-provider-20260907/CANDIDATE-DECLARATION-20260907.md)
built in a fresh source tree and passed six private runtime checks. All
55 unchanged context pairs retain their 33 constant agreements, 21 corresponding
rejections and one compound-category mismatch. A fresh 14-case run now rejects
the four missing-definition controls with the intended diagnostic, preserving
the reverse-order outcomes. At that candidate-3 milestone the VLA and typed-
arithmetic proposals were not yet applied. No architecture was promoted.

The [candidate-5 VLA/arithmetic handoff](build/framac-alignment-provider-20260907/CANDIDATE-VLA-ARITHMETIC-20260907.md)
retains candidate 4's measured regression and first expanded followup. The fresh
saved-bound `Local_init` correction builds and passes six runtime checks; basic
double/int VLA witnesses now match `[8,8,4]`/`[4,4,4]`. All 55 comparisons remain
33 agreements, 21 rejection correspondences and one compound mismatch. The
44-case successor records 156 executed queries, 66 skips, eleven initial
exit-zero and 33 exit-one outcomes per analyzer mode, and 22 exit-zero reparses.
Three expanded AST-check failures recover, but raw collection is not semantic
approval. Cast/constant-expression and static type-query gaps, three valid
unsupported VLA cases and broader integration gates remain. Patch 009 is an
unapplied, unbuilt proposal; further Hexagon work is parked. The 891-test result
below is dated shared-project evidence, not a new private-provider regression run.

The preceding [Hexagon layout calibration](profiles/HEXAGON-LAYOUT-20260906.md)
derives the complete `max_align_t` struct from authenticated headers, measures
all twelve GNU alignment fields and separates the Clang executable from the
analyzer's dialect selector. A fresh 100-query compiler run and actual Frama-C
parsing agree on all 28 paired layout values; three wrong representations are
rejected as intended. All [891 regression tests](results/tests-hexagon-gnu-model-20260906.log)
pass, and independent compiler/analyzer readback checks 4,069 unique file hashes
without drift. The original failed analyzer run is preserved. Extended alignment
remains blocked, and no profile or L1 acceptance is awarded.

The preceding [Hexagon generator adapter](profiles/HEXAGON-GENERATOR-ADAPTER-20260906.md)
completes all 84 actual compiler queries and extracts the full candidate without
warnings or unrelated errors. It handles explicit macro absence, separates
preprocessing mode and corrects two probe source defects. All
[802 regression tests](results/tests-hexagon-adapter-20260906.log) pass.
Emitted objects contradict four large alignment requests despite compiler exit
success, so the adapter returns nonzero and keeps integration/L1 closed. No
model field, old evidence or architecture registration was rewritten.

The preceding [Hexagon header milestone](profiles/HEXAGON-HEADER-PROVISION-20260906.md)
authenticates the complete musl source tree, provisions 217 workspace-local
headers offline, and independently reconstructs every installed header.
All [720 regression tests](results/tests-hexagon-headers-20260906.log) pass.
Actual compiler diagnostics confirm musl-first ordering and short-wchar types,
while exposing missing-`__WORDSIZE` handling and two upstream probe/command
portability issues. The generator gate remains closed; no Hexagon L1 or profile
was activated and no system package installation was needed.

The preceding [Clang interface milestone](profiles/CLANG-INTERFACE-20260906.md)
adds exact target/CPU, compiler-family and binary/resource checks while preserving
GCC behavior. All [690 regression tests](results/tests-clang-model-interface-20260906.log)
pass, and the fresh ten-profile renewal passes 182 L1 checks with unchanged
machine bytes/compiler flags. Actual preflight passes all 18 locked tools.
That step resolved Hexagon's source selection but did not provision its headers;
the new header milestone above supersedes that prerequisite status.

The preceding [Hexagon build milestone](profiles/LLVM-BUILD-20260906.md) passed
genuine preparation and `lib/string.o` with explicit LLVM 21.1.8/v68. Its 647-test
pass and build/source audit remain dated evidence, not full model support.
The shared build/profile/toolchain changes made earlier proof identities stale.
The [matrix at that transition](results/coverage-clang-model-interface-20260906/coverage.md)
recorded zero current acceptances, 25 dated acceptances and six legacy nonpasses.
The nine common24, seven non-common WP and nine Eva renewals above restore
current acceptance for all 25 previously accepted targets. No old receipt or
scoped review was rewritten; the six legacy nonpasses still need current runs
and resolution.

The preceding [wave-three continuation](common/WAVE3-20260906.md) adds Alpha,
hardware x86-64 and UML x86-64 common24 variants: the registry is now 31 targets
and still 24 distinct kernel functions. Exact Alpha ELF metadata and genuine
`-Os` compiler support are narrowly reviewed and tested, without replacing C,
compiler flags or the existing source-derived assertion identities. All
[610 regression tests](results/tests-common24-nine-reviewed-20260906.log) passed
with no skips at that identity. The [dated nine-profile L2 renewal](common/L2-WAVE3-20260906.md)
passed all targets in three separate batches: 164 model checks, 846 ordinary
goals and 738 selected properties. Independent accepted replay checked 5,114
hashes without drift at that identity; all 108 smoke outcomes remain inconclusive.
Its [then-current coverage matrix](results/coverage-common24-nine-reviewed-20260906/coverage.md)
recorded nine current acceptances and four distinct kernel functions with an
accepted-current variant. The new matrix supersedes those freshness counts;
profile reuse neither adds distinct functions nor completes the full suite.
The [remaining eleven-architecture toolchain plan](profiles/NEXT-WAVE.md)
separates LLVM bring-up and Nios II's pre-GCC-15 requirement from available
configured-profile work.

The dated [22-target CI refresh](results/pointer-policy-final-ci-20260906/suite/SUMMARY.md)
accepts seven proof groups and nine calibrations. Six legacy target variants
remain unaccepted, so CI returns failure rather than filtering them out.
[Coverage at that input identity](results/coverage-pointer-policy-final-20260906/coverage.md)
records accepted variants for 18 of 24 distinct kernel functions. The new common24
runner/manifest integration changes shared inputs, so this is no longer an
automatic current-coverage claim. ARM64 cpuid
coverage is runtime safety only; project witnesses and calibrations do not add
kernel functions. At that earlier input identity, all 382 evidence-backed
project tests passed with no skips; the common24 integration has additional tests.

The [dated s390 pilot](s390/PILOT-20260906.md) now meets L2 for exactly seven
helpers under `s390x-gcc`: all 183 ordinary goals, 158 selected proof properties,
three project round trips and the calibrated byte-order case pass. Its exact
inventory/model/native audit and all 17 audit tests pass. This does not establish
whole-pilot L3, full z13 emulation, broader trap behavior or kernel-caller proofs.
The [renewed nine common24 baselines](common/L2-CLANG-RENEWAL-20260907.md) establish scoped L2
for four byte helpers on ARM32, PowerPC32, m68k, ARM64, RISC-V64, SH, Alpha,
hardware x86-64 and UML x86-64. The
[current s390 renewal](s390/L2-RENEWAL-20260907.md) completes its separate
four-target scope checks across two authentic summaries. These are ten current
named architecture baselines, not ten fully supported architectures or
whole-profile suites. Eleven architectures still lack a documented L2 baseline.

The shared pointer-policy refresh includes ten fresh models, seven renewed
reviews and both freshly bound native providers. An actual EVA builtin-audit
serialization mismatch was corrected without changing analysis commands or
rehashing old tool-error receipts into approval. The final full run confirms
the correction; old failures and earlier pre-policy proofs remain historical.
The unresolved MPI pointer/alignment checks are not covered by the successful
string and s390 guard results.

Earlier pairs of clean string runs passed stable replay in both the original
and a freshly relocated workspace. Those are retained dated experiments,
not current certificates after the policy refresh. Automatic relocation without
manual review-path edits and broader-suite replay/acceptance remain open.
The [first reviewed common24 run](common/L2-20260906.md) accepted its three
ARM32, PowerPC32 and m68k variants: 54 model checks, 282 ordinary goals and 246
selected properties pass. Full contracts and actual inline policies are
preserved. The compiler provider, genuine-header mismatch controls and scoped
reviews are integrated; independent readback checks 1,250 file hashes without
drift and validates full replay. Its 556 evidence-backed tests passed with no
skips. The 36 smoke checks remain inconclusive, with no consistency or L3 claim.
The [coverage report at that identity](results/coverage-common24-reviewed-20260906/coverage.md)
recorded four of 24 distinct functions with accepted-current variants; 16 older
accepted targets are stale and six legacy nonpasses remain visible. The
[first unaccepted integrated run](common/INTEGRATION-20260906.md) is preserved.
The [configured-profile queue](common/NEXT-PROFILES.md) records completed
nine-profile common24 acceptance, including explicit Alpha ELF and x86/UML
optimization-policy support. Previous saved results are not renewed by review
edits or by the new tests.

Build a reproducible verification regression suite for selected Linux kernel
functions. Each result should identify the source, build configuration,
analysis model, specifications, trusted assumptions, and unresolved obligations
behind it.

The first milestone is a repeatable suite for the existing examples. The next
is 20–50 distinct, carefully selected kernel functions with explicit coverage
and automatic regression checks. That range is a planning target, not a measured
capacity estimate or a promise that every candidate will be fully proved.

The long-term portability goal is support for every architecture in the selected
Linux revision, starting with s390 as the first new port. Track architecture
support by explicit build/ABI profile and verification level. Grow the initial
20–50-function collection across the first supported profiles; this is separate
from the eventual architecture-coverage milestone.

## Starting point

These are the historical observations used to prepare the original plan.
The proofs were not rerun during initial planning; subsequent implementation
and fresh runs are tracked separately in [PROGRESS.md](PROGRESS.md).

| Area | Recorded evidence | Work needed |
| --- | --- | --- |
| String calibration | [README](README.md) records `strnchr` at 39/39 and `strlcat` at 39/40, with the latter's open goal deliberately false. | Reproduce results and check named properties, assumptions, and dependencies. |
| Trusted models | [specs.h](annotated/specs.h) supplies assumed contracts for external functions and a trap stub. | Record and review the assumptions supporting each proof. |
| Compiler semantics | [RISC-V investigation](riscv/REPORTABILITY.md) records a false alarm caused by a mismatch with compiler behavior. | Validate the analysis model for each supported build profile. |
| Architecture sweeps | [ARM64](arm64/FINDINGS.md), [RISC-V](riscv/FINDINGS.md), and [MPI](mpi/FINDINGS.md) contain function-level experiments and follow-up ideas. | Share infrastructure, source checks, and reporting. |
| Architecture roster | The recorded baseline commit `b9b3e33b70b71` contains 21 architecture directories, including `s390`. | Register every architecture and stage validated ports; derive the roster again on source updates. |
| Unresolved analysis | The saved [RISC-V miscellaneous report](riscv/annotated/riscv-misc.report.json) contains 12 valid goals and 19 timeouts. | Classify unresolved obligations without treating timeouts as defects. |
| Execution | [run-wp.sh](run-wp.sh) invokes WP; source checks and other analyses require separate commands. | Add an integrated regression command with meaningful failure status. |
| Installation | [install.sh](toolchain/install.sh) uses local paths and installs unpinned Frama-C/Alt-Ergo packages. | Lock dependencies and support a clean setup at another path. |

Historical goal counts are useful orientation. Splitting options, annotations,
and tool versions can change the number of goals, so counts alone must not
define correctness or regression success.

The inspected local kernel checkout is now at `388b607d107c`, whereas the
historical examples name `b9b3e33b70b71`. Phase 0 must select and record the
revision used for each baseline; a changed checkout cannot silently inherit an
earlier proof's source identity.

## Scope and result rules

- Focus first on sequential C helpers with manageable dependencies: strings,
  integer arithmetic, instruction encoding/decoding, and bounded array loops.
- State whether a result covers runtime safety, functional behavior, partial
  correctness, or termination, and under which input preconditions.
- Preserve a checked connection to the kernel source. An unchanged function
  body alone does not validate replacement macros, types, headers, or stubs.
- Keep assumed external contracts visible even when all generated goals pass.
  A proof of a caller using a contract does not prove that contract's external
  implementation.
- Record proved, invalid, unknown, timeout, unsupported, and tool-error outcomes
  separately. Track expected outcomes as separate metadata; a timeout cannot
  serve as evidence that a deliberately false specification is false.
- Keep the existing deliberately wrong specification and fault-injection
  examples explicitly labelled as calibration cases.
- Validate claimed caller coverage separately from a function's conditional
  proof. Review preconditions against the API rather than narrowing them merely
  to close open goals.
- Track architecture, kernel ABI, byte order, compiler, and relevant configuration
  as distinct profile inputs. Distinguish kernel data layouts from compatibility
  userspace layouts handled by particular functions.

Linux concurrency and RCU remain unsupported by the accepted kernel suite. C0
now pins the provider's limited Mthread+Eva capabilities and gaps; C1 binds
their scope and invalidates stale evidence without awarding a concurrent kernel
target. Follow the remaining [C2-C4](docs/CONCURRENCY-PLAN.md) for kernel integration
and weak-memory/RCU validation without waiting for all-architecture completion. Inline assembly,
MMIO and whole-subsystem verification still require additional models.
Unsupported features must be visible in coverage reports.

## Sequence

| Phase | Priority | Depends on | Deliverable |
| --- | --- | --- | --- |
| 0. Baseline and provenance | P0 | — | Target manifest and fresh baseline for existing cases |
| 1. Model and assumption checks | P0 | 0 | Validated profiles and an assumption ledger |
| 2. Reproducible regression suite | P0 | 0 and 1 | One command, pinned setup, structured results |
| A0–A3. Architecture support | P1 for s390; P2 for later waves | 0–2; alongside 3–4 | Common port interface, s390 first, then every architecture in the pinned tree |
| 3. Stronger specifications | P1 | 1 and 2 | Functional contracts and reusable proof components |
| 4. Curated coverage expansion | P1 | 2 and 3 | A measured collection of 20–50 distinct functions |
| C0–C4. Concurrency support | P1 active; C0-C1 accepted, C2 next | 1–2 for acceptance; independent of all-architecture completion | Reviewed thread/interrupt models, scoped kernel integration, then explicit weak-memory and RCU capabilities |
| 5. Maintenance and performance | P2 | 2; use 4 for measurement | Incremental checks and a documented update workflow |

Runner scaffolding and dependency pinning can start during phase 0. Accept a
baseline as verified only after its model and dependency checks are complete.

## Phase 0 — Inventory and establish provenance

Start with [run-wp.sh](run-wp.sh), the compilation database generators, existing
source gates, and the architecture findings documents.

- [x] Introduce a machine-readable target manifest. Record a stable target ID,
  kernel function and source path, harness path, build profile, analysis type,
  intended properties, declared assumptions, and expected calibration outcomes.
- [x] Register the architecture roster from the pinned kernel revision, with
  initial profile IDs and explicit planned/unsupported status for unported
  architectures. Record architecture aliases, kernel `ARCH`/`SUBARCH` selectors,
  and compiler target identifiers independently.
- [ ] Record the actual kernel revision and any local source changes, config
  hash, relevant source/header hashes, original compile command, effective
  analysis command, and Frama-C/Why3/prover/compiler versions for each run.
  Verify recorded revisions instead of relying only on findings-document labels.
- [ ] Integrate the existing comments-only and verbatim-body checks. Extend
  provenance checks to every standalone harness. Require successful extraction
  of exactly the intended function; missing files, empty output, ambiguous
  matches, and preprocessing failures must fail the check.
- [ ] Inventory harness typedefs, constants, macros, and header overrides.
  Record their source and configuration dependencies alongside body checks.
- [ ] Run the existing cases and capture fresh logs and structured results in
  a dedicated output directory. Keep historical reports identifiable.
- [ ] Investigate differences from historical results and classify the existing
  unresolved goals by cause: missing contract, solver limit, model limitation,
  unsupported construct, or still unexplained.

Acceptance: every existing registered case has traceable inputs and a fresh
outcome, including unsuccessful runs. Deliberately supplying a missing or changed
source to the provenance gate causes a clear failure. A fresh report cannot be
mistaken for a historical or partial result.

## Phase 1 — Validate models and expose assumptions

Use [specs.h](annotated/specs.h), compatibility headers, generated compilation
databases, and the [RISC-V compiler-model lesson](riscv/REPORTABILITY.md) as the
initial review set.

- [ ] Define explicit supported build/analysis profiles. Record integer widths,
  plain-char signedness, alignment, endianness where relevant, compiler dialect,
  arithmetic behavior, memory model, and configuration-sensitive behavior.
  Reusing `gcc_x86_64` for another LP64 target requires a documented justification
  for the constructs involved; matching integer widths is not a general ABI proof.
- [ ] Add small, independent calibration cases for arithmetic, shifts, casts,
  and relevant layout assumptions. Check the selected Frama-C interpretation
  against documented compiler behavior and controlled compiled examples.
  Keep shift-count validity distinct from overflow of the shifted value.
- [ ] Check the effective WP/EVA arithmetic configuration. Do not assume that
  importing a compilation database imports every semantic compiler option, or
  that suppressing a diagnostic establishes the required model.
- [ ] Review trap and unreachable models for each supported configuration.
  Distinguish normal return, abnormal termination, and divergence; verify the
  consequences of `terminates`, `exits`, and `ensures` together. Document which
  termination claims remain conditional or unresolved.
- [ ] Create an assumption ledger for external functions, substituted headers,
  macros, and types. Include justification, scope, source/configuration identity,
  review status, and the targets depending on each assumption.
- [ ] Enable WP smoke tests and review detected inconsistencies and dead paths.
  Explain intentionally unreachable calibration paths individually; avoid blanket
  suppression. A smoke test that finds no contradiction is inconclusive about
  overall consistency. [WP manual, smoke tests](https://www.frama-c.com/download/frama-c-wp-manual.pdf#page=37)
- [ ] Report unresolved dependencies of proved properties, including intermediate
  assertions. Prevent a downstream proof from being presented as complete when
  an assertion it relies on remains unproved.

Acceptance: each supported profile passes its calibration checks; every trusted
substitution is listed; each reported proof exposes its assumptions and unresolved
dependencies. An intentionally contradictory toy contract is detected by the
smoke-test check. Unknown profile settings prevent a target from being certified.

## Phase 2 — Deliver a reproducible regression command

Extend or wrap [run-wp.sh](run-wp.sh) and reuse the existing generation and
calibration scripts. Keep individual target runs available for investigation.

- [ ] Lock the complete toolchain, including transitive opam dependencies,
  Frama-C, Why3, provers, and compiler versions. Verify downloaded artifacts.
  Make the kernel path, install prefix, build directory, and output directory
  configurable. Avoid relying on manually installed binaries being on `PATH`.
- [ ] Add a preflight check for source/configuration availability, tool versions,
  supported profiles, and required analysis components. Make setup and analysis
  separate operations so verification runs do not silently install dependencies.
- [ ] Provide one documented suite command that performs provenance checks,
  generates inputs, validates the selected profile, runs WP/RTE and the relevant
  existing EVA/E-ACSL calibration cases, and writes a combined report.
  Support selecting architecture/profile/target without editing scripts; reject
  unknown selections and report unavailable analysis components explicitly.
- [x] Define a versioned result schema. Include target identity, input hashes,
  commands and versions, property names, goal outcomes, dependencies, assumptions,
  warnings, solver times, overall coverage status, and artifact paths.
  See [result semantics](docs/results.md); failed setup also records final dates
  and explicitly blocked selected targets.
- [ ] Implement regression policy over expected properties and dependencies.
  Detect missing targets, missing goals, incomplete reports, new unresolved
  obligations, tool failures, and unsupported input. A successful analyzer
  process exit is insufficient by itself.
- [ ] Handle calibration expectations explicitly. The deliberately wrong
  specification must remain distinguishable from solver uncertainty through its
  existing independent validation. Require review if an expected failure becomes
  valid, since that can indicate either an improvement or a modelling regression.
- [ ] Make source drift, configuration changes, modified models/contracts, and
  toolchain updates invalidate old baseline associations. Preserve old reports
  rather than overwriting evidence needed to explain a change.
- [ ] Verify the command from a clean environment at a different filesystem
  location. Add a local automation/CI entry point with a fast core suite and a
  separately selected extended suite for more expensive checks.

Acceptance: one command reproduces the existing supported suite after documented
setup, without manual path edits. Regression-policy tests distinguish valid,
unknown, missing, and expected-invalid results and return failure for incomplete
runs. Two clean runs agree on supported properties and outcomes; timing and
solver-specific incidental output may differ.

## Phase 3 — Strengthen contracts and reuse proof components

Use the stable regression suite to make stronger claims while preserving the
calibration examples.

- [x] Add a correct functional contract for `strlcat`: attempted total length,
  preserved destination prefix, exact copied source prefix, final length, and
  NUL termination on normal return. State how size arithmetic is interpreted and
  justify any bounds needed to express lengths as mathematical integers.
- [ ] Keep the deliberately false `strlcat` specification in an explicitly
  separate calibration variant so ordinary correctness results use only the
  intended API contract.
- [x] Review `strnchr`'s accepted input domain against the API, including zero
  count, searching for NUL, character conversion, and early string termination.
  Document any domain restriction or prove a broader contract where justified.
- [ ] Introduce reusable string, bounded-copy, bit-field, and shift specifications
  only as targets need them. Prove shared lemmas where feasible and label any
  remaining axioms; reuse should not introduce hidden assumptions.
- [ ] Add functional properties to selected existing instruction helpers:
  preservation of unrelated bits and encode/decode round trips over explicitly
  defined valid input domains, accounting for masking and sign extension.
- [ ] Reuse established contracts in caller checks. Record whether each caller
  precondition is proved, manually justified for a specific revision/configuration,
  or still unverified. Track indirect callers and configuration gaps explicitly.
- [ ] Extend calibration with small, controlled specification/mutation cases
  that exercise each new property. Require the intended property to distinguish
  the change; an unrelated timeout does not demonstrate sensitivity.

Acceptance: the core string targets have reviewed functional contracts and
resolved required proof dependencies, with remaining external assumptions shown.
At least one instruction-helper pair has a round-trip proof on a documented
domain. Controlled calibration cases demonstrate that the stronger properties
check behavior that the earlier safety-only contracts did not express.

## Phase 4 — Expand a curated collection

Draw initial candidates from the existing annotated directories and follow-up
items in [mpi/FINDINGS.md](mpi/FINDINGS.md) and
[arm64/FINDINGS.md](arm64/FINDINGS.md).

- [ ] Select an initial batch of small functions with clear APIs and manageable
  dependencies. Consider the MPI shift helpers and existing encoding/decoding
  clusters before introducing unrelated subsystems.
- [ ] Generalize harness extraction and provenance checks to these batches.
  Reuse real headers where supported; declare and review required substitutions.
- [ ] Add functions in small batches. For each, establish its input domain,
  intended properties, source identity, assumptions, and caller coverage before
  counting it as verified.
- [ ] Set a bounded analysis budget for each batch and retain unsupported or
  unresolved cases in the report. Route failures to contract, model, or solver
  investigation according to the evidence.
- [ ] Grow toward 20–50 distinct kernel functions. Count wrapper functions and
  repeated configurations separately from unique source functions; do not inflate
  coverage by counting harnesses or split goals as additional kernel functions.
- [x] Produce a coverage matrix showing runtime-safety, functional, termination,
  and caller-precondition coverage for each target and supported configuration.
  See [generated coverage](results/coverage-integrated-2-20260906/coverage.md)
  and [its explicit-evidence/freshness policy](docs/coverage.md). Reported claims
  remain conditional on the checked model; model-boundary audits remain open.

Acceptance: the suite tracks 20–50 distinct functions with provenance and explicit
coverage. Publish the fully verified subset and unresolved remainder separately.
Every function claimed verified meets its declared property/dependency criteria;
meeting the inventory target alone does not satisfy a proof claim.

## Architecture workstream — s390 first, then every architecture

Start the common port interface during phases 0–2. Bring up s390 once those
checks are available, alongside the stronger-contract and coverage work. Later
ports should reuse that interface and its acceptance checks.

### Meaning of architecture support

Each profile gets one of these evidence levels; planned or blocked profiles
remain visible with their missing prerequisites.

| Level | Required evidence | Permitted claim |
| --- | --- | --- |
| L0: registered | Architecture, intended ABI/configuration, toolchain requirements, and gaps listed. | Port planned; analysis support unverified. |
| L1: model checked | Compiler-derived machine description, kernel type/layout checks, preprocessing, and representative parsing checks pass. | Listed C constructs parse under a checked target model. |
| L2: proof suite checked | L1 plus source gates, assumptions, required proofs, and calibration expectations pass for a documented set of kernel functions. | Verification supported for those functions and that profile. |
| L3: runtime corroborated | L2 plus applicable independent compiled calibration checks run on the target or a suitable emulator, with evidence recorded. | Those checks have target-runtime corroboration. |

Parsing success does not establish functional correctness. A target run without
a failure does not prove universal safety. L3 applies to the runtime checks
actually executed and does not remove external proof assumptions.

The eventual all-architecture milestone requires at least one documented L2
baseline profile for every architecture supported by the pinned tree. Enumerate
additional kernel ABIs, endian modes, and configuration families with their own
status. Completion of one profile does not imply every variant is supported;
subsequent waves expand those variants explicitly.

### A0 — Common architecture port interface

- [ ] Add a shared architecture/profile schema containing kernel selectors,
  compiler target and version, relevant compiler flags, configuration recipe,
  generated-header/build paths, Frama-C machine description, permitted overrides,
  calibration targets, proof targets, and available runtime-check methods.
- [ ] Generate and review machine descriptions using the pinned target compiler
  where supported. Frama-C provides YAML machine descriptions and compiler-based
  generation; use this facility as a starting point, then validate it against the
  kernel build. [Frama-C machine descriptions](https://frama-c.com/2024/01/29/new-machdep.html)
- [ ] Validate widths, signedness, alignment, structure offsets, packed/bit-field
  layouts where used, and predefined macros with compiler checks against relevant
  kernel headers. Keep host/libc defaults from silently determining kernel types
  or constants. Record any layout the selected Frama-C model cannot represent.
- [ ] Generalize compilation-database and harness generation. Share only reviewed
  architecture-independent shims; select architecture-specific trap, atomic,
  builtin, and assembly handling through the profile. Unsupported operations
  remain explicit instead of being erased to obtain a successful parse.
- [ ] Add reusable calibration cases covering 32/64-bit size arithmetic, byte
  order, character signedness, conversions, alignment, and relevant bit layouts.
  Select cases by the constructs a profile claims to support.
- [ ] Run a common eligible subset of generic C helpers under each profile and
  add architecture-specific functions separately. Record conditional compilation
  so disabled or assembly-replaced functions cannot count as verified C bodies.
- [x] Discover required compiler/emulator capabilities during setup. A missing
  compiler blocks that profile; absent runtime execution limits L3 without
  disguising it as a passing check or preventing justified L1/L2 work.

Acceptance: existing x86-64, ARM64, and RISC-V experiments use the common profile
interface with explicit evidence levels. A selected profile determines the
effective preprocessing and analysis settings. Deliberately incorrect width or
byte-order settings are rejected by relevant calibration checks. Missing tools
and unsupported constructs appear in the profile report.

### A1 — s390 pilot

Use kernel `ARCH=s390` and a pinned s390x toolchain for the first new profile.
At baseline `b9b3e33b70b71`, `arch/s390/Kconfig` selects `64BIT` and
`CPU_BIG_ENDIAN`. This makes the pilot useful for checking whether the common
infrastructure handles a different byte order while preserving 64-bit types.
Derive the remaining ABI details from the actual compiler and configuration.

- [x] Register a reproducible s390 configuration and capture its real build
  commands/generated headers. Generate and check an s390-specific machine
  description rather than inheriting the x86 profile.
- [ ] Establish L1 with arithmetic, byte-order, type/layout, and preprocessing
  calibration. Check the selected build's trap behavior and list assembly or
  builtin dependencies of prospective proof targets.
- [x] Select 5–10 small C functions spanning an eligible common-helper subset
  and s390-specific arithmetic or data-conversion helpers. Keep the function
  selection contingent on inspected source and manageable dependencies.
- [x] Establish L2 for the registered pilot suite, including at least one
  functional property and explicit assumption/dependency reporting. Use a
  byte-order-sensitive calibration case to check that an incorrect profile
  cannot pass merely because its integer sizes match.
- [ ] Add applicable compiled calibration checks under an available s390 emulator
  or hardware to pursue L3. Verify cross-target availability of any instrumentation
  first; record unsupported checks and the achieved level accurately.
- [x] Document the port's supported profile, target list, results, and remaining
  limitations through the common reporting path.

The [2026-09-06 named-pilot baseline](s390/PILOT-20260906.md) records these two
completed tasks and the exact four-target evidence. The broader trap portion
of the compound L1 task and whole-pilot runtime work remain unchecked above;
they are not silently inferred from the seven-helper L2 result.

Acceptance: the common suite selects s390 without hand-editing commands; the
documented 5–10-function pilot meets L2 criteria and exercises big-endian
behaviour in calibration. Runtime evidence is reported independently. No claim
extends to unmodelled assembly, concurrency, or compatibility-data layouts.

### A2 — Expand in waves

This starting roster was checked against the architecture directories in
`b9b3e33b70b71`. Recompute it from each selected revision and validate the
corresponding build configurations. Newly added architectures enter the registry;
removed ones remain historical profiles rather than current coverage claims.

| Wave | Architecture directories | Main objective |
| --- | --- | --- |
| Existing experiments | `x86`, `arm64`, `riscv` | Replace implicit host assumptions with checked profiles and repeatable suites. |
| First new port | `s390` | Validate a 64-bit, big-endian profile through the common interface. |
| Broader ABI coverage | `arm`, `powerpc`, `mips`, `sparc`, `loongarch` | Add representative supported 32/64-bit and endian profiles, plus 32-bit profiles of existing architectures where the kernel supports them. |
| Remaining hardware architectures | `alpha`, `arc`, `csky`, `hexagon`, `m68k`, `microblaze`, `nios2`, `openrisc`, `parisc`, `sh`, `xtensa` | Reuse the port interface and resolve each architecture's actual toolchain/model gaps. |
| Hosted kernel profile | `um` | Track User-Mode Linux with its `SUBARCH`, host ABI, and kernel-specific configuration separately. |

This table is the starting wave order, not current support status. The named
nine common24 baselines below supplement the separately renewed s390 pilot;
all-architecture and additional ABI coverage remain open.

- [ ] Within each wave, choose order by toolchain availability, model readiness,
  and useful new ABI/layout coverage. Retain every planned architecture in the
  matrix even when it cannot yet progress.
- [ ] Move each profile through L1 and L2 using the same checks as the s390 pilot.
  Reuse generic specifications only after confirming the target's API and type
  assumptions, including changes in `size_t` and word-sized arithmetic.
  The next common subset is the four explicit-byte 24-bit helpers and their
  two project round trips. The [source eligibility review](build/common-byte-port-review/REVIEW.md)
  identifies the separate generic-header fixture needed for nine other
  configured profiles and PowerPC32's actual patchable-entry attribute
  difference. Per-profile proof and calibration acceptance remains required;
  reuse does not increase the distinct kernel-function count.
  The [first compiler-only stage](build/common-byte-port-work/HANDOFF.md)
  passes genuine-header and preserved-harness checks for ARM32, PowerPC32 and
  m68k, including rejection of wrong type/inline expectations. Later
  [ARM32/m68k diagnostics](build/common-byte-analysis-work/HANDOFF.md) and
  [PowerPC32 diagnostics](build/common-byte-ppc-analysis-work/HANDOFF.md) each
  close all 94 ordinary goals and 82 properties per profile, without accepting
  warnings or inferring consistency from the 12 smoke timeouts. The separate
  [compiler-only sensitivity audit](build/common-byte-calibration-work/AUDIT-20260906.md)
  checks 22 fixed observations and individually rejects 22 wrong expectations
  per profile, without native execution. The [common runner integration](common/README.md)
  now registers these variants with explicit target-local policies. The
  [first production run](common/INTEGRATION-20260906.md) preserves its unaccepted
  status. The subsequent [reviewed L2 baselines](common/L2-20260906.md) pass
  fresh model/source/compiler/proof/review gates on all three profiles and
  independent full replay validation, with complete 94/82 inventories.
  The [wave-two continuation](common/WAVE2-20260906.md) now registers ARM64,
  RISC-V and SH, with complete dated proof inventories, reviewed source-derived
  compiler assertion identities and 580 passing regression tests. The
  [six-profile L2 run](common/L2-WAVE2-20260906.md) passes fresh normal acceptance,
  full retained-evidence replay and independent coverage audit at that identity.
  The [wave-three continuation](common/WAVE3-20260906.md) now registers Alpha,
  hardware x86-64 and UML x86-64. Exact Alpha function metadata and the genuine
  `-Os` compiler mode have narrowly scoped, tested support; all 610 regression
  tests passed without skips at that identity. Independent profile-specific reviews are recorded
  for the new three, and the older six contexts explicitly bind the shared
  provider supplement. Fresh normal acceptance remains separate from review;
  old failures and stale results are not rewritten. The
  [configured-profile queue](common/NEXT-PROFILES.md) tracks the evidence.
  The [nine-profile L2 renewal](common/L2-WAVE3-20260906.md) completes that fresh
  acceptance and independent replay/coverage audit for all nine profiles.
  The [other eleven architectures](profiles/NEXT-WAVE.md)
  still need configured L1 bring-up, further LLVM support where selected and
  a separate pre-15 compiler pin for Nios II. This all-profile task remains open.
- [x] Add the first explicit LLVM compiler-build route, preserving GCC behavior:
  [Hexagon v68 preparation and string object](profiles/LLVM-BUILD-20260906.md),
  pinned tool aliases/versions/hashes, exact real-command/configuration/ELF gates,
  independent source/readback audit and 37 new mocked tests. No profile promotion.
- [x] Implement explicit Clang family/target/CPU/binary/resource interfaces and
  full genuine-TU flag matching, preserving GCC behavior. The
  [interface milestone](profiles/CLANG-INTERFACE-20260906.md) passes 690 tests,
  actual Clang metadata, 18-tool preflight and 182 fresh existing-model checks.
  Resolve the genuine header-source commit with retained primary metadata;
  keep the Clang generator gate closed and Hexagon unconfigured.
- [x] Authenticate and provision Hexagon's exact target header source offline,
  with complete source/generated/header evidence and independent byte readback.
  The [header milestone](profiles/HEXAGON-HEADER-PROVISION-20260906.md) passes
  720 tests and retains both real header-order diagnostics, without changing
  freestanding/short-wchar flags or awarding model support.
- [x] Implement and review the explicit unregistered Hexagon generator adapter
  using authenticated header receipts: observed macro absence, preprocessing-only
  commands, freestanding sanity return and distinct fallback struct tags. The
  [adapter milestone](profiles/HEXAGON-GENERATOR-ADAPTER-20260906.md) retains all
  84 actual compiler queries, complete schema validation and 802 passing tests.
  Emitted-object alignment checks correctly refuse integration; candidate
  extraction is not a configured or supported model.
- [x] Derive Hexagon's full `max_align_t` declaration from authenticated source
  and installed headers; compare fourteen actual/candidate compiler layout
  pairs and require three named rejection controls before model serialization.
  The [layout milestone](profiles/HEXAGON-LAYOUT-20260906.md) retains the
  88-query compiler result and the 867-test pass at that identity. Its first
  actual analyzer run is a preserved failure, not model acceptance.
- [x] Separate the executable path from Frama-C's literal `clang` dialect
  selector, measure all twelve GNU alignment fields, and pass the unchanged
  positive layout fixture plus all three analyzer rejection controls with a
  freshly generated candidate. The [100-query/Frama-C layout result](profiles/HEXAGON-LAYOUT-20260906.md)
  passes this diagnostic scope without suppressed diagnostics or rewritten old
  YAML; it does not resolve extended alignment or establish L1.
- [x] Execute the reviewed fixed Hexagon alignment-context diagnostic and retain
  all 55 compiler/analyzer pairs, language controls and unresolved observations.
  The [context milestone](profiles/HEXAGON-CONTEXT-20260907.md) completes 112 direct
  queries with no input drift and independently checked retained evidence, but
  exits 1 with seven unresolved observations and two unexpected negative-control
  acceptances. Low-alignment expression differences also remain; this checked
  diagnostic task is not alignment resolution or model support.
- [ ] Resolve the compiler/model extended-alignment mismatch. Integrate the
  reviewed adapter and full
  authenticated header/resource evidence into the normal profile pipeline;
  preserve warning/error gates without invented fields or hosted semantics.
  Pass full L1 before registration and scoped L2
  before awarding an architecture baseline. Preserve the default-v2/modern-CPU
  mismatch and wider `ELF_CORE_EFLAGS` limitation instead of treating one object
  as a whole-kernel compatibility result.
  The [private typing candidate](build/framac-alignment-provider-20260907/patches/ALIGNMENT-TYPING-REVIEW-20260907.md)
  and its policy/query patches are now applied to a separate editable source
  tree. The [corrected private build and core parse](build/framac-alignment-provider-20260907/CANDIDATE-BUILD-20260907.md)
  now pass; all 11,511 source entries match the pinned archive plus exactly three
  patches, nine files and 39 hunks. The first build's one-line module-shadowing
  error is corrected only in a fresh source tree and policy-v2 patch. The old
  standalone local-static proposal remains unapplied; its gated successor is
  included in the typing patch. The new
  [private context results](build/framac-alignment-provider-20260907/PRIVATE-CONTEXT-20260907.md)
  complete opt-in parsing of all 55 unchanged pairs: 33 constant agreements,
  21 corresponding rejection categories and one compound-category mismatch.
  A separate 14-case diagnostic confirms missing-definition, double-VLA and
  typed-arithmetic gaps. The local witness parser has nine passing offline
  regressions; both original private observations and the fresh run are retained.
  The [fresh declaration successor](build/framac-alignment-provider-20260907/CANDIDATE-DECLARATION-20260907.md)
  now applies the nine-line presence check as a fourth patch, builds and passes
  six runtime queries. It reruns all 55 unchanged pairs and all 14 extra pairs:
  the four forward missing-definition controls now reject as intended, while
  reverse-order results remain unchanged. The later
  [candidate-5 successor](build/framac-alignment-provider-20260907/CANDIDATE-VLA-ARITHMETIC-20260907.md)
  fixes the saved-bound initializer regression in fresh evidence: basic VLA
  witnesses and three expanded checked-AST cases recover, while the 55-pair
  summary stays 33/21/1. Its 44-case raw batch has 156 executed queries and
  66 skips, not 44 accepted cases. Cast/constant-expression, static type-query,
  stricter VLA allocation, multiple variable dimensions and compound-error
  recovery remain open. Patch 009 is unbuilt. Park further Hexagon implementation
  for the user's bounded kernel correctness review; on resumption, require
  fresh policy/local/VLA/AST and broader semantic controls. Pragma semantics, complete
  redeclarations, existing-profile regressions and normal integration remain
  open; the successful constant cases do not satisfy this whole gate.
- [ ] Renew existing suite results after the shared build/profile/toolchain changes;
  retain all dated acceptances and all six legacy nonpasses.
  The [first renewal attempts](common/RENEWAL-SOCKET-FAILURE-20260907.md) passed
  all 164 model checks but encountered sandbox-denied Why3 socket connections.
  They were stopped with failed receipts and unchanged partial summaries;
  those incomplete attempts remain outside completed matrix history and are
  documented separately. The nine Eva calibrations now have current acceptance;
  the six legacy nonpasses remain outstanding.

  - [x] Renew exactly the nine common24 proof variants in separately authorized
    socket-enabled batches, preserving their existing reviews and full domains.
    The [2026-09-07 scoped L2 record](common/L2-CLANG-RENEWAL-20260907.md)
    binds accepted proof/replay and coverage audits, 36 helper/profile pairs,
    unchanged old failure evidence and nine current target acceptances.

  - [x] Renew exactly seven existing non-common WP targets under unchanged
    sources, contracts and scoped reviews. The
    [seven-target renewal](docs/PROOF-RENEWAL-20260907.md) passes all three normal
    batches, 74 L1 checks, 418 ordinary goals and 331 selected properties, with
    retained warning/smoke outcomes and independently checked current coverage.
    The separate calibration renewal below supplies the Eva gates; this WP
    subtask alone does not establish full-suite acceptance.

  - [x] Renew exactly the nine existing valid-input Eva sensitivity cases with
    the explicit unchanged native-9/native-5 receipts revalidated read-only.
    The [calibration renewal](docs/CALIBRATION-RENEWAL-20260907.md) passes both
    normal batches, 38 model checks and 55 positive properties, preserving nine
    raw ambiguous negative labels and their independent false-specification
    corroboration. The [s390 scope decision](s390/L2-RENEWAL-20260907.md)
    separately renews the existing seven-helper L2 baseline; no L3 is awarded.

- [ ] Add architecture-specific C helpers where they provide meaningful coverage.
  Distinguish their proof results from generic helpers compiled for that profile.
- [ ] Track unsupported language constructs or machine layouts as specific
  engineering/research tasks with a small descriptive calibration case and a
  clear criterion for removing the limitation.
- [ ] Expand ABI/endian/configuration variants after each initial profile works.
  List supported combinations explicitly; avoid implying support for arbitrary
  combinations or for compatibility userspace ABIs not yet modelled.

Acceptance: each wave publishes L0–L3 status per profile, proven function counts,
and unresolved prerequisites. The all-architecture milestone is complete only
when every architecture in the selected roster has its required L2 baseline.
Architectures with blockers remain outstanding work, not exceptions counted as
successful ports.

### A3 — Keep architecture coverage reproducible

- [ ] Add a fast matrix covering representative 32/64-bit and little/big-endian
  profiles, including s390. Run the full supported profile matrix for baseline
  releases and relevant shared-model/toolchain changes.
- [ ] Record cross-compiler versions and profile hashes in every artifact and
  cache key. Track local patches and generated machine-description changes.
- [ ] Maintain onboarding instructions and a reusable port checklist. Record
  who reviews each maintained profile and how stale or failing coverage is shown.
- [ ] Budget runtime/emulator checks separately from static proof runs. Publish
  which runtime checks ran, were skipped, or are unsupported, with reasons.

Acceptance: adding an architecture primarily adds a checked profile, scoped
models, and targets to shared tooling. Architecture/profile status is generated
from recorded evidence and cannot remain green after a required check fails.

## Phase 5 — Maintain and measure the suite

- [ ] Measure wall time, proof outcomes, and manual work per added target before
  optimizing. Track recurring model/contract causes of unresolved obligations.
- [ ] Use proof sessions/caches only with validated input identities, including
  sources, headers, configuration, annotations, model settings, and tool versions.
  Schedule clean runs to check that cached outcomes remain reproducible.
- [ ] Recheck affected targets when a source, shared contract, header model, or
  configuration changes. Include dependants of shared assumptions and retain a
  full-suite check for changes whose impact cannot be determined safely.
- [x] Document adding a target, reviewing an assumption, updating a kernel
  revision/toolchain, and accepting an intentional baseline change. Baseline
  updates must explain changed obligations and outcomes.
  See [the maintenance workflow](docs/maintenance.md). Automatic affected-target
  scheduling, cache acceptance and broader matrix automation remain separate work.
- [ ] Tune solver selection and parallel analysis jobs based on measured
  bottlenecks and available resources. This concerns analysis throughput, not
  concurrent-program semantics. Revalidate outcomes after model or solver changes.
- [ ] Generate current result summaries from reports. Keep architecture findings
  documents as dated explanations linked to the relevant run evidence.

Acceptance: a maintainer can add a target and update a pinned source/toolchain
using documented steps. Cache use and incremental runs preserve the evidence
needed to audit results, and a clean full run confirms release baselines.

## Milestones and measures

1. **Existing suite reproducible:** phases 0–2 complete for the core cases,
   including provenance, profile checks, assumption reporting, and calibrated
   failure handling.
2. **Stronger guarantees:** phase 3 complete for the core string examples and
   an instruction-helper pair; their additional properties are explained in the
   generated report.
3. **Useful coverage:** phase 4 reaches its curated target with verified and
   unresolved coverage reported separately; the maintenance workflow is documented.
4. **s390 support:** A0–A1 complete at L2 or above for the pilot profile. This
   milestone can progress alongside milestones 2–3 after the core suite works.
5. **Every architecture represented by working verification:** A2 establishes
   at least one L2 baseline for every architecture in the pinned tree, A3 keeps
   the matrix reproducible, and additional ABI/configuration coverage is explicit.
6. **Scoped concurrency verification:** complete the separately gated
   [C0-C4 workstream](docs/CONCURRENCY-PLAN.md). Publish exactly which threading,
   interrupt, synchronization, weak-memory and RCU properties are supported;
   neither sequential architecture support nor a small Mthread pilot completes
   this milestone by itself.

Measure unique functions and configurations covered, required properties proved,
unresolved dependencies, reviewed assumptions, calibration checks passed,
reproduction success, suite runtime, and manual effort per added function.
Also measure architecture/profile counts at each support level, 32/64-bit and
endian coverage, architecture-specific versus generic targets, outstanding port
prerequisites, and freshness of the most recent successful matrix run.
Use these measurements to estimate later expansion. Raw goal totals and numbers
of suspected defects are not measures of verification quality.

For implementation, start with the manifest, robust source gates, and a fresh
baseline for `strnchr`, `strlcat`, and the existing calibration variants. Then
validate their model and build the common reporting/regression path before
expanding the target collection. Design that path around architecture profiles
from the start, then use s390 to validate it before scaling the port roster.
