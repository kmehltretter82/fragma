# Private VLA/typed-arithmetic candidates: candidate 5 audited, implementation parked

Updated 2026-09-07 after the terminal candidate-5 diagnostics. Candidate 5 fixes
candidate 4's saved-bound initializer regression in fresh source/build evidence.
The basic double/int VLA witnesses now agree with Clang, and three expanded
cases recover from AST-check failures. Broader semantics remain incomplete;
**Hexagon is still unconfigured and ineligible for integration.**

Per the user's priority change, further Hexagon implementation is parked while
actual bounded Linux kernel correctness review takes priority. No profile,
accepted proof/function/architecture count, installed provider or confirmed
kernel-bug count changes. These private tool/model findings are not kernel bugs.
The 891-test pass belongs to the dated September 6 shared-project milestone;
it was not rerun as regression validation of these private providers.

## Candidate 5: correction and audited results

[Preparation 5](worktree-5/preparation.json) retains ten changed files and 63
exact hunks across seven ordered patches. Its only additional correction is
[008](patches/0008-vla-bound-local-init.patch): the typed saved VLA bound now
uses `Local_init`, with its initialization/write information, instead of a
`Set` paired with `vdefined = true`. Candidate 4 remains unchanged.
[Build 5](candidate-build-5/receipt.json) completes at 05:41:25.798297 UTC;
[runtime 5](candidate-runtime-5/receipt.json) passes all six early/core-only
checks at 05:42:29.048508 UTC. Neither establishes full alignment or plugin support.

[Context run 5](context-run-5/receipt.json) completes at 05:43:55.312510 UTC.
All 55 comparisons replay identically to candidate 4: 33 constant agreements,
21 corresponding rejection categories and one compound-category mismatch;
the recorder still exits one. There are no unexpected negative acceptances.
[Extra run 4](extra-context-run-4/receipt.json), completed at 05:43:44.099207 UTC,
has six exit-zero and eight exit-one outcomes for each tool. Only the two VLA
analyzer outcomes change, from internal exit 125 to zero: double is `[8,8,4]`
and int is `[4,4,4]`, matching Clang. Their printed bodies contain `int tmp = n`
and retain the typed bound before allocation. The remaining twelve controls,
including the basic GNU arithmetic cases, are unchanged from candidate 4.

[Followup run 2](followup-run-2/receipt.json) completes at 05:45:27.313681 UTC:
all 44 unchanged cases occupy the fixed 222-row plan, with 156 executed queries
and 66 explicit parent-failure skips. Clang has 32 exit-zero and twelve exit-one
outcomes. Each initial analyzer mode, with and without optional `-constfold`,
has eleven exit-zero and 33 exit-one outcomes; all 22 eligible reparses exit zero.
Every analyzer parse/reparse uses `-check`. Exit zero for the recorder means
complete raw collection and checked input/preprocessing closure, not semantic
acceptance of all cases or diagnostic correspondence.

Only three initial case pairs change from internal exit four to zero:
typed GNU alignment from a double VLA, ordinary comma decay, and comma decay
with unevaluated increments. Their six previously skipped reparses now succeed.
Clang/initial-fold/reparse-fold witnesses are `[4,8,4]`, `[4,4,4,4]` and
`[4,4,4,4]`, respectively. Same-mode initial/reparsed printed C is byte-identical,
with one typed saved-bound initializer and no surviving increment. Compiler
warnings and analyzer side-effect-dropping notices on the comma controls remain
visible; they are not silently classified as clean semantic passes.

The bounded read-only audit checks 364 retained rows across context 5, extra 4
and followup 2, including exact commands/environments, process closure,
result/observation/receipt consistency, reparse parent pins, 179 preprocessing
closures and 537 linemarkers. Current and preceding run trees and selected
primary inputs are rehashed without drift. Apart from the named changes, raw
diagnostics and printed C are unchanged after exact run/build path normalization
and separate preprocessing verification. This is not a hermetic-host or
whole-language validation claim.

## Retained candidate-4 regression, 2026-09-07

Candidate 4 builds and passes the six early/core-runtime checks. The unchanged
55-pair matrix retains 33 constant agreements, 21 corresponding rejections and
one compound-category mismatch. GNU arithmetic now succeeds on the retained
`8 + 8` control and rejects the retained zero/negative/nonpower results with
typed-value diagnostics. However, both existing VLA controls now terminate with
an internal AST assertion. **This candidate is not eligible for integration.**
No architecture, accepted proof, installed provider or confirmed kernel-bug
count changes.

## Candidate 4 source, build and runtime

[Preparation 4](worktree-4/preparation.json) reconstructs the authenticated
archive with six ordered patches, ten changed files and 62 hunks. The rebased
[006](patches/0006-vla-typed-provenance-v2.patch) and
[007](patches/0007-clang-typed-gnu-alignment-v2.patch) preserve their original
proposal content except hunk coordinates; both original and sequential
contexts are checked exactly, without fuzz. The 11,511-entry source tree is
fresh. All fourteen preparation inputs match before/after; no subprocess runs
during preparation, which completes at 05:21:01.490091 UTC.

[Build 4](candidate-build-4/receipt.json) runs
05:21:55.436440–05:24:44.558171 UTC, with 156.552507 monitored Dune seconds.
It returns zero, with a terminal/reaped original process group, no leftovers,
no cleanup signal and no source/dependency drift. Normal Dune local IPC was
separately approved; no package installation or provider replacement occurs.

[Runtime 4](candidate-runtime-4/receipt.json) completes at 05:26:30.697618 UTC.
All five exact version/resource outputs and the unchanged inert legacy x86_64
core-only parse pass. This does not validate plugin loading or alignment.

Independent read-only audit freshly hashes 37,532 unique regular files and
checks 6,197 symlinks, with zero drift. It checks the complete build/source and
four selected dependency trees, thirteen dependency files, fourteen preparation
and fifteen build selected inputs, exact build/runtime commands, environments,
process closure, and all six runtime outputs. This is selected-closure evidence,
not a hermetic host or escaped-descendant attestation. No compiler warning/error
diagnostic is found in the retained build log.

## Candidate 4 unchanged 55 pairs and additional 14 controls

[Context run 4](context-run-4/receipt.json) completes all 112 direct queries at
05:28:41.922557 UTC, returning one for the retained compound-category mismatch.
Its summary remains 33 constant agreements, 21 corresponding rejection
categories, one mismatch, zero unresolved observations and zero unexpected
negative-control acceptances. Inputs do not drift.

[Extra context run 3](extra-context-run-3/receipt.json) completes all thirty
direct queries at 05:29:20.021395 UTC without drift. Its exit zero means raw
collection only, not semantic success. Clang has six successes and eight
rejections; the analyzer has four successes, eight rejections and two internal
errors (exit 125).

- The four forward missing-definition controls still reject, and the reverse
  declaration-order outcomes remain unchanged.
- GNU `8 + 8` now prints the original request as `16` and the matching witness
  `[4,16,4]`. The three invalid arithmetic controls diagnose typed values
  `0`, `-8` and `12`, respectively, rather than unsupported arithmetic.
- Both ordinary `double` and `int` VLA controls fail before producing printed
  C. The retained backtraces reach `Kernel_function.local_definition_opt`
  through destructor scope handling. No VLA alignment agreement is established.

Source inspection identifies the new saved-bound temporary as marked
`vdefined = true` but emitted with `Set`, whereas that invariant requires a
corresponding `Local_init`. Candidate 5 supplies the separate correction and
fresh evidence described above; candidate 4 and all its executed inputs remain
unchanged, including the two failing VLA observations.

## Followup and remaining gates

The [twenty arithmetic](arithmetic_followup_fixtures.py) and
[twenty-four VLA](vla_followup_fixtures.py) controls are source-reviewed and pass
pure inventory checks: 44 unique cases, fixed-size witnesses and deterministic
bounded source bytes. They contain 29 required acceptances, ten required
rejections and five reference observations. Three valid VLA cases explicitly
describe currently unsupported allocation/multidimension semantics; these are
not successful negative controls.

[Followup run 1](followup-run-1/receipt.json), completed at 05:37:00.115155 UTC,
retains candidate 4's first measurements: 150 executed queries and 72 skips.
Each initial analyzer mode has eight exit-zero, 33 exit-one and three internal
exit-four outcomes; sixteen reparses succeed. This history is not rewritten
by followup run 2. The original 55+14 cases are not replaced.

Remaining gaps include valid casts/promotions rejected by the attribute parser,
incorrect empty-call diagnostics, compiler/analyzer differences for signed
overflow and shift-by-width, and static type-query/VLA handling. Negative cases
rejected for syntax or unrelated diagnostics do not become passing validity
controls. Three compiler-valid controls still require unsupported stricter
C11/GNU VLA allocation or multiple variable dimensions; unsupported is not a
language-invalid rejection. [009](patches/0009-static-type-queries.patch) remains
an unapplied, unbuilt source proposal and has no new semantic results.

The successful high/low arithmetic controls preserve the original numbers
`536870912` and `16` in initial printing and plain reparsing, with harmless
attribute reordering. Folded reparsing drops the unused extern declaration;
it preserves witness constants but is not evidence of final attribute retention.
Plain typed-query outputs are not counted as independently measured literal
constant agreements. Full policy/legacy regressions,
complete redeclaration/pragma semantics, remaining expression/ABI consumers,
genuine-kernel L1, scoped L2 and normal-pipeline integration remain open as
specified in [CONTEXT-NEXT.md](CONTEXT-NEXT.md) and [PLAN.md](../../PLAN.md).

## Retained identities

| Artifact | SHA256 |
| --- | --- |
| Preparation 4 receipt | `964fa818a6d963513fbe7acce0df00d81f51150415add0c1ebbc831620eadd79` |
| Build V4 recorder | `137a711930a309399a220c5315ae298da7f950fdc57bcfb99b69dd577a728084` |
| Build 4 receipt | `1e59bd611fbdc513374856049d6d61f23cfb21c09eb5dff5356c6821256b4e9e` |
| Candidate 4 executable | `03aac0c5cb7eec9e72ec75bef9a8eefe0921a20e1f380d71d52f9a798d6ca748` |
| Runtime V4 recorder | `c6d6528257083d16a6b14536673b84fa071e91602f8b6b2bfbd8683faffd44cf` |
| Runtime 4 receipt | `025f0e9687013859d4c979ae7a615e2240bfd616689527d52af506ff5b2302b6` |
| Context V4 recorder | `7ecdaa5762f22d1c7979f2aba81cb23b29246acf24c17e469da34a247cf10dde` |
| Context run 4 receipt | `7e0602c7da3fc42de389f04f8511fca2a7085e630668a6d60753fbc4fa2a7824` |
| Extra V3 recorder | `6382b2442680c59229a7cb4baba7b10b7a242c373ae6c6c21594fbe1d86dd42c` |
| Extra run 3 receipt | `cc1b74dbd9be6624de09589b9f02eaca550c5877bd69908ed98d1cea793733d7` |
| Followup run 1 receipt | `14aaeb2d172ab7ea98661984ea512f53affeedf0eed73b91ac9820f3f692f2ff` |
| Preparation 5 receipt | `4567f327c2ff7f5943cbf650c5ff46d92b12b8c0ac643268a6e909ed99702c61` |
| Build 5 receipt | `3269ff1226f9fd31228c190eb03fd763578369f11edd34f1b84fe0f25fc2a13d` |
| Candidate 5 executable | `db71214d82eab3789aa0c15194e6b6c85dc58d76317eb8d2e289cd325b812e3b` |
| Runtime 5 receipt | `a000aeb47acec904cfba8ade8a77946cb835b55f938be1242544dfefa032da59` |
| Context run 5 receipt | `8902096d6bfd6360286d2fc2e3987224dc1802beff2ab865142f65b2e5b5783f` |
| Extra run 4 receipt | `f39e96539e4177da53fea65fbdd18c64a3e2765b7ef2fdd7eaf2cea4fa818932` |
| Followup run 2 receipt | `544750008b15711eb2a3d5bf1ea43e73f246ad0d9da7d768d277e558e0c5ec4a` |
