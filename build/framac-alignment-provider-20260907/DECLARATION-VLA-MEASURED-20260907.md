# Measured declaration/VLA gaps and the next narrow proposal

Subsequent execution: [candidate 3](CANDIDATE-DECLARATION-20260907.md) applies
patch 0005 in a fresh source tree, builds and verifies the four intended
rejections plus unchanged reverse-order controls. The proposal-only statements
below describe the earlier review; its original evidence remains preserved.
VLA and broader redeclaration semantics remain open.

Read-only review of completed observations, 2026-09-07. This note supersedes
only the previously unmeasured outcomes in `DECLARATION-VLA-DESIGN-20260907.md`;
that earlier source-design note and all run inputs remain unchanged. No build,
compiler, analyzer or target was executed while preparing this review. No
private patch was applied. Neither this note nor the raw observation receipt
establishes provider support or a Hexagon promotion.

## Evidence and measured distinctions

The completed `extra-context-run-1/receipt.json` has SHA256
`75a060bf654d531d0714b3627a6a88a9e70e0d327e7c0d66adb27d1e6c3b51bb`.
It records 30 queries (two versions and 14 compiler/analyzer pairs), terminal
status `private-extra-observations-complete-unclassified-not-support`, and no
input drift. The independent raw read for this note covers command 003 through
022, including source, diagnostics, LLVM IR and successful printed C. It is not
a full independent rehash of the receipt's complete dependency closure or an
audit of the four arithmetic pairs 023 through 030.

Here, "before" means the aligned extern occurs before the bare definition;
"after" reverses that order. Return codes alone are not diagnostic equivalence.

| Commands (Clang/private Frama-C) | Source sequence | Measured outcome |
| --- | --- | --- |
| 003/004, 005/006, 007/008 | Aligned extern, then tentative definition; requests 16, 0, 536870912 | Clang rejects each with the named missing-definition alignment error; Frama-C accepts each and prints the inherited original `_Alignas` on the merged object. |
| 009/010 | Aligned extern at 16, then initialized definition | The same compiler rejection/private acceptance mismatch. |
| 011/012, 013/014, 015/016 | Tentative definition, then aligned extern; requests 16, 0, 536870912 | Both accept. Their three constant witnesses agree: `[4,16,4]`, `[4,4,4]`, `[4,4,4]`, respectively. |
| 017/018 | Initialized definition, then aligned extern at 16 | Both reject for missing alignment on the earlier definition. Frama-C's existing diagnostic identifies the earlier unaligned definition; the compiler diagnoses the earlier definition and notes the later declaration. |
| 019/020 | Unqualified local `double` VLA | Both accept, but GNU expression/type/pointer witnesses are Clang `[8,8,4]` and Frama-C `[4,8,4]`. |
| 021/022 | Unqualified local `int` VLA | Both accept with `[4,4,4]`; this companion does not distinguish array-element alignment from pointer alignment. |

An additional measured distinction prevents overclaiming the after-order
agreement: command 011's LLVM IR gives the actual `fragma_object` global
`align 4`, although its GNU expression-alignment witness is 16. Command 012
prints a merged `_Alignas(16)` object. The matching witnesses therefore do not
establish preservation of the original tentative-definition storage alignment
or declaration provenance. Printed C alone does not independently establish a
private backend's storage placement either.

## Proposal 0005: source presence before canonical merging

`patches/0005-c11-missing-definition.patch` is an unapplied proposal, SHA256
`1a7ab19aaff5d3d8785bc73d838e54bbd0273c60844bf5f9336f44eb357aaa29`.
It adds nine lines in one hunk to `cabs2cil.ml:2543`, immediately before existing
`valignas` coherence and merging. Under the explicit `clang-21-u32-bits` policy,
it rejects only a new definition with absent source `_Alignas` when the prior
canonical declaration retains a source `_Alignas`. It does not change legacy
behavior, the representation of any request, or effective-alignment arithmetic.

The source establishes the required distinctions:

- `solveAlignas:4021–4058` retains `Some expression` for valid zero and ignored
  high requests; neither may be treated as source absence.
- `createGlobal:8548–8556` computes `isadef` for tentative and initialized
  definitions. The incoming aligned extern in the after-order tentative cases
  is not a definition and therefore does not trigger the new guard.
- `alreadyDefined` records initialized definitions separately from deferred
  tentative definitions. The existing reverse-order check remains intact. Do
  not substitute `oldvi.vdefined` and thereby reject all after-tentative cases.
- `makeGlobalVarinfo:2559` otherwise merges `Some` into `None`, erasing precisely
  the incoming absence which the forward check needs. Check before that merge.

The diagnostic names the object and the missing source specifier. It does not
pretend that the canonical lookup location is necessarily the original aligned
declaration's location after intervening redeclarations.

Strict, pure in-memory application of this one hunk was checked against current
worktree-2 `cabs2cil.ml` SHA256
`9c5fea44e1324b81b41d3f87dac27dd314f8d650c70bea77924a76f0269228fa`.
The hypothetical resulting bytes have SHA256
`74f90243bc9162a9de592597cd92f6c2e06b5f205975177a6490d3bfd161b035`.
The actual worktree file remained unchanged. This is an incremental patch atop
the current three private patches, not a patch against the original archive;
no OCaml typecheck or runtime success is claimed.

## VLA correction remains a separate provenance change

The double-VLA discrepancy is now measured, not hypothetical. Its source path
is consistent with the earlier design: `isVariableSizedArray:5106–5135` rewrites
the VLA declarator to a pointer; `makeVarSizeVarInfo:4583–4600` constructs that
pointer variable; the `varSizeArrays` table saves dynamic size but the direct
GNU query at `EXPR_ALIGNOF:5893–5915` does not consult original array provenance.
Thus the private output's first value is pointer alignment 4, while the retained
double type's alignment remains 8.

A next independently reviewed change should retain an explicit original-array
origin keyed by the final alpha-converted variable, alongside the saved size and
already evaluated bound. Resolve the proven direct-variable GNU query using
that origin and the existing alignment policy. Do not mutate the lowered
pointer type, add invented alignment attributes, evaluate a bound twice, or
replace dynamic `sizeof` with a constant. For the unqualified one-dimensional
double/int controls, the retained element type supplies the alignment base;
qualified, attributed, multidimensional and C11-aligned VLAs require a larger
typed-origin design before extending that claim.

## Required next gates and explicit remaining scope

After root review, a new source worktree/build/runtime receipt is required before
replaying the unchanged 55 cases and all 14 extra cases with newly reviewed
named diagnostics. The four forward missing-definition controls should change
to exact rejection; the three after-tentative controls must remain accepted and
the initialized-after control rejected. This is a proposed expectation, not an
observed result of patch 0005. Preserve legacy controls and all historical runs.

Neither 0005 nor these observations establish combined GNU/C11 redeclaration
comparison, zero/ignored versus explicit natural alignment, correct source
locations through intervening externs, full compound-error recovery, or the
after-tentative storage/declaration distinction. Additional finite controls are
needed for those topics. Keep the existing compound above-maximum/missing-
definition two-category compiler result distinct from a one-category analyzer
rejection; a presence guard alone does not reproduce recovery after an invalid
attribute is discarded by Clang.

A future VLA patch also needs discriminating double/int regressions, a retained
single evaluation of an effectful bound, GNU honored/ignored/default requests,
C11 requests below the original array's natural alignment, unchanged fixed
arrays and pointers, and retained rejection of evaluated-local/VLA-size static
initializers. Source `typeof`, address/dereference, allocation placement and
complete expression-context support remain outside the direct-query correction.
