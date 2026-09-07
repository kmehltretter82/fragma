# 006: typed VLA provenance proposal

Private, unapplied source proposal, 2026-09-07. No OCaml build, compiler,
analyzer, target or native program was executed for this work. This is not a
provider-support claim. The measured starting discrepancy remains the double
VLA pair in `extra-context-run-1/command-019` and `command-020`: Clang's three
witnesses are `[8,8,4]`, while the current private provider prints `[4,8,4]`.
Patch 006 has no measured result yet.

## Exact proposal and base

`patches/0006-vla-typed-provenance.patch` SHA256:
`eb782d053c1ea3f4a25b80ac5a3dfee25e89954f3c3226b26d9f4bfa1aa9c7f4`.
It changes one file, `cabs2cil.ml`, in 13 hunks: 175 additions, 14 removals.
Its exact base is worktree-2's source after the three private patches, SHA256:
`9c5fea44e1324b81b41d3f87dac27dd314f8d650c70bea77924a76f0269228fa`.
Strict in-memory hunk replay gives hypothetical source SHA256:
`bf74afa3d5a568cbe5a3413c1d9904362e8549d587a5c7fc496ded2afa1e265d`.
Changing one required context byte is rejected by the pure replay check.
The actual worktree file remains unchanged. Patch 006 must be explicitly
rebased/composed with 005 for a successor build; it must not replace 005.

## Data flow and intended accepted scope

Under the opt-in policy only:

1. `makeVarInfoCabs` passes an optional array-bound typing callback into
   `doType`. The original declarator is typed once, including ordinary type
   attributes and qualifiers. No reconstructed raw declarator is typed again.
2. A nonconstant bound, including a pure variable read, is saved in a temporary
   of its already-typed integral kind. Its side-effect chunk is retained once.
   The resulting typed array uses that saved expression; subsequent allocation
   and `typeof` use it without re-evaluating the original source bound.
3. `solveAlignas` runs on that original array type. A qualified, attributed or
   C11-aligned declaration therefore cannot use pointer alignment as its natural
   underalignment threshold.
4. For an outer variable dimension with fixed-size elements, the original typed
   varinfo is retained in a private origin table before pointer lowering. The
   elements may themselves be fixed arrays. The final alpha-converted lowered
   variable's id is the lookup key; the table is cleared at the existing
   per-function VLA-table reset.
5. Source GNU/C11 requests remain unchanged on the origin. They are not copied
   into invented requests on the synthetic pointer. Zero, cache-ignored and
   valid requests no stronger than the natural element requirement are allowed.
   A stricter requirement reports missing aligned-allocation support: the
   existing `__fc_vla_alloc` interface takes size only.
6. Direct source-variable GNU alignment uses the original declaration/type and
   folds the complete query before any origin-only varinfo could escape into
   the emitted AST. Direct `typeof` returns the original typed array, including
   its frozen bound and genuine type qualifiers/attributes. Direct `sizeof`
   retains the existing saved allocation-size expression.

The origin is a typing-time record, not a second emitted object or a new
serialized AST schema. Original source and preprocessing evidence must remain
retained by the eventual recorder. This proposal does not add an allocator
alignment contract or establish allocation-address fidelity.

## Source shape matters after normalization

Recovery requires an original Cabs `VARIABLE`, allowing ordinary parentheses,
and its matching normalized direct variable operand. A normalized CIL `Lval`
alone is insufficient: a comma expression may decay an array yet normalize to
that same pointer variable. The original `COMMA` handler at base lines
7213–7244 explicitly performs this decay for two or more operands.

Accordingly, genuine comma expressions preserve their normalized result type:
`typeof((0,a))` remains pointer-typed, `sizeof((0,a))` uses pointer size, and GNU
`__alignof__((0,a))` uses the decayed result type without inheriting declaration
alignment. This rule also avoids inheriting a normal variable's declaration
alignment after a comma operator. Other unmodeled VLA-containing compound query
forms fail explicitly, rather than being treated as direct array queries.

There is no new blanket `TYPE_SIZEOF` rejection. Fixed-size pointer-to-VLA types
and nested unevaluated `sizeof(sizeof(int[n]))` must remain legitimate controls;
the original typed `SizeOf` node is preserved for that path. This is not a claim
that all dynamic type-size queries or effectful type-only bounds are modeled.

The typed-original path also retains a source-derived ghost-qualification tie:
`Cil.makeVarinfo:142–168` calls `Ast_types.add_ghost` on the array;
`Ast_types.add_attributes:30–52` pushes array element qualifiers;
`Ast_attributes.qualifier_attributes:186` includes `ghost`.
`Cil.update_var_type:133–138` qualifies the lowered pointer as well. A dedicated
ghost control remains necessary; no ghost runtime/calibration pass is claimed.

## Required new controls and remaining limitations

Before any semantic acceptance, use a separately reviewed fresh build/runtime
and bounded diagnostic inventory, preserving all existing 55 and 14 cases:

- Double/int plus another model-derived scalar type; qualifiers and fixed inner
  arrays; direct `typeof(a)` used to declare a new VLA after the bound variable
  changes. Verify the copied type uses the frozen bound, not the new value.
- One effectful bound and one volatile bound: retained AST/IR must show exactly
  one original evaluation, with no width-changing bound cast before range
  validation. `sizeof(a)` must keep its saved-size dependency.
- C11 zero, ignored-high, natural, and under-natural requests; GNU ignored,
  natural, reduced and stricter requests; mixed GNU/C11 requests. An allocation
  limitation is unsupported valid input, not a successful language rejection.
- Parenthesized direct variables versus comma expressions for all three
  queries, including an effectful comma left operand which stays unevaluated.
  Include a non-VLA aligned variable after comma to check the general decay
  branch independently.
- `sizeof(int (*)[n])`, `sizeof(sizeof(int[n]))`, and an outer unevaluated query
  involving a VLA; retain rejection of genuinely evaluated local or VLA-size
  dependencies in a static initializer.
- Nested variable dimensions, pointer-to-VLA locals, whole-array address forms,
  and unsupported compound queries must remain explicit unsupported outcomes.
  Add a ghost declaration control and legacy/default-policy regressions.

Multiple variable dimensions, general variably modified typedefs, whole-array
address/pointer transformations, compound element-query support, stronger
allocation alignment and full dynamic type-size evaluation remain unimplemented
or unvalidated. Source assertions and strict hunk replay do not replace an
OCaml typecheck, actual compiler/analyzer observations, or the full negative
controls. Root's separate 005 build and observations do not validate 006.
