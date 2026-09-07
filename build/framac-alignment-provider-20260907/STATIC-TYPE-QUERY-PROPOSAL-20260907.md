# Private static type-query proposal 0009

Source-only proposal, not applied, compiled, parsed, or accepted. No installed
provider, policy, fixture, executed recorder, or worktree is changed. The patch
contains one hunk in `src/kernel_internals/typing/cabs2cil.ml`, adding ten lines
and removing two. It is specifically against worktree-5, after patch 0008.

## Exact source identity

All paths below are relative to
`worktree-5/source/frama-c-33.0-Arsenic/`.

| Source | SHA-256 |
| --- | --- |
| `src/kernel_internals/typing/cabs2cil.ml` | `ba559e4104697b990fb2c4bbd117424c59b2a88d9a5d87489a60eb185016eab0` |
| `src/kernel_services/ast_queries/cil.ml` | `8a134b1880db2df2b4738b9377c94d82f9ef56ae33cfd2e4ef359649a4a67dd5` |
| `src/kernel_services/ast_queries/cil.mli` | `46acca147406395ea73c8c16d924cc2f8ba9e12bbd0e7c781528850939e788ab` |

The hypothetical patched `cabs2cil.ml` SHA-256 is
`397f3f890359be9e2724c0cc4801a570d641c07cb49992f4d1a09f353f2c5d89`.
Strict in-memory hunk validation is a source-application check, not an OCaml
type check or semantic validation.

## Evidence and bounded correction

The preserved candidate-4 `followup-run-1` receipt
`14aaeb2d172ab7ea98661984ea512f53affeedf0eed73b91ac9820f3f692f2ff`
records valid type-query failures, including direct/parenthesized VLA controls
104/105 and 109/110, and pointer-to-VLA `sizeof` controls 209/210. The analyzer
reports forbidden references to `tmp` or `n` in static initializers; the
corresponding compiler emits constant witnesses. This note does not claim a
candidate-5 runtime result or that this patch repairs every VLA failure.

- `cabs2cil.ml:200-227` currently treats only `SizeOfE` and `AlignOfE` as
  candidate unevaluated queries. Its unchanged `vlval` method rejects any
  remaining non-global reference.
- `cil.ml:1605-1614` descends into the types of `SizeOf` and `AlignOf`.
  Consequently, an array bound can reach that local-reference check even
  when the queried type's alignment or pointer size is fixed.
- `cil.ml:3651-3660` computes pointer size without traversing the pointed-to
  array and unwraps named types. `cil.ml:3723-3750` requires an array bound to
  fold to an integer and otherwise raises `SizeOfError`. The exported layout
  contract is `cil.mli:1866-1874`.
- `cil.ml:3872-3891` folds complete size/alignment queries using the active
  machine and preserves the expression when layout cannot be computed.
  The patch still changes the initializer only for `Const (CInt64 _)`;
  all residual queries use `DoChildren` and retain the existing local guard.
- `cil.ml:6389-6404` answers its narrower variably-modified-type question;
  it is not a successful-layout computation. The new type-size branch uses
  `bitsSizeOf`, not a recursive pointer-target ban or an invented target size.

Patch 0009 adds `AlignOf (type, _)` to complete-query folding and considers
`SizeOf type` only when `bitsSizeOf` succeeds. It catches only `SizeOfError`.
The existing policy predicate moves before screening, so the additional
layout lookup is not performed for legacy machines. Existing expression-form
screening and all evaluated-local, address, and residual-initializer guards
are otherwise unchanged.

## Effects, remaining scope, and required controls

This visitor operates on an already typed expression. It neither creates nor
re-executes a bound. In `cabs2cil.ml:5076-5079`, type-only bounds still use
`doPureExp`; `cabs2cil.ml:8158-8165` records an error for a side-effect chunk.
The proposed fold does not clear that earlier error. Fresh type expressions
with effectful bounds may therefore remain false rejections; they must not
be counted as language-invalid controls. General bound-effect semantics and
allocation support are not repaired here.

Before any acceptance, run compiler-reference/core-only checks with retained
folded and plain printed C, `-check`, exact diagnostics, and successful-output
reparses. Required controls include:

1. The unchanged 55 + 14 + 44 cases, including direct/parenthesized original
   VLA alignment, frozen-bound `typeof`, effectful and volatile declaration
   bounds, all four VLA-family invalid controls, and legacy-policy companions.
2. Type-form C11/GNU alignment of `double[n]` and `__typeof__(array)`, plus
   pointer-to-VLA `sizeof` through direct, qualified, named, and fixed-array
   of pointer forms. Compare observed values, not hard-coded expected layout.
3. Static `sizeof(double[n])`, `sizeof(__typeof__(array))`, and direct VLA
   `sizeof` must remain nonconstant/rejected. Test evaluated automatic-local
   values and addresses beside the accepted constant queries.
4. Fresh effectful/volatile type bounds under C11/GNU type alignment,
   pointer-to-VLA `sizeof`, and nested outer `sizeof`. Retain reference
   warnings and actual effects. Do not assume optional bound evaluations are
   forbidden, erase diagnostics, or infer effects from witness constants.
5. Incomplete or otherwise invalid queried types must retain their prior
   diagnostics. Unfoldable layout must not suppress a residual local access.

The separate stronger-alignment allocation and multiple-variable-dimension
limitations remain. Success for these finite controls would still not imply
full architecture support, provider promotion, or proof acceptance.
