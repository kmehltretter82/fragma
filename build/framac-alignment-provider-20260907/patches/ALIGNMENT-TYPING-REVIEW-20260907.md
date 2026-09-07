# Private alignment typing candidate, 2026-09-07

Source review of [0004](0004-clang-alignment-typing.patch), SHA256
`970278b7dfd73a2206649583b2743b93f6bde6a349364c16c145b7370b0edc37`.
This patch is applied only to the editable private worktree. At this review
boundary it has not been compiled or run. The authenticated baseline and
installed verifier are unchanged. This is not alignment resolution or Hexagon
support; later execution must have separate receipts.

## Changes and source checks

- Gate new behavior on the explicit machine policy from [0002](0002-alignment-attribute-policy.patch).
  Existing profiles default to legacy behavior. The [0003 consumer patch](0003-clang-alignment-consumers.patch)
  supplies original-request validation and effective-contribution queries.
- Validate every original C11 request before selecting the largest effective
  contribution. Keep its original expression, including an ignored request.
  The existing single-expression AST representation still combines multiple
  C11 specifiers; the full original list remains in retained source/preprocessed
  inputs, not a new AST field.
- Validate GNU attributes during typing, including declarations and typedefs.
  An accepted request contributing no constraint returns `Some 0`, distinct
  from an invalid/unsupported request. The original attribute is not removed.
  Attribute arithmetic without retained C integer types remains unsupported.
- Check C11 underalignment against the fully declared type and the combined
  C11/GNU effective requests. Tagged Clang SemaDeclAttr source checks this
  combined constraint when a C11 directive exists, even a zero directive.
  Field checks now use the complete field declarator rather than its base type.
- Reject an array whose complete non-VLA element size is not divisible by its
  alignment. This does not claim complete VLA or bitfield semantics.
- Compare effective C11 redeclaration constraints rather than raw large values.
  The existing merge logic still has a known missing-required-alignment-on-
  definition gap; this patch does not establish full redeclaration fidelity.
- Before hoisting a static local initializer, replace a complete unevaluated
  `sizeof`/`alignof` query only if the policy-aware folder returns an integer.
  Non-VLA sizeof is eligible; residual queries, evaluated values/addresses and
  VLA size expressions still undergo the local-reference check. Compound
  initializers retain their offsets and order with `implicit:false` traversal.
- Reject active pragma pack/align at both field and composite transformation
  entries before old attribute replacement/drop logic can run. Ordinary packed
  attributes remain available; reset/inactive pragma state is not rejected.
  Full pragma behavior remains an implementation requirement, not an accepted
  compatibility fallback.

An independent read-only review confirmed both pragma guards and the static-
initializer traversal conditions. It did not execute the OCaml implementation.
The old [0001 proposal](0001-local-static-unevaluated-queries.patch) remains
unapplied and is not an additional patch in the candidate build: 0004 contains
its gated successor together with the typing changes.

A root read-only precheck subsequently reconstructed all 11,511 source entries
from the pinned original archive plus the three patch files: exactly nine files
and 39 hunks changed. It used SHA-checked recorder definitions without invoking
their main/build function, returned zero, and produced no saved audit sidecar.
This verifies source equivalence, not OCaml compilation or runtime behavior.

The new [private machine YAML](../candidate-policy.yaml), SHA256
`b02ad2c10ae51b4bb7dee7169fedb33e3f38a2f69f5b6eddf1527595a6cea44e`,
is exactly the [unchanged generator candidate](../../hexagon-max-align-20260906/generator-2/candidate.yaml)
(SHA256 `f731bc881c56b1129ce557352ae1394eb3df118f56a1c78a5ace1a54da8d9103`)
plus one appended line: `alignment_attribute_policy: clang-21-u32-bits`.
The direct diff contains no other change. It has not been analyzed or registered;
its original representation, GNU fields and maximum request are not weakened.

## Still required

Build the exact original archive plus 0002/0003/0004 and validate the private
runtime. Run all 55 unchanged compiler/analyzer context pairs, retaining new
failures rather than rewriting the old receipt. Add evaluated local value,
address, VLA-size and nested-compound negative controls and printed-AST reparse;
exercise explicit policy validation/default-off behavior and pragma rejection.
Retain max_align_t representation controls and genuine-kernel model checks.

Typed attribute arithmetic, expression-provenance loss during CIL normalization,
full redeclaration and pragma semantics, ACSL expression alignment, bitfields
and other documented consumer gaps remain open before broad integration. A
successful build or a finite fixture matrix cannot alone close those gaps.
