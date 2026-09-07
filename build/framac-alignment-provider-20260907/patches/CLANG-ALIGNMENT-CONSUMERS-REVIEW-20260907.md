# Private alignment-consumer proposal, 2026-09-07

This is an **unapplied, uncompiled source proposal**, not a successful provider,
alignment calibration, L1/L2 award or kernel-bug finding. The new
[patch](0003-clang-alignment-consumers.patch) touches only proposed `cil.ml` and
`cil.mli`. The authenticated unmodified baseline, installed toolchain, fixtures,
receipts, machine-description candidate, registry and project code were not
edited. No compiler, analyzer, proof, native target or build was executed here.

## Dependencies and scope

The proposal requires the separate
[machine-policy patch](0002-alignment-attribute-policy.patch) and root-owned
typing corrections. The policy API defaults to legacy behavior; old consumers
remain on their original branches when it is false. The new checked APIs are:

```ocaml
val effectiveAlignment: c11:bool -> Z.t -> int option
val integerOfAlignmentAttrparam: attrparam -> Z.t option
```

`effectiveAlignment` validates the original byte request before any conversion:
negative/non-power-of-two/GNU-zero requests and values above 2^32 abort. C11 zero
contributes nothing. Under the opt-in, it computes
`((requested * 8) mod 2^32) / 8`; a zero result means no contributed constraint,
not zero object/type alignment. Without the opt-in, this new helper leaves a
valid nonzero request unchanged. Existing legacy callers do not start using it.

Each GNU attribute is validated and mapped before contributions are combined.
The patch does not replace, remove, reorder or manufacture AST attributes.
Typedef layers are queried separately; record/enum declaration attributes are
applied to their natural alignment without permitting reduction, while an outer
typedef attribute can reduce its inherited type alignment. Packed members use
one byte as their unconstrained alignment and still honor effective C11/GNU
member requests. An ignored high GNU request no longer disables packing.

Variable declaration queries combine stored C11 alignment and GNU variable
attributes, falling back to the type only when both contribute nothing. A GNU
declaration request may reduce expression alignment: the retained control has
`aligned(1)` expression alignment 1 and type alignment 4. The public variable
alignment query receives the same declaration contribution handling; it is not
a preferred allocation/global-array alignment query.

The C expression folder keeps the original operand for normalized CIL direct
variable, one member-offset and plain-dereference queries. Member declaration/packing data and
pointed-to typedef attributes therefore survive to the relevant query. Other
forms, and the uncalibrated standard `_Alignof(expression)` extension, stay
unfolded through `SizeOfError`; they do not silently become a type-only answer.
The dereference/member-base wildcards can contain arbitrary pointer expressions:
this is a normalized CIL-shape boundary, not a source-syntax rejection filter.
ACSL `TAlignOfE` explicitly aborts under the opt-in because a calibrated
term-aware implementation is not supplied. Legacy term folding is unchanged.

The [local-static proposal](0001-local-static-unevaluated-queries.patch) depends
on this expression folder: its existing whole-operand constant folding can then
remove local names from genuinely unevaluated queries before static hoisting.
Do not replace the local fixture or hide local references to make it pass.
Actually evaluated local/VLA operands must still be rejected as described in
[its review](LOCAL-STATIC-UNEVALUATED-REVIEW-20260907.md).

## Evidence driving the proposal

The preserved [55-pair context receipt](../../hexagon-alignment-context-20260906/run-1/receipt.json)
is still the failing original analyzer run, SHA256
`4bedf09d1c43627ca717408227e4e0513f53707dd192180349fc05e0bd7541cc`.
An independent read-only pass checked all 19 fixture-source hashes, 55 Clang
stdout hashes and the 314 constants in 33 successful LLVM witnesses against
that receipt without discrepancies. This was retained-evidence inspection,
not a new execution or a saved audit sidecar.

Relevant compiler observations include member expression alignment 16 versus
member type alignment 4; normal versus packed ignored-high-request alignment
4 versus 1; both orders of low/high directives preserving 16; and GNU variable
underalignment 1 while its type remains 4. All 55 original cases, including
rejections and the four local cases, remain mandatory unchanged validation
inputs. The [retained tagged LLVM source](../../clang-21-alignment-source-20260907/README.md)
documents the upstream unsigned-cache mechanism and its installed-binary
equivalence limitation. The current published
[Clang declaration-query implementation](https://clang.llvm.org/doxygen/ASTContext_8cpp_source.html#l01862)
also distinguishes declaration attributes, packing and type alignment; it is
development documentation, not proof of the installed 21.1.8 binary's behavior.

## Deliberate gaps and required controls

This is a coherent bounded consumer correction, **not ready for broad profile
integration**. In particular:

- Attribute parameters have lost their C integer kinds. The new numeric reader
  accepts literal `AInt` values and typed `sizeof`/`alignof(type)` queries only.
  It rejects arithmetic/unary/conditional and expression-query forms instead of
  interpreting them using host integers or mathematical integers. For example,
  accepting mathematical 2^32 for `0xffffffffU + 1` would wrongly turn target-C
  unsigned zero into an ignored valid GNU request. The unchanged context matrix
  supplies literal decimal requests. Typed attribute arithmetic remains future
  work; add both a valid arithmetic control and unsigned-overflow/invalid-shape
  controls, with explicit unsupported outcomes until it is implemented.
- Unsupported or recursive GNU query forms abort instead of dropping the
  attribute. Typed query results use the existing target-C constant folder,
  including its `sizeof` integer kind, not an untyped host-size substitute.
- Bitfield alignment raises under the opt-in. Zero-width/packed bitfields,
  nested/indexed expressions, arrays/VLAs, competing declaration/type requests,
  packed typedef combinations, vector/atomic/incomplete types, parameter decay,
  and pragma-pack interactions are not newly calibrated by this patch.
- CIL simplifications can erase distinctions in the original C operand, such
  as address/dereference cancellation. The bounded helper must be tested with
  such controls before claiming source-expression equivalence beyond the
  retained simple forms; it does not reconstruct lost syntax/provenance.
- The root-owned typing patch must validate every original C11/GNU directive,
  compare effective C11 redeclarations, select by effective contribution without
  losing the chosen original expression, preserve GNU duplicates, reject
  invalid placements and reject invalid array-element alignment/size. Consumer
  folding cannot repair attributes discarded earlier in typing.
- Confirm policy-off behavior with unchanged existing profiles; then build the
  private provider and run the entire unchanged context matrix, local/evaluated
  controls, `max_align_t` controls and genuine model checks. None has run for
  this proposal. No support gate or overall alignment-resolution task is closed.

The existing project-state dependency chain is machdep parameter → Machine →
Ast → type-size cache, so a separate cache-state variable is not introduced.
Same-path external YAML mutation is not automatically detected by that chain;
fresh invocation input hashing remains necessary.

## Non-executing validation

A strict in-memory unified-diff reader checked all 12 hunks, exact old context,
old/new hunk line counts and both target paths. It materialized the proposed
bytes only in memory. Both original files also matched their members in the
SHA-pinned upstream archive. A separate small arithmetic-model check covered
ten accepted requests, five invalid GNU requests, C11 zero and two combination
orders; these are formula checks, **not execution of the OCaml implementation**.

| Input/result | SHA256 |
| --- | --- |
| New patch | `3dcd00320b8a07ac01879376bec8b4ee02ded8cd4b0646103fa926d30b2c8f49` |
| Original `cil.ml` | `2b09f3dd4ac67c90815bac1b7c8df160b88a636b9e44ed76fc5a8e21288750da` |
| Proposed `cil.ml`, in memory | `075c8a370bc3b54142afc5fdf50d755953379d5095cb6cc168f7cc1f9eee13c7` |
| Original `cil.mli` | `41b1e61ed2a69443e6a75faa166f832a7a31c77b16ba0d45d3e6d45fa673677b` |
| Proposed `cil.mli`, in memory | `1b623d7d9f4611715436d854218a6a5bcfd7cf8fbf61610c1b28c0a60aa2b9f6` |
