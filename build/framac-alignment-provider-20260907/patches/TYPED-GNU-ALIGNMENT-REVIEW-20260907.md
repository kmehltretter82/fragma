# Typed GNU alignment request proposal, 2026-09-07

Status: **unapplied, uncompiled source proposal** against the frozen
`worktree-2/source/frama-c-33.0-Arsenic`, not against root's later worktrees.
The [0007 patch](0007-clang-typed-gnu-alignment.patch) has SHA256
`b6323eff7cf792aa2bd0956349d49d0ad9cf48e7c14288473046bd384f352bd6`.
No compiler, analyzer, target/native program, build or original recorder main
was executed for this proposal. Frozen source/provider/evidence is unchanged.
Root must rebase independent 0005/0006 work explicitly before a combined build.

## Evidence and implementation boundary

The retained [extra-context sources](../extra-context-run-1/sources/) contain
four unchanged arithmetic controls. Compiler [023](../extra-context-run-1/command-023/stdout)
accepts `8 + 8` with witness values 4, 16, 4; analyzer
[024](../extra-context-run-1/command-024/stdout) rejects it as unsupported.
Compiler [025](../extra-context-run-1/command-025/stderr),
[027](../extra-context-run-1/command-027/stderr) and
[029](../extra-context-run-1/command-029/stderr) reject unsigned-wrap-to-zero,
negative and nonpower requests. The corresponding analyzer
[026](../extra-context-run-1/command-026/stdout),
[028](../extra-context-run-1/command-028/stdout) and
[030](../extra-context-run-1/command-030/stdout) instead report unsupported
untyped attribute expressions. These old observations are not rewritten.

The information loss is in `cabs2cil.ml`'s `doAttr` (worktree-2 lines
4602–4683): the original Cabs integer literal suffix/kind becomes `AInt`, while
arithmetic becomes `ABinOp` without its C operand/result kinds. Interpreting
that later using mathematical integers would incorrectly turn target unsigned
zero from `0xffffffffU + 1` into an accepted 2^32-byte request.

0007 changes this boundary, not the machine's alignment ceiling or cache rule:

- Canonical GNU `aligned` attributes are intercepted both in GNU wrapper call
  form and direct attribute form, only under `clang-21-u32-bits`.
- Plain integer literals keep the existing `Cil.parseIntExpRes` → `AInt` path,
  preserving the unchanged 55-case fixture's literal print/diagnostic shapes.
- Nonliteral requests pass through the existing Cabs `doExp` with `CConst` and
  no imposed destination type. Its usual integer promotions/conversions remain
  available before `Cil.constFold`/`Cil.constFoldToInt ~machdep:true` are used.
  No new host-integer or `Z.add`/`Z.mul` arithmetic evaluator is introduced.
- Require no evaluated read list, no effect chunk, an integral expression type,
  and an actual folded integer result. A mathematical simplification must not
  hide an evaluated local read. Failed folds and dynamic VLA sizes abort.
- Validate the folded **original byte request** for positive power-of-two shape
  and the unchanged 2^32 maximum. New nonliteral rejection messages include the
  original Cabs expression and its target-C result. Existing
  `effectiveAlignment` then performs the established validation/mapping as well.
- A temporary physical-Cabs-expression recursion stack is restored with
  `Fun.protect`, including exceptional exits. It detects re-entry of the same
  source request without prohibiting every distinct nested attribute. This is
  not a proof that every possible recursive type/layout query is handled.

Relevant existing paths also reviewed: `getIntConstExp`/`doExp` at 5459 onward,
`doBinOp` at 7689, `doPureExp` at 7889, sizeof/alignof conversion at 5848–5906,
`Cil.mkBinOp` at 5965, and typed folding/`kinteger64` at 2492 and 3815–4075.
The existing typed folder performs integer-kind truncation; untyped attrparam
arithmetic is still rejected by the consumer rather than independently guessed.

## Checked provenance and printing

For a successfully typed nonliteral request the private representation is:

```text
ACons ("__fc_clang_typed_alignment_request",
       [AInt original_byte_value; ASizeOf simple_integral_result_type;
        AStr original_Cabs_text])
```

`ASizeOf` is a type carrier only inside this exact private node; it is not
evaluated as a size query. The consumer requires the explicit policy, exact
three-field shape, an unqualified simple integer result type, nonempty original
text and a value representable in that target integer kind. It revalidates the
request through `effectiveAlignment`. Malformed/inactive markers abort.

The source attribute converter rejects the reserved marker spelling, including
underscore aliases. A source expression supplied to an actual `aligned` call
must still be typed and pass the read/effect/constant gates; it is not converted
directly into user-chosen provenance fields. A function call hidden inside a
legitimate unevaluated query is a typed query, not permission to trust that
function's argument list as metadata. This is source-conversion protection and
structural validation, **not cryptographic authentication of arbitrary ASTs
constructed by trusted plugins or other OCaml code**.

The printer calls the same checked reader and emits the original byte numeral,
never the effective cache contribution. Thus a valid arithmetic request of
2^29 must print 536870912, not 0. Original expression text remains in the AST
metadata and retained input source; it is not inserted into output C, where it
could refer to an out-of-scope local after hoisting. Print/reparse is intended
to preserve the request's numeric semantics, not its original spelling or
metadata identity. It must be tested before integration.

No public AST constructor is added. Existing `ACons`/`ASizeOf` visitor, copying
and comparison behavior is reused. The simple integral carrier has no local
variable references. The consumer interface documentation is updated. The new
printer source is a fourth patch target and an additional combined-build source
whitelist entry; it must not be omitted from the authenticated build closure.

## Non-executing patch validation

A strict in-memory reader validated all nine unified-diff hunks, old/new counts,
exact old context and the four-file whitelist. Each original source hash also
matched the frozen run-2 private source inventory. Files were re-read unchanged
after reconstruction. This is not an OCaml syntax check or execution test.

| Source | Original SHA256 | Proposed SHA256, in memory |
| --- | --- | --- |
| `src/kernel_internals/typing/cabs2cil.ml` | `9c5fea44e1324b81b41d3f87dac27dd314f8d650c70bea77924a76f0269228fa` | `6434c9732af630c77cc400318e99bab0a4e652b1e6855b4804ac5adf54fd990c` |
| `src/kernel_services/ast_queries/cil.ml` | `075c8a370bc3b54142afc5fdf50d755953379d5095cb6cc168f7cc1f9eee13c7` | `8a134b1880db2df2b4738b9377c94d82f9ef56ae33cfd2e4ef359649a4a67dd5` |
| `src/kernel_services/ast_queries/cil.mli` | `1b623d7d9f4611715436d854218a6a5bcfd7cf8fbf61610c1b28c0a60aa2b9f6` | `46acca147406395ea73c8c16d924cc2f8ba9e12bbd0e7c781528850939e788ab` |
| `src/kernel_services/ast_printing/cil_printer.ml` | `4ef661a6fc78fb938c5559888774d50f92408ec466f08b98b56914c14f80873c` | `b77c48a484e52df0629b245ab187ffe33c48171b68cb396cd09deb9d594cfe6e` |

## Mandatory acceptance gates and unresolved limits

1. Build the exact rebased candidate and retain independent identity/runtime
   receipts. Repeat all 55 original pairs and all 14 extra pairs unchanged.
   The four arithmetic inputs must be compared to their actual pinned compiler
   results, not re-labelled to match a new analyzer outcome.
2. Add positive casts, enum constants, promotions, bitwise/conditional forms and
   target-size/align queries. Include an arithmetic ignored-high request plus an
   honored low request in both orders; ensure the printed request is original
   bytes and the combined contribution is correct.
3. Keep negative unsigned wrap to zero, negative/nonpower arithmetic, above-max,
   non-integral/nonconstant values, evaluated local/address/call/increment cases,
   and malformed source attempts to forge the private marker. Add direct AST
   malformed-marker/type-width cases through an explicitly reviewed unit test.
4. Exercise fixed local `sizeof`/`__alignof__`, unevaluated increments, dynamic
   VLA sizeof, side-effecting VLA bounds, incomplete/self-referential types,
   distinct nested attribute queries and true recursive conversion. Do not
   discard warnings/errors or waive local/static initializer checks. VLA
   alignment correctness depends on the separate 0006 provenance work; 0007
   does not repair pointer-lowering losses itself.
5. Check AST scope and full print/reparse with and without optional `-constfold`.
   Hoisted attributes must contain no residual automatic-variable references,
   repeated typing/classification must not leave extra evaluated operations,
   and original source/provenance must remain retained. Verify multi-file/error
   recovery restores the temporary recursion stack.
6. Test signed overflow, signed minimum divided by -1, division by zero, invalid
   shift counts, signed left shifts, conditional/short-circuit unevaluated
   branches, and float-to-integer constant casts against the exact compiler
   flags. **This proposal reuses Frama-C's typed folder; it does not add a full
   Clang integer-constant-expression validity checker.** The existing folder
   can truncate integer kinds and simplify expressions. Matching the four
   arithmetic controls alone cannot establish all undefined/extension-sensitive
   C constant-expression rules or prove that prior typing has retained every
   validity-relevant operation. Any mismatch remains an implementation blocker.
7. Recheck policy-off behavior and existing profiles, then max-align
   representation, genuine-kernel model validation and full provider integration.
   This patch neither promotes Hexagon nor closes the complete alignment goal.

No new semantic result or test pass is claimed in this note. The patch is an
actual proposed implementation of typed request handling, with the remaining
compiler-equivalence and provenance gates left explicitly open.
