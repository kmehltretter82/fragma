# Proposed local-static unevaluated-query correction

Status: source-reviewed proposal only. The [patch](0001-local-static-unevaluated-queries.patch)
has not been applied, compiled or tested. The authenticated unmodified baseline,
installed toolchain, project providers, old fixtures and all evidence remain
unchanged. This is one typing substep, not completed alignment resolution or
Hexagon support.

## Source identity and narrowly selected change

The only proposed upstream file is
`src/kernel_internals/typing/cabs2cil.ml` in
`baseline-1/source/frama-c-33.0-Arsenic`. Its baseline SHA256 is
`624907038cda23f5a12555760173271b198c9219cf1828611a362506bdd20e79`, matching the
[completed build receipt](../baseline-1/receipt.json). Applying the exact three
hunks in memory yields SHA256
`64124e5c089a5fb0326fbd0021008d3ca6e13d9b8027847b227e39776c8c383c`.
No second copy of the source has been written by this proposal.

`check_no_locals` currently descends through every `SizeOfE` and `AlignOfE`
operand and rejects an ordinary local lvalue, even when that operand is not
evaluated. C11 distinguishes runtime VLA sizes from fixed-size `sizeof`, and
requires constant initialization of static objects; see
[N1570, 6.5.3.4 paragraphs 2–3 and 6.7.9 paragraph 4](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf).
This is not permission to waive evaluated-local or VLA-size checks.

Merely skipping those operands would leave out-of-scope local names in a
hoisted global initializer. The printer preserves `SizeOfE`/`AlignOfE` operands,
and AST checking still checks their variable bindings. The patch instead keeps
the result of visiting each initializer, including nested compounds, and
resolves only a successfully integer-folded query before hoisting. Compound
offsets, order, type and implicit-initializer policy remain unchanged. All
ordinary lvalue checks and the nonempty initializer-effect-chunk gate remain.

The `SizeOfE` path requires both a non-VLA operand-type guard and an actual
integer result from the existing constant folder. The guard alone is not enough:
the baseline's `isConstant` treats nested size queries as constant, so an
unfoldable query falls back to normal traversal. `SizeOf` and `AlignOf` type-form
handling are deliberately not broadened by this patch.

## Mandatory expression-alignment dependency

Do not validate this patch alone as a semantic alignment fix. Baseline
`Cil.constFold` handles `AlignOfE` by reducing it to the operand type; that is the
already observed declaration/expression-alignment mismatch. GNU expression
alignment can depend on declaration attributes, as documented in the
[GCC alignment reference](https://gcc.gnu.org/onlinedocs/gcc/Alignment.html).

The new visitor passes the **complete original query** to `Cil.constFold`; it
does not itself replace `AlignOfE` by a type-only query, remove attributes or
alter the operand's varinfo. A companion, independently reviewed expression-aware
constant-folder correction must consume that original information before
returning the replacement integer. Using the current type-only folder would
remove the local-reference diagnostics while baking known-wrong alignment
values; that must not be accepted as successful calibration. No model ceiling,
alignment field, fixture witness or saved YAML is changed here.

Relevant baseline paths/locations reviewed:

- `cabs2cil.ml`: local check/initializer traversal (200–230), `checkGlobal`
  (767–807), dropped operand chunks (1753 onward), local VLA lowering
  (5005–5034, 8840–8919), type-name arrays (4749 onward, 5036–5048), sizeof/alignof
  translation (5735–5790), pure bound expressions (7777–7784), static hoisting
  and initializer-effect gate (8740–8810).
- `src/kernel_services/ast_queries/cil.ml`: expression traversal (1590–1640),
  constant folding (3731–3748), compound folding (6148–6209), and VLA detection
  (6237–6252).
- `src/kernel_services/ast_queries/filecheck.ml`: variable sharing/scope checks
  (167–179) and expression traversal (1241–1260);
  `src/kernel_services/ast_printing/cil_printer.ml`: query printing (803–809).

## Required future regressions, not executed here

Use a new authenticated source/build directory and keep the baseline immutable.
The existing [local fixture](../../hexagon-alignment-context-20260906/fixtures/locals.c)
has SHA256 `9f33e0ac090c717f3cf4d20ebb9e177282be793dec5a6e8deb87867a3f4d0ba4`.
Its four unchanged cases at 16, 2^28, 2^29 and 2^32 must parse without the false
local-access errors and retain all six witness fields. Compare to the original
compiler observations in commands 053, 055, 057 and 059 of
[context run-1](../../hexagon-alignment-context-20260906/run-1/receipt.json).
Require declaration-aware agreement, not merely exit zero. The separate 2^33
case must retain its applicable alignment-limit rejection.

Additional isolated compile/parse-only controls are required:

- Positive fixed-size queries: a local scalar, fixed array and member;
  nested scalar/compound initializers; `sizeof(n++)`; and an outer
  `sizeof(sizeof(int[n]))`, whose operand has fixed integer type. Confirm no
  evaluated increment/load appears in the resulting initializer or statements.
- Negative evaluated references: `static int x = n`, `static int *p = &n`,
  and `static unsigned long x = sizeof(n) + n`. Keep named nonconstant/local
  rejections; a safe query must not hide an evaluated sibling.
- Negative VLA sizes: `sizeof(a)` for local `int a[n]`, `sizeof(int[n])`, and
  residual `sizeof(*(int (*)[n])0)`. The ordinary local-VLA case is rewritten to
  `sizeof(element) * __lengthof_a`; its saved length must still be rejected in a
  static initializer. Type-name and residual bounds must also remain visible.
- Side-effecting VLA-bound controls must preserve the existing unsupported/effect
  diagnostics. Ordinary automatic VLA declarations must still evaluate and save
  their bound once; this patch must not alter their effect/allocation chunks.
- Run AST checking and print/reparse both with and without optional `-constfold`.
  Hoisted static initializers must contain no out-of-scope automatic variables.
  Recheck full context controls, max-align layout controls and genuine-kernel
  model validation after the companion alignment changes, before integration.

No target program, compiler, analyzer, native harness, solver, test suite or build
was executed for this proposal. In-memory hunk matching and source hashing are
not evidence that the OCaml change compiles or that the regression expectations
pass. No Hexagon architecture/model acceptance gate is opened.
