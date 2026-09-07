# Next private alignment diagnostic: read-only findings

Subsequent execution: [PRIVATE-CONTEXT-20260907.md](PRIVATE-CONTEXT-20260907.md)
records fresh runs of all 55 unchanged pairs and 14 additional controls. The
double-VLA risk and missing-definition/typed-arithmetic gaps below now have
measured observations. The remaining controls are still required. This original
source-review note is retained as its pre-execution rationale, not a test result.

Prepared 2026-09-07 from source and retained evidence. This note is not a new
compiler/analyzer execution, a reclassification of historical results, a test
pass, or an architecture-support decision. No fixture, old receipt, patch,
candidate source or build output was modified by this review. Source-derived
risks below remain untested.

The reviewed inputs were the complete [55-case recorder](../hexagon-alignment-context-20260906/diagnose-v2.py),
all [19 unchanged fixtures](../hexagon-alignment-context-20260906/fixtures/),
selected retained diagnostics, and the policy/consumer/typing patches:

| Input | SHA256 |
| --- | --- |
| Existing `diagnose-v2.py` | `7ce09c8784d9d2c16dd29d98b024ad688d8653923200f43411c283be17ac6cf0` |
| Existing context `run-1/receipt.json` | `4bedf09d1c43627ca717408227e4e0513f53707dd192180349fc05e0bd7541cc` |
| [0002 policy patch](patches/0002-alignment-attribute-policy.patch) | `bc59c22b6fc18a9a4e0ab8406e7e0332e5a53091029de6e611314ad2079fec9b` |
| [0003 consumer patch](patches/0003-clang-alignment-consumers.patch) | `3dcd00320b8a07ac01879376bec8b4ee02ded8cd4b0646103fa926d30b2c8f49` |
| [0004 typing patch](patches/0004-clang-alignment-typing.patch) | `970278b7dfd73a2206649583b2743b93f6bde6a349364c16c145b7370b0edc37` |

## Preserve the complete original matrix

A new recorder must retain all 55 original pairs: the nine matrix fixtures at
16, 2^28, 2^29, 2^32 and 2^33, plus the ten fixed controls. Preserve fixture bytes,
field order, compiler flags, full original requests and the unsigned-long-long
witness transport. Do not replace the four valid local cases, lower an alignment
ceiling, change declarations, or convert expression queries into type queries.
Keep the original receipt and its seven unresolved observations unchanged.

The existing 112-query budget is exactly two version queries plus 55 pairs.
Additional controls, AST checks and reparses require a new explicitly enumerated
query inventory and corresponding finite budgets; they are not hidden retries
within the old inventory. Each added fixture needs its own expected witness
fields, function/global inventory and semantic intent. The old IR recognizer's
special cases for only `locals` and `c11-redeclaration-conflict` must not become
an unrestricted allowance for arbitrary extra definitions.

Pin the exact private build receipt, executable, private runtime configuration,
private machine YAML, source patches and actual preprocessing/header closure.
The new YAML must remain the original generator candidate plus the one policy
line; the original representation and maximum request are unchanged. Do not use
the installed analyzer path or installed Frama-C libraries by accident. The new
recorder needs its own reviewed import/execution and cleanup boundary; copying
the old command launcher without review is not sufficient.

## Precise compiler-classifier corrections for the new recorder

These recognize already retained wording; they do not rewrite old observations.

1. In `named_compiler_rejection`, the `gnu-typedef-array` expression omitted the
   typedef's printed underlying type. Retained [command-033 stderr](../hexagon-alignment-context-20260906/run-1/command-033/stderr)
   and [command-035 stderr](../hexagon-alignment-context-20260906/run-1/command-035/stderr)
   both contain the exact phrase `(aka 'int')`. For those cases at 16 and 2^28,
   the full-match expression should include it literally:

   ```python
   r"size of array element of type 'fragma_aligned_int' "
   r"\(aka 'int'\) \(4 bytes\) isn't a multiple of its alignment "
   r"\((?:16|268435456) bytes\)"
   ```

   Scope this category to this fixture and these two requests. Do not permit
   arbitrary `aka` types or arbitrary size/alignment numerals. Any changed
   spelling remains unresolved until examined against the actual new output.

2. Retained [command-091 stderr](../hexagon-alignment-context-20260906/run-1/command-091/stderr)
   contains two primary errors, not just the maximum-request error:
   `requested alignment must be 4294967296 bytes or smaller`, followed by
   `'_Alignas' must be specified on definition if it is specified on any declaration`.
   Add a distinct `missing-definition-alignas` class with a full-match of the
   latter wording, scoped to `c11-redeclaration-conflict` at 2^33 in the unchanged
   matrix. Preserve both errors and the source-qualified declaration note.
   The installed `DiagnosticSemaKinds.inc` separately names this diagnostic
   `err_alignas_missing_on_definition`; it is not the different-requirement
   category `err_alignas_mismatch`.

3. Do not collapse this two-category compiler failure into a singleton
   `above-maximum` failure for comparison with an analyzer that stops at its
   first error. Both tools rejecting is weaker than demonstrating that both
   detect every independent invalid condition. Preserve ordered primary
   messages/classes and report missing/additional categories explicitly. A
   separate valid-maximum missing-definition control is needed to avoid having
   the maximum-request error mask the known redeclaration gap.

All existing transport, exact return-code, empty compiler stdout, primary-error
count and unexpected-warning/error checks remain relevant. Known diagnostics
must be scoped to their fixed cases, not recognized globally merely because
their text contains `alignment`.

## Candidate analyzer-classifier changes

The new source changes some messages deliberately; expecting the installed
provider's exact old wording would make useful new observations unresolved.
The classifier must nevertheless recognize actual complete diagnostic blocks,
not treat arbitrary exit 1 as a successful negative control.

- `effectiveAlignment` now emits `requested alignment exceeds 2^32 bytes`.
  It can occur in all nine matrix fixtures at 2^33, including GNU-only cases.
  Its power-of-two messages are `GNU alignment must be a positive power of two`
  and `C11 alignment must be a positive power of two`; scope these to the
  relevant zero/nonpower controls. C11 zero remains a valid input.
- Array-element validation introduces the source template
  `size of array element '%a' (%d bytes) is not a multiple of its alignment (%d bytes)`.
  Scope a future exact matcher to the typedef-array fixture, size 4 and its two
  honored alignments. The precise `%a` type-printer spelling has not been
  observed from this candidate; do not invent a permissive matcher in advance.
- The underalignment, C11 placement and incompatible-redeclaration messages
  retain their existing source templates. Keep original expressions in the
  diagnostics and preserve any newly observed different error order.
- Explicit unsupported GNU arithmetic/query, pragma, ACSL or bitfield outcomes
  are unsupported semantics, not correct language rejections of otherwise
  valid C. Give them separate classes and retain the unresolved support gap.
  Do not label a valid arithmetic test an expected rejection merely because
  this prototype currently rejects it.

Local-initializer checks need a separate structured diagnostic grammar. The old
single-source-block matcher cannot handle genuine repeated `User Error` blocks
plus the terminal stopping wrapper, as shown in retained
[command-054 stdout](../hexagon-alignment-context-20260906/run-1/command-054/stdout).
Require every primary block to match a case-scoped local/nonconstant diagnostic;
recognize the exact `stopping on ... that has errors.` wrapper separately, and
still require the terminal invalid-user-input line. Preserve all messages and
unexpected extras. Potential source messages include `Forbidden access to local
variable ... in static initializer`, `... is not a compile-time constant`,
`Initializer element is not a compile-time constant`, and `global static
initializer`. Which ones actually occur remains an execution observation.

The existing comparison records unexpected acceptance only for controls marked
`reject`. New controls also need explicit required-acceptance accounting: both
tools rejecting a valid control must not appear to complete its semantic gate.

## Separate early policy gates

Policy-validation errors occur while decoding the machine, before preprocessing.
Do not route them through the old analyzer classifier, which unconditionally
requires retained `.i` files and a generated `__fc_machdep.h` before recognizing
any nonzero return. Use a separate early-configuration phase with its own
expected artifact inventory and verify that no preprocessing was reached.

The source wrapper is `Error during machdep parsing: ...`. Test isolated copies
of the YAML, retaining each exact derivation and leaving the candidate untouched:

- Omitted policy and explicit `legacy`: both must use legacy behavior. Compare
  the private candidate's results for each form, then selected unchanged
  fixtures against retained installed-provider observations. Include a case
  discriminating the branch, such as member alignment 16 or 2^29, GNU zero, and
  the local initializer. A small selection establishes only these controls,
  not absence of regressions across all existing profiles.
- Correct `clang-21-u32-bits`: successful machine decoding and actual
  policy-dependent layout behavior, not just successful `-version` output.
- Unknown string: exact source suffix `unknown alignment_attribute_policy: ...`.
- Duplicate policy keys, including repeated identical values: exact suffix
  `duplicate alignment_attribute_policy`; check conflicting duplicate order too.
- Wrong compiler with the opt-in: exact suffix
  `alignment_attribute_policy=clang-21-u32-bits requires compiler=clang`.
- Wrong maximum with the opt-in: exact suffix
  `alignment_attribute_policy=clang-21-u32-bits requires max_extended_alignment=4294967296 bytes`.
  Include a lowered ceiling so that silently weakening the maximum cannot pass.
- Non-string policy values: preserve the generated YAML decoder's actual typed
  rejection. Its exact runtime wording has not yet been observed here.

CLI YAML checks do not exercise invalid direct OCaml machine-record construction
or the schema generator's required/optional-field behavior. Those are separate
unit/integration requirements; do not claim that the early CLI gates cover them.

## Static-local and VLA controls

Run new isolated compile/parse-only fixtures with and without optional
`-constfold`, with AST checking and print/reparse. No function is called and no
native/target program is executed. A parse exit zero alone is insufficient:
check witness constants, hoisted initializer scope, initializer field/offset
order, and residual evaluated operations in the printed AST.

Required valid controls are fixed local scalar, fixed array and fixed member
queries; nested scalar/compound initializers; `sizeof(n++)`; and the outer
`sizeof(sizeof(int[n]))`, whose immediate operand has fixed integer type. The
unevaluated increment and inner size must not become evaluated operations.
Clang has a named `warn_side_effects_unevaluated_context` diagnostic: if the
chosen fixture emits it, retain and classify its exact text separately; do not
silently suppress it or waive every warning. Function-parameter setup at -O0
is not itself evidence that `n++` was evaluated.

Isolate these required negative cases so that one early failure cannot mask
another:

- `static int x = n;`
- `static int *p = &n;`
- `static unsigned long x = sizeof(n) + n;`
- A nested compound initializer containing both a safe fixed-size query and
  an evaluated local value/address in another member.
- `sizeof(a)` for local `int a[n]` in a static initializer.
- `sizeof(int[n])` in a static initializer.
- Residual `sizeof(*(int (*)[n])0)` in a static initializer.
- A side-effecting VLA-bound size in a static initializer, retaining its
  existing nonconstant/effect/unsupported diagnostics rather than discarding
  the bound's effects.

Also check that an ordinary automatic VLA with a side-effecting bound still
evaluates and saves its bound exactly once in the AST. This is different from
making its dynamic size legal in a static initializer.

### Discriminating valid double-VLA alignment risk — untested

Add a valid control of this shape, with the usual fixed-width transport guard:

```c
void fragma_scope(int n)
{
    double a[n];
    static const unsigned long long fragma_alignment_witness[]
        __attribute__((used)) = { __alignof__(a) };
}
```

Source inspection shows that local VLA lowering changes the variable type to a
pointer and stores its dynamic byte-size expression in `varSizeArrays`.
`Cabs.EXPR_SIZEOF` consults that table, while `Cabs.EXPR_ALIGNOF` does not. The
new direct-variable alignment consumer queries the resulting variable type.
It may therefore report pointer alignment 4 rather than double-array alignment
8 on this machine. This is a source-derived risk, not a confirmed execution
result. An `int` VLA would not discriminate it because both alignments are 4.
Compiler acceptance versus analyzer refusal is also a remaining semantics gap,
not a successful negative control.

## Other remaining semantic controls and gates

- Isolate `_Alignas(16) extern int x; int x;` from the above-maximum case, and
  test both declaration/definition orders and zero/ignored effective requests.
  The current typing review explicitly leaves missing-definition handling open.
- Exercise valid GNU arithmetic, unsigned-wrap-to-zero arithmetic such as
  `0xffffffffU + 1`, nonpower/negative arithmetic, and typed/recursive queries.
  Attribute parameters have lost C integer kinds; mathematical-integer or host
  evaluation must not replace target-C semantics.
- Add mixed C11/GNU directives, including C11 zero plus GNU underalignment and
  C11 underalignment plus a sufficient GNU request. Preserve every original
  request before combination. Check a pointer field whose base type has a
  different alignment, so complete-declarator validation is observable.
- Exercise source-expression provenance: direct declaration versus plain
  dereference, address/dereference cancellation, nested/indexed expressions,
  array/member alignment, and competing declaration/typedef requests. Matching
  a supported normalized CIL shape does not prove source-syntax equivalence.
- Add active pragma pack/align controls for explicit unsupported handling,
  alongside inactive/reset pragma controls. Full pragma semantics remain open;
  an explicit abort of valid compiler input is not support.
- Bitfields, ACSL expression alignment, vectors/atomics/incomplete types,
  parameter decay, packed typedef interactions and other documented consumer
  gaps remain open beyond the unchanged 55-case matrix.
- Retain the positive `max_align_t` representation and three wrong-
  representation controls, then genuine-kernel model validation, existing-
  profile regression checks and production integration gates. No successful
  finite context run alone supplies these remaining requirements.

Do not promote the private YAML/provider or mark the alignment-resolution goal
complete on the basis of a successful build, early runtime queries, matching
rejection categories, or this non-executing review.
