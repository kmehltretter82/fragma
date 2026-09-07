# Private Hexagon context results, 2026-09-07

Subsequent milestone: [candidate 3](CANDIDATE-DECLARATION-20260907.md) builds and
correctly rejects the four missing-definition controls after applying patch
0005 in a fresh tree. The candidate-2 observations below remain unchanged;
VLA, typed arithmetic and broader semantic/integration gates are still open.

The private candidate now matches all 33 successful constant-witness cases in
the unchanged 55-case matrix. Twenty-one rejection categories correspond; the
compound missing-definition case remains a category mismatch. A separate
14-case run confirms missing-definition, VLA and typed-arithmetic limitations.
**Alignment resolution, production integration, Hexagon L1 and L2 remain open.**
These are compiler/analyzer model observations, not Linux kernel bug findings.

The installed analyzer, private source/build 2, original machine candidate,
existing profiles and accepted proofs are unchanged. Only the existing private
[one-field policy YAML](candidate-policy.yaml) is exercised by these runs.

## Preserved first run and corrected fresh run

[Private context run 1](context-run-1/receipt.json) completed at 04:08:38 UTC:
29 constant agreements, 21 corresponding rejection categories, four unresolved
local witnesses and one compound-category mismatch. It remains unchanged.
Independent readback freshly hashes 2,345 unique files without drift and checks
112 commands, 55 comparisons, 55 preprocessing records and 165 linemarkers.

The four successful local parses already produce all 24 correct constants.
The old value parser permits a prefixed witness name, but does not recognize
the private printer's multiline `__used__` attribute. The new pure
[V2 classifier](context_classifiers_v2.py) handles only the exact local witness,
uint64 type, six fields, complete prototype/function body and original alignment
attributes. Other fixture parsers and diagnostic gates are unchanged. Values
are read from output, not replaced with expected values.

All nine [offline parser tests](test_context_classifiers_v2.py) pass (root rerun:
0.144 seconds). They replay all 55 retained pairs, change only four local
observations, reject malformed/extra output and preserve actual changed values
as mismatches. They do not rewrite the first receipt or count as new tool runs.

The reviewed [V2 recorder](diagnose_candidate_context_v2.py) performs a fresh
full run, not a replay: [context run 2](context-run-2/receipt.json),
04:25:40.876544–04:26:08.157536 UTC, terminal exit 1, no input drift.

| Unchanged 55-case matrix | Count |
| --- | ---: |
| Constant values agree | 33 |
| Named rejection categories correspond | 21 |
| Rejection categories differ | 1 |
| Unresolved observations | 0 |
| Unexpected acceptance of its negative controls | 0 |

Both tools reject the remaining compound case at 2^33, but
[Clang](context-run-2/command-091/stderr) reports both above-maximum alignment and
missing definition alignment. The [analyzer](context-run-2/command-092/stdout)
stops at above-maximum. Corresponding exit codes do not establish both checks.
The new recorder also preserves and verifies the complete first private run's
artifact tree before and after execution. Its commands and 55 fixture inputs
are unchanged apart from fresh output/source-copy paths and the new classifier.

Independent run-2 readback verifies the exact 949-file/280-directory artifact
tree (27,252,052 bytes), all 112 command records, all 55 replayed comparisons,
628 compiler/analyzer constants, 55 preprocessing records and 165 linemarkers.
It additionally rehashes 445 current selected/primary/fixture/libc/preprocessor
paths and all 297 compiler resource headers, without drift. Full before/after
snapshots match; deep source/build/dependency inventories are not independently
rehashed wholesale in this readback.

## Additional controls expose independent remaining gaps

The reviewed [extra recorder](diagnose_candidate_extra_context.py) and
[14 fixed fixtures](extra_context_fixtures.py) produced
[extra context run 1](extra-context-run-1/receipt.json),
04:24:33.717538–04:24:48.634889 UTC. Terminal exit 0 means only complete raw
observation collection; the receipt explicitly leaves semantics unclassified
and support false. Compiler returns are six successes/eight rejections;
analyzer returns are nine successes/five rejections. No input drift occurred.

The following is a readback of retained outputs, not a rewritten classification
or a broader semantic proof:

| Controls | Compiler versus private analyzer | Remaining implication |
| --- | --- | --- |
| Aligned extern before bare tentative definition: 16, 0, 2^29; aligned extern before initialized definition: 16 | Compiler rejects missing `_Alignas`; analyzer accepts all four. | Preserve source presence before declaration merging, even zero/ignored requests. |
| Bare tentative definition before aligned extern: 16, 0, 2^29 | Both accept; respective triples `[4,16,4]`, `[4,4,4]`, `[4,4,4]` agree. | Do not reject this order merely because the opposite order fails. |
| Bare initialized definition before aligned extern: 16 | Both reject missing `_Alignas`. | Keep tentative and initialized definitions distinct. |
| `double` VLA alignment | Compiler `[8,8,4]`; analyzer `[4,8,4]`. | Lowering loses array alignment in favor of pointer alignment. |
| `int` VLA companion | Both `[4,4,4]`. | This non-discriminating case alone would hide the double-VLA error. |
| GNU request `8 + 8` | Compiler accepts with `[4,16,4]`; analyzer explicitly reports unsupported typed expression. | Valid target-C arithmetic remains unsupported. |
| GNU requests `0xffffffffU + 1`, `-8`, `8 + 4` | Compiler rejects invalid alignment; analyzer reports unsupported typed expression. | Shared exit 1 does not validate typed arithmetic or invalid-request detection. |

For declaration cases the three values are object size, GNU object-expression
alignment and type alignment. For VLA cases they are array-expression, element
type and pointer type alignment. The VLA function is never called.
The double-VLA disagreement is visible directly in the
[compiler IR](extra-context-run-1/command-019/stdout) and
[printed analyzer source](extra-context-run-1/command-020/printed.c).
The four forward failures are retained in command pairs 003/004, 005/006,
007/008 and 009/010; the valid arithmetic gap is pair 023/024.

There is a further provenance distinction in the reverse tentative-16 control:
[Clang IR](extra-context-run-1/command-011/stdout) defines `fragma_object` with
storage alignment 4 while its expression-alignment witness is 16. The analyzer
prints the merged object with `_Alignas(16)`. Matching the three query values
does not establish complete definition/storage alignment fidelity.

Independent extra-run readback freshly hashes 2,611 unique files without drift,
checks all 30 command records, 14 pairs, 14 preprocessing records and 42
linemarkers. Its exact artifact tree contains 264 files and 75 directories,
24,248,913 bytes including the receipt. All original process groups are terminal
and reaped. Fresh audit hashes include selected inputs, flat retained
prerequisites, resources, private libc targets and candidate executable; full
nested source/build/dependency inventories are compared as recorded against
runtime inputs, not independently rehashed in that audit.

## Execution and next gates

Each full 55-case run uses exactly 112 direct queries: two versions, 55 textual
LLVM IR emissions and 55 private core-only parses. The extra run uses 30 direct
queries: two versions plus 14 pairs. Explicit preprocessor descendants are
additional. The private runtime, source/build/dependency closure, compiler,
resource/private-libc inputs, generated headers and actual preprocessing argv
are checked before/after or against retained per-command evidence. Original
process groups, cancellation and finite query/output limits remain checked;
this is not a hermetic host or escaped-descendant attestation.

No object/link/native/target program, WP/Eva proof, kernel build, installation
or production change was run here. The previous 891-test project regression
result is unchanged and is not a private-provider regression pass.

The [measured declaration/VLA note](DECLARATION-VLA-MEASURED-20260907.md) narrows
the next change using these outputs. A new
[nine-line missing-definition proposal](patches/0005-c11-missing-definition.patch)
checks original C11 presence before merging, including zero/ignored requests.
Its exact hunk applies in memory to the retained source; it is not applied,
built or behaviorally validated. It does not fix VLA or full redeclaration
semantics, and does not erase the compound error-recovery mismatch.

Next, implement and build the measured declaration/VLA corrections in a fresh
successor source tree, preserving these failures. Use the
[source-derived design](DECLARATION-VLA-DESIGN-20260907.md) with the measured note,
not the earlier untested hypothesis alone. Typed GNU arithmetic must retain
target-C types and wrapping. Full policy/legacy controls, evaluated-local and
VLA-bound effects, AST checking/print-reparse, mixed directives, pragma
semantics, expression provenance, bitfields/ACSL, positive/wrong `max_align_t`
controls, existing-profile regressions, genuine-kernel L1 and integration remain
required as enumerated in [CONTEXT-NEXT.md](CONTEXT-NEXT.md).

Current acceptance remains 25/31 targets, 18/24 distinct functions and ten
named scoped architecture baselines; eleven families still lack one.

## Retained identities

| Artifact | SHA256 |
| --- | --- |
| First private context receipt | `6d71f4cfe091264d70d1bc49ad95b611eb3aaaeb1024c3efd7b351ec9d300e60` |
| Fresh V2 context receipt | `9ee43d6597e0841315f4b070190f7cfba815548e02cd997993699d6feaa30630` |
| Extra raw context receipt | `75a060bf654d531d0714b3627a6a88a9e70e0d327e7c0d66adb27d1e6c3b51bb` |
| V2 context recorder | `1c24b64a83f6648c5c67c7b3d74c55b02c9e7018c158cf19bc5b06df47fbaeda` |
| V2 classifier | `ca315f499eff71d75a05d1a1100cdb8ae5a51fa8d119870c0f63e7d778b7d8a8` |
| Offline parser tests | `8263faee2dbbdd5f22ab571abf804edc5a0bb676c4e71f041150150f37ed54bb` |
| Extra context recorder | `323dec3eb034671911624eaeb4652c298339ef271c1c8af77f7ade38d818ec12` |
| Extra fixture inventory | `c6c07c34214d74737f88ca1cf06905713c69c1fc77948f246023bdba21900c89` |
| Unapplied missing-definition proposal | `1a7ab19aaff5d3d8785bc73d838e54bbd0273c60844bf5f9336f44eb357aaa29` |
