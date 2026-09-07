# Hexagon alignment-context diagnostic, 2026-09-07

The reviewed diagnostic completed all 55 compiler/analyzer pairs, but returned
exit 1 with `context-observations-complete-unresolved-not-support`. Hexagon
remains unregistered, `integration_eligible` is false, and the extended-alignment
gate remains blocked. This is diagnostic evidence, not L1, a proof, an
architecture baseline or a confirmed Linux kernel defect.

## Actual run and retained evidence

The reviewed [successor recorder](../build/hexagon-alignment-context-20260906/diagnose-v2.py)
ran once in [run-1](../build/hexagon-alignment-context-20260906/run-1/receipt.json)
from 01:09:15.707678 to 01:09:51.553764 UTC on September 7. The terminal
invocation returned exit 1. Its original receipt SHA256 is
`4bedf09d1c43627ca717408227e4e0513f53707dd192180349fc05e0bd7541cc`.
The original draft, [pre-execution successor review](../build/hexagon-alignment-context-20260906/REVIEW-V2.md),
fixtures and failed/unresolved receipt remain unchanged.

The [fixed inventory](../build/hexagon-alignment-context-20260906/run-1/case-inventory.json)
uses nine fixtures at each of 16, 2^28, 2^29, 2^32 and 2^33 bytes, followed by
ten language controls: 55 pairs and 112 direct queries. Those queries are two
version checks, 55 Clang textual LLVM-IR compilations and 55 Frama-C parses.
Frama-C's explicitly configured preprocessing descendants are additional
processes, not included in the 112 direct-query count. All direct children have
recorded terminal outcomes; no input drift or incomplete artifact inventory is
reported. The receipt lists 839 retained artifact references.

Clang 21.1.8 targets `hexagon-linux-musl`/v68 with the retained freestanding GNU11,
unsigned-char and short-wchar flags. Frama-C 33.0 uses the existing blocked
candidate, exact compiler preprocessing command and private generated headers.
Each command retains its intent, actual argv, explicit environment, DEVNULL
stdin, exit status, timestamps and raw output. Limits remain 10 seconds per
compiler query, 30 seconds per analyzer query and 600 seconds overall, with
bounded output and no automatic retry. The
[before](../build/hexagon-alignment-context-20260906/run-1/inputs-before.json)
and [after](../build/hexagon-alignment-context-20260906/run-1/inputs-after.json)
snapshots bind the explicit source/tool/header/consumer closure; they are not a
hermetic host, Python, plugin or dynamic-library closure.

No target program or object was executed. No object/assembly/linker command,
WP/Eva proof, kernel build, tool installation or production/configuration change
was performed by this calibration. The preceding
[891-test regression](../results/tests-hexagon-gnu-model-20260906.json) remains
dated evidence; this diagnostic did not rerun that suite.

## Original result, without reclassification

| Retained pair classification | Count | Meaning |
| --- | ---: | --- |
| `constant-mismatch` | 24 | Both tools exposed constants, with recorded field differences. |
| `named-rejections-correspond-not-support` | 13 | Both tools produced recognized rejection diagnostics; this is not support. |
| `acceptance-rejection-mismatch` | 6 | One tool accepted the fixture and the other rejected it. |
| `constants-agree-not-support` | 5 | The measured constants agree only for that fixture and alignment. |
| `unresolved-observation` | 7 | The recorder could not classify at least one actual result. |

The two unexpected negative-control acceptances are a subset of the six
acceptance/rejection mismatches, not two additional pairs. No failed or
unclassified observation is counted as a successful calibration.

Concrete retained findings include:

- At just 16 bytes, the C11 member fixture's expression alignment is 16 in
  [Clang's IR](../build/hexagon-alignment-context-20260906/run-1/command-003/stdout)
  but 4 in [Frama-C's folded output](../build/hexagon-alignment-context-20260906/run-1/command-004/printed.c).
  Member-type alignment is 4 in both, while that fixture's other layout fields
  agree. The GNU normal/packed member fixture likewise reports expression
  alignment 16 versus 4. Thus reducing only a large-alignment ceiling would not
  resolve all observed differences.
- Larger requests expose record/type layout differences. For example, the C11
  member fixture at 2^29 has record alignment 4 and size 12 in
  [Clang's observation](../build/hexagon-alignment-context-20260906/run-1/command-007/observation.json),
  versus alignment 2^29 and size 2^30 in
  [Frama-C's observation](../build/hexagon-alignment-context-20260906/run-1/command-008/observation.json).
  At 2^32 the analyzer's recorded record alignment and size are zero, while
  the compiler still records 4 and 12. These are folded target-C witness values,
  not measurements of allocated objects or a claim that the analyzer's internal
  layout arithmetic itself produced zero. They do not replace the earlier
  emitted-object checks.
- GNU `aligned(0)` and `aligned(3)` are rejected by Clang but accepted by
  Frama-C, with expression alignment 4 in its folded witnesses. The respective
  [zero](../build/hexagon-alignment-context-20260906/run-1/command-096/printed.c)
  and [non-power-of-two](../build/hexagon-alignment-context-20260906/run-1/command-100/printed.c)
  outputs preserve the attributes. Both are explicitly flagged as unexpected
  analyzer acceptance of a fixed rejection control.

Raw-log inspection explains the seven unresolved observations without editing
their original classifications:

- Two GNU typedef-array compilations, at 16 and 2^28, actually reject an array
  whose element size is not a multiple of its alignment. The diagnostic includes
  `(aka 'int')`, which the recorder's pattern did not accept. The
  [first raw diagnostic](../build/hexagon-alignment-context-20260906/run-1/command-033/stderr)
  and [second](../build/hexagon-alignment-context-20260906/run-1/command-035/stderr)
  are compiler rejections, not compiler transport failures or measured layouts.
- Four local-variable cases, at 16, 2^28, 2^29 and 2^32, encounter genuine
  Frama-C errors about access to local variables in the fixture's static
  initializer. The [first analyzer log](../build/hexagon-alignment-context-20260906/run-1/command-054/stdout)
  contains multiple such errors; the classifier rejects the ambiguous diagnostic
  block. Local alignment was not measured by the analyzer in these cases.
- The conflicting C11 redeclaration at 2^33 receives a
  [compound Clang rejection](../build/hexagon-alignment-context-20260906/run-1/command-091/stderr):
  both the requested-alignment limit and a missing-definition `_Alignas`
  diagnostic. The unrecognized second diagnostic leaves this pair unresolved.

## Independent retained readback and remaining work

A separate read-only execution-tool readback verified all 112 retained
intent/result/classifier equalities and all 55 comparisons. It checked 70 raw
witness arrays containing 673 constants, the 55 actual preprocessed `.i` files,
19 copied sources and 74 permitted line-marker paths. The final hash readback
checked 9,820 references resolving to 5,012 unique paths with no drift, including
the 839 artifacts and unchanged receipt (840 run files including the receipt).
These are reported execution-tool readbacks, not a separately saved audit JSON.
An initial broader hash pass stopped because a reused pathname whitelist rejected
the genuine `c++config.h` path; a subsequent standard-library-only stable regular
file/hash check completed successfully. No evidence was rewritten to satisfy it.

The next work is a separately reviewed successor for the observed diagnostic
formats and an isolated frontend build for the required semantic corrections.
The local fixture uses unevaluated `sizeof`/alignment operands: correct the
analyzer's handling so the unchanged fixture can be measured, retaining its
present rejection as a regression case. A replacement witness must not hide that
limitation. Expression-alignment, layout and rejection-policy differences also
need resolution. Simply recognizing a diagnostic does not resolve its semantic
discrepancy.
Preserve this run and the original candidate; do not lower a model ceiling,
erase attributes, suppress errors or promote a profile on the basis of these
results. Full L1, normal-pipeline integration and scoped L2 remain outstanding.
This finite matrix also does not calibrate ACSL-term alignment or exhaust every
C/GNU declaration and expression context.
