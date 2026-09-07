# Hexagon source-derived layout and parser calibration

Updated 2026-09-06. This is an unregistered compiler/analyzer diagnostic, not
Hexagon L1, a kernel proof, or a whole-architecture support claim. Existing
configured profiles and the tool lock are unchanged.

## Source-derived `max_align_t`

The authenticated Hexagon musl source and installed header define
`struct { long long __ll; long double __ld; }`. The old upstream probe chose
`long long` by alignment alone. Both align to eight bytes, but the actual
structure occupies sixteen bytes rather than eight: matching alignment alone
does not give a faithful representation.

[The layout reader](../fragma/hexagon_layout.py) derives the exact declaration
from both authenticated source and installed header. The generator measures
fourteen actual/candidate layout pairs in a compile-only, constant-data fixture:
size, C and GNU alignment, member sizes/offsets, arrays, and a containing
structure. It reads the resulting ELF data without executing the object.
Three separate static-assertion controls reject the old scalar, reversed
members, and a wrong member type. The derived declaration enters the model
before validation and its single YAML serialization; old candidates are not
rewritten.

The [first 88-query run](../build/hexagon-max-align-20260906/generator-1/receipt.json)
passed this compiler layout stage and all three controls, with unchanged
inputs. Its overall result remains `blocked-object-alignment`, with the same
four extended-alignment contradictions as the preceding
[84-query adapter milestone](HEXAGON-GENERATOR-ADAPTER-20260906.md).

## Analyzer calibration exposed a separate producer issue

The [first actual Frama-C run](../build/hexagon-max-align-20260906/analyzer-1/receipt.json)
used the unchanged candidate and all four unchanged layout fixtures. Frama-C
33.0 rejected the positive fixture's GNU alignment expression. Two controls
failed at their intended static assertions; the type control also emitted an
unrelated builtin warning. This run is failed evidence, not a calibration pass.

The candidate's `compiler` field contains the executable path
`/usr/bin/clang-21`. Frama-C uses this field as a language-extension selector:
the installed `Machdep.gccMode` recognizes the literal names `gcc` and `clang`,
not executable paths. Its twelve optional `gcc_alignof_*` fields also default
to unsupported when omitted. The required correction is to keep executable
identity in the invocation evidence, select the real `clang` dialect in a
newly generated model, and measure all twelve GNU alignment fields separately.
Neither relabelling Clang as GCC nor suppressing the warning is needed.

This interpretation follows the installed
[machine implementation](../toolchain/verified-prefix/opam/fragma/lib/frama-c/kernel/kernel_internals/runtime/machdep.ml)
and [alignment consumers](../toolchain/verified-prefix/opam/fragma/lib/frama-c/kernel/kernel_services/ast_data/machine.ml).
The [Frama-C development guide](https://www.frama-c.com/download/frama-c-plugin-development-guide.pdf)
also describes the compiler field as controlling compiler-specific extensions;
the exact installed source and actual diagnostic remain authoritative for this
version's additional `clang` spelling.

The corrected producer now completes a [fresh 100-query run](../build/hexagon-max-align-20260906/generator-2/receipt.json):
52 standard probes, twelve unchanged GNU probes, four layout checks, a version
query, thirty alignment trials and a macro query. All 78 schema fields are
present, with no warnings or unrelated compiler errors. The exact executable,
binary hash and target arguments remain separate from `compiler: clang`.
The independent C and GNU maximum-alignment observations both agree with the
paired layout object. The alignment contradictions still require a nonzero exit.

The [fresh Frama-C run](../build/hexagon-max-align-20260906/analyzer-2/receipt.json)
passes its complete diagnostic scope: exact version, warning-free positive
parse and all three named static-assertion rejections. The
[printed constant array](../build/hexagon-max-align-20260906/analyzer-2/command-positive/printed.c)
agrees with all 28 actual compiler values. The generated machine header retains
the genuine struct definition. Input inventories are unchanged before/after;
all commands, streams, generated headers and preprocessed sources are retained.
No YAML or C fixture is rewritten between compiler and analyzer runs.

`generator-1`, failed `analyzer-1`, and their original recorders remain unchanged.
The [pretransition readback](../build/hexagon-max-align-20260906/pretransition-readback.json)
checked 4,094 referenced file hashes before the intentional producer update.
The [old producer source](../build/hexagon-max-align-20260906/adapter-layout-stage.py)
is preserved byte-for-byte; subsequent edits do not turn historical receipts
into current acceptance.

Independent [dated-stage audit](../build/hexagon-max-align-20260906/STAGE1-EVIDENCE-AUDIT.md)
checks all 88 original commands and decodes the layout ELF separately from the
production reader. The [fresh Clang/analyzer readback](../build/hexagon-max-align-20260906/READBACK-CLANG.md)
checks all 100 producer command identities, twelve GNU observations, five
analyzer calls, exact preprocessing, generated headers, printed values and
named rejection diagnostics. It rehashes 4,069 unique files without drift.
The `clang` selector also enables other GNU language/builtin branches; this
layout check does not establish all GNU extensions, varargs ABI or WP semantics.

## Extended alignment is still unresolved

A separate [sixteen-query LLVM-IR diagnostic](../build/hexagon-alignment-semantics-20260906/run-1/receipt.json)
compares `_Alignas` and GNU `aligned` declarations, each with zero and nonzero
initializers. All four forms give the same observations:

| Requested byte alignment | Compiler `__alignof__` | LLVM IR global alignment |
| --- | --- | --- |
| 2^28 | 2^28 | 2^28 |
| 2^29 | 4 | 4 |
| 2^32 | 4 | 4 |
| 2^33 | Named compiler rejection | No IR produced |

The lost alignment is already visible before assembly. This does not establish
its exact implementation cause or a Linux kernel defect. Merely reducing a
YAML ceiling would not model the compiler's accept-and-ignore behavior; Frama-C
also treats C alignment specifiers and GNU attributes through different paths.
No maximum is hand-filled, and the integration gate remains closed.

## Regression and remaining acceptance

The current [891-test regression](../results/tests-hexagon-gnu-model-20260906.log)
passes without failures, errors or skips in 86.183 seconds. Its
[exact-command sidecar](../results/tests-hexagon-gnu-model-20260906.json)
binds the final producer/layout code, all four Hexagon test modules, registry,
lock and prior invocation. New checks cover literal dialect selection,
individually measured GNU fields, strict probe inventories and C/GNU layout
agreement. All frozen inputs are unchanged before/after.

The [867-test regression](../results/tests-hexagon-layout-20260906.log) passed
without failures, errors or skips in 85.432 seconds at the first layout-stage
identity. Its [command sidecar](../results/tests-hexagon-layout-20260906.json)
preserves the exact invocation and before/after frozen input hashes. These
tests use synthetic data and retained evidence; they do not execute historical
native fault, trap or out-of-bounds harnesses.

Still required: a faithful extended-alignment policy, normal profile-pipeline integration,
genuine-kernel L1, and a documented L2 function set. The target libc's wide
character limit differs from the kernel short-wchar mode and remains an explicit
limitation. No target program, WP/Eva proof, kernel build, installation or profile
activation occurs in this layout stage.
