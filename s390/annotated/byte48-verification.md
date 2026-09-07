# Exact 48-bit byte proofs

The separate [48-bit harness](unaligned48.verified.c) and
[64-bit strategies](byteproof64.h) leave the accepted 24-bit/TOD inputs unchanged.
All six retained kernel helper bodies/declarators and all three project
round-trip bodies have the original C tokens. Every original function contract
and accepted input domain is preserved; stores and the witness accept every
`u64` input, not just inputs below 2⁴⁸.

The new 48-bit annotations are 23 proved intermediate assertions: six store
decompositions, five decoder decompositions, six extracted-byte equalities, and
six arithmetic quotient/remainder decompositions in the project witness. They
are not new preconditions, axioms, admissions, or assumed solver results.

The isolated combined replay in `build/s390-pilot/byte48-work/group-1` has all
**74 ordinary WP goals and all 59 selected property/dependency TSV entries
Valid**, including the exact full-domain round trip modulo 2⁴⁸. The fresh final
replay of the permanent files in
[byte48-final](../../build/s390-pilot/byte48-final/receipt.json) independently
repeats **74/74 ordinary goals and 59/59 selected dependency rows Valid**. Six
smoke checks time out inconclusively; none is waived as a failed check. Printed
termination/exit/default-behavior bookkeeping is not added to the ordinary total.

## Checked proof steps

Stores decompose the unsigned input at successive byte boundaries using
`q = (q & 255) + 256 * (q >> 8)`, retaining the high discarded quotient. This
establishes every stored byte as the exact specified quotient modulo 256 without
an input-width restriction. Decoder assertions establish the analogous packed
value decompositions before extracting the original bytes. The witness's
additional arithmetic decompositions then establish reconstruction modulo 2⁴⁸;
no callee contract is accepted without its implementation and dependency proofs.

The actual getter mixes explicit `u64` shifts by 40, 32, and 24 with promoted
32-bit signed byte shifts by 16 and 8. The latter operands are in `[0,255]`, so
their largest shifted value is 16711680, within signed 32-bit range. The proof
retains and checks the corresponding signed-32/unsigned-64 conversions rather
than dropping them or imposing a no-overflow input assumption.

Proof search first exposes constant-times-byte values from left shifts, then
splits signed/unsigned conversion cases. Right shifts still follow conversion
handling, preserving every positivity side obligation. Bitwise equalities have
separately checked 64-bit range conditions. In those range children, masks are
rewritten before BitRange to avoid Frama-C 33's already documented missing-verdict
corner case for initially trivial constant-mask positivity branches.

Both decoder search orders were actually completed with unmodified tools:

| Focused experiment in `build/s390-pilot/byte48-work/` | Ordinary WP / selected TSV | Tactics | Wall time |
| --- | --- | --- | --- |
| `put-be48-1` | 36 Valid / 21 Valid | 17 | 34 s |
| `get-be48-1` (conversion cases first) | 22 Valid / 24 Valid | 322 | 435 s |
| `get-be48-left-1` (left shifts first) | 22 Valid / 24 Valid | 99 | 140 s |

These were concurrent development runs, not a controlled performance benchmark.
The lower tactic count explains why the left-shift-first strategy was selected.
Toolchain binaries, tactic implementations, and proof-result files were never
edited to force a verdict. Exact commands, audit inputs, retained preprocessed
streams, source/model checks, WP JSON, TSV dependencies, and solver scripts are
retained in each output directory.

## Scope and warning review

The proofs use pinned Linux `b9b3e33b70b71e516930117e21de3ad2a7723747`, the actual
configured s390x **z13** machine/build, native annotation preprocessing, and the
clean workspace toolchain. The genuine kernel-header fixture checks aliases,
widths, byte alignment, signatures, and effective inline macros. There are no
substituted external contracts, function pointers, concurrency, MMIO or assembly.

Any warning review is limited to these two selected 48-bit helpers and their one
direct-call project witness, bound to exact source, strategy, model/build,
toolchain, preprocessing, and proof-search identities. Every access is to a byte
or six-byte array with alignment one. Stores use unsigned 64-bit right shifts
with constant counts in range; the getter's two promoted signed shifts have the
explicit bounds above. All generated guards and conversion branches must pass.
The generic alignment, function-pointer, signed-overflow-policy and missing-RTE
diagnostics are not waived for other targets. Ignored GNU inline linkage hints
are reviewed only for the retained sequential helper bodies and direct calls.
The single ignored-attribute diagnostic is printed at the first, unselected
24-bit definition in this translation unit; the exact same local inline macro
is used by the two selected 48-bit definitions and checked by the real-header
fixture. The review does not infer a proof of those unselected 24-bit functions.

The independent project-only false byte-order calibration remains unchanged in
the original harness. It is not a hidden unselected caller in this proof-only
translation unit. Kernel callers are still unverified. These explicit-byte
helpers do not themselves corroborate native endianness, and no target-runtime
execution is claimed by these WP proofs.

Smoke attempts remain inconclusive if their contradiction search times out;
they never count as ordinary theorems or a proof of satisfiable specifications.
Standalone receipts always say `certified: false`. The common runner must still
complete its fresh source, model, toolchain, assumption, warning and final-input
integrity gates before accepting the registered target.

Run preservation/progress tests with:

```sh
python3 -m unittest tests.test_s390_byte48_annotations tests.test_s390_byte_annotations tests.test_s390_proof_progress tests.test_s390_targets
```

After target-manifest promotion, reproduce local proof progress with a fresh
output directory and an independent overall wall bound:

```sh
python3 s390/prove.py --strategy fragma_byte64_leftmath --timeout 1 --wall-timeout 600 s390.unaligned48 build/s390-pilot/byte48-new-run
```

The fresh common-suite replay remains required for integrated target acceptance.
