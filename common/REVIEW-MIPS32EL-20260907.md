# MIPS32el common24 review

Date: 2026-09-07
Reviewer: Codex AI assistant; not a human approval.

## Decision and exact boundary

The `common.unaligned24.mips32el` target may use scoped reviewed assumptions
for the four explicit-byte 24-bit helpers and the two direct project round-trip
witnesses under the configured `mips32el-clang` profile. The five diagnostics
from the initial proof run may be reviewed only with their exact plugin,
message, severity, location where present, analyzed function set, file hashes
and evidence identities.

This decision does not prove either assumption implementation. It does not
approve a warning for another target, profile, source revision, machine model,
frontend policy, proof command or dependency set. It adds no kernel-caller,
instruction, linker, runtime, device, concurrency, big-endian, MIPS64, L3 or
whole-kernel claim.

## Initial evidence

The fresh initial run is retained at
`build/common24-mips-l2-initial-20260907/run-7`. Its target result is correctly
`unsupported`: approval was absent when it ran. The evidence nevertheless
establishes the inputs and outcomes that this review considers:

- configured MT7621 MIPS32el L1 passed for kernel revision
  `b9b3e33b70b71e516930117e21de3ad2a7723747`;
- source-token and declaration-prefix gates matched all four selected kernel
  functions in `include/linux/unaligned.h`;
- the effective standalone types are exactly `u8 = unsigned char` and
  `u32 = unsigned int`;
- the compiler-produced frontend fixture is ELF32 little-endian machine 8 and
  contains the exact selected `gnu_inline`, `unused` and
  `no_instrument_function` spelling;
- the wrong-type control produced exactly five intended Clang static-assert
  errors and the wrong-inline control produced exactly one intended error and
  its exact explanatory note;
- all 22 fixed-input compiler sensitivity mutations were rejected with their
  exact derived `__compiletime_assert_*` identity and diagnostic chain;
- the positive calibration definition is a nonempty eight-byte global
  function in an ELF32 little-endian MIPS object. Its O32/MIPS32r2 header flags,
  `.reginfo`, `.MIPS.abiflags` and empty `.llvm_addrsig` metadata pass a
  dedicated fail-closed reader; this observes container metadata, not MIPS
  instruction behavior;
- Frama-C completed normally. All 94 nonsmoke WP goals and all 82 selected
  consolidated properties are valid, with an unconditional dependency closure
  and no inventory issue;
- the 12 smoke goals were inconclusive timeouts, not inconsistency witnesses.
  No smoke result is waived or classified as unreachable.

The first sandboxed attempt (`run-6`) is deliberately not approval evidence:
Why3's private Unix-socket connection was denied and the analyzer hit its wall
limit. Run 7 repeated the same declared analysis outside that restriction and
completed normally.

## Type and arithmetic review

Every selected source access is an access to an alignment-one `u8`. Each getter
requires exactly three readable bytes and each writer requires exactly three
writable bytes. There is no word load, wider-pointer cast or architecture
alignment premise in these six bodies.

Integer promotion of each `u8` produces a value in 0 through 255. The largest
signed promoted shift in a getter is `255 << 16`, or 16,711,680; combining all
three bytes is at most 16,777,215, within the checked 32-bit `int` model. Writer
shifts operate on `u32`, and each stored result is reduced to the low eight
bits. The proof inventory retains all memory-access, pointer-value, shift,
call-precondition, assignment and postcondition obligations.

This is enough for the declared sequential C helper domain. It is not evidence
for other MIPS integer modes, compiler flags, objects or callers.

## Frontend and direct-call review

Frama-C reports that it ignores `__gnu_inline__`. The target does not use that
attribute to claim linkage or code-generation semantics: the four function
bodies are selected directly. The separate genuine-compiler fixture and
wrong-inline control bind the exact effective spelling and target compiler
context. The warning is therefore harmless only for this direct, static,
sequential source proof.

The six-body source graph contains no indirect call. The two project witnesses
make four direct helper calls, and their call preconditions remain present in
the unconditional proof/dependency inventory. Consequently Frama-C's global
warning that it cannot generate `\\valid_function` guards does not hide an
indirect call in this target. It grants no exception to targets that contain
function pointers.

## RTE warning review

The initial log has exactly these five warnings:

1. `kernel:attrs:unknown`: ignored `__gnu_inline__` at the first selected helper;
2. `wp`: skipped unaligned-pointer guards because `\\aligned` is unsupported;
3. `wp`: skipped invalid-function-pointer guards because `\\valid_function` is
   unsupported;
4. `wp`: signed-overflow annotation can be enabled because the corresponding
   warning option is disabled by the declared arithmetic model;
5. `wp`: `Missing RTE guards`.

The first four are covered by the exact source, type, frontend, call-graph and
arithmetic arguments above. The final aggregate message is reviewed only with
all its companion diagnostics. The complete raw goal and consolidated-property
inventories contain every selected helper and witness, every ordinary goal is
valid, all required named properties are present, and the common24 inventory
reports no missing dependency link. The review therefore does not manufacture
an absent goal or reinterpret an analyzer failure; it records why these known
generator limitations do not invalidate this exact byte-access proof.

Any changed warning text/count, source location, selected function, input hash,
machine description, compiler calibration, proof strategy, runtime-check
policy, toolchain lock or kernel revision invalidates the review before proof
classification.

## Acceptance conditions after this review

A later run may pass only if it freshly revalidates L1, provenance, the exact
machine model, preprocessing and annotations, both compiler fixture controls,
all 22 compiler mutations, complete ELF tables, all proof/dependency records,
the five warnings one-to-one, the empty reviewed-smoke list and final input
drift. The initial run itself remains an unaccepted pre-review observation.
