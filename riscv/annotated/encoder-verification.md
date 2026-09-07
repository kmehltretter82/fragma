# Checked RISC-V encoder proof and diagnostic scope

The complete retained probe `build/riscv-verified/proof-work/all-fields-5`
reports **119 ordinary WP goals Valid and 119 selected consolidated properties
Valid**, across seven kernel encoder definitions and five project-only decode
witnesses. All 47 named functional postconditions and every direct callee/call
precondition are present. The analyzer completed in 286.410 seconds. All 14
attempted smoke goals timed out; they remain inconclusive, never consistency
proofs. No smoke result is waived.

The promoted `base-encoders.proved.c` retains every line of the original
`base-encoders.verified.c` and adds only a trailing include of the comment-only
`encoder-fieldproof.h`. Every function declaration, C body, precondition,
postcondition and full immediate domain is unchanged. The permanent strategy
header is byte-identical to the successful `fields-5.h` experiment. The original
harness and all failed/intermediate probes remain intact for hash-bound review.
The pinned kernel revision is `b9b3e33b70b71e516930117e21de3ad2a7723747`.

## Proof graph and strategy

`rv_amo_insn` calls `rv_r_insn`. Each of the five project witnesses calls its
corresponding I/S/B/U/J encoder. All twelve functions are selected together;
there is no omitted or assumed external callee. The witness functions do not
increase the count of kernel definitions. The complete probe's read-only
coverage checker reconstructs this graph from C tokens and requires each named
functional property, ordinary goal, selected function and consolidated status.

Checked bitwise equality creates both range and bit-equality obligations.
Checked bit-test range splits connect the existing register/control bounds
with their high bits being clear. Integer mask/shift equality hypotheses from
callee contracts are expanded explicitly so modular callers can use them.
Boolean equalities are excluded from that integer-only selector, avoiding a
first-match obstruction. Cast/shift arithmetic tactics retain checked side
conditions. There are no axioms, new assumed contracts, manual JSON verdicts,
unchecked tactic children, or input-domain restrictions.

## Individually reviewed diagnostics

The warning records in `config/riscv-targets.json` bind the exact twelve-function
scope, source/model/build/tool inputs, proof-search settings and these reasons.
They do not globally suppress diagnostics or accept a missing goal.

1. **Ignoring unknown attribute: `__gnu_inline__`.** The real configured kernel
   fixture checks the exact inline expansion, each helper signature, scalar
   typedef and promotion. All seven functions are pure sequential scalar
   helpers with matched declarations/bodies. Linkage/inlining does not alter
   this source-level integer relation; no instrumentation, assembly or external
   call is modeled.
2. **Skipped RTE guards: unaligned pointers.** None of the selected twelve
   functions contains a pointer parameter, pointer cast, pointer arithmetic,
   dereference, array access or indirect memory operation. All data are local
   scalar integers. The global unsupported alignment-guard class is inapplicable
   to this exact scope.
3. **Skipped RTE guards: invalid function pointer calls.** There are no function
   pointers. The only calls are the six direct edges described above, whose
   preconditions and callee proof dependencies are selected and Valid.
4. **`-wp-rte can annotate signed overflow because -warn-signed-overflow is not
   set`.** This batch deliberately uses the genuine configured kernel
   `-fno-strict-overflow` execution policy and the compiler-calibrated WP
   two's-complement wrapping model. In particular `u8`/`u16` shifts promote to
   signed 32-bit int; their shifted values are not assumed to stay below
   `INT_MAX`. Unsigned `u32` shifts and downcasts likewise retain their actual
   modulo semantics. Every generated shift-count guard is proved. No immediate
   value is excluded to avoid wrapping, and no ISO-C signed-overflow defect is
   inferred from these kernel operations. Real-header and compiler/EVA profile
   calibration evidence remain explicit trust gates.
5. **Missing RTE guards.** This exact summary is reviewed only together with the
   three individually scoped guard/policy diagnostics above. All generated
   ordinary, functional, frame, termination, exit and call/dependency properties
   must still pass. New skipped guard classes, additional warnings, unknown
   statuses, tool errors, and missing reports fail closed.

## Limits

The successful probe is measured proof-search evidence, not an L2/common-suite
certificate. Promotion requires a fresh configured L1 profile, real kernel
header/model fixture, source identity, clean toolchain/assumption preflight,
actual preprocessing/audit inventories, strict report parsing and final input
integrity checks. No runtime execution of generated RISC-V instructions, BPF
program correctness, ISA legality of reserved encodings, atomicity, kernel
caller coverage, or defect claim is made. The old 81-Valid/38-timeout baseline
and two later whole-batch wall timeouts remain preserved failures/progress
records, not rewritten successes.
