# arch/arm64 — RTE hunt log

Tree: ~/linux-work/linux @ b9b3e33b70b71 (7.2-rc6).
Method: standalone leaf harness (verbatim body + minimal typedefs), RTE-prove
UB-freedom under the function's implicit preconditions, then audit callers.
arm64 is LP64 like x86_64, so `-machdep gcc_x86_64` models its integer widths
exactly (only char-signedness differs, irrelevant to these u32/u64 leaves).

## cpuid_feature_extract_{signed,unsigned}_field_width  (cpufeature.h) — NO BUG

Harness: annotated/cpuid_extract.acsl.c. Body:
    return (s64)(features << (64 - width - field)) >> (64 - width);
Two shift-width UB hazards; RTE clean (18/18) under
    width >= 1, field >= 0, field + width <= 64.
Load-bearing check: dropping `field+width<=64` makes BOTH rte_shift goals
unprovable => the UB is real when a caller violates it (confirmed, not assumed).

Caller audit (tree-wide):
  * All ranged callers go through cpuid_feature_extract_field_width(), which
    guards width==0 -> 4 (but NOT field+width<=64).
  * The one DIRECT caller of the unsigned _width variant, has_user_cpuid_feature
    (cpufeature.c:1660), bypasses even the width==0 guard -> looked promising.
  * BUT every capability entry sets field_pos/field_width via ARM64_CPUID_FIELDS
    -> __ARM64_CPUID_FIELDS -> .field_width = reg_field_WIDTH,
       .field_pos  = reg_field_SHIFT
    both auto-generated from the ARM sysreg field tables, where a field always
    lies within its 64-bit register: width>=1 and pos+width<=64 by construction.
  => no reachable violation. Well-formed by construction. Not a bug.

## Also surveyed, all careful (no leads)
  * lib/insn.c immediate encode/decode + generators: mask-before-shift,
    negative-imm rejected, shift/mask tables shared -> consistent. Heavily
    exercised by the BPF JIT/kprobes (hardened).
  * hw_breakpoint.c get_hbp_len / arch_check_bp_in_kernelspace /
    arch_bp_generic_fields: defensive switch()es, bounded len set.

## Broad RTE sweep — insn immediate cluster (annotated/insn_imm.sweep.c) — NO BUG

5 verbatim leaves from lib/insn.c swept together: aarch64_get_imm_shift_mask,
aarch64_insn_{decode,encode}_immediate, aarch64_insn_adrp_{get,set}_offset.
RTE result: **100/102**, and every RTE goal (shift-width, signed/unsigned
overflow, mem-access, init) is PROVED. The 2 residuals are `terminates`
through the BUG_ON->noreturn stub (a modelling artifact, not UB).

Two contract-refinement lessons the sweep forced (both "annotation too weak",
not bugs, but each pinpointed exactly what the code relies on):
  * decode/encode's `insn >> shift` is safe only because the helper returns
    shift in {0,5,10,12,15,16,22} (all < 32). Had to expose that as a
    postcondition to close the shift goals.
  * the postcondition's success-guard must be `\result >= 0`, matching the
    callers' `if (... < 0)` test -- NOT `== 0`. WP flagged the mismatch: on
    the taken path it only knows result>=0, so a `==0`-guarded ensures is
    useless there. (Helper returns 0 or -EINVAL, so >=0 == success.)

Infra note: whole-file arm64 parse got 3 walls deep (min()/__auto_type ->
minmax.h override; __aarch64__/__uint128_t shims; then arm64 LSE atomic/cmpxchg
headers mis-modelled -> would need atomic-header stubs). Pivoted to the
batch-harness approach (verbatim bodies + tiny preamble) which sidesteps the
whole swamp and is the robust path for leaf sweeps. minmax.h + shims preserved
in arm64/override + arm64/gen-db.py for a future whole-file attempt.

## Meta
Hand-picking well-known arm64 files keeps landing on hardened code. Higher-yield
next steps: (a) BROAD automated RTE sweep over many arm64 leaves at once, let
alarms surface; (b) target genuinely obscure/recent code (new drivers, recent
commits) rather than famous files; (c) functional round-trip proofs
(encode/decode inverse) rather than UB-only.
