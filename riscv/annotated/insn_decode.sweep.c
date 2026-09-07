/* FRAGMA: RTE sweep of the arithmetic in arch/riscv/kernel/traps_misaligned.c
 * (linux-7.2-rc4-clean == rc6 HEAD, byte-identical) using the REAL decode
 * macros from arch/riscv/include/asm/insn.h (included below, so no
 * transcription risk).  These drivers apply the exact operations the misaligned
 * load/store handlers perform to an ARBITRARY faulting instruction, and RTE
 * asks whether any is UB or escapes bounds.
 *
 * Two security-relevant questions, phrased to avoid WP's blind spots:
 *   1. REG_OFFSET (the register selector inside REG_PTR) is a PURE integer
 *      expression; proving it stays <= 248 shows a malicious insn's 5-bit reg
 *      field can never push REG_PTR past the 32-register block of pt_regs.
 *      (REG_PTR itself casts ulong->pointer, which WP can't track; the integer
 *      bound is the checkable core of the same property.)
 *   2. The load sign-extension `(long)(val << shift) >> shift` with
 *      shift = 8*(sizeof(ulong) - len): is the shift count ever >= 64 (UB)?
 */
#define CONFIG_64BIT 1
/* minimal kernel-type context asm/insn.h's __RISCV_INSN_FUNCS macro needs */
typedef unsigned int   u32;
typedef signed int     s32;
typedef unsigned long  ulong;
typedef _Bool          bool;
#define __always_inline inline
#define BUILD_BUG_ON(cond) ((void)0)
#include <asm/insn.h>

/*@ assigns \nothing;
    // The register selector is masked to REG_MASK (0xF8 on 64-bit) => a byte
    // offset in {0,8,...,248}, i.e. one of 32 registers.  Proving the bound
    // for an ARBITRARY insn is the "no OOB register access" property.
    ensures rd_bound:  0 <= REG_OFFSET(insn, SH_RD)  <= 248;
    ensures rs2_bound: 0 <= REG_OFFSET(insn, SH_RS2) <= 248;
  @*/
unsigned long fragma_reg_offsets(unsigned long insn)
{
	return REG_OFFSET(insn, SH_RD) | REG_OFFSET(insn, SH_RS2);
}

/* The exact len->shift->sign-extend arithmetic from handle_scalar_misaligned
 * _load: len is one of {2,4,8}. RTE must show `val << shift` and `... >> shift`
 * never shift by >= 64. */
/*@ requires len == 2 || len == 4 || len == 8;
    assigns \nothing;
  @*/
long fragma_load_signext(unsigned long val, int len)
{
	int shift = 8 * (sizeof(unsigned long) - len);
	return (long)(val << shift) >> shift;
}

/* INSN_LEN and the compressed re-encode `RVC_RS2S(insn) << SH_RD` used before
 * SET_RD in the C.* load cases. RTE: shift/mask well-defined for any insn. */
/*@ assigns \nothing; @*/
unsigned long fragma_rvc_reencode_and_len(unsigned long insn)
{
	unsigned long reenc = RVC_RS2S(insn) << SH_RD;
	return reenc + INSN_LEN(reenc);
}

int (*fragma_a)(unsigned long, int) = 0;
