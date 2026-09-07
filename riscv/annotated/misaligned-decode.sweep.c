/* FRAGMA: RTE sweep of the STORE-side decode arithmetic in
 * arch/riscv/kernel/traps_misaligned.c (linux-7.2-rc6 HEAD), extending
 * insn_decode.sweep.c to cover handle_scalar_misaligned_store's register
 * selectors and the INSN_LEN epc advance.  Uses the REAL macros from
 * arch/riscv/include/asm/insn.h (included below, no transcription risk).
 *
 * Store side selects the value register three ways (see store handler):
 *   GET_RS2(insn, regs)   -> REG_OFFSET(insn, SH_RS2)          (SH_RS2  = 20)
 *   GET_RS2C(insn, regs)  -> REG_OFFSET(insn, SH_RS2C)         (SH_RS2C = 2)
 *   GET_RS2S(insn, regs)  -> REG_OFFSET(RVC_RS2S(insn), 0)     (pos = 0)
 * and finishes with  regs->epc = epc + INSN_LEN(insn).
 *
 * Questions (phrased around WP's blind spots; REG_PTR's ulong->ptr cast is
 * untrackable, the integer REG_OFFSET bound is the checkable core):
 *   1. Does any store-side REG_OFFSET stay in {0,8,...,248} for an ARBITRARY
 *      faulting insn? (no OOB register access past the 32-reg pt_regs block)
 *   2. SHIFT_RIGHT inside REG_OFFSET picks << vs >> by sign of (pos-LOG_REGBYTES);
 *      SH_RS2C=2 gives pos-LOG=-1 (a LEFT shift of insn) and GET_RS2S uses
 *      pos=0 => pos-LOG=-3 (a left shift of RVC_RS2S). Any shift >= width / UB?
 *   3. INSN_LEN advance: ternary + ulong add, any UB?
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
    // GET_RS2: full-width insn, pos=SH_RS2=20 => insn>>17, masked to REG_MASK.
    ensures rs2_bound:  0 <= REG_OFFSET(insn, SH_RS2)  <= 248;
    // GET_RS2C: pos=SH_RS2C=2 => pos-LOG=-1 => insn<<1, masked to REG_MASK.
    ensures rs2c_bound: 0 <= REG_OFFSET(insn, SH_RS2C) <= 248;
    // GET_RS2S: selector is RVC_RS2S(insn) (=8..15), pos=0 => (x<<3)&REG_MASK.
    ensures rs2s_bound: 0 <= REG_OFFSET(RVC_RS2S(insn), 0) <= 248;
  @*/
unsigned long fragma_store_reg_offsets(unsigned long insn)
{
	return REG_OFFSET(insn, SH_RS2)
	     | REG_OFFSET(insn, SH_RS2C)
	     | REG_OFFSET(RVC_RS2S(insn), 0);
}

/* The epc advance shared by every store case:
 *   regs->epc = epc + INSN_LEN(insn);
 * INSN_LEN is INSN_IS_16BIT(insn) ? 2 : 4. RTE: ternary/add well-defined,
 * result in {epc+2, epc+4}. */
/*@ assigns \nothing;
    ensures len_ok: INSN_LEN(insn) == 2 || INSN_LEN(insn) == 4;
  @*/
unsigned long fragma_insn_len_advance(unsigned long epc, unsigned long insn)
{
	return epc + INSN_LEN(insn);
}

/* address-taken so WP/EVA keeps them alive */
void *fragma_keep[] = {
	(void *)&fragma_store_reg_offsets,
	(void *)&fragma_insn_len_advance,
};
