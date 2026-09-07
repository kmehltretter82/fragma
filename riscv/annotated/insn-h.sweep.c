/* FRAGMA: RTE sweep of the RVG/RVC encode helpers and field-extract macros in
 * arch/riscv/include/asm/insn.h.  The static-inline encode/extract helpers come
 * straight from the header (included verbatim below, so no transcription risk);
 * the IMM_ and RV_X field-extract MACROS are exercised through thin driver wrappers
 * that apply the macro to an arbitrary instruction word exactly as written.
 *
 * Focus: signed left-shift UB in the sign-extraction / immediate-insertion
 * arithmetic.
 */
#define CONFIG_64BIT 1
typedef unsigned int   u32;
typedef signed int     s32;
typedef unsigned long  ulong;
typedef _Bool          bool;
#define __always_inline inline
#define BUILD_BUG_ON(cond) ((void)0)
#include <asm/insn.h>

/* ---- field-extract MACRO drivers (macro body applied verbatim) ---- */

/*@ assigns \nothing; */
s32 fragma_imm_i(u32 insn) { return IMM_I(insn); }

/*@ assigns \nothing; */
s32 fragma_imm_s(u32 insn) { return IMM_S(insn); }

/*@ assigns \nothing; */
unsigned long fragma_rv_x(u32 insn) { return RV_X(insn, 7, 5); }

/*@ assigns \nothing; */
s32 fragma_extract_jtype(u32 insn) { return RV_EXTRACT_JTYPE_IMM(insn); }

/*@ assigns \nothing; */
s32 fragma_extract_itype(u32 insn) { return RV_EXTRACT_ITYPE_IMM(insn); }

/*@ assigns \nothing; */
s32 fragma_extract_btype(u32 insn) { return RV_EXTRACT_BTYPE_IMM(insn); }

/* ---- keep the header's static-inline helpers alive for WP/EVA ---- */
void *fragma_keep[] = {
	(void *)riscv_insn_extract_jtype_imm,
	(void *)riscv_insn_insert_jtype_imm,
	(void *)riscv_insn_extract_utype_itype_imm,
	(void *)riscv_insn_insert_utype_itype_imm,
	(void *)fragma_imm_i,
	(void *)fragma_imm_s,
	(void *)fragma_rv_x,
	(void *)fragma_extract_jtype,
	(void *)fragma_extract_itype,
	(void *)fragma_extract_btype,
};
