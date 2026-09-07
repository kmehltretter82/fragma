/* FRAGMA: batch RTE-sweep harness for the arm64 instruction IMMEDIATE cluster
 * (arch/arm64/lib/insn.c @ b9b3e33b70b71).
 *
 * All function bodies below are VERBATIM copies (check-verbatim.sh).  The
 * preamble supplies only the typedefs, macros, the imm-type enum, and small
 * stubs (BUG/BUG_ON as noreturn, is_adrp/pr_err) that the kernel headers would
 * otherwise provide.  These are pure u32/u64/s32 bit-arithmetic leaves, so a
 * standalone harness is sound and dodges the arm64 atomic/sysreg header swamp.
 *
 * RTE sweep asks: is any of these UB (shift width, signed overflow, OOB)?
 */
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef signed int     s32;
typedef signed long    s64;

#define BIT(n)		(1UL << (n))
#define GENMASK(h, l)	(((~0UL) << (l)) & (~0UL >> (64 - 1 - (h))))
#define SZ_2M		0x00200000
#define AARCH64_BREAK_FAULT	0xD4207D00	/* BRK #0x3e8 */
#define AARCH64_INSN_SF_BIT	BIT(31)
#define AARCH64_INSN_N_BIT	BIT(22)
#define AARCH64_INSN_LSL_12	BIT(22)
#define EINVAL		22
#define __kprobes

enum aarch64_insn_imm_type {
	AARCH64_INSN_IMM_ADR, AARCH64_INSN_IMM_26, AARCH64_INSN_IMM_19,
	AARCH64_INSN_IMM_16, AARCH64_INSN_IMM_14, AARCH64_INSN_IMM_12,
	AARCH64_INSN_IMM_9, AARCH64_INSN_IMM_7, AARCH64_INSN_IMM_6,
	AARCH64_INSN_IMM_S, AARCH64_INSN_IMM_R, AARCH64_INSN_IMM_N,
	AARCH64_INSN_IMM_MAX
};

/*@ assigns \nothing; ensures never: \false; @*/
extern void fragma_unreachable(void) __attribute__((__noreturn__));
#define BUG()		fragma_unreachable()
#define BUG_ON(c)	do { if (c) fragma_unreachable(); } while (0)
#define pr_err(...)	do {} while (0)

/*@ terminates \true; assigns \nothing; @*/
extern int aarch64_insn_is_adrp(u32 insn);

#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		SZ_2M
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5

/* ==== VERBATIM bodies from insn.c ==== */

/*@ requires \valid(maskp) && \valid(shiftp);
    assigns *maskp, *shiftp;
    // On success the shift is one of {0,5,10,12,15,16,22}: always < 32, so
    // every `insn >> *shiftp` / `x << *shiftp` in the callers is well-defined
    // (unsigned left-shift overflow is defined, so only the count matters).
    // success-condition must match the callers' `< 0` test, not `== 0`:
    // the helper returns 0 or -EINVAL, so `\result >= 0` is exactly success.
    ensures shift_bounded: \result >= 0 ==> (0 <= *shiftp <= 22);
  @*/
static int __kprobes aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
						u32 *maskp, int *shiftp)
{
	u32 mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	case AARCH64_INSN_IMM_N:
		mask = 1;
		shift = 22;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn)
{
	u32 immlo, immhi, mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
		immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
		insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
		mask = ADR_IMM_SIZE - 1;
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			pr_err("%s: unknown immediate encoding %d\n", __func__,
			       type);
			return 0;
		}
	}

	return (insn >> shift) & mask;
}

u32 __kprobes aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
				  u32 insn, u64 imm)
{
	u32 immlo, immhi, mask;
	int shift;

	if (insn == AARCH64_BREAK_FAULT)
		return AARCH64_BREAK_FAULT;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (imm & ADR_IMM_LOMASK) << ADR_IMM_LOSHIFT;
		imm >>= ADR_IMM_HILOSPLIT;
		immhi = (imm & ADR_IMM_HIMASK) << ADR_IMM_HISHIFT;
		imm = immlo | immhi;
		mask = ((ADR_IMM_LOMASK << ADR_IMM_LOSHIFT) |
			(ADR_IMM_HIMASK << ADR_IMM_HISHIFT));
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			pr_err("%s: unknown immediate encoding %d\n", __func__,
			       type);
			return AARCH64_BREAK_FAULT;
		}
	}

	/* Update the immediate field. */
	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}

s32 aarch64_insn_adrp_get_offset(u32 insn)
{
	BUG_ON(!aarch64_insn_is_adrp(insn));
	return aarch64_insn_decode_immediate(AARCH64_INSN_IMM_ADR, insn) << 12;
}

u32 aarch64_insn_adrp_set_offset(u32 insn, s32 offset)
{
	BUG_ON(!aarch64_insn_is_adrp(insn));
	return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_ADR, insn,
						offset >> 12);
}
