/* FRAGMA: RTE sweep of the RISC-V compressed-instruction encoders,
 * VERBATIM from arch/riscv/net/bpf_jit.h @ rc6. Pure arithmetic over u8/u16/u32.
 */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef signed int     s32;
typedef signed long    s64;
typedef unsigned long  ulong;

static inline u16 rv_cr_insn(u8 funct4, u8 rd, u8 rs2, u8 op)
{
	return (funct4 << 12) | (rd << 7) | (rs2 << 2) | op;
}

static inline u16 rv_ci_insn(u8 funct3, u32 imm6, u8 rd, u8 op)
{
	u32 imm;

	imm = ((imm6 & 0x20) << 7) | ((imm6 & 0x1f) << 2);
	return (funct3 << 13) | (rd << 7) | op | imm;
}

static inline u16 rv_css_insn(u8 funct3, u32 uimm, u8 rs2, u8 op)
{
	return (funct3 << 13) | (uimm << 7) | (rs2 << 2) | op;
}

static inline u16 rv_ciw_insn(u8 funct3, u32 uimm, u8 rd, u8 op)
{
	return (funct3 << 13) | (uimm << 5) | ((rd & 0x7) << 2) | op;
}

static inline u16 rv_cl_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rd,
			     u8 op)
{
	return (funct3 << 13) | (imm_hi << 10) | ((rs1 & 0x7) << 7) |
		(imm_lo << 5) | ((rd & 0x7) << 2) | op;
}

static inline u16 rv_cs_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rs2,
			     u8 op)
{
	return (funct3 << 13) | (imm_hi << 10) | ((rs1 & 0x7) << 7) |
		(imm_lo << 5) | ((rs2 & 0x7) << 2) | op;
}

static inline u16 rv_ca_insn(u8 funct6, u8 rd, u8 funct2, u8 rs2, u8 op)
{
	return (funct6 << 10) | ((rd & 0x7) << 7) | (funct2 << 5) |
		((rs2 & 0x7) << 2) | op;
}

static inline u16 rv_cb_insn(u8 funct3, u32 imm6, u8 funct2, u8 rd, u8 op)
{
	u32 imm;

	imm = ((imm6 & 0x20) << 7) | ((imm6 & 0x1f) << 2);
	return (funct3 << 13) | (funct2 << 10) | ((rd & 0x7) << 7) | op | imm;
}

void *fragma_keep[] = {
	rv_cr_insn, rv_ci_insn, rv_css_insn, rv_ciw_insn,
	rv_cl_insn, rv_cs_insn, rv_ca_insn, rv_cb_insn,
};
