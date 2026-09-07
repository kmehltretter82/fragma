/* FRAGMA: RTE sweep of the RISC-V BPF JIT base instruction encoders,
 * VERBATIM from arch/riscv/net/bpf_jit.h @ rc4-clean(==rc6). Pure arithmetic
 * over u8/u16/u32; standalone harness needs only the width typedefs.
 *
 * Hypothesis under test: several encoders shift a u8/u16 operand left far
 * enough that, after the C integer promotion to *signed int*, the result
 * exceeds INT_MAX -> signed left-shift overflow (UB per C11 6.5.7p4).
 * Frama-C -wp-rte flags this as `assert rte: signed_shift/...`.
 */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

static inline u32 rv_r_insn(u8 funct7, u8 rs2, u8 rs1, u8 funct3, u8 rd,
			    u8 opcode)
{
	return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
		(rd << 7) | opcode;
}

static inline u32 rv_i_insn(u16 imm11_0, u8 rs1, u8 funct3, u8 rd, u8 opcode)
{
	return (imm11_0 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) |
		opcode;
}

static inline u32 rv_s_insn(u16 imm11_0, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u8 imm11_5 = imm11_0 >> 5, imm4_0 = imm11_0 & 0x1f;

	return (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
		(imm4_0 << 7) | opcode;
}

static inline u32 rv_b_insn(u16 imm12_1, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u8 imm12 = ((imm12_1 & 0x800) >> 5) | ((imm12_1 & 0x3f0) >> 4);
	u8 imm4_1 = ((imm12_1 & 0xf) << 1) | ((imm12_1 & 0x400) >> 10);

	return (imm12 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
		(imm4_1 << 7) | opcode;
}

static inline u32 rv_u_insn(u32 imm31_12, u8 rd, u8 opcode)
{
	return (imm31_12 << 12) | (rd << 7) | opcode;
}

static inline u32 rv_j_insn(u32 imm20_1, u8 rd, u8 opcode)
{
	u32 imm;

	imm = (imm20_1 & 0x80000) | ((imm20_1 & 0x3ff) << 9) |
		((imm20_1 & 0x400) >> 2) | ((imm20_1 & 0x7f800) >> 11);

	return (imm << 12) | (rd << 7) | opcode;
}

/* address-taking so nothing is dead-code-eliminated before WP sees it */
void *fragma_keep[] = {
	rv_r_insn, rv_i_insn, rv_s_insn, rv_b_insn, rv_u_insn, rv_j_insn,
};
