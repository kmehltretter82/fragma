/* FRAGMA: RTE sweep of the RISC-V BPF JIT instruction *wrappers*,
 * VERBATIM from arch/riscv/net/bpf_jit.h @ rc6 (== rc4 for this file).
 *
 * The wrappers are thin: they forward operands to the base encoders
 * rv_i_insn / rv_u_insn / rv_r_insn (included verbatim below so the harness
 * is closed). The base rv_i_insn has a known signed-shift overflow
 * (imm11_0 << 20, u16 promoted to signed int, overflows when imm11_0>=0x800).
 * Question under test: do the wrappers pass argument ranges that make that
 * inherited overflow REACHABLE?
 *   - I-type wrappers forward imm11_0 unchanged  -> potentially reachable
 *   - rv_srai passes (0x400 | imm11_0)           -> sets bit10, not bit11
 *   - U-type (rv_lui/rv_auipc) use u32 (unsigned) -> no signed overflow
 *   - R-type wrappers pass small constant funct7  -> no overflow
 */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef signed int     s32;
typedef signed long    s64;
typedef unsigned long  ulong;

/* ---- base encoders (verbatim) ---- */
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

static inline u32 rv_u_insn(u32 imm31_12, u8 rd, u8 opcode)
{
	return (imm31_12 << 12) | (rd << 7) | opcode;
}

/* ---- wrappers under test (verbatim) ---- */
static inline u32 rv_addi(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 0, rd, 0x13);
}

static inline u32 rv_andi(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 7, rd, 0x13);
}

static inline u32 rv_ori(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 6, rd, 0x13);
}

static inline u32 rv_xori(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 4, rd, 0x13);
}

static inline u32 rv_slli(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 1, rd, 0x13);
}

static inline u32 rv_srli(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(imm11_0, rs1, 5, rd, 0x13);
}

static inline u32 rv_srai(u8 rd, u8 rs1, u16 imm11_0)
{
	return rv_i_insn(0x400 | imm11_0, rs1, 5, rd, 0x13);
}

static inline u32 rv_lui(u8 rd, u32 imm31_12)
{
	return rv_u_insn(imm31_12, rd, 0x37);
}

static inline u32 rv_auipc(u8 rd, u32 imm31_12)
{
	return rv_u_insn(imm31_12, rd, 0x17);
}

static inline u32 rv_add(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 0, rd, 0x33);
}

static inline u32 rv_sub(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0x20, rs2, rs1, 0, rd, 0x33);
}

static inline u32 rv_and(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 7, rd, 0x33);
}

static inline u32 rv_or(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 6, rd, 0x33);
}

static inline u32 rv_sll(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 1, rd, 0x33);
}

static inline u32 rv_srl(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0, rs2, rs1, 5, rd, 0x33);
}

static inline u32 rv_sra(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(0x20, rs2, rs1, 5, rd, 0x33);
}

static inline u32 rv_mul(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 0, rd, 0x33);
}

static inline u32 rv_div(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 4, rd, 0x33);
}

static inline u32 rv_remu(u8 rd, u8 rs1, u8 rs2)
{
	return rv_r_insn(1, rs2, rs1, 7, rd, 0x33);
}

/* keep everything alive for WP/EVA */
void *fragma_keep[] = {
	rv_r_insn, rv_i_insn, rv_u_insn,
	rv_addi, rv_andi, rv_ori, rv_xori, rv_slli, rv_srli, rv_srai,
	rv_lui, rv_auipc,
	rv_add, rv_sub, rv_and, rv_or, rv_sll, rv_srl, rv_sra,
	rv_mul, rv_div, rv_remu,
};
