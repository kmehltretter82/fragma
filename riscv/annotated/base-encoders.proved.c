/* SPDX-License-Identifier: GPL-2.0 */
/* Seven exact Linux instruction-format helpers, pinned b9b3e33b70b71.
 * This is an encoding proof, not execution of generated instructions.
 * The configured riscv64-gcc model has wrapping signed arithmetic. See
 * ../REPORTABILITY.md: the older ISO-C shift-base warning was a model mismatch.
 * Register/control fields have their ISA widths; immediate arguments retain
 * their ENTIRE C type domain, including sign-extended negative immediates.
 * Their low 12/20 bits are encoded. No axioms or external-function stubs.
 */
#define inline inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

/*@ requires fields: funct7 < 128 && rs2 < 32 && rs1 < 32 && funct3 < 8 && rd < 32 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures rd_field: ((\result >> 7) & 31) == rd;
    ensures funct3_field: ((\result >> 12) & 7) == funct3;
    ensures rs1_field: ((\result >> 15) & 31) == rs1;
    ensures rs2_field: ((\result >> 20) & 31) == rs2;
    ensures funct7_field: (\result >> 25) == funct7;
 */
static inline u32 rv_r_insn(u8 funct7, u8 rs2, u8 rs1, u8 funct3, u8 rd,
			    u8 opcode)
{
	return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
		(rd << 7) | opcode;
}

/*@ requires fields: rs1 < 32 && funct3 < 8 && rd < 32 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures rd_field: ((\result >> 7) & 31) == rd;
    ensures funct3_field: ((\result >> 12) & 7) == funct3;
    ensures rs1_field: ((\result >> 15) & 31) == rs1;
    ensures immediate_field: (\result >> 20) == (imm11_0 & 4095);
 */
static inline u32 rv_i_insn(u16 imm11_0, u8 rs1, u8 funct3, u8 rd, u8 opcode)
{
	return (imm11_0 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) |
		opcode;
}

/*@ requires fields: rs2 < 32 && rs1 < 32 && funct3 < 8 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures funct3_field: ((\result >> 12) & 7) == funct3;
    ensures rs1_field: ((\result >> 15) & 31) == rs1;
    ensures rs2_field: ((\result >> 20) & 31) == rs2;
    ensures immediate_low: ((\result >> 7) & 31) == (imm11_0 & 31);
    ensures immediate_high: (\result >> 25) == ((imm11_0 >> 5) & 127);
 */
static inline u32 rv_s_insn(u16 imm11_0, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u8 imm11_5 = imm11_0 >> 5, imm4_0 = imm11_0 & 0x1f;

	return (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
		(imm4_0 << 7) | opcode;
}

/*@ requires fields: rs2 < 32 && rs1 < 32 && funct3 < 8 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures funct3_field: ((\result >> 12) & 7) == funct3;
    ensures rs1_field: ((\result >> 15) & 31) == rs1;
    ensures rs2_field: ((\result >> 20) & 31) == rs2;
    ensures immediate_4_1: ((\result >> 8) & 15) == (imm12_1 & 15);
    ensures immediate_10_5: ((\result >> 25) & 63) == ((imm12_1 >> 4) & 63);
    ensures immediate_11: ((\result >> 7) & 1) == ((imm12_1 >> 10) & 1);
    ensures immediate_12: (\result >> 31) == ((imm12_1 >> 11) & 1);
 */
static inline u32 rv_b_insn(u16 imm12_1, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u8 imm12 = ((imm12_1 & 0x800) >> 5) | ((imm12_1 & 0x3f0) >> 4);
	u8 imm4_1 = ((imm12_1 & 0xf) << 1) | ((imm12_1 & 0x400) >> 10);

	return (imm12 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) |
		(imm4_1 << 7) | opcode;
}

/*@ requires fields: rd < 32 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures rd_field: ((\result >> 7) & 31) == rd;
    ensures immediate_field: (\result >> 12) == (imm31_12 & 1048575);
 */
static inline u32 rv_u_insn(u32 imm31_12, u8 rd, u8 opcode)
{
	return (imm31_12 << 12) | (rd << 7) | opcode;
}

/*@ requires fields: rd < 32 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures rd_field: ((\result >> 7) & 31) == rd;
    ensures immediate_10_1: ((\result >> 21) & 1023) == (imm20_1 & 1023);
    ensures immediate_11: ((\result >> 20) & 1) == ((imm20_1 >> 10) & 1);
    ensures immediate_19_12: ((\result >> 12) & 255) == ((imm20_1 >> 11) & 255);
    ensures immediate_20: (\result >> 31) == ((imm20_1 >> 19) & 1);
 */
static inline u32 rv_j_insn(u32 imm20_1, u8 rd, u8 opcode)
{
	u32 imm;

	imm = (imm20_1 & 0x80000) | ((imm20_1 & 0x3ff) << 9) |
		((imm20_1 & 0x400) >> 2) | ((imm20_1 & 0x7f800) >> 11);

	return (imm << 12) | (rd << 7) | opcode;
}

/*@ requires fields: funct5 < 32 && aq < 2 && rl < 2 && rs2 < 32 && rs1 < 32 && funct3 < 8 && rd < 32 && opcode < 128;
    terminates \true;
    assigns \nothing;
    ensures opcode_field: (\result & 127) == opcode;
    ensures rd_field: ((\result >> 7) & 31) == rd;
    ensures funct3_field: ((\result >> 12) & 7) == funct3;
    ensures rs1_field: ((\result >> 15) & 31) == rs1;
    ensures rs2_field: ((\result >> 20) & 31) == rs2;
    ensures release_field: ((\result >> 25) & 1) == rl;
    ensures acquire_field: ((\result >> 26) & 1) == aq;
    ensures funct5_field: (\result >> 27) == funct5;
 */
static inline u32 rv_amo_insn(u8 funct5, u8 aq, u8 rl, u8 rs2, u8 rs1,
			      u8 funct3, u8 rd, u8 opcode)
{
	u8 funct7 = (funct5 << 2) | (aq << 1) | rl;

	return rv_r_insn(funct7, rs2, rs1, funct3, rd, opcode);
}

/* Project-only witnesses decode the encoded immediate; not kernel functions.
 * For B/J, input and result are halfword offsets (the implicit bit zero is
 * absent). No claim about execution, target alignment, or opcode legality.
 */
/*@ terminates \true; assigns \nothing;
    ensures roundtrip: \result == (immediate & 4095);
 */
u32 fragma_riscv_roundtrip_i(u16 immediate)
{
	u32 word = rv_i_insn(immediate, 31, 7, 31, 127);
	return word >> 20;
}

/*@ terminates \true; assigns \nothing;
    ensures roundtrip: \result == (immediate & 4095);
 */
u32 fragma_riscv_roundtrip_s(u16 immediate)
{
	u32 word = rv_s_insn(immediate, 31, 31, 7, 127);
	return ((word >> 7) & 31) | ((word >> 25) << 5);
}

/*@ terminates \true; assigns \nothing;
    ensures roundtrip: \result == (immediate & 4095);
 */
u32 fragma_riscv_roundtrip_b(u16 immediate)
{
	u32 word = rv_b_insn(immediate, 31, 31, 7, 127);
	return ((word >> 8) & 15) | (((word >> 25) & 63) << 4) |
		(((word >> 7) & 1) << 10) | ((word >> 31) << 11);
}

/*@ terminates \true; assigns \nothing;
    ensures roundtrip: \result == (immediate & 1048575);
 */
u32 fragma_riscv_roundtrip_u(u32 immediate)
{
	u32 word = rv_u_insn(immediate, 31, 127);
	return word >> 12;
}

/*@ terminates \true; assigns \nothing;
    ensures roundtrip: \result == (immediate & 1048575);
 */
u32 fragma_riscv_roundtrip_j(u32 immediate)
{
	u32 word = rv_j_insn(immediate, 31, 127);
	return ((word >> 21) & 1023) | (((word >> 20) & 1) << 10) |
		(((word >> 12) & 255) << 11) | ((word >> 31) << 19);
}

#include "encoder-fieldproof.h"
