/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal ARMv7/BPF declarations for the source-identical build_insn() slice.
 * The first analyzer pass deliberately treats instruction-emission helpers as
 * external dependencies.  Their contracts are refined only after raw triage.
 */
#ifndef FRAGMA_ARM32_RECENT_BPF_BUILD_INSN_MODEL_H
#define FRAGMA_ARM32_RECENT_BPF_BUILD_INSN_MODEL_H

#include "arm32_recent_specs.h"

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned int size_t;
typedef _Bool bool;

#define true 1
#define false 0
#define NULL ((void *)0)
#define __LINUX_ARM_ARCH__ 7

#define EFAULT 14
#define EINVAL 22

#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_JMP32 0x06
#define BPF_ALU64 0x07

#define BPF_SIZE(code) ((code) & 0x18)
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10
#define BPF_DW 0x18

#define BPF_MODE(code) ((code) & 0xe0)
#define BPF_IMM 0x00
#define BPF_MEM 0x60
#define BPF_MEMSX 0x80
#define BPF_ATOMIC 0xc0

#define BPF_OP(code) ((code) & 0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR 0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_MOD 0x90
#define BPF_XOR 0xa0
#define BPF_MOV 0xb0
#define BPF_ARSH 0xc0
#define BPF_END 0xd0

#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40
#define BPF_JNE 0x50
#define BPF_JSGT 0x60
#define BPF_JSGE 0x70
#define BPF_CALL 0x80
#define BPF_EXIT 0x90
#define BPF_JLT 0xa0
#define BPF_JLE 0xb0
#define BPF_JSLT 0xc0
#define BPF_JSLE 0xd0

#define BPF_SRC(code) ((code) & 0x08)
#define BPF_K 0x00
#define BPF_X 0x08
#define BPF_TO_LE 0x00
#define BPF_TO_BE 0x08
#define BPF_FROM_LE BPF_TO_LE
#define BPF_FROM_BE BPF_TO_BE

#define BPF_TAIL_CALL 0xf0
#define BPF_NOSPEC 0xc0
#define BPF_PSEUDO_CALL 1
#define BPF_PSEUDO_FUNC 4

enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};
#define MAX_BPF_REG __MAX_BPF_REG
#define BPF_REG_FP BPF_REG_10
#define BPF_REG_AX (MAX_BPF_REG + 1)
#define MAX_BPF_EXT_REG (MAX_BPF_REG + 2)
#define MAX_BPF_JIT_REG MAX_BPF_EXT_REG
#define TMP_REG_1 (MAX_BPF_JIT_REG + 0)
#define TMP_REG_2 (MAX_BPF_JIT_REG + 1)
#define FLAG_IMM_OVERFLOW (1U << 0)

#define ARM_R0 0
#define ARM_R1 1
#define ARM_R2 2
#define ARM_R3 3
#define ARM_R4 4
#define ARM_R5 5
#define ARM_R6 6
#define ARM_R7 7
#define ARM_R8 8
#define ARM_R9 9
#define ARM_FP 11
#define ARM_IP 12
#define ARM_SP 13
#define ARM_LR 14

#define ARM_COND_EQ 0x0
#define ARM_COND_NE 0x1
#define ARM_COND_CS 0x2
#define ARM_COND_CC 0x3
#define ARM_COND_HI 0x8
#define ARM_COND_LS 0x9
#define ARM_COND_GE 0xa
#define ARM_COND_LT 0xb

#define ARM_INST_ADD_I 0x02800000U
#define ARM_INST_AND_R 0x00000000U
#define ARM_INST_B 0x0a000000U
#define ARM_INST_EOR_R 0x00200000U
#define ARM_INST_MOV_R 0x01a00000U
#define ARM_INST_UXTH 0x06ff0070U
#define _AL3_R(op, rd, rn, rm) ((op ## _R) | (rd) << 12 | (rn) << 16 | (rm))
#define _AL3_I(op, rd, rn, imm) ((op ## _I) | (rd) << 12 | (rn) << 16 | (imm))
#define ARM_ADD_I(rd, rn, imm) _AL3_I(ARM_INST_ADD, rd, rn, imm)
#define ARM_AND_R(rd, rn, rm) _AL3_R(ARM_INST_AND, rd, rn, rm)
#define ARM_B(imm24) (ARM_INST_B | ((imm24) & 0xffffff))
#define ARM_EOR_R(rd, rn, rm) _AL3_R(ARM_INST_EOR, rd, rn, rm)
#define ARM_MOV_R(rd, rm) _AL3_R(ARM_INST_MOV, rd, 0, rm)
#define ARM_UXTH(rd, rm) (ARM_INST_UXTH | (rd) << 12 | (rm))
#define imm8m(value) (value)

#define unlikely(value) (value)
#define pr_err_once(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_info_once(...) ((void)0)

struct bpf_insn {
	u8 code;
	u8 dst_reg:4;
	u8 src_reg:4;
	s16 off;
	s32 imm;
};

struct bpf_prog_aux {
	bool verifier_zext;
};

struct bpf_prog {
	u32 len;
	void *bpf_func;
	struct bpf_prog_aux *aux;
	struct bpf_insn insnsi[3];
};

struct jit_ctx {
	const struct bpf_prog *prog;
	unsigned int idx;
	unsigned int prologue_bytes;
	unsigned int epilogue_offset;
	unsigned int cpu_architecture;
	u32 flags;
	u32 *offsets;
	u32 *target;
	u32 stack_size;
};

static const s8 bpf2a32[MAX_BPF_JIT_REG + 2][2] = {
	[BPF_REG_0] = { ARM_R1, ARM_R0 },
	[BPF_REG_1] = { ARM_R3, ARM_R2 },
	[BPF_REG_2] = { -4, -8 },
	[BPF_REG_3] = { -12, -16 },
	[BPF_REG_4] = { -20, -24 },
	[BPF_REG_5] = { -28, -32 },
	[BPF_REG_6] = { ARM_R5, ARM_R4 },
	[BPF_REG_7] = { -36, -40 },
	[BPF_REG_8] = { -44, -48 },
	[BPF_REG_9] = { -52, -56 },
	[BPF_REG_FP] = { -60, -64 },
	[TMP_REG_1] = { ARM_R7, ARM_R6 },
	[TMP_REG_2] = { ARM_R9, ARM_R8 },
	[BPF_REG_AX] = { -76, -80 },
};

#define dst_lo dst[1]
#define dst_hi dst[0]
#define src_lo src[1]
#define src_hi src[0]

void _emit(int cond, u32 instruction, struct jit_ctx *ctx);
void emit(u32 instruction, struct jit_ctx *ctx);
s8 arm_bpf_get_reg32(s8 reg, s8 tmp, struct jit_ctx *ctx);
const s8 *arm_bpf_get_reg64(const s8 *reg, const s8 *tmp,
			    struct jit_ctx *ctx);
void arm_bpf_put_reg32(s8 reg, s8 src, struct jit_ctx *ctx);
void arm_bpf_put_reg64(const s8 *reg, const s8 *src, struct jit_ctx *ctx);
int bpf2a32_offset(int to, int from, const struct jit_ctx *ctx);
int epilogue_offset(const struct jit_ctx *ctx);
int emit_bpf_tail_call(struct jit_ctx *ctx);
void emit_blx_r(u8 reg, struct jit_ctx *ctx);
void emit_push_r64(const s8 *src, struct jit_ctx *ctx);
void emit_rev16(u8 dst, u8 src, struct jit_ctx *ctx);
void emit_rev32(u8 dst, u8 src, struct jit_ctx *ctx);
u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

/* The first direct-operation pass models these emitters as inert calls. */
void emit_a32_alu_i(s8 dst, u32 value, struct jit_ctx *ctx, u8 op);
void emit_a32_alu_r64(bool is64, const s8 *dst, const s8 *src,
		      struct jit_ctx *ctx, u8 op);
void emit_a32_arsh_i64(const s8 *dst, u32 value, struct jit_ctx *ctx);
void emit_a32_arsh_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx);
void emit_a32_lsh_i64(const s8 *dst, u32 value, struct jit_ctx *ctx);
void emit_a32_lsh_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx);
void emit_a32_mov_i(s8 dst, u32 value, struct jit_ctx *ctx);
void emit_a32_mov_i64(const s8 *dst, u64 value, struct jit_ctx *ctx);
void emit_a32_mov_r64(bool is64, const s8 *dst, const s8 *src,
		      struct jit_ctx *ctx);
void emit_a32_mov_se_i64(bool is64, const s8 *dst, u32 value,
			 struct jit_ctx *ctx);
void emit_a32_movsx_r64(bool is64, u8 off, const s8 *dst, const s8 *src,
			struct jit_ctx *ctx);
void emit_a32_mul_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx);
void emit_a32_neg64(const s8 *dst, struct jit_ctx *ctx);
void emit_a32_rsh_i64(const s8 *dst, u32 value, struct jit_ctx *ctx);
void emit_a32_rsh_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx);
void emit_ar_r(u8 rd, u8 rt, u8 rm, u8 rn, struct jit_ctx *ctx, u8 op,
	       bool is_jmp64);
void emit_ldsx_r(const s8 *dst, s8 src, s16 off, struct jit_ctx *ctx, u8 size);
void emit_ldx_r(const s8 *dst, s8 src, s16 off, struct jit_ctx *ctx, u8 size);
void emit_str_r(s8 dst, const s8 *src, s16 off, struct jit_ctx *ctx, u8 size);
void emit_udivmod(u8 rd, u8 rm, u8 rn, struct jit_ctx *ctx, u8 op, u8 sign);
void emit_udivmod64(const s8 *rd, const s8 *rm, const s8 *rn,
		    struct jit_ctx *ctx, u8 op, u8 sign);

int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx);

#endif /* FRAGMA_ARM32_RECENT_BPF_BUILD_INSN_MODEL_H */
