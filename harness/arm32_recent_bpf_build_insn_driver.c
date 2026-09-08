/* SPDX-License-Identifier: GPL-2.0 */
/* Broad verifier-shaped first pass. It does not encode an expected JIT result. */
#include "arm32_recent_bpf_build_insn_model.h"

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

/* Fake-pass dependency model: build_body() first calls the JIT with no output
 * buffer. These stubs intentionally expose only build_insn()'s direct C
 * operations. A helper-closure pass replaces them with source-gated bodies.
 */
void _emit(int cond, u32 instruction, struct jit_ctx *ctx)
{
	(void)cond; (void)instruction; (void)ctx;
}

void emit(u32 instruction, struct jit_ctx *ctx)
{
	(void)instruction; (void)ctx;
}

s8 arm_bpf_get_reg32(s8 reg, s8 tmp, struct jit_ctx *ctx)
{
	(void)reg; (void)ctx; return tmp;
}

const s8 *arm_bpf_get_reg64(const s8 *reg, const s8 *tmp,
			    struct jit_ctx *ctx)
{
	(void)reg; (void)ctx; return tmp;
}

void arm_bpf_put_reg32(s8 reg, s8 src, struct jit_ctx *ctx)
{
	(void)reg; (void)src; (void)ctx;
}

void arm_bpf_put_reg64(const s8 *reg, const s8 *src, struct jit_ctx *ctx)
{
	(void)reg; (void)src; (void)ctx;
}

int bpf2a32_offset(int to, int from, const struct jit_ctx *ctx)
{
	(void)to; (void)from; (void)ctx; return 0;
}

int epilogue_offset(const struct jit_ctx *ctx)
{
	(void)ctx; return 0;
}

int emit_bpf_tail_call(struct jit_ctx *ctx)
{
	(void)ctx; return 0;
}

void emit_blx_r(u8 reg, struct jit_ctx *ctx)
{
	(void)reg; (void)ctx;
}

void emit_push_r64(const s8 *src, struct jit_ctx *ctx)
{
	(void)src; (void)ctx;
}

void emit_rev16(u8 dst, u8 src, struct jit_ctx *ctx)
{
	(void)dst; (void)src; (void)ctx;
}

void emit_rev32(u8 dst, u8 src, struct jit_ctx *ctx)
{
	(void)dst; (void)src; (void)ctx;
}

void emit_a32_alu_i(s8 dst, u32 value, struct jit_ctx *ctx, u8 op)
{
	(void)dst; (void)value; (void)ctx; (void)op;
}

void emit_a32_alu_r64(bool is64, const s8 *dst, const s8 *src,
		      struct jit_ctx *ctx, u8 op)
{
	(void)is64; (void)dst; (void)src; (void)ctx; (void)op;
}

void emit_a32_arsh_i64(const s8 *dst, u32 value, struct jit_ctx *ctx)
{
	(void)dst; (void)value; (void)ctx;
}

void emit_a32_arsh_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx)
{
	(void)dst; (void)src; (void)ctx;
}

void emit_a32_lsh_i64(const s8 *dst, u32 value, struct jit_ctx *ctx)
{
	(void)dst; (void)value; (void)ctx;
}

void emit_a32_lsh_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx)
{
	(void)dst; (void)src; (void)ctx;
}

void emit_a32_mov_i(s8 dst, u32 value, struct jit_ctx *ctx)
{
	(void)dst; (void)value; (void)ctx;
}

void emit_a32_mov_i64(const s8 *dst, u64 value, struct jit_ctx *ctx)
{
	(void)dst; (void)value; (void)ctx;
}

void emit_a32_mov_r64(bool is64, const s8 *dst, const s8 *src,
		      struct jit_ctx *ctx)
{
	(void)is64; (void)dst; (void)src; (void)ctx;
}

void emit_a32_mov_se_i64(bool is64, const s8 *dst, u32 value,
			 struct jit_ctx *ctx)
{
	(void)is64; (void)dst; (void)value; (void)ctx;
}

void emit_a32_movsx_r64(bool is64, u8 off, const s8 *dst, const s8 *src,
			struct jit_ctx *ctx)
{
	(void)is64; (void)off; (void)dst; (void)src; (void)ctx;
}

void emit_a32_mul_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx)
{
	(void)dst; (void)src; (void)ctx;
}

void emit_a32_neg64(const s8 *dst, struct jit_ctx *ctx)
{
	(void)dst; (void)ctx;
}

void emit_a32_rsh_i64(const s8 *dst, u32 value, struct jit_ctx *ctx)
{
	(void)dst; (void)value; (void)ctx;
}

void emit_a32_rsh_r64(const s8 *dst, const s8 *src, struct jit_ctx *ctx)
{
	(void)dst; (void)src; (void)ctx;
}

void emit_ar_r(u8 rd, u8 rt, u8 rm, u8 rn, struct jit_ctx *ctx, u8 op,
	       bool is_jmp64)
{
	(void)rd; (void)rt; (void)rm; (void)rn; (void)ctx; (void)op;
	(void)is_jmp64;
}

void emit_ldsx_r(const s8 *dst, s8 src, s16 off, struct jit_ctx *ctx, u8 size)
{
	(void)dst; (void)src; (void)off; (void)ctx; (void)size;
}

void emit_ldx_r(const s8 *dst, s8 src, s16 off, struct jit_ctx *ctx, u8 size)
{
	(void)dst; (void)src; (void)off; (void)ctx; (void)size;
}

void emit_str_r(s8 dst, const s8 *src, s16 off, struct jit_ctx *ctx, u8 size)
{
	(void)dst; (void)src; (void)off; (void)ctx; (void)size;
}

void emit_udivmod(u8 rd, u8 rm, u8 rn, struct jit_ctx *ctx, u8 op, u8 sign)
{
	(void)rd; (void)rm; (void)rn; (void)ctx; (void)op; (void)sign;
}

void emit_udivmod64(const s8 *rd, const s8 *rm, const s8 *rn,
		    struct jit_ctx *ctx, u8 op, u8 sign)
{
	(void)rd; (void)rm; (void)rn; (void)ctx; (void)op; (void)sign;
}

static struct bpf_prog fragma_prog;
static struct bpf_prog_aux fragma_aux;
static u32 fragma_offsets[4];

void fragma_arm32_bpf_build_insn(void)
{
	unsigned int code = Frama_C_unsigned_int_interval(0, 255);
	unsigned int dst = Frama_C_unsigned_int_interval(BPF_REG_0, BPF_REG_10);
	unsigned int src = Frama_C_unsigned_int_interval(BPF_REG_0, BPF_REG_10);
	struct jit_ctx ctx = { 0 };

	fragma_prog.len = 3;
	fragma_prog.aux = &fragma_aux;
	fragma_prog.insnsi[0].code = (u8)code;
	fragma_prog.insnsi[0].dst_reg = (u8)dst;
	fragma_prog.insnsi[0].src_reg = (u8)src;
	/* At instruction zero, off == 0 names the following instruction and is
	 * valid for every branch class accepted by the verifier.
	 */
	fragma_prog.insnsi[0].off = 0;
	fragma_prog.insnsi[0].imm = (s32)Frama_C_unsigned_int_interval(0, ~0U);
	fragma_prog.insnsi[1].code = BPF_JMP | BPF_EXIT;
	fragma_prog.insnsi[2].code = BPF_JMP | BPF_EXIT;

	ctx.prog = &fragma_prog;
	ctx.offsets = fragma_offsets;
	ctx.target = NULL;
	ctx.epilogue_offset = 0;
	fragma_aux.verifier_zext = Frama_C_unsigned_int_interval(0, 1);

	/*@ assert arm32_bpf_build_insn_driver_domain:
	      code <= 255 && dst <= BPF_REG_10 && src <= BPF_REG_10; */
	(void)build_insn(&fragma_prog.insnsi[0], &ctx);

	/* Verifier-permitted MOVSX widths exercise the nonzero off path. */
	switch (Frama_C_unsigned_int_interval(0, 2)) {
	case 0: fragma_prog.insnsi[0].off = 8; break;
	case 1: fragma_prog.insnsi[0].off = 16; break;
	default: fragma_prog.insnsi[0].off = 32; break;
	}
	fragma_prog.insnsi[0].code = BPF_ALU64 | BPF_MOV | BPF_X;
	(void)build_insn(&fragma_prog.insnsi[0], &ctx);

	/* A one-instruction conditional branch in the three-insn program. */
	fragma_prog.insnsi[0].code = BPF_JMP | BPF_JEQ | BPF_K;
	fragma_prog.insnsi[0].off = 1;
	(void)build_insn(&fragma_prog.insnsi[0], &ctx);
}
