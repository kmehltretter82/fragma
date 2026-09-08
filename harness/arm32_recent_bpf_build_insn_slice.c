/* SPDX-License-Identifier: GPL-2.0 */
/* Mechanically extracted from the pinned kernel source. The provenance
 * gate compares build_insn() token-for-token with the pinned Git blob.
 */
#include "arm32_recent_bpf_build_insn_model.h"
int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const u8 code = insn->code;
	const s8 *dst = bpf2a32[insn->dst_reg];
	const s8 *src = bpf2a32[insn->src_reg];
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s16 off = insn->off;
	const s32 imm = insn->imm;
	const int i = insn - ctx->prog->insnsi;
	const bool is64 = BPF_CLASS(code) == BPF_ALU64;
	const s8 *rd, *rs;
	s8 rd_lo, rt, rm, rn;
	s32 jmp_offset;

#define check_imm(bits, imm) do {				\
	if ((imm) >= (1 << ((bits) - 1)) ||			\
	    (imm) < -(1 << ((bits) - 1))) {			\
		pr_info("[%2d] imm=%d(0x%x) out of range\n",	\
			i, imm, imm);				\
		return -EINVAL;					\
	}							\
} while (0)
#define check_imm24(imm) check_imm(24, imm)

	switch (code) {
	/* ALU operations */

	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		switch (BPF_SRC(code)) {
		case BPF_X:
			if (imm == 1) {
				/* Special mov32 for zext */
				emit_a32_mov_i(dst_hi, 0, ctx);
				break;
			}
			if (insn->off)
				emit_a32_movsx_r64(is64, insn->off, dst, src, ctx);
			else
				emit_a32_mov_r64(is64, dst, src, ctx);
			break;
		case BPF_K:
			/* Sign-extend immediate value to destination reg */
			emit_a32_mov_se_i64(is64, dst, imm, ctx);
			break;
		}
		break;
	/* dst = dst + src/imm */
	/* dst = dst - src/imm */
	/* dst = dst | src/imm */
	/* dst = dst & src/imm */
	/* dst = dst ^ src/imm */
	/* dst = dst * src/imm */
	/* dst = dst << src */
	/* dst = dst >> src */
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		switch (BPF_SRC(code)) {
		case BPF_X:
			emit_a32_alu_r64(is64, dst, src, ctx, BPF_OP(code));
			break;
		case BPF_K:
			/* Move immediate value to the temporary register
			 * and then do the ALU operation on the temporary
			 * register as this will sign-extend the immediate
			 * value into temporary reg and then it would be
			 * safe to do the operation on it.
			 */
			emit_a32_mov_se_i64(is64, tmp2, imm, ctx);
			emit_a32_alu_r64(is64, dst, tmp2, ctx, BPF_OP(code));
			break;
		}
		break;
	/* dst = dst / src(imm) */
	/* dst = dst % src(imm) */
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_X:
		rd_lo = arm_bpf_get_reg32(dst_lo, tmp2[1], ctx);
		switch (BPF_SRC(code)) {
		case BPF_X:
			rt = arm_bpf_get_reg32(src_lo, tmp2[0], ctx);
			break;
		case BPF_K:
			rt = tmp2[0];
			emit_a32_mov_i(rt, imm, ctx);
			break;
		default:
			rt = src_lo;
			break;
		}
		emit_udivmod(rd_lo, rd_lo, rt, ctx, BPF_OP(code), off);
		arm_bpf_put_reg32(dst_lo, rd_lo, ctx);
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(dst_hi, 0, ctx);
		break;
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_X:
		rd = arm_bpf_get_reg64(dst, tmp2, ctx);
		switch (BPF_SRC(code)) {
		case BPF_X:
			rs = arm_bpf_get_reg64(src, tmp, ctx);
			break;
		case BPF_K:
			rs = tmp;
			emit_a32_mov_se_i64(is64, rs, imm, ctx);
			break;
		}
		emit_udivmod64(rd, rd, rs, ctx, BPF_OP(code), off);
		arm_bpf_put_reg64(dst, rd, ctx);
		break;
	/* dst = dst << imm */
	/* dst = dst >> imm */
	/* dst = dst >> imm (signed) */
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_ARSH | BPF_K:
		if (unlikely(imm > 31))
			return -EINVAL;
		if (imm)
			emit_a32_alu_i(dst_lo, imm, ctx, BPF_OP(code));
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(dst_hi, 0, ctx);
		break;
	/* dst = dst << imm */
	case BPF_ALU64 | BPF_LSH | BPF_K:
		if (unlikely(imm > 63))
			return -EINVAL;
		emit_a32_lsh_i64(dst, imm, ctx);
		break;
	/* dst = dst >> imm */
	case BPF_ALU64 | BPF_RSH | BPF_K:
		if (unlikely(imm > 63))
			return -EINVAL;
		emit_a32_rsh_i64(dst, imm, ctx);
		break;
	/* dst = dst << src */
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit_a32_lsh_r64(dst, src, ctx);
		break;
	/* dst = dst >> src */
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit_a32_rsh_r64(dst, src, ctx);
		break;
	/* dst = dst >> src (signed) */
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit_a32_arsh_r64(dst, src, ctx);
		break;
	/* dst = dst >> imm (signed) */
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		if (unlikely(imm > 63))
			return -EINVAL;
		emit_a32_arsh_i64(dst, imm, ctx);
		break;
	/* dst = ~dst */
	case BPF_ALU | BPF_NEG:
		emit_a32_alu_i(dst_lo, 0, ctx, BPF_OP(code));
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(dst_hi, 0, ctx);
		break;
	/* dst = ~dst (64 bit) */
	case BPF_ALU64 | BPF_NEG:
		emit_a32_neg64(dst, ctx);
		break;
	/* dst = dst * src/imm */
	case BPF_ALU64 | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		switch (BPF_SRC(code)) {
		case BPF_X:
			emit_a32_mul_r64(dst, src, ctx);
			break;
		case BPF_K:
			/* Move immediate value to the temporary register
			 * and then do the multiplication on it as this
			 * will sign-extend the immediate value into temp
			 * reg then it would be safe to do the operation
			 * on it.
			 */
			emit_a32_mov_se_i64(is64, tmp2, imm, ctx);
			emit_a32_mul_r64(dst, tmp2, ctx);
			break;
		}
		break;
	/* dst = htole(dst) */
	/* dst = htobe(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE: /* also BPF_TO_LE */
	case BPF_ALU | BPF_END | BPF_FROM_BE: /* also BPF_TO_BE */
	/* dst = bswap(dst) */
	case BPF_ALU64 | BPF_END | BPF_FROM_LE: /* also BPF_TO_LE */
		rd = arm_bpf_get_reg64(dst, tmp, ctx);
		if (BPF_SRC(code) == BPF_FROM_LE && BPF_CLASS(code) != BPF_ALU64)
			goto emit_bswap_uxt;
		switch (imm) {
		case 16:
			emit_rev16(rd[1], rd[1], ctx);
			goto emit_bswap_uxt;
		case 32:
			emit_rev32(rd[1], rd[1], ctx);
			goto emit_bswap_uxt;
		case 64:
			emit_rev32(ARM_LR, rd[1], ctx);
			emit_rev32(rd[1], rd[0], ctx);
			emit(ARM_MOV_R(rd[0], ARM_LR), ctx);
			break;
		}
		goto exit;
emit_bswap_uxt:
		switch (imm) {
		case 16:
			/* zero-extend 16 bits into 64 bits */
#if __LINUX_ARM_ARCH__ < 6
			emit_a32_mov_i(tmp2[1], 0xffff, ctx);
			emit(ARM_AND_R(rd[1], rd[1], tmp2[1]), ctx);
#else /* ARMv6+ */
			emit(ARM_UXTH(rd[1], rd[1]), ctx);
#endif
			if (!ctx->prog->aux->verifier_zext)
				emit(ARM_EOR_R(rd[0], rd[0], rd[0]), ctx);
			break;
		case 32:
			/* zero-extend 32 bits into 64 bits */
			if (!ctx->prog->aux->verifier_zext)
				emit(ARM_EOR_R(rd[0], rd[0], rd[0]), ctx);
			break;
		case 64:
			/* nop */
			break;
		}
exit:
		arm_bpf_put_reg64(dst, rd, ctx);
		break;
	/* dst = imm64 */
	case BPF_LD | BPF_IMM | BPF_DW:
	{
		u64 val = (u32)imm | (u64)insn[1].imm << 32;

		if (insn->src_reg == BPF_PSEUDO_FUNC)
			goto notyet;

		emit_a32_mov_i64(dst, val, ctx);

		return 1;
	}
	/* LDX: dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_DW:
	/* LDSX: dst = *(signed size *)(src + off) */
	case BPF_LDX | BPF_MEMSX | BPF_B:
	case BPF_LDX | BPF_MEMSX | BPF_H:
	case BPF_LDX | BPF_MEMSX | BPF_W:
		rn = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
		if (BPF_MODE(insn->code) == BPF_MEMSX)
			emit_ldsx_r(dst, rn, off, ctx, BPF_SIZE(code));
		else
			emit_ldx_r(dst, rn, off, ctx, BPF_SIZE(code));
		break;
	/* speculation barrier */
	case BPF_ST | BPF_NOSPEC:
		break;
	/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		switch (BPF_SIZE(code)) {
		case BPF_DW:
			/* Sign-extend immediate value into temp reg */
			emit_a32_mov_se_i64(true, tmp2, imm, ctx);
			break;
		case BPF_W:
		case BPF_H:
		case BPF_B:
			emit_a32_mov_i(tmp2[1], imm, ctx);
			break;
		}
		emit_str_r(dst_lo, tmp2, off, ctx, BPF_SIZE(code));
		break;
	/* Atomic ops */
	case BPF_STX | BPF_ATOMIC | BPF_W:
	case BPF_STX | BPF_ATOMIC | BPF_DW:
		goto notyet;
	/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_DW:
		rs = arm_bpf_get_reg64(src, tmp2, ctx);
		emit_str_r(dst_lo, rs, off, ctx, BPF_SIZE(code));
		break;
	/* PC += off if dst == src */
	/* PC += off if dst > src */
	/* PC += off if dst >= src */
	/* PC += off if dst < src */
	/* PC += off if dst <= src */
	/* PC += off if dst != src */
	/* PC += off if dst > src (signed) */
	/* PC += off if dst >= src (signed) */
	/* PC += off if dst < src (signed) */
	/* PC += off if dst <= src (signed) */
	/* PC += off if dst & src */
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		/* Setup source registers */
		rm = arm_bpf_get_reg32(src_hi, tmp2[0], ctx);
		rn = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
		goto go_jmp;
	/* PC += off if dst == imm */
	/* PC += off if dst > imm */
	/* PC += off if dst >= imm */
	/* PC += off if dst < imm */
	/* PC += off if dst <= imm */
	/* PC += off if dst != imm */
	/* PC += off if dst > imm (signed) */
	/* PC += off if dst >= imm (signed) */
	/* PC += off if dst < imm (signed) */
	/* PC += off if dst <= imm (signed) */
	/* PC += off if dst & imm */
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		if (off == 0)
			break;
		rm = tmp2[0];
		rn = tmp2[1];
		/* Sign-extend immediate value */
		emit_a32_mov_se_i64(true, tmp2, imm, ctx);
go_jmp:
		/* Setup destination register */
		rd = arm_bpf_get_reg64(dst, tmp, ctx);

		/* Check for the condition */
		emit_ar_r(rd[0], rd[1], rm, rn, ctx, BPF_OP(code),
			  BPF_CLASS(code) == BPF_JMP);

		/* Setup JUMP instruction */
		jmp_offset = bpf2a32_offset(i+off, i, ctx);
		switch (BPF_OP(code)) {
		case BPF_JNE:
		case BPF_JSET:
			_emit(ARM_COND_NE, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JEQ:
			_emit(ARM_COND_EQ, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JGT:
			_emit(ARM_COND_HI, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JGE:
			_emit(ARM_COND_CS, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSGT:
			_emit(ARM_COND_LT, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSGE:
			_emit(ARM_COND_GE, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JLE:
			_emit(ARM_COND_LS, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JLT:
			_emit(ARM_COND_CC, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSLT:
			_emit(ARM_COND_LT, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSLE:
			_emit(ARM_COND_GE, ARM_B(jmp_offset), ctx);
			break;
		}
		break;
	/* JMP OFF */
	case BPF_JMP | BPF_JA:
	case BPF_JMP32 | BPF_JA:
	{
		if (BPF_CLASS(code) == BPF_JMP32 && imm != 0)
			jmp_offset = bpf2a32_offset(i + imm, i, ctx);
		else if (BPF_CLASS(code) == BPF_JMP && off != 0)
			jmp_offset = bpf2a32_offset(i + off, i, ctx);
		else
			break;

		check_imm24(jmp_offset);
		emit(ARM_B(jmp_offset), ctx);
		break;
	}
	/* tail call */
	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(ctx))
			return -EFAULT;
		break;
	/* function call */
	case BPF_JMP | BPF_CALL:
	{
		const s8 *r0 = bpf2a32[BPF_REG_0];
		const s8 *r1 = bpf2a32[BPF_REG_1];
		const s8 *r2 = bpf2a32[BPF_REG_2];
		const s8 *r3 = bpf2a32[BPF_REG_3];
		const s8 *r4 = bpf2a32[BPF_REG_4];
		const s8 *r5 = bpf2a32[BPF_REG_5];
		const u32 func = (u32)__bpf_call_base + (u32)imm;

		if (insn->src_reg == BPF_PSEUDO_CALL)
			goto notyet;

		emit_a32_mov_r64(true, r0, r1, ctx);
		emit_a32_mov_r64(true, r1, r2, ctx);
		emit_push_r64(r5, ctx);
		emit_push_r64(r4, ctx);
		emit_push_r64(r3, ctx);

		emit_a32_mov_i(tmp[1], func, ctx);
		emit_blx_r(tmp[1], ctx);

		emit(ARM_ADD_I(ARM_SP, ARM_SP, imm8m(24)), ctx); // callee clean
		break;
	}
	/* function return */
	case BPF_JMP | BPF_EXIT:
		/* Optimization: when last instruction is EXIT
		 * simply fallthrough to epilogue.
		 */
		if (i == ctx->prog->len - 1)
			break;
		jmp_offset = epilogue_offset(ctx);
		check_imm24(jmp_offset);
		emit(ARM_B(jmp_offset), ctx);
		break;
notyet:
		pr_info_once("*** NOT YET: opcode %02x ***\n", code);
		return -EFAULT;
	default:
		pr_err_once("unknown opcode %02x\n", code);
		return -EINVAL;
	}

	if (ctx->flags & FLAG_IMM_OVERFLOW)
		/*
		 * this instruction generated an overflow when
		 * trying to access the literal pool, so
		 * delegate this filter to the kernel interpreter.
		 */
		return -1;
	return 0;
}
