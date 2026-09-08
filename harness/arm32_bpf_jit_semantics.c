/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef BPF_JMP32
#define BPF_JMP32 0x06
#endif
#ifndef BPF_ALU64
#define BPF_ALU64 0x07
#endif
#ifndef BPF_DW
#define BPF_DW 0x18
#endif

#define I(C, D, S, O, M) ((struct bpf_insn) { \
	.code = (C), .dst_reg = (D), .src_reg = (S), .off = (O), .imm = (M) })

static int failures;
static int passes;

static int bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int load_program(const struct bpf_insn *insns, size_t count, char *log,
			size_t log_size)
{
	static const char license[] = "GPL";
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = count;
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;
	attr.log_buf = (uintptr_t)log;
	attr.log_size = log_size;
	attr.log_level = 1;
	return bpf_sys(BPF_PROG_LOAD, &attr);
}

static int run_program(int fd, uint32_t *retval)
{
	unsigned char input[64] = { 0 };
	unsigned char output[128] = { 0 };
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = fd;
	attr.test.data_in = (uintptr_t)input;
	attr.test.data_out = (uintptr_t)output;
	attr.test.data_size_in = sizeof(input);
	attr.test.data_size_out = sizeof(output);
	attr.test.repeat = 1;
	if (bpf_sys(BPF_PROG_TEST_RUN, &attr))
		return -1;
	*retval = attr.test.retval;
	return 0;
}

static void check(const char *name, struct bpf_insn *insns, size_t count,
		  uint32_t expected)
{
	char log[65536] = { 0 };
	uint32_t actual = 0;
	int fd = load_program(insns, count, log, sizeof(log));

	if (fd < 0) {
		printf("FRAGMA_BPF: LOAD_FAIL %-30s errno=%d %s\n%s\n",
		       name, errno, strerror(errno), log);
		failures++;
		return;
	}
	if (run_program(fd, &actual)) {
		printf("FRAGMA_BPF: RUN_FAIL  %-30s errno=%d %s\n",
		       name, errno, strerror(errno));
		failures++;
	} else if (actual != expected) {
		printf("FRAGMA_BPF: MISMATCH  %-30s got=%08x expected=%08x\n",
		       name, actual, expected);
		failures++;
	} else {
		printf("FRAGMA_BPF: PASS      %-30s value=%08x\n", name, actual);
		passes++;
	}
	close(fd);
}

static size_t ld64(struct bpf_insn *out, unsigned int reg, uint64_t value)
{
	out[0] = I(BPF_LD | BPF_DW | BPF_IMM, reg, 0, 0, (int32_t)value);
	out[1] = I(0, 0, 0, 0, (int32_t)(value >> 32));
	return 2;
}

static size_t expose_high32(struct bpf_insn *out)
{
	/* The retained ARM32 configuration is little-endian. Observe R0's high
	 * half without using another arithmetic instruction from build_insn().
	 */
	out[0] = I(BPF_STX | BPF_DW | BPF_MEM, BPF_REG_10, BPF_REG_0, -8, 0);
	out[1] = I(BPF_LDX | BPF_W | BPF_MEM, BPF_REG_0, BPF_REG_10, -4, 0);
	return 2;
}

static void check_mov64(const char *name, uint64_t value, int high)
{
	struct bpf_insn p[6];
	size_t n = ld64(p, BPF_REG_0, value);
	if (high)
		n += expose_high32(p + n);
	p[n++] = I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	check(name, p, n, high ? (uint32_t)(value >> 32) : (uint32_t)value);
}

static uint64_t alu64_expected(uint8_t op, uint64_t a, uint64_t b)
{
	switch (op) {
	case BPF_ADD: return a + b;
	case BPF_SUB: return a - b;
	case BPF_MUL: return a * b;
	case BPF_OR: return a | b;
	case BPF_AND: return a & b;
	case BPF_XOR: return a ^ b;
	case BPF_LSH: return a << (b & 63);
	case BPF_RSH: return a >> (b & 63);
	default: abort();
	}
}

static void check_alu64_reg(const char *name, uint8_t op, uint64_t a,
			    uint64_t b, int high)
{
	struct bpf_insn p[10];
	uint64_t expected = alu64_expected(op, a, b);
	size_t n = ld64(p, BPF_REG_0, a);
	n += ld64(p + n, BPF_REG_2, b);
	p[n++] = I(BPF_ALU64 | op | BPF_X, BPF_REG_0, BPF_REG_2, 0, 0);
	if (high)
		n += expose_high32(p + n);
	p[n++] = I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	check(name, p, n, high ? (uint32_t)(expected >> 32) : (uint32_t)expected);
}

static void check_shift_imm(const char *name, uint8_t op, uint64_t value,
			    unsigned int shift, int high, int is64)
{
	struct bpf_insn p[8];
	uint64_t expected;
	size_t n = ld64(p, BPF_REG_0, value);

	if (is64) {
		if (op == BPF_LSH)
			expected = value << shift;
		else if (op == BPF_RSH)
			expected = value >> shift;
		else
			expected = (uint64_t)((int64_t)value >> shift);
		p[n++] = I(BPF_ALU64 | op | BPF_K, BPF_REG_0, 0, 0, shift);
	} else {
		uint32_t low = value;
		if (op == BPF_LSH)
			low <<= shift;
		else if (op == BPF_RSH)
			low >>= shift;
		else
			low = (uint32_t)((int32_t)low >> shift);
		expected = low;
		p[n++] = I(BPF_ALU | op | BPF_K, BPF_REG_0, 0, 0, shift);
	}
	if (high)
		n += expose_high32(p + n);
	p[n++] = I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	check(name, p, n, high ? (uint32_t)(expected >> 32) : (uint32_t)expected);
}

static void check_movsx(const char *name, uint64_t value, unsigned int width,
			int alu64, int high)
{
	struct bpf_insn p[9];
	uint64_t expected;
	size_t n = ld64(p, BPF_REG_2, value);

	if (alu64) {
		if (width == 8)
			expected = (int8_t)value;
		else if (width == 16)
			expected = (int16_t)value;
		else
			expected = (int32_t)value;
		p[n++] = I(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_2,
			   width, 0);
	} else {
		uint32_t low = width == 8 ? (int8_t)value : (int16_t)value;
		expected = low;
		p[n++] = I(BPF_ALU | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_2,
			   width, 0);
	}
	if (high)
		n += expose_high32(p + n);
	p[n++] = I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	check(name, p, n, high ? (uint32_t)(expected >> 32) : (uint32_t)expected);
}

static uint64_t sdiv_expected(uint64_t a, uint64_t b, int mod)
{
	int64_t x = a, y = b;
	if (!y)
		return 0;
	if (x == INT64_MIN && y == -1)
		return mod ? 0 : (uint64_t)INT64_MIN;
	return mod ? (uint64_t)(x % y) : (uint64_t)(x / y);
}

static void check_signed64_reg(const char *name, uint8_t op, uint64_t a,
			       uint64_t b, int high)
{
	struct bpf_insn p[10];
	uint64_t expected = sdiv_expected(a, b, op == BPF_MOD);
	size_t n = ld64(p, BPF_REG_0, a);
	n += ld64(p + n, BPF_REG_2, b);
	p[n++] = I(BPF_ALU64 | op | BPF_X, BPF_REG_0, BPF_REG_2, 1, 0);
	if (high)
		n += expose_high32(p + n);
	p[n++] = I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	check(name, p, n, high ? (uint32_t)(expected >> 32) : (uint32_t)expected);
}

static int cmp_expected(uint8_t op, uint64_t a, uint64_t b, int jmp32)
{
	if (jmp32) {
		uint32_t x = a, y = b;
		switch (op) {
		case BPF_JEQ: return x == y;
		case BPF_JNE: return x != y;
		case BPF_JGT: return x > y;
		case BPF_JGE: return x >= y;
		case BPF_JLT: return x < y;
		case BPF_JLE: return x <= y;
		case BPF_JSGT: return (int32_t)x > (int32_t)y;
		case BPF_JSGE: return (int32_t)x >= (int32_t)y;
		case BPF_JSLT: return (int32_t)x < (int32_t)y;
		case BPF_JSLE: return (int32_t)x <= (int32_t)y;
		case BPF_JSET: return (x & y) != 0;
		}
	} else {
		switch (op) {
		case BPF_JEQ: return a == b;
		case BPF_JNE: return a != b;
		case BPF_JGT: return a > b;
		case BPF_JGE: return a >= b;
		case BPF_JLT: return a < b;
		case BPF_JLE: return a <= b;
		case BPF_JSGT: return (int64_t)a > (int64_t)b;
		case BPF_JSGE: return (int64_t)a >= (int64_t)b;
		case BPF_JSLT: return (int64_t)a < (int64_t)b;
		case BPF_JSLE: return (int64_t)a <= (int64_t)b;
		case BPF_JSET: return (a & b) != 0;
		}
	}
	abort();
}

static void check_jump(const char *name, uint8_t op, uint64_t a, uint64_t b,
		       int jmp32)
{
	struct bpf_insn p[12];
	size_t n = ld64(p, BPF_REG_0, a);
	n += ld64(p + n, BPF_REG_2, b);
	p[n++] = I((jmp32 ? BPF_JMP32 : BPF_JMP) | op | BPF_X,
		   BPF_REG_0, BPF_REG_2, 2, 0);
	p[n++] = I(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0);
	p[n++] = I(BPF_JMP | BPF_JA, 0, 0, 1, 0);
	p[n++] = I(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1);
	p[n++] = I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	check(name, p, n, cmp_expected(op, a, b, jmp32));
}

static void check_stack(void)
{
	struct bpf_insn p[] = {
		I(BPF_ST | BPF_DW | BPF_MEM, BPF_REG_10, 0, -8, 0x89abcdef),
		I(BPF_LDX | BPF_DW | BPF_MEM, BPF_REG_0, BPF_REG_10, -8, 0),
		I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
	};
	check("stack_st_imm_dw_ldx_dw", p, sizeof(p) / sizeof(p[0]), 0x89abcdef);
}

int main(void)
{
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	static const unsigned int shifts64[] = { 0, 1, 31, 32, 33, 63 };
	static const unsigned int shifts32[] = { 0, 1, 15, 31 };
	static const uint8_t alu_ops[] = { BPF_ADD, BPF_SUB, BPF_MUL, BPF_OR,
		BPF_AND, BPF_XOR, BPF_LSH, BPF_RSH };
	static const uint8_t jump_ops[] = { BPF_JEQ, BPF_JNE, BPF_JGT, BPF_JGE,
		BPF_JLT, BPF_JLE, BPF_JSGT, BPF_JSGE, BPF_JSLT, BPF_JSLE, BPF_JSET };
	char name[96];
	unsigned int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	setrlimit(RLIMIT_MEMLOCK, &lim);
	printf("FRAGMA_BPF: ARM32 JIT differential start\n");

	check_mov64("ldimm64-low", UINT64_C(0x8877665544332211), 0);
	check_mov64("ldimm64-high", UINT64_C(0x8877665544332211), 1);

	for (i = 0; i < sizeof(alu_ops); i++) {
		snprintf(name, sizeof(name), "alu64-reg-%02x-low", alu_ops[i]);
		check_alu64_reg(name, alu_ops[i], UINT64_C(0xf123456789abcdef),
				UINT64_C(0x0000000000000021), 0);
		snprintf(name, sizeof(name), "alu64-reg-%02x-high", alu_ops[i]);
		check_alu64_reg(name, alu_ops[i], UINT64_C(0xf123456789abcdef),
				UINT64_C(0x0000000000000021), 1);
	}

	for (i = 0; i < sizeof(shifts64) / sizeof(shifts64[0]); i++) {
		snprintf(name, sizeof(name), "lsh64-imm-%u-low", shifts64[i]);
		check_shift_imm(name, BPF_LSH, UINT64_C(0x8123456789abcdef), shifts64[i], 0, 1);
		snprintf(name, sizeof(name), "lsh64-imm-%u-high", shifts64[i]);
		check_shift_imm(name, BPF_LSH, UINT64_C(0x8123456789abcdef), shifts64[i], 1, 1);
		snprintf(name, sizeof(name), "rsh64-imm-%u-low", shifts64[i]);
		check_shift_imm(name, BPF_RSH, UINT64_C(0x8123456789abcdef), shifts64[i], 0, 1);
		snprintf(name, sizeof(name), "arsh64-imm-%u-high", shifts64[i]);
		check_shift_imm(name, BPF_ARSH, UINT64_C(0x8123456789abcdef), shifts64[i], 1, 1);
	}
	for (i = 0; i < sizeof(shifts32) / sizeof(shifts32[0]); i++) {
		snprintf(name, sizeof(name), "lsh32-imm-%u", shifts32[i]);
		check_shift_imm(name, BPF_LSH, UINT64_C(0xffffffff89abcdef), shifts32[i], 0, 0);
		snprintf(name, sizeof(name), "arsh32-imm-%u", shifts32[i]);
		check_shift_imm(name, BPF_ARSH, UINT64_C(0xffffffff89abcdef), shifts32[i], 0, 0);
	}

	check_movsx("movsx64-8-low", 0x80, 8, 1, 0);
	check_movsx("movsx64-8-high", 0x80, 8, 1, 1);
	check_movsx("movsx64-16-low", 0x8001, 16, 1, 0);
	check_movsx("movsx64-16-high", 0x8001, 16, 1, 1);
	check_movsx("movsx64-32-low", 0x80000001, 32, 1, 0);
	check_movsx("movsx64-32-high", 0x80000001, 32, 1, 1);
	check_movsx("movsx32-8", 0x80, 8, 0, 0);
	check_movsx("movsx32-16", 0x8001, 16, 0, 0);

	check_signed64_reg("sdiv64-pos-neg-low", BPF_DIV, 123456789, -123, 0);
	check_signed64_reg("sdiv64-pos-neg-high", BPF_DIV, 123456789, -123, 1);
	check_signed64_reg("smod64-neg-pos-low", BPF_MOD, -123456789, 123, 0);
	check_signed64_reg("smod64-neg-pos-high", BPF_MOD, -123456789, 123, 1);
	check_signed64_reg("sdiv64-zero", BPF_DIV, 123456789, 0, 0);
	check_signed64_reg("sdiv64-min-minus1-low", BPF_DIV, INT64_MIN, -1, 0);
	check_signed64_reg("sdiv64-min-minus1-high", BPF_DIV, INT64_MIN, -1, 1);

	for (i = 0; i < sizeof(jump_ops); i++) {
		snprintf(name, sizeof(name), "jmp64-%02x-true", jump_ops[i]);
		check_jump(name, jump_ops[i], UINT64_C(0x8000000100000001),
			   UINT64_C(0x7fffffff00000001), 0);
		snprintf(name, sizeof(name), "jmp32-%02x-true", jump_ops[i]);
		check_jump(name, jump_ops[i], UINT64_C(0x8000000100000001),
			   UINT64_C(0x7fffffff00000001), 1);
	}

	check_stack();
	printf("FRAGMA_BPF: SUMMARY pass=%d fail=%d\n", passes, failures);
	return failures ? 1 : 0;
}
