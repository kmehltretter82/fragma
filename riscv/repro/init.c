/* FRAGMA: minimal riscv64 init that installs a trivial seccomp cBPF filter.
 * With CONFIG_BPF_JIT_ALWAYS_ON the kernel JITs it; the JIT prologue emits
 * `addi sp, sp, -frame` -> rv_i_insn(imm11_0 with bit 11 set) -> the UBSAN
 * shift-out-of-bounds we proved with Frama-C, IF it fires at runtime.
 * Built with the kernel's nolibc (no external libc needed). */

struct sock_filter { unsigned short code; unsigned char jt, jf; unsigned int k; };
struct sock_fprog { unsigned short len; struct sock_filter *filter; };

#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_SECCOMP      22
#define SECCOMP_MODE_FILTER 2
#define BPF_RET  0x06
#define BPF_K    0x00
#define SECCOMP_RET_ALLOW 0x7fff0000U

static void say(const char *s)
{
	long n = 0; const char *p = s; while (*p++) n++;
	write(1, s, n);
}

int main(void)
{
	/* filter[0] = BPF_LD|BPF_IMM, A = 0xFFFFFFFF (-1): the cBPF->eBPF->JIT
	 * path emits `mov reg, -1` == addiw reg, zero, -1 (rd != rs, imm=0xFFF)
	 * -> rv_i_insn(0xFFF,...) -> the signed-shift-overflow. filter[1] returns
	 * ALLOW so we survive to print the AFTER marker. */
	/* A = 2048: mov of 2048 doesn't fit a 12-bit addi, so the JIT splits it
	 * into lui + addi(rd, rd, -2048); -2048 is not 6-bit, so emit_addi falls
	 * to rv_addi -> rv_i_insn((u16)-2048 = 0xF800) -> the shift overflow. */
	/* Return A so the A=2048 load can't be dead-code-eliminated; the mov of
	 * 2048 -> emit_imm -> emit_addiw(rd,rd,-2048) -> rv_i_insn(0xF800). The
	 * runtime action (2048) is invalid -> the task is killed on its next
	 * syscall, but the JIT (and thus the splat, if real) runs at load time. */
	struct sock_filter f[] = {
		{ 0x00, 0, 0, 2048u },    /* BPF_LD|BPF_IMM   A = 2048 */
		{ 0x16, 0, 0, 0 },        /* BPF_RET|BPF_A    return A */
	};
	struct sock_fprog prog = { 2, f };
	long r;
	char c;

	/* mount /proc and enable JIT debug dump (allowed even under ALWAYS_ON) */
	mount("proc", "/proc", "proc", 0, 0);
	{
		int fd = open("/proc/sys/net/core/bpf_jit_enable", 1 /*O_WRONLY*/);
		if (fd >= 0) { write(fd, "2\n", 2); close(fd); say("FRAGMA: jit_debug=2 set\n"); }
		else say("FRAGMA: could not open bpf_jit_enable\n");
	}
	say("FRAGMA-MARKER-BEFORE: installing seccomp filter (about to JIT)\n");
	syscall(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	r = syscall(__NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	if (r == 0)
		say("FRAGMA-MARKER-AFTER: seccomp installed OK (JIT ran)\n");
	else
		say("FRAGMA-MARKER-AFTER: seccomp load returned nonzero (JIT still ran)\n");
	say("FRAGMA-DONE\n");
	read(0, &c, 1);   /* block instead of exiting (avoids init-death panic) */
	return 0;
}
