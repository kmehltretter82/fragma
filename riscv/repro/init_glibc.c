#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

/* FRAGMA seccomp JIT trigger for the rv_i_insn shift-overflow repro. */

typedef struct { uint16_t code; uint8_t jt; uint8_t jf; uint32_t k; } filt_t;
typedef struct { uint16_t len; filt_t *filter; } fprog_t;

#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_SECCOMP      22
#define SECCOMP_MODE_FILTER 2

static void say(const char *s)
{
	long n = 0;
	const char *p = s;
	while (*p++)
		n++;
	write(1, s, n);
}

int main(void)
{
	filt_t f[1] = { { 0x06, 0, 0, 0x7fff0000u } };  /* BPF_RET|BPF_K, ALLOW */
	fprog_t prog = { 1, f };
	long r;
	char c;

	say("FRAGMA-MARKER-BEFORE: about to install seccomp filter (JIT)\n");
	syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	r = syscall(SYS_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
	if (r == 0)
		say("FRAGMA-MARKER-AFTER: seccomp OK, JIT ran\n");
	else
		say("FRAGMA-MARKER-AFTER: seccomp nonzero, JIT still ran\n");
	say("FRAGMA-DONE\n");
	read(0, &c, 1);
	return 0;
}
