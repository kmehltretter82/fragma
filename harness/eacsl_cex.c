/* FRAGMA: executable (E-ACSL) witness for the strlcat truncation
 * counterexample.
 *
 * kstrlcat below is a VERBATIM copy of strlcat from
 *   ~/linux-work/linux/lib/string.c @ b9b3e33b70b71 (lib/string.c:234)
 * renamed (glibc >= 2.38 owns "strlcat") and with the kernel macro layer
 * reduced to: BUG_ON -> runtime abort (CONFIG_BUG=y behaviour),
 * __builtin_memcpy left to the compiler, size_t from stdlib.
 *
 * e-acsl-gcc.sh instruments the ACSL assertions; running the binary makes
 * the naive claim fail AT RUNTIME on a real execution -- the strongest,
 * most portable form of the counterexample.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUG_ON(cond) do { if (cond) abort(); } while (0)

static size_t kstrlcat(char *dest, const char *src, size_t count)
{
	size_t dsize = strlen(dest);
	size_t len = strlen(src);
	size_t res = dsize + len;

	/* This would be a bug */
	BUG_ON(dsize >= count);

	dest += dsize;
	count -= dsize;
	if (len >= count)
		len = count-1;
	__builtin_memcpy(dest, src, len);
	dest[len] = 0;
	return res;
}

int main(void)
{
	char buf[8] = "ab";
	size_t r = kstrlcat(buf, "cdef", 5);

	printf("kstrlcat(\"ab\", \"cdef\", 5) = %zu, buf = \"%s\", strlen = %zu\n",
	       r, buf, strlen(buf));

	/*@ assert result_is_intended_total: r == 6; */
	/*@ assert truncated_string: buf[4] == 0; */
	/*@ assert naive_claim: \forall integer j; 0 <= j < r ==> buf[j] != 0; */
	return 0;
}
