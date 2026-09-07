/* FRAGMA: executable witness that strlcat's BUG_ON is load-bearing.
 *
 * kstrlcat_nobug is the strlcat body from ~/linux-work/linux/lib/string.c
 * @ b9b3e33b70b71 with the BUG_ON line removed (the string.fault.c fault
 * injection, mirrored in userspace).  Driving it with a dest string that
 * does NOT fit in count (dsize=4 >= count=2) underflows "count -= dsize",
 * defeats the truncation clamp, and writes one byte past the buffer.
 *
 * Build with e-acsl-gcc + RTE assertions: the instrumented run must abort
 * on the out-of-bounds store that the WP collapse (string.fault.c) predicts.
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static size_t kstrlcat_nobug(char *dest, const char *src, size_t count)
{
	size_t dsize = strlen(dest);
	size_t len = strlen(src);
	size_t res = dsize + len;

	/* FRAGMA fault injection: BUG_ON(dsize >= count) removed */

	dest += dsize;
	count -= dsize;		/* underflows: 2 - 4 wraps to SIZE_MAX-1 */
	if (len >= count)	/* false now (clamp defeated) */
		len = count-1;
	/*@ assert store_in_bounds:
	      \valid(dest + (0 .. len)); */	/* fails: dest+len past buf */
	__builtin_memcpy(dest, src, len);
	dest[len] = 0;
	return res;
}

int main(void)
{
	char buf[5] = "AAAA";	/* dsize = 4, buffer exactly full */
	size_t r = kstrlcat_nobug(buf, "cd", 2);	/* count=2 < dsize=4 */

	printf("returned %zu, buf=\"%s\"\n", r, buf);
	return 0;
}
