/* SPDX-License-Identifier: GPL-2.0 */
/* Hosted observation adapter only; never included in the kernel object. */
#include <stdio.h>
#include <stdlib.h>

_Static_assert(sizeof(char) == 1 && (char)-1 > 0, "unsigned plain char");
_Static_assert(sizeof(int) == 4 && sizeof(long) == 8, "integer model");
_Static_assert(sizeof(void *) == 8, "pointer model");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "byte order");

static void fragma_native_begin(const char *entry)
{
	printf("{\"kind\":\"begin\",\"entry\":\"%s\"}\n", entry);
}

static void fragma_native_end(const char *entry)
{
	printf("{\"kind\":\"normal-return\",\"entry\":\"%s\"}\n", entry);
	if (fflush(stdout) != 0)
		exit(74);
}

static void fragma_native_expect(const char *name, int observed, int expected)
{
	printf("{\"kind\":\"property\",\"name\":\"%s\",\"observed\":%s,\"expected\":%s}\n",
	       name, observed ? "true" : "false", expected ? "true" : "false");
	/* Stop on a mismatching positive before any later dependent dereference.
	 * A matching false-spec observation continues to the normal-return marker.
	 */
	if (!!observed != !!expected)
		exit(3);
}

static void fragma_native_bytes(const char *bytes, unsigned long size)
{
	unsigned long i;
	putchar('[');
	for (i = 0; i < size; i++) {
		if (i)
			putchar(',');
		printf("%u", (unsigned int)(unsigned char)bytes[i]);
	}
	putchar(']');
}

static void fragma_native_append_state(unsigned long result,
		const char *dest, unsigned long dest_size,
		const char *src, unsigned long src_size)
{
	printf("{\"kind\":\"state\",\"result\":%lu,\"dest\":", result);
	fragma_native_bytes(dest, dest_size);
	printf(",\"src\":");
	fragma_native_bytes(src, src_size);
	printf("}\n");
}

static void fragma_native_search_state(const char *input, unsigned long size,
		const char *result)
{
	long offset = -2;
	unsigned long i;
	if (!result)
		offset = -1;
	else if (input)
		for (i = 0; i < size; i++)
			if (result == input + i)
				offset = (long)i;
	/* Equality only: no unrelated-pointer subtraction or result dereference.
	 * -1 denotes NULL; -2 denotes an unexpected, unrecognized result pointer.
	 */
	printf("{\"kind\":\"state\",\"result_offset\":%ld,\"input\":", offset);
	fragma_native_bytes(input, size);
	printf("}\n");
}
