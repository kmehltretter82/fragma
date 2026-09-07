/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded analyzer-first drivers for the frozen ARM32 string batch.
 *
 * Domains come from include/linux/string.h, its fortify wrappers, and ordinary
 * C-string requirements.  They deliberately use separate local objects and
 * retain a terminator inside every string object.  No candidate implementation
 * detail is encoded here.  Each entry is analyzed in a separate RTE+Eva run.
 */

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern int Frama_C_interval(int min, int max) __attribute__((FC_BUILTIN));
/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned char Frama_C_unsigned_char_interval(unsigned char min,
						     unsigned char max)
	__attribute__((FC_BUILTIN));

extern int sized_strscpy(char *dest, const char *src, unsigned int count);
extern void *memchr_inv(const void *start, int c, unsigned int bytes);
extern char *strstr(const char *s1, const char *s2);
extern int strncasecmp(const char *s1, const char *s2, unsigned int len);
extern char *strnstr(const char *s1, const char *s2, unsigned int len);
extern char *strsep(char **s, const char *ct);
extern int memcmp(const void *cs, const void *ct, unsigned int count);
extern int strncmp(const char *cs, const char *ct, unsigned int count);

/* linux/ctype.h indexes exactly one unsigned-byte value.  The first safety
 * scan needs the real object extent, not case-folding functional semantics.
 * A later functional pass must replace this explicit abstraction with the
 * source-gated lib/ctype.c table before making a comparison-result claim.
 */
const unsigned char _ctype[256] = { 0 };

/* Conventional strchr semantics for the external ARM assembly dependency.
 * This model is reached only with a driver-owned NUL-terminated string.  It
 * is an explicit assumption, not verification of arch/arm/lib/strchr.S.
 */
char *fragma_arm32_strchr_model(const char *string, int character)
{
	char wanted = (char)character;

	for (;;) {
		char current = *string;

		if (current == wanted)
			return (char *)string;
		if (current == 0)
			return (char *)0;
		string++;
	}
}

static void arm32_unknown_bytes(char *buffer, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; ++i)
		buffer[i] = (char)Frama_C_unsigned_char_interval(0, 255);
}

void fragma_arm32_sized_strscpy(void)
{
	char dest[17];
	char src[24];
	unsigned int count;

	arm32_unknown_bytes(dest, 17);
	arm32_unknown_bytes(src, 24);
	src[16] = 0;
	count = (unsigned int)Frama_C_interval(0, 16);
	/*@ assert arm32_sized_strscpy_domain:
	      count <= 16 && src[16] == 0; */
	(void)sized_strscpy(dest, src, count);
}

void fragma_arm32_memchr_inv(void)
{
	char input[40];
	unsigned int count;
	int value;

	arm32_unknown_bytes(input, 40);
	count = (unsigned int)Frama_C_interval(0, 40);
	value = Frama_C_interval(0, 255);
	/*@ assert arm32_memchr_inv_domain:
	      count <= 40 && 0 <= value <= 255; */
	(void)memchr_inv(input, value, count);
}

void fragma_arm32_strstr(void)
{
	char haystack[9];
	char needle[9];

	arm32_unknown_bytes(haystack, 8);
	arm32_unknown_bytes(needle, 8);
	haystack[8] = 0;
	needle[8] = 0;
	/*@ assert arm32_strstr_domain:
	      haystack[8] == 0 && needle[8] == 0; */
	(void)strstr(haystack, needle);
}

void fragma_arm32_strncasecmp(void)
{
	char left[17];
	char right[17];
	unsigned int count;

	arm32_unknown_bytes(left, 16);
	arm32_unknown_bytes(right, 16);
	left[16] = 0;
	right[16] = 0;
	count = (unsigned int)Frama_C_interval(0, 16);
	/*@ assert arm32_strncasecmp_domain:
	      count <= 16 && left[16] == 0 && right[16] == 0; */
	(void)strncasecmp(left, right, count);
}

void fragma_arm32_strnstr(void)
{
	char haystack[9];
	char needle[9];
	unsigned int count;

	arm32_unknown_bytes(haystack, 8);
	arm32_unknown_bytes(needle, 8);
	haystack[8] = 0;
	needle[8] = 0;
	count = (unsigned int)Frama_C_interval(0, 8);
	/*@ assert arm32_strnstr_domain:
	      count <= 8 && haystack[8] == 0 && needle[8] == 0; */
	(void)strnstr(haystack, needle, count);
}

void fragma_arm32_strsep(void)
{
	char string[9];
	char delimiters[5];
	char *cursor = string;

	arm32_unknown_bytes(string, 8);
	arm32_unknown_bytes(delimiters, 4);
	string[8] = 0;
	delimiters[4] = 0;
	/*@ assert arm32_strsep_domain:
	      cursor == string && string[8] == 0 && delimiters[4] == 0; */
	(void)strsep(&cursor, delimiters);
}

void fragma_arm32_memcmp(void)
{
	char left[16];
	char right[16];
	unsigned int count;

	arm32_unknown_bytes(left, 16);
	arm32_unknown_bytes(right, 16);
	count = (unsigned int)Frama_C_interval(0, 16);
	/*@ assert arm32_memcmp_domain: count <= 16; */
	(void)memcmp(left, right, count);
}

void fragma_arm32_strncmp(void)
{
	char left[17];
	char right[17];
	unsigned int count;

	arm32_unknown_bytes(left, 16);
	arm32_unknown_bytes(right, 16);
	left[16] = 0;
	right[16] = 0;
	count = (unsigned int)Frama_C_interval(0, 16);
	/*@ assert arm32_strncmp_domain:
	      count <= 16 && left[16] == 0 && right[16] == 0; */
	(void)strncmp(left, right, count);
}
