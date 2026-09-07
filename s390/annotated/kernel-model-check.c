/* SPDX-License-Identifier: GPL-2.0 */
/* Compile against the actual configured kernel headers, never the proof
 * harness typedefs. This fixture checks the pilot's entire substitution set
 * and that all seven source functions exist in the selected configuration.
 */
#include <linux/types.h>
#include <linux/unaligned.h>
#include <asm/timex.h>

_Static_assert(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__, "s390 pilot byte order");
_Static_assert(sizeof(unsigned long) == 8, "TOD input width");
_Static_assert(__builtin_types_compatible_p(u8, unsigned char), "u8 model");
_Static_assert(__builtin_types_compatible_p(u32, unsigned int), "u32 model");
_Static_assert(__builtin_types_compatible_p(u64, unsigned long long), "u64 model");
_Static_assert(sizeof(u8) == 1 && sizeof(u32) == 4 && sizeof(u64) == 8,
	       "pilot integer widths");
_Static_assert(__alignof__(u8) == 1, "byte pointers need no stronger alignment");

typedef u32 (*read24_fn)(const u8 *);
typedef void (*write24_fn)(u32, u8 *);
typedef u64 (*read48_fn)(const u8 *);
typedef void (*write48_fn)(u64, u8 *);
typedef unsigned long (*tod_fn)(unsigned long);

_Static_assert(__builtin_types_compatible_p(typeof(&__get_unaligned_be24), read24_fn), "BE24 read function");
_Static_assert(__builtin_types_compatible_p(typeof(&__get_unaligned_le24), read24_fn), "LE24 read function");
_Static_assert(__builtin_types_compatible_p(typeof(&__put_unaligned_be24), write24_fn), "BE24 write function");
_Static_assert(__builtin_types_compatible_p(typeof(&__put_unaligned_le24), write24_fn), "LE24 write function");
_Static_assert(__builtin_types_compatible_p(typeof(&__get_unaligned_be48), read48_fn), "BE48 read function");
_Static_assert(__builtin_types_compatible_p(typeof(&__put_unaligned_be48), write48_fn), "BE48 write function");
_Static_assert(__builtin_types_compatible_p(typeof(&tod_to_ns), tod_fn), "TOD function");

#define FRAGMA_STRINGIFY_INNER(x) #x
#define FRAGMA_STRINGIFY(x) FRAGMA_STRINGIFY_INNER(x)
_Static_assert(__builtin_strcmp(FRAGMA_STRINGIFY(__always_inline),
	       "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__)) __attribute__((__always_inline__))") == 0,
	       "unchanged __always_inline replacement");
_Static_assert(__builtin_strcmp(FRAGMA_STRINGIFY(inline),
	       "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))") == 0,
	       "unchanged inline replacement");
