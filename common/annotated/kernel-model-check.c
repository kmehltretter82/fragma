/* SPDX-License-Identifier: GPL-2.0 */
/* Compile-only common24 fixture using genuine configured kernel headers.
 * No proof-harness typedefs, kernel macro redefinitions, TOD, u64/48-bit,
 * native-endian assertion, fixed long/size_t width, or executable entry point.
 */
#include <linux/types.h>
#include <linux/unaligned.h>
#include "inline-policy.h"

/* Only the controlled wrong-type compile overrides this expectation. */
#ifndef FRAGMA_COMMON24_EXPECT_U32
#define FRAGMA_COMMON24_EXPECT_U32 unsigned int
#endif

_Static_assert(__CHAR_BIT__ == 8, "common24 eight-bit bytes");
_Static_assert(sizeof(int) == 4 && __INT_MAX__ == 2147483647,
               "common24 32-bit signed promotion range");
_Static_assert(__builtin_types_compatible_p(u8, unsigned char),
               "common24 exact u8 type");
_Static_assert(__builtin_types_compatible_p(u32, FRAGMA_COMMON24_EXPECT_U32),
               "common24 exact u32 type");
_Static_assert(sizeof(u8) == 1 && sizeof(u32) == 4,
               "common24 fixed integer widths");
_Static_assert(__alignof__(u8) == 1, "common24 byte alignment");

typedef FRAGMA_COMMON24_EXPECT_U32 (*read24_fn)(const u8 *);
typedef void (*write24_fn)(FRAGMA_COMMON24_EXPECT_U32, u8 *);
_Static_assert(__builtin_types_compatible_p(typeof(&__get_unaligned_be24), read24_fn),
               "common24 exact BE24 read signature");
_Static_assert(__builtin_types_compatible_p(typeof(&__get_unaligned_le24), read24_fn),
               "common24 exact LE24 read signature");
_Static_assert(__builtin_types_compatible_p(typeof(&__put_unaligned_be24), write24_fn),
               "common24 exact BE24 write signature");
_Static_assert(__builtin_types_compatible_p(typeof(&__put_unaligned_le24), write24_fn),
               "common24 exact LE24 write signature");

#define FRAGMA_COMMON24_STRINGIFY_INNER(x) #x
#define FRAGMA_COMMON24_STRINGIFY(x) FRAGMA_COMMON24_STRINGIFY_INNER(x)
_Static_assert(__builtin_strcmp(FRAGMA_COMMON24_STRINGIFY(inline),
                               FRAGMA_COMMON24_INLINE_TEXT) == 0,
               "common24 exact effective inline expansion");

/* Audit metadata is retained in compiler-only preprocessed output and object;
 * it is never linked or executed by this stage.
 */
const char fragma_common24_effective_inline[] = FRAGMA_COMMON24_STRINGIFY(inline);
const char fragma_common24_expected_inline[] = FRAGMA_COMMON24_INLINE_TEXT;
