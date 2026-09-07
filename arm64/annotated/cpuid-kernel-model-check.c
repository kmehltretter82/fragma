/* SPDX-License-Identifier: GPL-2.0 */
/* Staged model check: actual configured ARM64 kernel headers and compiler.
 * This is not a replacement header, emulator witness, or caller audit.
 */
#include <linux/types.h>
#include <asm/cpufeature.h>

_Static_assert(__CHAR_BIT__ == 8, "eight-bit bytes");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "selected ARM64 byte order");
_Static_assert(__builtin_types_compatible_p(u64, unsigned long long), "exact u64 substitution");
_Static_assert(__builtin_types_compatible_p(s64, signed long long), "exact s64 substitution");
_Static_assert(sizeof(u64) == 8 && sizeof(s64) == 8, "64-bit feature values");
_Static_assert(sizeof(int) == 4 && sizeof(unsigned int) == 4, "32-bit field and return values");
_Static_assert(__INT_MAX__ == 2147483647, "int range");
_Static_assert(__builtin_types_compatible_p(typeof(64), int), "shift-width literal type");
_Static_assert((u64)-1 == 18446744073709551615ULL, "u64 full domain");
_Static_assert((s64)((u64)1 << 63) == (-9223372036854775807LL - 1), "signed high-bit conversion");
_Static_assert((s64)(u64)-1 == -1, "unsigned-to-signed bit-preserving conversion");
_Static_assert(((s64)-2 >> 1) == -1, "s64 arithmetic right shift");
_Static_assert(((s64)(u64)-1 >> 63) == -1, "s64 high-count arithmetic shift");
_Static_assert((int)(s64)4294967295ULL == -1, "signed return narrowing");
_Static_assert((int)(s64)4294967296ULL == 0, "signed return low bits");
_Static_assert((unsigned int)(u64)-1 == 4294967295U, "unsigned return narrowing");

typedef int (*signed_field_fn)(u64, int, int) __attribute_const__;
typedef unsigned int (*unsigned_field_fn)(u64, int, int) __attribute_const__;
_Static_assert(__builtin_types_compatible_p(typeof(&cpuid_feature_extract_signed_field_width),
               signed_field_fn), "actual signed helper signature");
_Static_assert(__builtin_types_compatible_p(typeof(&cpuid_feature_extract_unsigned_field_width),
               unsigned_field_fn), "actual unsigned helper signature");

#define FRAGMA_STRINGIFY_INNER(x) #x
#define FRAGMA_STRINGIFY(x) FRAGMA_STRINGIFY_INNER(x)
_Static_assert(__builtin_strcmp(FRAGMA_STRINGIFY(__attribute_const__),
               "__attribute__((__const__))") == 0, "exact const attribute expansion");
_Static_assert(__builtin_strcmp(FRAGMA_STRINGIFY(inline),
               "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))") == 0,
               "exact inline expansion");
_Static_assert(__builtin_strcmp(FRAGMA_STRINGIFY(__always_inline),
               "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__)) __attribute__((__always_inline__))") == 0,
               "exact always-inline expansion");
