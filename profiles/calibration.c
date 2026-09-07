/* SPDX-License-Identifier: MIT
 * Benign model fixtures; all expressions have bounded, known inputs.
 * Expected constants come from the selected profile and are independently
 * checked by the target compiler, Frama-C evaluation, and available runtime.
 */
#include "kernel-types.h"

_Static_assert(__CHAR_BIT__ == 8, "eight-bit bytes");
_Static_assert(sizeof(short) == FRAGMA_SHORT_BYTES, "short width");
_Static_assert(sizeof(int) == FRAGMA_INT_BYTES, "int width");
_Static_assert(sizeof(long) == FRAGMA_LONG_BYTES, "long width");
_Static_assert(sizeof(long long) == FRAGMA_LONG_LONG_BYTES, "long long width");
_Static_assert(sizeof(void *) == FRAGMA_POINTER_BYTES, "pointer width");
_Static_assert(sizeof(__WCHAR_TYPE__) == FRAGMA_WCHAR_BYTES, "short wchar");
_Static_assert(((char)-1 > 0) == FRAGMA_CHAR_UNSIGNED, "plain-char signedness");
_Static_assert(__BYTE_ORDER__ == FRAGMA_BYTE_ORDER, "compiler byte order");
_Static_assert(__BITS_PER_LONG == FRAGMA_BITS, "kernel word width");
_Static_assert(sizeof(__kernel_size_t) == sizeof(void *), "kernel size_t width");
_Static_assert((__kernel_size_t)-1 > 0, "kernel size_t unsigned");
_Static_assert(sizeof(__kernel_ptrdiff_t) == sizeof(void *), "kernel ptrdiff_t width");
_Static_assert((__kernel_ptrdiff_t)-1 < 0, "kernel ptrdiff_t signed");
_Static_assert(sizeof(__u8) == 1 && sizeof(__u16) == 2 && sizeof(__u32) == 4 && sizeof(__u64) == 8, "kernel fixed-width unsigned types");
_Static_assert((__s8)-1 < 0 && (__s16)-1 < 0 && (__s32)-1 < 0 && (__s64)-1 < 0, "kernel fixed-width signed types");
_Static_assert(_Alignof(long) == FRAGMA_LONG_ALIGNMENT, "long alignment");
_Static_assert(_Alignof(void *) == FRAGMA_POINTER_ALIGNMENT, "pointer alignment");
_Static_assert(_Alignof(long long) == FRAGMA_LONG_LONG_ALIGNMENT, "long long alignment");

struct natural_layout { char c; long word; void *pointer; };
struct packed_layout { char c; unsigned int word; } __attribute__((packed));
_Static_assert(__builtin_offsetof(struct natural_layout, word) == FRAGMA_LONG_ALIGNMENT, "natural field offset");
_Static_assert(sizeof(struct natural_layout) == FRAGMA_NATURAL_SIZE, "natural structure size");
_Static_assert(__builtin_offsetof(struct packed_layout, word) == 1, "packed field offset");
_Static_assert(sizeof(struct packed_layout) == 5, "packed structure size");
_Static_assert((-2 >> 1) == -1, "arithmetic right shift");
_Static_assert((signed char)255 == -1, "signed conversion");

int main(void)
{
    unsigned int marker = 0x01020304U;
    unsigned char *bytes = (unsigned char *)&marker;
    unsigned long wrap = ~0UL;
    int signed_wrap = 2147483647;
    int signed_shift = -2;
    unsigned int high_bit = 1U;
    signed char narrowed = (signed char)255;
    char plain = (char)255;
    wrap += 1UL;
    signed_wrap += 1;
    signed_shift >>= 1;
    high_bit <<= 31;
    /*@ assert byte_order_memory: bytes[0] == FRAGMA_FIRST_BYTE; */
    /*@ assert unsigned_wrap: wrap == 0; */
    /*@ assert signed_wrap_model: signed_wrap == (-2147483647 - 1); */
    /*@ assert arithmetic_right_shift: signed_shift == -1; */
    /*@ assert shift_high_bit: high_bit == 2147483648U; */
    /*@ assert signed_conversion: narrowed == -1; */
    /*@ assert plain_char_model: plain == 255; */
    return !(bytes[0] == FRAGMA_FIRST_BYTE && wrap == 0 &&
             signed_wrap == (-2147483647 - 1) && signed_shift == -1 &&
             high_bit == 2147483648U && narrowed == -1 && plain == 255);
}
