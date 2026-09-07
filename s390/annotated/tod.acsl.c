/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Unchanged tod_to_ns body from arch/s390/include/asm/timex.h,
 * Linux b9b3e33b70b71e516930117e21de3ad2a7723747.
 * __always_inline below is the exact compiler_attributes.h definition, and
 * inline expands as in this configured kernel's compiler_types.h. Both are
 * checked against the actual headers by kernel-model-check.c.
 * This selected helper uses only unsigned long arithmetic; its siblings use
 * register instructions and are outside this harness. No instruction is erased.
 */
#define inline inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))
#define __always_inline inline __attribute__((__always_inline__))
#include "bitproof.h"

/*@ terminates \true;
    assigns \nothing;
    ensures nanoseconds: \result == ((integer)todval * 125) / 512;
    ensures bounded: \result <= todval;
 */
static __always_inline unsigned long tod_to_ns(unsigned long todval)
{
	return ((todval >> 9) * 125) + (((todval & 0x1ff) * 125) >> 9);
}
