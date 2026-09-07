/* FRAGMA: minimal linux/bits.h for including asm/insn.h standalone.
 * Only the macros asm/insn.h actually uses (BIT, GENMASK). */
#ifndef FRAGMA_BITS_H
#define FRAGMA_BITS_H
#define BIT(n)		(1UL << (n))
#define GENMASK(h, l)	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (64 - 1 - (h))))
#define __ASSEMBLY__ 0
#endif
