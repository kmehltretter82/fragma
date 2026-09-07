/* SPDX-License-Identifier: GPL-2.0 */
/* Frama-C 33 compatibility wrapper for Linux's inferred auto temporaries.
 *
 * The genuine pinned header remains authoritative.  Only macro expansion of
 * inferred temporaries is adapted, and only for targets which explicitly put
 * this directory first in their include path.  For scalar arguments,
 * typeof(argument) preserves the type and the original single evaluation.
 */
#ifndef FRAGMA_ARM32_RECENT_MINMAX_H
#define FRAGMA_ARM32_RECENT_MINMAX_H

#include_next <linux/minmax.h>

#undef __careful_cmp_once
#define __careful_cmp_once(op, x, y, ux, uy) ({		\
	typeof(x) ux = (x); typeof(y) uy = (y);		\
	BUILD_BUG_ON_MSG(!__types_ok(ux, uy),		\
		#op"("#x", "#y") signedness error");	\
	__cmp(op, ux, uy); })

#undef __careful_op3
#define __careful_op3(op, x, y, z, ux, uy, uz) ({		\
	typeof(x) ux = (x); typeof(y) uy = (y); typeof(z) uz = (z); \
	BUILD_BUG_ON_MSG(!__types_ok3(ux, uy, uz),		\
		#op"3("#x", "#y", "#z") signedness error");	\
	__cmp(op, ux, __cmp(op, uy, uz)); })

#undef clamp
#define clamp(val, lo, hi) __careful_clamp(typeof(val), val, lo, hi)

#endif /* FRAGMA_ARM32_RECENT_MINMAX_H */
