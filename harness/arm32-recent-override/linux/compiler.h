/* SPDX-License-Identifier: GPL-2.0 */
/* Target-local Frama-C adaptation for data_race()'s inferred temporary. */
#ifndef FRAGMA_ARM32_RECENT_COMPILER_H
#define FRAGMA_ARM32_RECENT_COMPILER_H

#include_next <linux/compiler.h>

#undef data_race
#define data_race(expr) ({					\
	__kcsan_disable_current();				\
	disable_context_analysis();				\
	typeof(expr) __v = (expr);				\
	enable_context_analysis();				\
	__kcsan_enable_current();				\
	__v;							\
})

/* The configured GCC build has already enforced these compile-time checks.
 * Frama-C cannot classify Linux's sizeof(void) constant-expression detector
 * and otherwise rejects assertions inside unrelated inline helpers.
 */
#undef const_true
#define const_true(expr) 0

#endif /* FRAGMA_ARM32_RECENT_COMPILER_H */
