/* SPDX-License-Identifier: GPL-2.0 */
/* Explicit staged frontend policies. No implicit host or s390 default.
 * These definitions do not redefine the genuine kernel's inline macro when
 * included by kernel-model-check.c. The standalone harness selects the same
 * spelling only after a profile-specific real-header check.
 */
#ifndef FRAGMA_COMMON24_INLINE_POLICY_H
#define FRAGMA_COMMON24_INLINE_POLICY_H

#ifndef FRAGMA_COMMON24_INLINE_POLICY
#error "An explicitly reviewed common24 inline policy is required"
#elif FRAGMA_COMMON24_INLINE_POLICY == 1
#define FRAGMA_COMMON24_INLINE inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))
#define FRAGMA_COMMON24_INLINE_TEXT "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))"
#elif FRAGMA_COMMON24_INLINE_POLICY == 2
#define FRAGMA_COMMON24_INLINE inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((patchable_function_entry(0, 0)))
#define FRAGMA_COMMON24_INLINE_TEXT "inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((patchable_function_entry(0, 0)))"
#else
#error "Unknown common24 inline policy"
#endif

#endif
