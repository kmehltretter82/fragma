/* SPDX-License-Identifier: GPL-2.0 */
/* Shared declarations for analyzer-first, direct-source ARM32 candidates. */
#ifndef FRAGMA_ARM32_RECENT_SPECS_H
#define FRAGMA_ARM32_RECENT_SPECS_H

/*@ terminates \false;
    exits \false;
    assigns \nothing;
    ensures no_normal_return: \false;
  @*/
extern void fragma_unreachable(void) __attribute__((__noreturn__));

#endif
