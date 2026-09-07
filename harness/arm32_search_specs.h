/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal declarations for the analyzer-first ARM32 safety search.
 *
 * The selected drivers do not reach BUG() under their bounded domains.  This
 * declaration only gives the configured kernel's __builtin_unreachable token
 * replacement a parseable target; it does not model normal kernel control
 * flow or prove an ARM trap implementation.
 */
#ifndef FRAGMA_ARM32_SEARCH_SPECS_H
#define FRAGMA_ARM32_SEARCH_SPECS_H

/* ARM implements strchr in assembly outside lib/string.c.  Rename that one
 * external symbol to the bounded C semantic model supplied by the driver.
 * Only the strsep target reaches it, and that target records the dependency.
 */
#define strchr fragma_arm32_strchr_model

/*@ terminates \false;
    exits \false;
    assigns \nothing;
    ensures no_normal_return: \false;
  @*/
extern void fragma_unreachable(void) __attribute__((__noreturn__));

/* Frama-C lowers packed unaligned scalar reads through memcpy.  This is the
 * exact byte-copy footprint needed by the Eva builtin; it does not claim that
 * ARM's external assembly implementation has been verified here.
 */
/*@ requires destination: \valid((char *)to + (0 .. len - 1));
    requires source: \valid_read((const char *)from + (0 .. len - 1));
    requires disjoint:
      \separated((char *)to + (0 .. len - 1),
                 (const char *)from + (0 .. len - 1));
    terminates \true;
    exits \false;
    assigns ((char *)to)[0 .. len - 1] \from ((const char *)from)[0 .. len - 1];
    assigns \result \from to;
    ensures exact_copy: \forall integer i; 0 <= i < len ==>
      ((char *)to)[i] == \at(((const char *)from)[i], Pre);
    ensures destination_result: \result == to;
  @*/
void *memcpy(void *to, const void *from, unsigned int len);

#endif
