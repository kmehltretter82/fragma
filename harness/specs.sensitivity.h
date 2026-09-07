/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal model for independent concrete EVA calibration, not the strong WP
 * contracts. The kernel strlen and search/append C bodies are retained.
 * Kernel byte-copy implementation correctness remains explicitly trusted.
 */
#ifndef FRAGMA_SPECS_SENSITIVITY_H
#define FRAGMA_SPECS_SENSITIVITY_H

/* The driver domain and calibration_valid_api_domain assertion exclude this
 * call. No termination or return behavior of real trap assembly is claimed.
 */
/*@ terminates \false;
    exits \false;
    assigns \nothing;
    ensures no_normal_return: \false;
  @*/
extern void fragma_unreachable(void) __attribute__((__noreturn__));

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
void *memcpy(void *to, const void *from, unsigned long len);

#endif
