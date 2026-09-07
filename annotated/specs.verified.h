/* SPDX-License-Identifier: GPL-2.0 */
/* Reviewed, explicit assumptions for the verified x86-64 kernel string TU.
 * Kernel size_t is unsigned long in this profile; the machine/configuration
 * check must establish that identity before these declarations are consumed.
 * All logic below is defined, not axiomatized. The external implementations
 * remain trusted and are listed in verification-notes.md and the manifest.
 */
#ifndef FRAGMA_SPECS_VERIFIED_H
#define FRAGMA_SPECS_VERIFIED_H

/*@ predicate fragma_cstring{L}(char *s, integer n) =
      0 <= n < (integer)((unsigned long)-1) &&
      \valid_read(s + (0 .. n)) && s[n] == 0 &&
      (\forall integer i; 0 <= i < n ==> s[i] != 0);

    logic integer fragma_min(integer a, integer b) = a < b ? a : b;

    predicate fragma_scan_readable{L}(char *s, integer count) =
      count == 0 || \valid_read(s + (0 .. count - 1)) ||
      (\exists integer z; 0 <= z < count &&
        \valid_read(s + (0 .. z)) && s[z] == 0);
  @*/

/* A non-returning stub may diverge. It is deliberately NOT claimed both to
 * terminate and to have neither a normal nor an abnormal exit. In the selected
 * build, the existing x86 header override removes UD2 and routes BUG_ON to
 * this stub, even with CONFIG_BUG=n. Its model is reviewed only for targets
 * which prove that call unreachable; callers requiring termination must
 * discharge that fact. It is not a model of arbitrary trap-handler effects.
 */
/*@ terminates \false;
    exits \false;
    assigns \nothing;
    ensures never_returns: \false;
  @*/
extern void fragma_unreachable(void) __attribute__((__noreturn__));

/* Trusted modular strlen: bounded, readable first-NUL input and no writes.
 * The bound follows from requiring storage for n+1 bytes in a size_t-sized
 * object. The generic strlen body is present but is not selected for proof.
 */
/*@ requires readable_string:
      \exists integer n; fragma_cstring(s, n);
    terminates \true;
    exits \false;
    assigns \nothing;
    ensures first_nul_result: fragma_cstring(s, \result);
  @*/
unsigned long strlen(const char *s);

/* Trusted external memcpy: exact byte copy from the prestate and no changes
 * outside its footprint. A zero-byte copy has empty ranges and requires no
 * dereference. Separation is an API requirement, not a proved caller fact.
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
void *memcpy(void *to, const void *from, unsigned long len);

#endif
