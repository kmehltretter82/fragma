/* FRAGMA-ACSL: assumed contracts for functions that are extern in the
 * lib/string.c TU on x86-64 (arch-provided asm implementations).
 *
 * This header is force-included (-include) BEFORE any kernel header, so it
 * must not depend on kernel types: size_t is spelled "unsigned long" here,
 * which merges cleanly with the kernel's later __kernel_size_t declarations.
 *
 * These contracts are AXIOMS of the verification, not proved facts: WP
 * trusts them when reasoning about callers.  Keep them as weak as possible.
 */
#ifndef FRAGMA_SPECS_H
#define FRAGMA_SPECS_H

/* Frama-C has no builtin model for __builtin_unreachable (it becomes an
 * implicitly-declared RETURNING function, so "dead" paths fall through!).
 * gen-db.py maps it to this noreturn stub.  In the kernel it only appears
 * after a trapping instruction (x86 BUG() is "ud2; __builtin_unreachable()"),
 * so modelling it as "execution ends here" matches the machine behaviour.
 */
/* The contract makes any path reaching a call logically dead (it neither
 * returns nor exits): the ACSL model of "the CPU trapped, this thread of
 * execution is over".  This is the standard modelling for BUG()/panic(). */
/*@ terminates \true;
    exits \false;
    assigns \nothing;
    ensures never: \false;
  @*/
extern void fragma_unreachable(void) __attribute__((__noreturn__));

/*@ requires valid_string:
        \exists integer n; 0 <= n && s[n] == 0 && \valid_read(s + (0 .. n));
    terminates \true;
    exits \false;
    assigns \nothing;
    ensures nul_at_result: s[\result] == 0;
    ensures first_nul: \forall integer i; 0 <= i < \result ==> s[i] != 0;
  @*/
unsigned long strlen(const char *s);

/*@ requires dst_ok: \valid((char *)to + (0 .. len - 1));
    requires src_ok: \valid_read((char *)from + (0 .. len - 1));
    requires no_overlap:
        \separated((char *)to + (0 .. len - 1), (char *)from + (0 .. len - 1));
    terminates \true;
    exits \false;
    assigns ((char *)to)[0 .. len - 1] \from ((char *)from)[0 .. len - 1];
    assigns \result \from to;
    ensures copied: \forall integer i; 0 <= i < len ==>
        ((char *)to)[i] == ((char *)from)[i];
    ensures \result == to;
  @*/
void *memcpy(void *to, const void *from, unsigned long len);

#endif /* FRAGMA_SPECS_H */
