/* FRAGMA: concrete counterexample driver for strlcat's naive_no_truncation.
 *
 * Candidate counterexample (from the failed WP goal's truncation path):
 *   buf[8] = "ab" (dsize=2), src = "cdef" (len=4), count = 5
 *   -> res = 6, but only "cd" fits: buf becomes "abcd", length 4 != 6.
 *
 * EVA analyzes this with the REAL kernel strlcat body from the annotated TU
 * (linked in the same Frama-C project).  The naive claim must evaluate to
 * a definitively-invalid (red) assertion; the sanity asserts must be valid.
 *
 * NB: the naive claim is stated as "all chars before r are non-NUL" (i.e.
 * strlen(buf) >= r).  Asserting just buf[r]==0 would be accidentally TRUE
 * here because the tail of buf is zero-initialized.
 */
unsigned long strlcat(char *dest, const char *src, unsigned long count);

const char *fragma_src = "cdef";

void fragma_naive_cex(void)
{
	char buf[8] = "ab";
	unsigned long r = strlcat(buf, fragma_src, 5);

	/*@ assert result_is_intended_total: r == 6; */
	/*@ assert truncated_string: buf[4] == 0; */
	/*@ assert naive_claim_REFUTED:
	      \forall integer j; 0 <= j < r ==> buf[j] != 0; */
}
