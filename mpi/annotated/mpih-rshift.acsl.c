/* FRAGMA: standalone RTE harness for mpihelp_rshift.
 *
 * The typedefs below are the kernel's (include/linux/mpi.h,
 * lib/crypto/mpi/mpi-internal.h); mpihelp_rshift's BODY is a VERBATIM copy of
 * lib/crypto/mpi/generic_mpih-rshift.c @ b9b3e33b70b71 (checked by
 * check-verbatim.sh).  The function is a pure leaf: its semantics depend on
 * nothing but these integer types, so verifying it standalone is sound and
 * avoids the kernel-header swamp that mpi-internal.h drags in.
 *
 * The contract states the function's OWN documented argument constraints
 * (from the file's header comment).  RTE mode then asks: given these, is the
 * body free of undefined behaviour (shift width, pointer OOB)?  A leftover
 * alarm UNDER these preconditions is a code bug; the separate question of
 * whether callers ESTABLISH them is the caller audit.
 */
typedef unsigned long int mpi_limb_t;
typedef mpi_limb_t *mpi_ptr_t;
typedef int mpi_size_t;
#define BITS_PER_MPI_LIMB 64

/*@ // Documented constraints (generic_mpih-rshift.c header, "Argument
    //  constraints"): 0 < cnt < BITS_PER_MP_LIMB; usize limbs readable at up,
    //  usize limbs writable at wp-1..wp+usize-1 (wp is pre-decremented).
    requires cnt_range:   0 < cnt < BITS_PER_MPI_LIMB;
    requires usize_pos:   usize >= 1;
    requires up_readable:  \valid_read(up + (0 .. usize - 1));
    // wp is pre-decremented then indexed wp[1..usize], i.e. original
    // wp[0..usize-1]; wp[0] (== wp_dec[1]) is the lowest cell touched.
    requires wp_writable:  \valid(wp + (0 .. usize - 1));
    assigns wp[0 .. usize - 1];
  @*/
mpi_limb_t
mpihelp_rshift(mpi_ptr_t wp, mpi_ptr_t up, mpi_size_t usize, unsigned cnt)
{
	mpi_limb_t high_limb, low_limb;
	unsigned sh_1, sh_2;
	mpi_size_t i;
	mpi_limb_t retval;

	sh_1 = cnt;
	wp -= 1;
	sh_2 = BITS_PER_MPI_LIMB - sh_1;
	high_limb = up[0];
	retval = high_limb << sh_2;
	low_limb = high_limb;
	/*@ loop invariant i_bounds: 1 <= i <= usize;
	    loop invariant shifts: sh_1 == cnt && sh_2 == BITS_PER_MPI_LIMB - cnt;
	    // wp here is the DECREMENTED pointer; wp[1..i-1] have been written,
	    // which is original wp[0..i-2].
	    loop assigns i, high_limb, low_limb, wp[1 .. usize - 1];
	    loop variant usize - i;
	  @*/
	for (i = 1; i < usize; i++) {
		high_limb = up[i];
		wp[i] = (low_limb >> sh_1) | (high_limb << sh_2);
		low_limb = high_limb;
	}
	wp[i] = low_limb >> sh_1;

	return retval;
}
