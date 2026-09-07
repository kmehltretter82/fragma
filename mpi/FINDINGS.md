# lib/crypto/mpi — RTE hunt log

Tree: ~/linux-work/linux @ b9b3e33b70b71 (7.2-rc6).
Method: standalone RTE harness per leaf (verbatim body + kernel typedefs,
enforced by check-verbatim.sh), prove UB/OOB-freedom under the function's OWN
documented preconditions, then audit whether every caller establishes them.

## mpihelp_rshift  (generic_mpih-rshift.c)  —  NO BUG

Harness: annotated/mpih-rshift.acsl.c.  RTE result: **29/29 proved** under
  0 < cnt < 64 ; usize >= 1 ; up[0..usize-1] readable ; wp[0..usize-1] writable.
Two ways the body has UB if a precondition is broken:
  * cnt == 0  -> sh_2 = 64 - 0 = 64 -> `high_limb << 64` is shift-width UB.
  * usize <= 0 -> `up[0]` read (and final `wp[i]`) out of bounds.

Caller audit (all 4 call sites):
  mpi-bit.c:127,151,163  guarded by `nbits` (= n%64, so 1..63) and nlimbs!=0;
                         line 165 even comments "not specified for NBITS==0".
  mpi-div.c:214          guarded by `normalization_steps && rsize`.
  mpi-pow.c:278,284      guarded by `if (mod_shift_cnt)`; sizes are modulus/
                         result limb counts (>=1 in a valid modexp).
=> every caller establishes cnt in 1..63 and size >= 1.  Contract respected.
   Result: proof of safety, not a bug.  (GnuPG-heritage code is careful.)

## TODO
  * mpihelp_lshift: has `i = usize-1; ... while (--i >= 0)` with the final
    `wp[i]` at i == -1 (relies on wp being pre-incremented) and reads
    up[usize-1] first -- worth the same leaf-RTE + caller audit.
  * mpi-bit.c mpi_set_bit / mpi_rshift limb-index arithmetic.
  * mpi-add/sub/mul carry propagation loops.
