/* SPDX-License-Identifier: GPL-2.0 */
/* Proof search only: these tactics transform obligations and produce checked
 * side conditions. They add no axioms and change no C execution semantics.
 * Cast range cases precede shifts: this avoids a Frama-C 33 bookkeeping hole
 * where a shift's already-true positivity child has no recorded prover result.
 * Every emitted range case still requires an actual checked proof verdict.
 */

/* Experimental byte strategy: two decoder bounds improve, but exact decoding
 * and store dependencies remain open. It is not registered as a complete suite.
 */
/*@ strategy fragma_byte32_math:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitrange", \children(fragma_byte32_math)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_byte32_math)),
      \tactic("Wp.overflow", \ingoal(to_uint32(_)), \children(fragma_byte32_math)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_byte32_math)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_byte32_math)),
      \tactic("Wp.bitwised", \goal(_ == _),
        \param("Wp.bitwised.range", 32), \children(fragma_byte32_math));
 */
/*@ strategy fragma_scalar_math:
      \prover("qed"),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_scalar_math)),
      \tactic("Wp.overflow", \ingoal(to_uint64(_)), \children(fragma_scalar_math)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_scalar_math)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_scalar_math)),
      \prover("alt-ergo", "z3", 5);
 */
