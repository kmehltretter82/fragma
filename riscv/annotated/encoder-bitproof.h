/* SPDX-License-Identifier: GPL-2.0 */
/* Experimental checked search, not an axiom or a replacement C semantics.
 * Promoted u8/u16 shifts require signed-32 conversion handling; the result
 * and u32 shifts require unsigned-32 handling. Both case splits precede
 * logical shift elimination. Every emitted side condition needs a recorded
 * proof result, including trivial children affected by Frama-C bookkeeping.
 */
/*@ strategy fragma_encoder_fields:
      \prover("qed"),
      \tactic("Wp.bitrange", \children(fragma_encoder_fields)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_encoder_fields)),
      \tactic("Wp.overflow", \ingoal(to_sint32(_)), \children(fragma_encoder_fields)),
      \tactic("Wp.overflow", \ingoal(to_uint32(_)), \children(fragma_encoder_fields)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_encoder_fields)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_encoder_fields)),
      \prover("alt-ergo", "z3", 2);
 */
