/* SPDX-License-Identifier: GPL-2.0 */
/* Checked proof search for the full-domain 24-bit byte helpers.
 * This header introduces no axioms, admitted lemmas, or C definitions.
 * Every tactic's range, positivity, and arithmetic children remain obligations.
 *
 * Extraction uses bitwise equality (32-bit range checked separately). In its
 * range children, masks become modulo before BitRange: this avoids Frama-C 33's
 * missing-verdict corner case for an already-trivial constant-mask positivity
 * child. Generic quotient/remainder assertions precede extraction assertions
 * in the harness, so rewriting does not hide a mask behind a known byte value.
 * See byte-verification.md for scope, rejected experiments, and evidence.
 */
/*@ strategy fragma_byte_extract:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitwised", \goal(_ == _),
        \param("Wp.bitwised.range", 32), \children(fragma_byte_extract)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_byte_extract)),
      \tactic("Wp.bitrange", \children(fragma_byte_extract)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_byte_extract)),
      \prover("alt-ergo", "z3", 5);
    proof fragma_byte_extract: extracted_high;
    proof fragma_byte_extract: extracted_middle;
    proof fragma_byte_extract: extracted_low;
 */
/*@ strategy fragma_byte_decompose:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitrange", \children(fragma_byte_decompose)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_byte_decompose)),
      \tactic("Wp.overflow", \ingoal(to_uint32(_)), \children(fragma_byte_decompose)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_byte_decompose)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_byte_decompose)),
      \prover("alt-ergo", "z3", 5);
 */
