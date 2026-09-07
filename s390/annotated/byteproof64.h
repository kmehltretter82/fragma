/* SPDX-License-Identifier: GPL-2.0 */
/* Checked full-domain 48-bit byte proof search; no axioms or C definitions.
 * Left shifts expose constant-times-byte bounds before conversion splitting.
 * Right shifts follow conversions so all positivity conditions remain checked.
 * Exact bitwise equality has a separately checked 64-bit range obligation.
 * See byte48-verification.md for proof scope and retained experiments.
 */
/*@ strategy fragma_byte64_extract:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitwised", \goal(_ == _),
        \param("Wp.bitwised.range", 64), \children(fragma_byte64_extract)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_byte64_extract)),
      \tactic("Wp.bitrange", \children(fragma_byte64_extract)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_byte64_extract)),
      \prover("alt-ergo", "z3", 5);
    proof fragma_byte64_extract: extracted_48_byte_0;
    proof fragma_byte64_extract: extracted_48_byte_1;
    proof fragma_byte64_extract: extracted_48_byte_2;
    proof fragma_byte64_extract: extracted_48_byte_3;
    proof fragma_byte64_extract: extracted_48_byte_4;
    proof fragma_byte64_extract: extracted_48_byte_5;
 */

/* Left shifts first expose constant-times-byte bounds before cast case splits.
 * Right shifts still follow cast splitting so every positivity case is checked.
 */
/*@ strategy fragma_byte64_leftmath:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitrange", \children(fragma_byte64_leftmath)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_byte64_leftmath)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_byte64_leftmath)),
      \tactic("Wp.overflow", \ingoal(to_sint32(_)), \children(fragma_byte64_leftmath)),
      \tactic("Wp.overflow", \ingoal(to_uint64(_)), \children(fragma_byte64_leftmath)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_byte64_leftmath)),
      \prover("alt-ergo", "z3", 5);
 */
