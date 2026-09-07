/* Checked proof search only; no axioms, contracts, or C definitions. */
/*@ strategy fragma_riscv_extract:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitwised", \goal(_ == _),
        \param("Wp.bitwised.range", 32), \children(fragma_riscv_extract)),
      \tactic("Wp.bitwised", \incontext((_ & _) == _),
        \param("Wp.bitwised.range", 32),
        \child("range", fragma_riscv_math), \children(fragma_riscv_extract)),
      \tactic("Wp.bitwised", \incontext((_ >> _) == _),
        \param("Wp.bitwised.range", 32),
        \child("range", fragma_riscv_math), \children(fragma_riscv_extract)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 7)), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 6)), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 5)), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 4)), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 3)), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 2)), \children(fragma_riscv_extract)),
      \tactic("Wp.bittestrange", \ingoal(bit_test(_, 1)), \children(fragma_riscv_extract)),
      \tactic("Wp.bitrange", \children(fragma_riscv_extract)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_riscv_extract)),
      \tactic("Wp.overflow", \ingoal(to_sint32(_)), \children(fragma_riscv_extract)),
      \tactic("Wp.overflow", \ingoal(to_uint32(_)), \children(fragma_riscv_extract)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_riscv_extract)),
      \prover("alt-ergo", "z3", 2);
    proof fragma_riscv_extract: opcode_field;
    proof fragma_riscv_extract: rd_field;
    proof fragma_riscv_extract: immediate_field;
    proof fragma_riscv_extract: funct3_field;
    proof fragma_riscv_extract: rs1_field;
    proof fragma_riscv_extract: rs2_field;
    proof fragma_riscv_extract: funct7_field;
    proof fragma_riscv_extract: immediate_low;
    proof fragma_riscv_extract: immediate_high;
    proof fragma_riscv_extract: immediate_4_1;
    proof fragma_riscv_extract: immediate_10_5;
    proof fragma_riscv_extract: immediate_11;
    proof fragma_riscv_extract: immediate_12;
    proof fragma_riscv_extract: immediate_10_1;
    proof fragma_riscv_extract: immediate_19_12;
    proof fragma_riscv_extract: immediate_20;
    proof fragma_riscv_extract: release_field;
    proof fragma_riscv_extract: acquire_field;
    proof fragma_riscv_extract: funct5_field;
    proof fragma_riscv_extract: roundtrip;
 */
/*@ strategy fragma_riscv_math:
      \prover("qed"),
      \prover("alt-ergo", "z3", 1),
      \tactic("Wp.bitrange", \children(fragma_riscv_math)),
      \tactic("Wp.modmask", \ingoal(_ & _), \children(fragma_riscv_math)),
      \tactic("Wp.shift", \ingoal(_ << _), \children(fragma_riscv_math)),
      \tactic("Wp.overflow", \ingoal(to_sint32(_)), \children(fragma_riscv_math)),
      \tactic("Wp.overflow", \ingoal(to_uint32(_)), \children(fragma_riscv_math)),
      \tactic("Wp.shift", \ingoal(_ >> _), \children(fragma_riscv_math)),
      \prover("alt-ergo", "z3", 2);
 */
