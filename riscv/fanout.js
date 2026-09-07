export const meta = {
  name: 'riscv-rte-fanout',
  description: 'Fan out Frama-C RTE over RISC-V encode/decode leaves, confirm UB via EVA, triage reachability',
  phases: [
    { title: 'Sweep', detail: 'one agent per function cluster: verbatim harness + WP-RTE + EVA confirm + reachability' },
    { title: 'Synthesize', detail: 'aggregate + rank confirmed reachable UB' },
  ],
}

const FRAMAC_ENV =
  'export PATH=$HOME/.local/bin:$PATH LD_LIBRARY_PATH=$HOME/.local/lib && eval "$(opam env --switch=fragma)"'

// A proven, self-contained harness template the agents adapt (pure-arithmetic
// leaves need only width typedefs; NO kernel headers).
const TEMPLATE = `
typedef unsigned char u8; typedef unsigned short u16;
typedef unsigned int u32; typedef unsigned long u64;
typedef signed int s32; typedef signed long s64; typedef unsigned long ulong;
/* ... paste VERBATIM function bodies here ... */
/* keep them alive so WP/EVA sees them (address-taking or a driver): */
void *fragma_keep[] = { /* fn1, fn2, ... */ };
`

const RECIPE = `
ENVIRONMENT (run this once at the start of every bash command):
  ${FRAMAC_ENV}

WORKING DIR: /home/karl/linux-work/fragma
SOURCE TREE: /home/karl/linux-work/linux   (rc6 HEAD; identical to the rc4 build tree for these files)
TEMPLATE HARNESS (self-contained, no kernel headers):
${TEMPLATE}

WORKING EXAMPLES you may read for reference:
  riscv/annotated/bpf_encoders.sweep.c   (base BPF encoders; known signed-overflow)
  riscv/annotated/insn_decode.sweep.c    (misaligned decode; includes real asm/insn.h)

STEP-BY-STEP for your assigned cluster:
1. Read the assigned functions from the source file (use the given file + function names).
2. Write a harness at riscv/annotated/<CLUSTER>.sweep.c: the typedef preamble above
   + the VERBATIM function bodies (copy exactly, do not edit the code) + a
   fragma_keep[] array taking their addresses. If a body calls a helper not in
   your list, either include that helper verbatim too or add a stub with a
   contract. Bodies MUST stay byte-identical to the tree (that is the whole point).
3. Run WP-RTE:
   frama-c -machdep gcc_x86_64 -cpp-extra-args=-std=gnu11 riscv/annotated/<CLUSTER>.sweep.c \\
     -wp -wp-rte -wp-prover alt-ergo,cvc5,z3 -wp-timeout 15 -wp-par 4 2>&1 | tail -40
   Note every UNPROVEN goal (Timeout/Unsuccess), especially rte_signed_overflow,
   rte_shift, rte_mem_access. A proved goal (in "Proved goals: N/N") = clean.
4. For each unproven signed_overflow / shift goal, CONFIRM it is a real violation
   (not just prover weakness) with EVA on a concrete input: write a tiny driver
   u32 drv(void){ return THE_FN(<concrete args>); } appended to a copy, then
   frama-c -machdep gcc_x86_64 <file> -eva -main drv 2>&1 | grep -iE 'overflow|invalid|shift'
   A "final status invalid" / "sure alarm" = CONFIRMED UB for that input.
5. REACHABILITY (the key judgment): is the confirming input a VALID one the kernel
   actually produces? For encoders, work out the real value ranges: e.g. a 12-bit
   I-type immediate imm11_0 is 0..0xFFF and NEGATIVE immediates give imm11_0>=0x800
   (reachable); a funct7 is a 7-bit opcode field and only specific instructions set
   its high bits. State the smallest realistic triggering input and WHY it is (or is
   not) reachable from real JIT/decoder callers. Grep the callers in
   arch/riscv/net/ or arch/riscv/kernel/ to check.

Return ONLY the structured object. Bodies you could not make parse -> note in 'notes'.
`

const FINDING_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['cluster', 'functions_analyzed', 'findings', 'notes'],
  properties: {
    cluster: { type: 'string' },
    functions_analyzed: { type: 'integer' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['function', 'rte_class', 'expression', 'wp_status', 'eva_confirmed', 'reachable', 'trigger_input', 'reasoning', 'verdict'],
        properties: {
          function: { type: 'string' },
          rte_class: { type: 'string', description: 'e.g. signed_overflow, shift, mem_access, none' },
          expression: { type: 'string', description: 'the offending C sub-expression' },
          wp_status: { type: 'string', enum: ['proved', 'unproven'] },
          eva_confirmed: { type: 'boolean', description: 'EVA gave a sure/invalid alarm for a concrete input' },
          reachable: { type: 'boolean', description: 'triggerable with inputs real callers produce' },
          trigger_input: { type: 'string', description: 'smallest realistic triggering args, or n/a' },
          reasoning: { type: 'string' },
          verdict: { type: 'string', enum: ['real-UB-reachable', 'UB-unreachable', 'clean', 'inconclusive'] },
        },
      },
    },
    notes: { type: 'string' },
  },
}

const CLUSTERS = [
  { name: 'base-encoders', file: 'arch/riscv/net/bpf_jit.h',
    funcs: 'rv_r_insn, rv_i_insn, rv_s_insn, rv_b_insn, rv_u_insn, rv_j_insn, rv_amo_insn (lines ~231-282)',
    hint: 'I already confirmed rv_i_insn overflows for imm11_0>=0x800. Formalize ALL of them: which shifted operand (u8/u16 promoted to signed int) overflows, and the smallest reachable trigger per function. rv_amo_insn feeds funct7 = funct5<<2|.. into rv_r_insn.' },
  { name: 'compressed-encoders', file: 'arch/riscv/net/bpf_jit.h',
    funcs: 'rv_cr_insn, rv_ci_insn, rv_css_insn, rv_ciw_insn, rv_cl_insn, rv_cs_insn, rv_ca_insn, rv_cb_insn (lines ~286-335)',
    hint: 'These return u16 but compute with int promotions; check funct/imm shifts (e.g. funct3<<13, funct6<<10) for signed overflow and for truncation into the u16 return.' },
  { name: 'insn-wrappers', file: 'arch/riscv/net/bpf_jit.h',
    funcs: 'rv_addi, rv_andi, rv_ori, rv_xori, rv_slli, rv_srli, rv_srai, rv_lui, rv_auipc, rv_add, rv_sub, rv_and, rv_or, rv_sll, rv_srl, rv_sra, rv_mul, rv_div, rv_remu (lines ~339-459)',
    hint: 'These call the base encoders. Include the base encoders they need (verbatim) so the harness is closed. Question: do the wrappers pass argument ranges that make the inherited overflow REACHABLE (e.g. rv_addi forwards imm11_0 unchanged)? rv_srai does 0x400|imm11_0.' },
  { name: 'insn-h', file: 'arch/riscv/include/asm/insn.h',
    funcs: 'the RVG/RVC encode helpers and field-extract macros (grep for "static inline" and the RV_X/REG_OFFSET/IMM_* macros)',
    hint: 'Include the header directly like riscv/annotated/insn_decode.sweep.c does (define CONFIG_64BIT, provide u32/s32/bool/__always_inline/BUILD_BUG_ON, -I the real include dir and riscv/override for bits.h). Check the IMM_I/IMM_S sign-extract shifts and any encode helper.' },
  { name: 'misaligned-decode', file: 'arch/riscv/kernel/traps_misaligned.c',
    funcs: 'the decode arithmetic already partly covered by riscv/annotated/insn_decode.sweep.c: extend to cover the store-side GET_RS2/GET_RS2S offsets and the INSN_LEN advance for every case',
    hint: 'Reuse riscv/annotated/insn_decode.sweep.c approach. Confirm REG_OFFSET stays in [0,248] and no shift-UB. This one is expected CLEAN; confirm and report clean.' },
  { name: 'riscv-misc', file: 'arch/riscv/kernel/',
    funcs: 'pick 2-3 self-contained arithmetic leaves from RECENTLY changed files: sys_hwprobe.c (hwprobe_get_cpus bit/key math), stacktrace.c walk_stackframe frame arithmetic, kexec_elf.c riscv_kexec_elf_load. Choose whichever are self-contained enough to harness.',
    hint: 'These are less-encoder-like; look for shift/index/bounds arithmetic. If a function is too entangled to harness cleanly, say so in notes and move to the next candidate.' },
]

phase('Sweep')
const results = await parallel(CLUSTERS.map(c => () =>
  agent(
    `You are a Frama-C RTE bug-hunter analyzing RISC-V kernel code. Cluster: "${c.name}".\n` +
    `Source file: ${c.file}\nFunctions: ${c.funcs}\nHint: ${c.hint}\n\n${RECIPE}`,
    { label: `sweep:${c.name}`, phase: 'Sweep', schema: FINDING_SCHEMA, effort: 'high' }
  )
))

phase('Synthesize')
const clean = results.filter(Boolean)
const synthesis = await agent(
  `Aggregate these Frama-C RTE sweep results over RISC-V kernel code into one report.\n\n` +
  `DATA (JSON array of per-cluster findings):\n${JSON.stringify(clean, null, 1)}\n\n` +
  `Produce a markdown report for a kernel developer:\n` +
  `1. Executive summary: how many CONFIRMED reachable UB findings (verdict real-UB-reachable), across which functions.\n` +
  `2. A ranked table of the real-UB-reachable findings: function, offending expression, RTE class, smallest reachable trigger.\n` +
  `3. Root-cause grouping: e.g. "u8/u16 operand promoted to signed int then left-shifted past bit 30" — list every function sharing each root cause.\n` +
  `4. Reportability assessment: this is ISO C signed-left-shift-overflow, NOT covered by the kernel's -fno-strict-overflow (that flag covers +,-,* only), benign on current GCC/Clang but flagged by CONFIG_UBSAN (shift-out-of-bounds) at runtime when the JIT emits e.g. a negative immediate. State honestly whether each is worth an upstream hardening patch and the fix shape (cast operand to u32 before shifting).\n` +
  `5. Anything UB-unreachable or clean, briefly, so we know coverage.\n` +
  `Be precise and skeptical. Do not inflate: only call something reachable if a real caller produces the triggering input.`,
  { label: 'synthesize', phase: 'Synthesize', effort: 'high' }
)

return { clusters: clean, report: synthesis }
