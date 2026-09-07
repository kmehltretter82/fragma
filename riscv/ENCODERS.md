# RISC-V base instruction encoder batch

This batch selects seven exact function definitions from
`arch/riscv/net/bpf_jit.h` at Linux
`b9b3e33b70b71e516930117e21de3ad2a7723747`: `rv_r_insn`, `rv_i_insn`,
`rv_s_insn`, `rv_b_insn`, `rv_u_insn`, `rv_j_insn`, and `rv_amo_insn`.
It constructs integer words; it does not execute generated instructions or
verify BPF programs, JIT reachability, atomicity, or the memory model.

The original `annotated/base-encoders.verified.c` preserves every selected body and
declarator token. Its only model substitutions are `u8`, `u16`, `u32`, and the
configured `inline` expansion. `base-encoders.kernel-model.c` compiles against
the genuine configured RISC-V headers and checks the types, promotions,
declarators and macro expansion. `riscv64-gcc` must separately pass fresh L1
calibration using its kernel LP64 ABI and wrap semantics.

The older sweep's ISO-C signed-shift explanation is historical, not a defect
claim. The selected kernel compiler uses `-fno-strict-overflow`; its calibrated
Frama-C arithmetic configuration is required. Shift counts remain checked even
though shifted-value overflow is modeled as wrapping. See [the earlier model
correction](REPORTABILITY.md).

## Contract domains and properties

Registers are five-bit numbers (0–31), opcode and funct7 seven-bit fields,
funct3 a three-bit field, funct5 a five-bit field, and aq/rl one-bit flags. These
are format widths, not proofs that every possible combination is a legal
instruction. They agree with the official [base instruction formats and
immediate variants](https://docs.riscv.org/reference/isa/v20260120/unpriv/rv32.html#_base_instruction_formats)
and [atomic format](https://docs.riscv.org/reference/isa/v20260120/unpriv/a-st-ext.html).
No kernel-caller precondition coverage is claimed.

All immediate arguments retain their entire C type domain. In particular,
negative signed immediates passed through `u16` or `u32` conversions are not
excluded. Only the low immediate field is retained:

| Format | Immediate argument | Encoded field recovered by witness |
| --- | --- | --- |
| I | all `u16` | low 12 bits, word bits 31:20 |
| S | all `u16` | low 12 bits, word bits 31:25 and 11:7 |
| B | all `u16` halfword offset | low 12 bits, reordered as offset bits 12:1 |
| U | all `u32` | low 20 bits, word bits 31:12 |
| J | all `u32` halfword offset | low 20 bits, reordered as offset bits 20:1 |

Named field properties cover every output bit and separation from neighboring
fields. Five project-only C decode witnesses check encode/decode round trips
modulo the immediate width, with all lower non-immediate fields set. They are
not additional kernel functions. B/J witnesses recover halfword offsets, not
byte offsets or execution target addresses. AMO properties check encoded aq/rl
bits only, not their hardware ordering effects.

No axioms or assumed external function contracts are introduced. AMO calls the
included R-format helper; its callee preconditions and all five witness call
preconditions must be proved. Ordinary WP goals and consolidated dependency
statuses are required together. Inconclusive smoke results do not establish
consistency, and a successful process exit is not a proof certificate.

## Complete checked proof-search result

The [combined checked-strategy probe](../build/riscv-verified/proof-work/all-fields-5/receipt.json)
closes all **119 ordinary WP goals and 119 selected consolidated properties**,
including all 47 named postconditions, every callee/precondition dependency,
and all five complete encode/decode chains. It completed in 286.410 seconds
with two solver workers; its 14 smoke attempts remain inconclusive.

The common-runner target now uses `annotated/base-encoders.proved.c`, an exact
copy of the original harness with a trailing include of the comment-only
`encoder-fieldproof.h`. Neither contracts nor C function tokens change. The
original harness and failed experiments remain intact. Checked bit equality,
bit-test bounds and integer-only context equality expansion close the original
obligations without narrowing the full immediate domains or adding axioms.

All five emitted diagnostic classes have individual, source/model/build/tool-
bound reviews in the target registry. In particular signed promoted shifts use
the genuine configured wrapping policy; their values are not falsely assumed
below `INT_MAX`. See [the detailed proof and review scope](annotated/encoder-verification.md).
A fresh common-suite run still gates acceptance; this probe alone is not L2,
kernel-caller coverage, native RISC-V execution, or a consistency proof.

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" python3 -m fragma run \
  --target riscv.base-encoders --timeout 1 --wall-timeout 600 --jobs 2 \
  --output results/riscv-encoders-fresh
FRAGMA_RISCV_PROOF_RESULTS=build/riscv-verified/proof-work/all-fields-5 \
  python3 -m unittest tests.test_riscv_targets -v
```

## Historical baseline and retained failures

`config/riscv-targets.json` is an integration fragment for the common runner.
The bounded experiment script `riscv/prove-encoders.py` records source gates,
real-header checks, actual preprocessor inputs, ordinary WP JSON, consolidated
TSV, warnings and checked inputs. It never awards L2 by itself.

Fresh results and unresolved obligations belong under `build/riscv-verified/`,
not in historical sweep reports. Baseline outcomes are measured rather than
declared successful by this manifest. Runtime execution is unavailable for this
cross profile and is not replaced by host execution.

The fresh [ordinary baseline](../build/riscv-verified/baseline-2/receipt.json)
passes all seven function/declarator source gates, fresh configured L1 model
calibration, and the genuine-header fixture (772 consumed inputs checked).
At a three-second per-prover budget it records 119 ordinary WP goals:
81 valid and 38 timeouts. The selected consolidated report has 80 `Valid`
properties and 39 `Unknown`. All 14 smoke attempts are inconclusive; none is a
consistency proof. The initial sandboxed run is retained separately as
`baseline-1`: Why3 local IPC was denied and the process timed out, so it is not
proof evidence.

| Selected functions | Valid / timed-out ordinary goals |
| --- | --- |
| R / I / S encoders | 6 / 6; 5 / 5; 6 / 6 |
| B / U / J encoders | 8 / 7; 2 / 3; 4 / 5 |
| AMO encoder | 13 / 3 |
| Project I / U witnesses | 8 / 0 each |
| Project S / B / J witnesses | 7 / 1 each |

In that historical baseline, the I/U witness goals use callee contracts whose
functional obligations remain open, so those particular receipts are not
completed encode/decode proofs. Many historical AMO field goals likewise depend
on the open R-format contract. No historical timeout is reclassified as
invalidity or silently replaced with the newer proof result.

Reproduce the bounded baseline with:

```sh
python3 riscv/prove-encoders.py build/riscv-verified/new-baseline --timeout 3
python3 -m unittest discover -s tests -p test_riscv_targets.py -v
```

Local Why3 Unix-domain socket access must be available. The separate
`probe-encoder-strategy.py` experiment selects only I/U helpers and tries
checked signed-32 and unsigned-32 cast-range cases before eliminating shifts.
Its strategy adds no axioms and does not alter the baseline contract or input
domain; ordinary JSON and consolidated TSV outcomes still determine progress.

That [single cast-strategy probe](../build/riscv-verified/cast-strategy-1/summary.json)
did not improve the eight I/U field obligations: the raw JSON reports seven
ordinary goals valid and eight timeouts. It additionally emits two smoke
verdicts named `none`, which the strict parser rejects as unsupported rather
than accepting as consistency evidence. Its saved child proofs do not establish
their unproved parents. The post-hoc summary is explicitly not a process
receipt; original JSON/TSV/logs are retained unchanged. Later whole-batch
`all-fields-3` and `all-fields-4` experiments each hit their 600-second analyzer
cap without complete reports. The integer-only context selector correction is
measured separately in the successful `all-fields-5` result above.
