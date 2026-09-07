# s390 pilot targets

Status: all seven source-checked kernel functions now pass the common runner's
proof, source/model, assumption, dependency and input-integrity gates. The
independent calibration is still awaiting integrated acceptance, so this pilot
does **not** establish whole-pilot L2 yet. The configured
`s390x-gcc` profile and its machine/layout calibration are separate evidence.
Baseline recorded 2026-09-06 against Linux
`b9b3e33b70b71e516930117e21de3ad2a7723747`.

The [target fragment](../config/s390-targets.json) contains the three proof
groups, a separate deliberately false byte-order calibration, and the proposed
assumption-ledger entries. It uses the shared target/profile interface; the
common suite should select profile `s390x-gcc` and those registered target IDs.

## Current integrated proof result

The [fresh all-helper run](../results/s390-all-proofs-integrated-20260906/SUMMARY.md)
uses the genuine configured z13 profile and the clean local toolchain. It
accepts all three proof groups, including the three project round-trip
witnesses and their required callee dependencies:

| Target | Ordinary WP goals valid | Selected dependency rows valid |
| --- | --- | --- |
| `s390.unaligned24` | 82 / 82 | 70 / 70 |
| `s390.unaligned48` | 74 / 74 | 59 / 59 |
| `s390.tod_to_ns` | 3 / 3 | 5 / 5 |

No input domain or exact functional contract was weakened. All intermediate
assertions are proved, with no axioms, admissions, or manually inserted verdicts.
The [48-bit derivation](annotated/byte48-verification.md) documents the signed
promotion, shift and modulo decomposition checks needed by that group.
The retained runs use one-second solver attempts with an independent 600-second
analyzer cap; a cap being reached would remain incomplete. Smoke timeouts are
inconclusive about consistency, not additional proved properties.

The separate byte-order calibration still needs independently reached runtime
evidence and fresh integrated policy checks. A
[pinned local emulator](../docs/runtime-tools.md) is now available, but its
installation does not establish runtime corroboration. Kernel callers,
unmodelled operations and other configurations remain outside these proofs.

## Function and model scope

| Group | Kernel functions | Contract |
| --- | --- | --- |
| `s390.unaligned24` | `__get_unaligned_be24`, `__get_unaligned_le24`, `__put_unaligned_be24`, `__put_unaligned_le24` | Exact 24-bit byte decoding, exact stored bytes, output bounds, and full-domain encode/decode round trips modulo 2²⁴. |
| `s390.unaligned48` | `__get_unaligned_be48`, `__put_unaligned_be48` | Exact 48-bit big-endian decoding/stores, output bounds, and a round trip modulo 2⁴⁸. |
| `s390.tod_to_ns` | `tod_to_ns` | For every unsigned-long TOD input, result equals mathematical `floor(todval × 125 / 512)` and does not exceed the input. |

The byte helpers come from `include/linux/unaligned.h`; the TOD conversion comes
from `arch/s390/include/asm/timex.h`. All seven named declarators and bodies match
the pinned source. No instruction, branch, or statement was removed. The three
`fragma_roundtrip_*` functions and `fragma_byte_order_calibration` are project
witnesses and do not increase the kernel-function count. The kernel's callers
remain unverified; the round-trip witnesses exercise explicit caller
preconditions but depend on their callees' contracts.

The [byte harness](annotated/unaligned.acsl.c) reads or writes exactly three or
six valid bytes and imposes no alignment stronger than byte alignment. Stores
accept the full `u32`/`u64` domain and retain the low 24/48 bits. Explicit-byte
packing works independently of native machine byte order, so it does not itself
validate the s390 memory model. The shared profile's independent compiled/EVA
byte-order calibration provides that check.

The [kernel-model fixture](annotated/kernel-model-check.c) compiles the actual
configured kernel headers. It checks the complete substitution set: exact
`u8`/`u32`/`u64` type identity, widths and byte alignment; 64-bit unsigned long;
big-endian compiler selection; all seven visible function signatures; and the
effective `inline`/`__always_inline` expansions. The fixture uses the recorded
`lib/string.c` compiler command with source/output/dependency arguments replaced.
Its [successful result](../build/s390-pilot/kernel-model-2.json) is recorded after
an [earlier rejected check](../build/s390-pilot/kernel-model.json) caught the
additional GNU inline, unused, and no-instrument-function attributes.

## Historical first attempts

The genuine kernel build used `-march=z13 -mtune=z13`; the initial
compiler-generated Frama-C description used `-march=z10`. The fixture confirms
the actual kernel types/signatures for the selected helpers, whose bodies have
no architecture-level conditional macros or instructions. This limited evidence
must not be generalized to other s390 helpers without checking their relevant
compiler flags and dependencies.

The [fresh baseline](../build/s390-pilot/baseline-1/process-results.json) records
successful analyzer process exits, not complete proofs. It retains
[input hashes](../build/s390-pilot/baseline-1/input-hashes.json),
[source-gate evidence](../build/s390-pilot/baseline-1/provenance.json), and the
[exact commands](../build/s390-pilot/baseline-1/commands.json), alongside each
target's logs, WP JSON, and property CSV. The property report runs after WP with
`-then -report -report-csv`; otherwise it can describe the pre-proof state.

| Target | Initial regular WP goals valid / unresolved | Historical interpretation |
| --- | --- | --- |
| `s390.unaligned24` | 56 / 10 | Memory/shift guards and the round-trip witnesses pass. Required helper byte-value and range properties time out, so the witnesses remain conditional. |
| `s390.unaligned48` | 42 / 9 | Memory/shift guards pass. Required byte-value/range properties and the 48-bit round trip time out. |
| `s390.tod_to_ns` | 1 / 2 | Assigns passes; exact scale and result bound time out. Termination/normal-exit bookkeeping is reported separately by WP. |

The byte groups also requested 18 smoke checks. WP marked these checks passed
because attempts to prove inconsistent paths timed out; this is inconclusive
about specification consistency. Smoke `passed: true` must not be converted into
a proved ordinary property. No timeout here is evidence of a kernel defect.

The separate [EVA calibration](../build/s390-pilot/baseline-1/calibration.s390.byte-order.eva.log)
decodes bytes `12 34 56`. Its `decoded_be24` assertion is valid and the deliberately
false `byte_order_REFUTED` assertion is locally invalid, with no generated memory
alarms. Its consolidated TSV status is `Invalid or unreachable`, which alone
is insufficient for integrated calibration acceptance.
EVA stops propagation at the false assertion; its resulting non-returning
analysis state is a calibration effect. This entry is excluded from ordinary WP
function selection. It checks the contract's sensitivity to reversed bytes, and
does not count as independent s390 target-runtime execution.

[bitproof.h](annotated/bitproof.h) contains proof-only strategies
for replacing logical shifts and low-bit masks with arithmetic. It introduces no
axioms. In the original strategy, arithmetic subgoals could be discharged, but that run
leaves some trivial child goals without a recorded verdict; the parent remains
unknown. [Diagnostic output](../build/s390-pilot/strategy-debug.log) shows both
children as `Prove: true`, with a Qed verdict attached to only one. The
[saved scripts](../build/s390-pilot/scalar-strategy-4/stores-session/script)
retain that incomplete state. No proof verdict has been inserted manually.
The exact mathematical specifications remain intact. The TOD workaround and
remaining byte limitations are detailed below.

All logs retain Frama-C's warnings about unsupported alignment/function-pointer
RTE guards, signed-overflow settings, and the ignored `__gnu_inline__` attribute.
This pilot uses byte pointers and direct calls only; signed wrap behavior belongs
to the checked compiler/profile model. These scope facts do not authorize
silencing the warnings for future targets. There are no substituted external
function contracts, atomics, concurrency, MMIO, or assembly in these harnesses.

Run the five inventory/source integration tests with:

```sh
python3 -m unittest discover -s tests -p test_s390_targets.py -v
```

Set `FRAGMA_KERNEL_TREE` to another local kernel Git checkout when necessary.
The tests verify the seven source identities, named functions, separate
calibration, and explicit models. They do not assert that unresolved proofs have
passed. L2 still requires all declared properties/dependencies and the configured
profile gates to pass through the shared suite. L3 additionally requires actual
target/emulator execution; `qemu-s390x` was unavailable during the initial
attempts. The current local emulator and in-progress runtime work are separate
from that historical evidence.

## Exact 24-bit group completed locally

The new [proof-only byte harness](annotated/unaligned.verified.c) adds sixteen
proved intermediate assertions without changing any kernel C tokens, contracts,
or input domains. Its [fresh combined replay](../build/s390-pilot/byte24-final-2/receipt.json)
closes all 82 ordinary WP goals and all 70 selected property/dependency entries,
including both full-domain round trips modulo 2²⁴. Twelve smoke checks time out
inconclusively; none is counted as an ordinary theorem or waived as a failure.

The independent project-only false calibration remains unchanged in the original
harness. It is not an unselected caller in the new proof-only translation unit;
an earlier combined replay retained that caller and correctly remained incomplete
because its generic getter precondition was pending. No kernel helper or
round-trip witness was removed. The checked mask/quotient decompositions,
bit-extraction strategy, failed experiments, warning scope and replay commands
are documented in [byte-verification.md](annotated/byte-verification.md).

The new [byteproof.h](annotated/byteproof.h) is separate from the successful TOD
strategy. There are no new axioms, solver verdicts, or toolchain modifications.
As with TOD, standalone local proof completion is not itself a common-suite L2
certificate, and kernel callers/actual s390 runtime execution remain unverified.

## Exact TOD proof completed locally

The cache-disabled [final TOD experiment](../build/s390-pilot/tod-final/receipt.json)
uses the configured **z13** model, a fresh genuine-kernel-header model check,
native Frama-C annotation preprocessing, and the unchanged pinned helper.
Neither its mathematical contract nor its accepted input domain was modified.
For every unsigned-long input `t` in `[0,2^64-1]`, the proof establishes:

- `result = floor(t * 125 / 512)`, using mathematical multiplication in the contract;
- `result <= t`;
- termination, no abnormal exit, and no memory writes.

All three ordinary JSON goals are `valid`; all five exported TOD property rows
are `Valid`. Frama-C's text report additionally marks the complete default
behavior valid. The generated scripts contain 52 checked tactic applications
and 68 child prover verdicts (38 Qed, 30 Alt-Ergo); no verdict was inserted by
hand. The printed `5/5` total includes termination/exit bookkeeping and is not
used as the ordinary-goal count. Smoke checks were enabled, but Frama-C emits
no smoke goal for this parameter-only, call-free leaf; no consistency proof is
inferred from that absence.

The arithmetic follows `t = 512*q + r`: shifts/masks represent `q` and `r`, and
the returned expression is `125*q + floor(125*r/512)`. The proof also checks
the machine-range cases introduced by the C unsigned conversions. It does not
silently replace modular machine arithmetic with unbounded arithmetic.

### Strategy bookkeeping and checked workaround

Inspection of the pinned Frama-C 33 implementation explains the earlier
missing-verdict pattern: `wpo.ml`'s `resolve` short-circuits a syntactically
trivial goal without recording a Qed result; `ProofEngine.commit` resolves
new tactic children, while `ProverScript.process` skips locally proved children
and the parent statistics still aggregate recorded results. The retained
`Prove: true` / no-verdict child is therefore not accepted as a solved parent.
This diagnosis is an inference from source inspection and the retained traces,
not an upstream tool fix or a license to amend its result files.

Merely reordering masks before shifts did not close the TOD goals; the fresh
z13 [failed attempt](../build/s390-pilot/mask-first-tod-2/receipt.json) is retained.
The working `fragma_scalar_math` strategy first rewrites the low-bit mask to
modulo, then uses `Wp.overflow` to split the `to_uint64` range cases **before**
logical-shift elimination. This avoids an already-trivial positivity side goal
on an unsigned conversion. Every generated range, positivity and arithmetic
case is still checked by the unmodified prover/toolchain. There are no added
axioms, admitted lemmas, weakened contracts, or inserted solver verdicts.

The target fragment now specifies the strategy, its consumed header, permitted
Alt-Ergo/Z3 portfolio, depth 64 and smoke timeout. Its exact warning reviews are
bound to source/model/build/toolchain/preprocessing/search hashes. The ignored
GNU inline attribute affects linkage/inlining only for this sequential,
call-free leaf; the actual kernel-header fixture checks the macro and signature.
Alignment and indirect-call guards do not apply because there are no pointers
or calls. The signed-overflow diagnostic does not describe executed signed
arithmetic here; every C operation is unsigned long, and both shifts use the
constant valid count 9. These reviews apply only to this target and configuration.

The common suite must still run its complete integrity, model, toolchain and
review checks before accepting an integrated target result. The standalone
experiment always records `certified: false`, even when all local proof
dependencies pass. Kernel callers and independent target-runtime execution
remain unverified.

Reproduce local proof progress with:

```sh
python3 s390/prove.py s390.tod_to_ns build/s390-pilot/tod-new-run
python3 -m unittest tests.test_s390_targets tests.test_s390_proof_progress
```

Choose a fresh output directory; existing evidence is never overwritten. Use
`--kernel` and `--prefix` before the positional arguments for other local trees
or verified toolchain prefixes. No installation is performed.

### Earlier byte strategy and remaining 48-bit work

The separately named, experimental `fragma_byte32_math` strategy completed
both 24-bit decoder bounds in the fresh z13
[byte experiment](../build/s390-pilot/byte32-strategy/receipt.json): 58 ordinary
goals valid, two timeouts and six unknown. That historical run left exact decoding
and store-byte obligations open, including the trivial-child bookkeeping shape
for some masks; nine exported dependency rows were unknown. No completion was
claimed from it. The new, separately scoped 24-bit proof above supersedes that
incomplete attempt without changing the TOD header. The original 48-bit
obligations remain open and were not rerun by this bounded follow-up.
