# Common24 wave-two and assertion-symbol scoped review

Decision date: 2026-09-06. Reviewer: Codex AI assistant, with independent AI
source/operation and implementation review by `pointer_audit`. Not a human
approval. Linux pin: `b9b3e33b70b71e516930117e21de3ad2a7723747`.

The assumptions `common24-wave2-types` and `common24-wave2-frontend` are
reviewed assumptions for exactly the four common24 byte helpers and two project
round trips under `arm64-gcc`, `riscv64-gcc` and `sh-gcc`. Their implementations
remain unproved. This decision also reviews the assertion-symbol checker change
for those three profiles and the original `arm-gcc`, `powerpc32-gcc` and
`m68k-gcc` profiles. It does not broaden the original profiles' function scope
or transfer their assumption approvals to wave two.

This review supplies no fresh proof, result acceptance or architecture level.
All six targets must pass their current model/source/frontend/compiler/proof
and dependency gates in subsequent normal runs. Earlier results remain dated;
updating a current manifest's review context does not update any saved result.
No smoke waiver is granted and no consistency theorem is claimed.

## Unchanged operations and full domains

The four selected bodies are `__get_unaligned_be24`, `__get_unaligned_le24`,
`__put_unaligned_be24` and `__put_unaligned_le24` from
`include/linux/unaligned.h`. The two project round trips are not kernel
functions. Source gates preserve these bodies/declarators; actual preprocessing
must retain all six bodies, both typedefs, 24 ordered ACSL blocks and the same
16 intermediate assertions and checked strategy.

Getters require only three readable bytes. Promoted byte values are 0–255;
the largest C shift is `255 << 16 == 16711680`, and the combined value is at
most 16777215, within the checked signed-int range. C shift counts are 8 and
16; annotations also use 24, below 32. The four exported shift properties are
nonnegative-operand checks, not four independently exported count checks.

Writers accept every `u32` and require only three writable bytes. Unsigned
right shifts and masks yield stored bytes in 0–255. The final increment may
form one-past but never dereferences it. The two witnesses initialize all
three local bytes before decoding and recover the input modulo 2^24. All four
direct-call precondition instances and every selected access/pointer guard
remain mandatory. No extra alignment, buffer extent or value restriction is
introduced; no `long`, `size_t`, indirect call or external implementation is
used by this source graph.

## Profile-specific model and frontend review

| Profiles | Relevant checked C model | Genuine inline policy |
| --- | --- | --- |
| ARM64, RISC-V64 | 32-bit int/u32, 64-bit long/pointer, byte alignment one | `no-instrument` |
| SH | 32-bit int/u32/long/pointer, byte alignment one | `no-instrument` |
| Original ARM32, PowerPC32, m68k | Original reviewed model scope remains unchanged | Original explicit policy; PowerPC32 remains `patchable-entry-0` |

The genuine fixture checks `u8` as unsigned char and `u32` as unsigned int,
integer widths/promotion range, byte alignment and all four signatures. The
wrong-type control substitutes unsigned long in the expected type/signatures,
not in the genuine typedef. On ARM64/RISC-V this differs in width and type;
on SH and the original three profiles it is a same-width distinct C type.
All five intended type/signature errors and the sole wrong-inline error remain
required. Width equality alone is never the justification.

ARM64 keeps its genuine LP64, general-register-only and selected branch-protection
settings. RISC-V keeps LP64, medany, strict alignment, no-save-restore and actual
attribute switches; the generator-only musl sysroot is not used for kernel
analysis. SH keeps its ordered SH4/SH4A no-FPU options, little endian and no-FDPIC.
Neither replacing a target's compiler flags nor borrowing a host model is allowed.

The five actual diagnostics on each new profile receive individual reviews:

1. GNU inline attributes: the genuine declaration spelling and selected policy
   are checked. The abstraction covers the six sequential C bodies and direct
   witness calls, not linkage, instrumentation, timing or emitted instructions.
2. Unsupported alignment guards: every dereference is through genuine `u8`
   with alignment one; no cast or word-sized access is present. All emitted
   access and pointer-formation properties remain required.
3. Unsupported indirect-call guards: there are no indirect calls. The four
   direct witness calls and their preconditions remain in the proof closure.
4. Disabled signed-overflow reporting: the complete-domain range argument above
   covers all getter promotions/shifts and writer conversions. This does not
   pretend a disabled guard was generated.
5. Missing RTE guards: the review uses that complete operation map and retained
   inventory. As documented against installed Frama-C 33's implementation in
   the [first scoped review](REVIEW-20260906.md), alignment/indirect-call
   categories are excluded from the missing-status list, disabled arithmetic
   categories can set it, and the message reports an earlier status snapshot.
   The two unsupported-feature warnings alone do not explain it.

The existing PowerPC patchable-entry review remains restricted to its genuine
`(0,0)` metadata and sequential C abstraction; the provider correction does
not model entry patching or widen that earlier warning review.

## Source-derived compiler assertion identities

The [initial wave-two run](WAVE2-20260906.md) exposed a checker assumption:
RISC-V headers consume two `__COUNTER__` values before the fixed calibration.
The first intended wrong expectation correctly names `__compiletime_assert_2`,
while the old validator assumed suffix zero. Its four-command error receipt
and absent WP result remain unchanged.

The reviewed correction is in `fragma/common24_calibration.py`, SHA-256
`c4729612d3d2417b22845e2faf1332f86c5aa9fedebdf8a0a43f06ec1f88db3b`.
It derives exact error identities from the unique positive calibration function:
22 ordered known labels, exact error-attributed declarations, canonical unique
consecutive symbols and one matching direct call per declaration. The expected
symbol is mandatory for negative matching. No negative diagnostic can choose
its own expectation, no architecture offset is hard-coded, and no kernel macro
or source body is changed.

The map is derived after successful positive preprocessing, before any negative
command, and independently rederived during command/hash readback. Final checks
still require genuine source/dependencies, exact commands and streams, every
intended sole error, no negative object, and a bounded defined positive ELF
function. The original 25-command plan and fixed calibration C are unchanged.
Derived maps are exposed in validated/logical observations, never trusted merely
because a receipt contains them. Compiler controls remain finite observations,
not runtime reachability or full-domain proofs.

The [independent implementation review](../build/common24-wave2-initial-audit-20260906/PARSER-DELTA.md)
found no concrete defect in this correction. The
[137-test focused run](../results/tests-common24-wave2-symbols-20260906.log)
passes with no skips, including zero/two-offset maps, malformed and mismatched
identities, complete readback and raw historical controls. The
[fresh RISC-V run](../results/common24-wave2-riscv-symbols-20260906/SUMMARY.md)
then passes all 25 core commands and two fixture controls, and closes 94 ordinary
goals and 82 selected properties. It still records pending reviews, not acceptance.
The initial ARM64/SH runs retain the same complete proof inventories and their
own compiler observations at the earlier provider identity.

## Invalidation and remaining boundaries

Current target reviews must bind this supplement, their specific profile/model,
genuine build, preprocessing and analysis policy, source/specification/strategy,
provider implementation and inspectable evidence. The original three target
contexts must be renewed explicitly for the checker change; their old hashes
must not be treated as current. The preserved full regression log exposes those
three stale review bindings rather than concealing them.

Every new normal run must produce fresh compiler receipts and complete proof
evidence under the resulting current context. All 12 smoke attempts per profile
remain individually inconclusive unless fresh raw evidence changes their outcome;
`reviewed_smoke` stays empty. Required proof dependencies cannot be omitted or
replaced by finite compiler predicates. Kernel callers, compatibility ABIs,
traps, assembly, MMIO, concurrency, instrumentation and emitted-code correctness
remain outside this review. L2/L3 decisions require their separate evidence and
documented scope after fresh acceptance.
