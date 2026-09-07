# Next configured common24 profiles

Configured-port continuation, 2026-09-06. The readiness work below led to
profile-specific compiler, proof and review gates; readiness alone never
awarded support. Genuine `build/kernel/<profile>/lib/string.c` commands and
headers remain mandatory, together with each profile's own configured model.

The first three candidates are now registered in the
[wave-two manifest](../config/common-byte-wave2-targets.json); their initial
compiler/proof runs and corrected RISC-V assertion mapping are recorded in
[the wave-two log](WAVE2-20260906.md). Their separate scoped reviews were
completed, and all 580 then-current regression tests passed. The dated
[six-profile run and audit](L2-WAVE2-20260906.md) established their scoped L2
baselines and renewed the original three. Wave three then added Alpha, hardware
x86-64 and UML in a [separate manifest](../config/common-byte-wave3-targets.json).
All [nine common24 baselines](L2-WAVE3-20260906.md) passed normal acceptance and
independent audit at that identity, with 610 regression tests passing without
skips. The subsequent [LLVM build-helper extension](../profiles/LLVM-BUILD-20260906.md)
changes a shared recorded input, so those proof runs now require current-identity
renewal. The subsequent [Clang interface work](../profiles/CLANG-INTERFACE-20260906.md)
passes 690 tests and 182 existing-model checks, but does not renew those proofs;
all dated evidence remains unchanged.

All six variants in this table reuse the same four byte helpers and two
project witnesses. Each independently checks the explicit `no-instrument`
inline policy (selector 1) against genuine headers. An older width/layout
match is not a substitute for those type/signature/inline assertions.

| Profile | Model / observed ELF machine | Genuine optimization | Delivered evidence and remaining scope |
| --- | --- | --- | --- |
| `arm64-gcc` | LE64 / 183 | `-O2` | Accepted scoped baseline; 25+2 compiler commands and 94/82 proof inventory pass. Retain LP64, general-register-only and selected branch-protection settings. |
| `riscv64-gcc` | LE64 / 243 | `-O2` | Accepted scoped baseline; corrected 25+2 and 94/82 pass. Positive ELF has no relocations/undefined symbols. Keep LP64, medany, strict alignment and source-derived assertion identities; generator-only musl headers are not kernel headers. |
| `sh-gcc` | LE32 / 42 | `-O2` | Accepted scoped baseline; 25+2 and 94/82 pass. Keep SH4/4A, no-FPU, little-endian and no-FDPIC settings; `long` is 32-bit. |
| `alpha-gcc` | LE64 / 36902 | `-O2` | Accepted scoped baseline. Fresh calibration observes `st_other=0x80`; the reviewed ELF gate preserves only exact `0x80`/`0x88` on eligible Alpha function definitions. `0x88` is documented/tested, not observed on that calibration function. |
| `x86_64-gcc` | LE64 / 62 | `-Os` | Accepted scoped baseline. The unchanged genuine command and positive `__OPTIMIZE_SIZE__=1` now pass the reviewed sole-`-O2`/`-Os` policy. Kernel code model, no red zone and selected branch protection remain explicit. |
| `um-x86_64-gcc` | LE64 / 62 | `-Os` | Accepted separate UML baseline. Its own model/header route, large code model, no builtins, `__arch_um__` and kernel symbol renamings are retained; no hardware-x86 approval or UML execution is inherited. |

The earlier retained `lib/string.o` inspection was metadata scouting, not
calibration evidence. Fresh genuine fixtures, both mismatch controls and all
25 fixed-calibration commands now pass per profile, followed by full-domain
94-goal/82-property proofs and explicit scoped review. The
[wave-three review](REVIEW-WAVE3-20260906.md) explains the exact Alpha container
and symbol restrictions and optimization-macro checks. No metadata is masked,
compiler flag replaced, or negative error/absent-object requirement relaxed.

For every future profile or variant, complete the same sequence:

1. Bind the explicit target to a current configured model and genuine command.
2. Run the genuine fixture, both mismatch controls and all 25 fixed-calibration
   commands; retain exact failures and complete input/object/diagnostic records.
3. Check the actual parsed six C bodies and all 24 ACSL blocks, full helper
   domains, proof dependencies, access/pointer/shift/call inventories and smoke
   outcomes. A changed model's inventory needs an explicit reviewed expectation,
   not a relaxed count check.
4. Add profile-bound assumption/diagnostic reviews, complete fresh normal proof
   acceptance, and audit retained replay/coverage before documenting scoped L2.

Six additional variants add no new distinct kernel functions. These configured
candidates also do not replace L1 bring-up and L2 baselines for the remaining
architectures in the pinned 21-architecture roster. Runtime, further ABIs,
endian variants and kernel callers remain separate work.

The Alpha/x86/UML provider blockers recorded in the
[dated read-only assessment](../build/common24-next3-assessment-20260906/NEXT3.md)
are resolved by those narrow, tested changes and fresh evidence, not by
relabeling the failed initial receipts. All nine common24 variants retain 12
inconclusive smoke checks each; no consistency theorem follows. Hardware x86's
benign model-native `-O2` fixture is separate from its nonexecuted common24
`-Os` object, and no L3 is established.

The existing s390 pilot already covers these four source helpers in its own
seven-helper scope; adding a common-provider variant there would not add an
architecture baseline or distinct function. Nine dated GCC common24 scopes,
the dated s390 pilot and the fresh
[MIPS32el common24 result](L2-MIPS32EL-20260907.md) make eleven named
architecture baselines; the other ten families have no L2 baseline. The pinned
21-architecture roster is not a claim of complete support. Those ten
unconfigured families remain in the
[separate toolchain/LLVM readiness queue](../profiles/NEXT-WAVE.md),
including Nios II's need for a pre-GCC-15 toolchain.
