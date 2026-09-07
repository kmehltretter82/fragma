# Common24 wave-three and compiler-policy scoped review

Decision date: 2026-09-06. Reviewer: Codex AI assistant, with independent AI
source, operation, implementation and retained-evidence review by
`pointer_audit`. This is not a human approval. Linux pin:
`b9b3e33b70b71e516930117e21de3ad2a7723747`.

The assumptions `common24-wave3-types` and `common24-wave3-frontend` are
reviewed assumptions for exactly four common24 byte helpers and two project
round trips under `alpha-gcc`, `x86_64-gcc` and `um-x86_64-gcc`. Their
implementations remain unproved. This decision separately reviews the shared
ELF and optimization-policy changes for those profiles and the original six
common24 profiles. Original and wave-two assumption scopes remain unchanged;
their approvals are not transferred to the new three profiles.

This document grants no fresh result acceptance or architecture level. Every
target requires a subsequent normal run with its current model, source,
frontend, compiler, proof and dependency gates. Saved results remain dated.
No smoke waiver, consistency theorem, kernel-caller or L3 claim is supplied.

## Exact source and profile scope

The selected kernel bodies are `__get_unaligned_be24`, `__get_unaligned_le24`,
`__put_unaligned_be24` and `__put_unaligned_le24` in
`include/linux/unaligned.h`. The two project witnesses are not kernel functions.
All six bodies, both typedefs, 24 ordered ACSL blocks, 16 intermediate assertions
and the checked byte-decomposition strategy remain unchanged.

All three new profiles independently check eight-bit bytes, `u8` as unsigned
char, `u32` as unsigned int, 32-bit int with `INT_MAX == 2147483647`, byte
alignment one and all four exact signatures. They use LP64, little-endian
models; neither matching widths nor a common compiler executable substitutes
for a profile-specific model and genuine-header check. The wrong-type control
expects unsigned long instead of the genuine unsigned int: all five intended
type/signature errors are required, alongside the sole wrong-inline error.

| Profile | Genuine configured compiler context retained | Inline policy |
| --- | --- | --- |
| Alpha | Sole `-O2`, EV56/EV6, no floating-point registers; own Alpha build and headers | `no-instrument` |
| Hardware x86-64 | Sole `-Os`, kernel code model, no red zone and selected branch protection | `no-instrument` |
| UML x86-64 | Sole `-Os`, large code model, no builtins, `__arch_um__`, kernel symbol renamings and its own UML header route | `no-instrument` |

The standalone analyzer frontend remains a separately recorded abstraction of
these sequential C bodies, not the complete kernel compilation command. Both
that actual preprocessing/analysis policy and the genuine compiler command
must be checked. UML does not inherit hardware x86's configuration or
host-facing libc, signal, ptrace or USER_CFLAGS model.

Getters require only three readable bytes. Each byte promotes to int in
0–255; the largest shift is `255 << 16 == 16711680`, and the combined value
is at most 16777215. C shift counts are 8 and 16; decomposition annotations
also use 24, below 32. The four exported shift guards concern nonnegative
operands, not four separately exported shift-count guards.

Writers accept every `u32` and require only three writable bytes. Unsigned
right shifts and masks produce stored bytes in 0–255. The final increment
may form one-past without dereferencing it. Witnesses initialize all three bytes
before reading and recover the input modulo 2^24. All access, pointer-formation
and four direct-call precondition instances remain mandatory. No stricter
alignment, extra storage extent or narrowed value domain is introduced.

## Five individual warnings per new profile

The completed initial normal runs retain the same five actual diagnostics:

1. GNU inline: exact genuine spelling and selected inline policy are checked.
   The abstraction covers the sequential static bodies and direct witness
   calls, not linkage, instrumentation, timing or emitted instructions.
2. Unsupported alignment guards: every dereference uses genuine alignment-one
   `u8`; no word load or pointer cast occurs. Emitted access and pointer guards
   remain required, and no other target receives this exception.
3. Unsupported indirect-call guards: the source graph contains no indirect
   calls. Its four direct calls and their preconditions remain in the closure.
4. Disabled signed-overflow reporting: the complete-domain range argument above
   covers the getter promotions/shifts and writer conversions. This does not
   claim that a disabled guard was generated.
5. Missing RTE guards: review uses the complete operation map and raw inventory.
   Installed Frama-C 33 `wpRTE.ml` excludes alignment and indirect-call categories
   from its missing-status list; disabled arithmetic categories can set that
   status. `cfgGenerator.ml` reports the earlier snapshot. The two unsupported
   warnings alone are not an explanation for this separate message.

The original PowerPC `(0,0)` patchable-entry review remains confined to its
earlier profile and sequential-C abstraction. No new profile inherits it.

## Narrow compiler-provider changes

`fragma/common24_calibration.py`, SHA-256
`490fe3d10bdcc7a5d50c8ac94760921ab60710fc1ffbcf8462624ce464ffbe3b`,
now recognizes exactly one genuine `-O2` or `-Os` token, without rewriting argv.
Absent, duplicate, competing or unsupported optimization modes fail. Joined
and split optimization-macro overrides fail. Positive raw macros must contain
exactly one `__OPTIMIZE__ 1`, and exactly one `__OPTIMIZE_SIZE__ 1` for `-Os`
or none for `-O2`. Duplicate, malformed and function-like definitions fail;
distinct longer identifiers cannot spoof those names.

The source-derived 22-assertion map, exact command/environment/dependency
bindings, both genuine-header mismatch controls, sole intended negative errors,
absence of negative objects and all 25 core commands remain mandatory. No
negative diagnostic chooses its own expected assertion identity. The six
earlier positive `-O2` expansions also pass the new macro rules in read-only
regression checks; that does not renew their enclosing old receipts.

`fragma/elf.py`, SHA-256
`f77fddcb23cc862393a7f25db4992e925c2f822d1456ec0ffd7ca60ed4102531`,
recognizes only exact Alpha `st_other` values `0x80` and `0x88` on named,
defined, nonempty, bounded local/global function symbols in allocated,
executable, nonwritable PROGBITS, with ELF64 little-endian EM_ALPHA and header
flags zero. The required calibration definition still must be global.
Unknown values, mixed visibility bits, weak marked functions, other machines,
wrong class/endian/flags, undefined symbols and executable relocations receive
no new allowance. General table, extent, ordering and metadata checks remain.

Pinned `arch/alpha/include/asm/elf.h` names `STO_ALPHA_NOPV` and
`STO_ALPHA_STD_GPLOAD` and the Alpha ELF class/byte order. Installed target
`/usr/alpha-linux-gnu/include/elf.h:2507` describes their procedure-value
meanings. Pinned `arch/alpha/kernel/module.c:204` illustrates why prologue and
linker behavior are outside this observation. Exact reference hashes are in
the [pre-change capture](../build/common24-wave3-compiler-audit-20260906/PRECHANGE-CAPTURE.md).
The actual positive Alpha function records only `0x80`; `0x88` is documented
and regression-tested, not claimed as observed on that function. Metadata is
preserved in observations, never masked away or equated with ISA correctness.

## Evidence and explicit invalidation

The initial compiler-only failures remain unchanged: Alpha completed its
commands but failed the old symbol gate; x86/UML stopped at the old `-O2`-only
context. The [corrected compiler audit](../build/common24-wave3-compiler-audit-20260906/REPORT.md)
checked all three genuine fixtures, 75 core commands, six fixture controls and
407 unique hashes without drift. Its saved driver incorrectly labels the
already-registered pending definitions as unregistered; the audit records this
classification defect explicitly. It is compiler-only evidence, not normal
dispatch, fresh model generation or approval.

The separate [normal registered-target run](../results/common24-wave3-initial-20260906/SUMMARY.md)
completed at 18:55:44.877736 UTC, still unaccepted pending reviews. Each profile
closes 94 ordinary goals and 82 selected properties with complete unconditional
dependency closure; all 36 smoke outcomes remain inconclusive. Independent
readback in `build/common24-wave3-initial-audit-20260906/audit-2.json` checks
2,264 unique hashes without drift and confirms that replay rejects incomplete
assumption approvals. Its earlier auditor-only 18-check inventory error remains
in `audit-1.json`; the corrected auditor requires the exact named 18/20/18 model
checks, not a relaxed count.

The 56 passing model checks include hardware x86's existing build/run of the
benign `profiles/calibration.c` fixture. That model fixture uses its separately
recorded `-O2` context and wrap policy. It is not execution of the genuine
`-Os` common24 object, a kernel helper runtime test, UML execution or L3 evidence.
Alpha/UML have no model-native execution; no historical fault/trap/OOB harness
is run. Finite compiler predicates do not replace full-domain proof obligations.

All 177 common-family tests pass. The [610-test full regression](../results/tests-common24-wave3-pending-20260906.log)
has exactly six stale common-review failures and no errors or skips. They must
be resolved by explicitly binding this supplement and the reviewed provider
changes, not by weakening hash checks. New Alpha metadata and size-optimization
tests preserve rejection cases and inspect retained bytes without executing them.

All nine current contexts must bind this supplement, their own model/build,
actual frontend/analysis, source/contracts/strategy and inspectable evidence.
Original six contexts retain their earlier scoped review documents and
assumptions. New three contexts use only the independent wave-three pair.
Subsequent normal acceptance remains required for every profile; reviews never
rehash old results into approval. Kernel callers, broader ABIs, assembly,
traps, concurrency, MMIO and emitted-code correctness remain outside scope.
