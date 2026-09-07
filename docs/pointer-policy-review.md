# Explicit pointer-formation policy review

Reviewed 2026-09-06 for pinned Linux
`b9b3e33b70b71e516930117e21de3ad2a7723747`. This renews the seven existing
proof-target review contexts under an explicit runtime-check policy. It does
not renew a saved proof result or award an architecture level.

## Model and execution boundary

All ten configured profiles now declare
`runtime_checks.pointer_formation = "object-or-null"`, separately from the
unchanged five integer-arithmetic flags and Typed memory model. The runner
requests `-warn-invalid-pointer` before analysis and checks the actual retained
Frama-C correctness audit. Missing or conflicting model settings, engines,
function selections or phase order fail validation. Reviews bind the exact
model, derived pipeline and `fragma/analysis_policy.py` hash. Numeric values
cannot stand in for Boolean review settings.

Within-object arithmetic, including legal one-past pointers, is the supported
domain. This does not model every GCC wrapping-pointer extension or discharge
readability, lifetime or alignment by itself. The actual installed compiler and
Frama-C model observations are retained in the
[diagnostic review](../build/pointer-formation-review/REVIEW.md).
Integer wrapping choices and shift-count obligations remain unchanged.

Every WP target still uses WP/RTE. The fixed s390 byte-order calibration now
uses RTE before EVA, with all selected helpers and its entry selected, and
`-rte-no-use-eva-results`. Its explicit guards must remain individually visible.
Other EVA targets retain their declared ordinary EVA pipeline with the explicit
pointer setting. A checked policy envelope establishes the settings used, not
that all required properties exist or have been proved.

## Unchanged source, contracts and reviewed operations

No kernel body, harness C, contract, accepted domain, compiler flag, strategy,
required functional property, trusted external contract or observation mapping
is changed by this renewal. The following scopes retain their existing exact
warning reasons; none grants a blanket missing-guards waiver.

| Reviewed target | Pointer and diagnostic scope |
| --- | --- |
| `string.verified.strnchr` | Byte reads and advancement within the readable scan/NUL prefix, at most one-past; zero count does not advance. No calls, wider access or indirect call. The original early-match domain limitation remains. |
| `string.verified.strlcat` | Destination additions are bounded by the unchanged destination-fits contract and trusted exact `strlen`; copy and final byte stay within capacity. Byte alignment only; direct trusted `strlen`/`memcpy` remain unproved implementations. The selected trap branch is independently dead. |
| `s390.unaligned24` | Four byte helpers and both direct-call round trips; offsets remain in the required three-byte extent, and stores advance at most one-past. Promoted signed shifts are bounded by byte ranges; unsigned inputs retain their full domain. |
| `s390.unaligned48` | Two byte helpers and the direct-call round trip; six-byte extent and one-past bound, full u64 store/witness inputs. The two promoted signed shifts retain their proved byte bounds; all conversions remain modeled. |
| `s390.tod_to_ns` | Pure unsigned scalar arithmetic, no pointer operations, memory accesses, calls, trap or assembly. Existing exact conversion/range contracts and frontend review remain unchanged. |
| `riscv.base-encoders` | Seven scalar encoders and five scalar direct-call witnesses; no pointer parameters, arithmetic, dereferences or indirect calls. Existing integer wrap/conversion and shift-count review still applies, without narrowing immediates. |
| `arm64.cpuid` | Two scalar leaves, no pointer arithmetic, dereferences or calls. Global function addresses do not create indirect calls. Full feature and width-1-through-64 domains remain; count bounds and signed/narrowing model remain explicit. |

Exact frontend/attribute, alignment, function-pointer and integer-policy review
records remain individually scoped in the manifests. The original reasoning is
in [string contracts](../annotated/verification-notes.md),
[24-bit proofs](../s390/annotated/byte-verification.md),
[48-bit proofs](../s390/annotated/byte48-verification.md),
[s390 target scope](../s390/TARGETS.md),
[RISC-V encoder review](../riscv/annotated/encoder-verification.md), and
[ARM64 scalar review](../arm64/CPUID.md). Byte-alignment reasoning does not
transfer to MPI limbs or other multibyte targets.

The two strlcat smoke IDs remain exactly
`typed_fragma_unreachable_wp_smoke_dead_call_s4355` and
`typed_strlcat_wp_smoke_dead_code_s4355`, at `string.verified.c:274`.
The pointer-enabled run emits these same IDs and location. The unchanged
destination-fits/first-NUL facts exclude the branch before the trap's false
postcondition could be used. Only these two findings are reviewed; their
ambiguous raw dead-path status is not an ordinary proof or kernel defect.
Inconclusive smoke attempts remain inconclusive.

## Diagnostic basis and fresh-run requirement

The independently inspected diagnostic artifact is
`build/pointer-formation-review/inspected-3.json`, SHA-256
`58ef03f6d35a23c5e19d2ac3712fe29cce75fff2a4a288a5a90932a9bec9526b`.
It compares complete retained C/ACSL streams (removing only line-location
directives), commands, source/model/strategy identities and ordinary/selected
property inventories against the explicit old-policy baseline.

| Pointer-enabled diagnostic | Ordinary WP, all Valid | Selected properties, all Valid | Added ordinary pointer guards |
| --- | ---: | ---: | ---: |
| `run-3/string.verified.strnchr` | 48 | 19 | 1 |
| `run-3/string.verified.strlcat` | 62 | 25 | 3 |
| `run-2/s390.unaligned24` | 94 | 82 | 12 |
| `run-2/s390.unaligned48` | 86 | 71 | 12 |

Every prior ordinary goal, selected property and round-trip witness remains
present and Valid. The strlcat increase includes two leaves of one consolidated
pointer property; neither leaf may disappear. No unresolved dependency is
discharged through this review.

`calibration-rte-2/receipt.json` has SHA-256
`b9cc37525b3a9dbe5d32006a8dc0628428548f4f55ec82b01bd4442614f862ea`.
Its three pointer, three access and three alignment guards are Valid; all 16
positive selected properties are Valid. The same deliberately false assertion
at line 153 retains raw `Invalid or unreachable`. It still needs fresh, exact
native reached-state corroboration; no status is rewritten by this review.

These diagnostic runs deliberately omitted approval envelopes and are not
accepted suite receipts. Each renewed target must pass a fresh common run with
configured L1, source/model fixtures, toolchain and assumptions, raw complete
properties/dependencies, exact diagnostics and final input-drift checks. The
three scalar-only targets also require fresh runs despite having no new pointer
operations. Old native/model/proof receipts remain historical; neither a copied
`checked` flag nor rehashing old output makes execution current.

The named s390 pilot must include all four targets, all seven kernel helpers
and all three project witnesses. Its leaf/direct-call closure has no trap
dependency, but broader selected-build trap behavior remains unchecked. Native
BE24 corroboration retains z13 compilation/request versus QEMU `max` execution;
it is not full z13, whole-pilot runtime coverage, or an assembly proof. Current
run results and remaining plan work are reported separately in
[PROGRESS.md](../PROGRESS.md), so status updates do not mutate this review.
