# Fragma-first Linux kernel bug search

Status: active execution track, restricted initially to the configured 32-bit
ARMv7 `arm-gcc` / `multi_v7_defconfig` profile. The generic string batch is a
frontend/driver calibration only. The primary batch is the eight-function
recent-risk inventory in `config/bug-search-arm32-recent.json`. This protocol
distinguishes analyzer discovery from source-review discovery and from
verification of already changed code.

## What counts as a Fragma-found bug

A defect is `fragma-found` only when a retained Frama-C result on unchanged,
source-gated kernel code identifies the failing operation or property before a
manual source diagnosis or candidate fix is written. Confirmation additionally
requires a concrete valid input or execution witness and a source-level reason
why the kernel violates its intended contract.

Other outcomes remain useful but have different labels:

| Classification | Required evidence |
| --- | --- |
| `fragma-found-confirmed` | Analyzer-first lead, valid contract/domain, concrete witness, diagnosed original source, and fix A/B |
| `review-found-confirmed` | Manual/static review precedes the analyzer lead; concrete witness and fix may still use Fragma infrastructure |
| `analyzer-lead-unconfirmed` | Alarm or failed obligation survives initial triage but has no concrete witness yet |
| `model-or-contract-gap` | Result is caused by an unsound/weak model, missing precondition, unsupported construct or incorrect specification |
| `false-positive` | The reported behavior is infeasible under the validated kernel configuration and API domain |
| `verified-no-finding` | The selected properties close under the stated assumptions; this does not prove absence of every bug |

The RV32 `load_unaligned_zeropad()` defect is
`review-found-confirmed`. It must never be relabeled as Fragma-found.

## Search pipeline

1. Select and freeze a bounded candidate batch using mechanical criteria such
   as size, pointer/arithmetic density, existing callers and configured build
   availability. Record the candidate list before deep manual review.
2. Export the unchanged functions from the pinned kernel, retain their source,
   configuration, header and compile-command identities, and reject source
   drift or hand-rewritten bodies.
3. Derive minimal API properties independently from declarations,
   documentation, callers and tests. Record the origin of every precondition;
   do not strengthen it merely to silence an alarm.
4. Run Eva plus RTE first for undefined-behavior leads: invalid accesses,
   indeterminate values, bad shifts, division by zero, invalid pointer
   arithmetic and configured integer-overflow classes.
5. Run WP for the named functional and safety properties. An unproved goal is a
   lead, never a bug verdict. Retain all valid, invalid, unknown, timeout and
   unsupported outcomes.
6. Triage each lead against the exact frontend/model, configuration
   reachability, API domain and callers. Keep model fixes and kernel fixes in
   separate commits and rerun the original observation after either changes.
7. Produce a concrete witness with the smallest suitable mechanism: native
   unit test, E-ACSL-instrumented harness, bounded exhaustive driver, KUnit, or
   architecture emulator. A witness must fail on the original source for the
   intended reason.
8. Prepare the minimal kernel correction. Run the same witness A/B, prove the
   corrected function under the same domain, and retain a mutation that shows
   the property is sensitive to the defect. Proving only a different fixed
   function is supporting evidence, not proof that the original was buggy.
9. Record checkpatch/applicability/regression evidence where a kernel patch is
   justified. The project never sends email on this host.

## Current ARM32 execution

The recent-risk batch was frozen from commit metadata, zero-context changed
function names, configured object availability/size and raw token counts before
candidate-body review. It covers ARM cache synchronization, the BPF JIT,
module relocations/PLTs, PCI resource alignment, uprobes and DMA scatterlists.

The first canary, `pcibios_align_resource()`, exposed an important frontend
boundary. Six attempts on the exact pinned `bios32.c` translation unit stopped
in unrelated transitive headers. A mechanically extracted function slice then
passed a 124-token identity gate against the pinned Git blob. Its first Eva run
correctly exposed a wrong callback declaration in the project model; after that
source-derived declaration was fixed, the final bounded RTE/Eva run completed
with 20 valid properties, no unknown/invalid properties and no warnings. It is
classified `verified-no-finding`, restricted to the stated driver and external
models—not as whole-TU or functional verification.
The compact [checkpoint record](../results/arm32-recent-pci-20260907/SUMMARY.md)
contains the exact scope, identities and retained-output hashes.

The second target, the April 2026 ARM module-relocation function
`module_frob_arch_sections()`, produced the campaign's first
`fragma-found-confirmed` bug. In the unchanged source-gated body, Eva retained
exactly two alarms: forming `sechdrs + s->sh_info` may create a non-object
pointer, and the following `dstsec->sh_flags` access may be invalid. Review of
the caller then established that the generic module loader had not yet checked
the SHT_REL/SHT_RELA target index. A concrete malformed module faults the
original kernel at `module_frob_arch_sections()` under QEMU ARM32; the same
input is rejected with `ENOEXEC` after early generic validation. Current
upstream remains affected. The complete
[evidence record](../results/arm32-module-sh-info-20260908/SUMMARY.md) retains
analysis identities, output hashes, the QEMU A/B and the send-ready-but-unsigned
patch. The reproducer source remains local and ignored under current kernel
AI-reporting guidance.

The third target, the April 2026 ARM32 BPF JIT `build_insn()`, now has an
analyzer-first partial pass. Eleven exact-TU attempts documented unrelated
header frontend gaps; a 2,797-token source-identical slice then produced 197
valid properties, three structurally dead properties and no warning. It found
no reachable direct-operation alarm under its deliberately inert emitter/helper
model. A separate `BPF_JIT_ALWAYS_ON` QEMU ARMv7 run matched 88 generated-code
results against C oracles across arithmetic, shift boundaries, MOVSX, signed
division, comparisons and a stack access. The
[checkpoint record](../results/arm32-recent-build-insn-20260908/SUMMARY.md)
classifies this `partial-no-finding`: live output-buffer and source-gated
helper-closure analysis still remain.

The fourth target, April 2026 ARM cache synchronization function
`__sync_icache_dcache()`, now has both a sequential RTE/Eva pass and a
source-bound two-caller Mthread + Eva pilot. Current source validates the
property that a caller publishes `PG_dcache_clean` only after its own modeled
flush; a mutation-equivalent early-publication control makes the same property
invalid. This re-detects the ordering defect already fixed by its trigger
commit, so it is a known-fix detection calibration with zero new bugs—not a
rediscovery claim or a hardware/LKMM proof. The
[cache checkpoint](../results/arm32-cache-mthread-20260908/SUMMARY.md) records
the exact source, configured object, provider, A/B results and exclusions.

The fifth target, January 2026 ARM uprobes function
`arch_uprobe_copy_ixol()`, is a `verified-no-finding-bounded-rte`. One exact-TU
attempt stopped before the candidate on unrelated `__auto_type` syntax. A
76-token source-identical slice then proved 13 selected properties for any
0–64-byte copy in any 64-byte XOL slot. The in-tree callers copy only 4 or 8
bytes. A deliberate 65-byte final-slot control raises the destination alarm and
remains fail-closed because the consolidated loop property is `Unknown`. The
[uprobes checkpoint](../results/arm32-uprobe-copy-20260908/SUMMARY.md) records
the exact domain, warnings, hashes and exclusions.

Four candidates have completed an initial stage and the BPF JIT has a retained
partial stage. The remaining untouched strict targets are
`dma_cache_maint_page()` and `__map_sg_chunk()`. `get_module_plt()` remains
useful calibration, but its body was exposed during dependency inspection and
is conservatively ineligible for the strict discovery label. The mature generic
strings remain calibration only.

## First campaign acceptance

- [x] Freeze a mechanically selected 5–10-function ARM32 batch before body
  review. Prefer 32-bit word/size arithmetic, 31/32-bit shift boundaries,
  sign/zero extension, pointer-range calculations and page-boundary helpers.
- [ ] Run unchanged-source Eva/RTE triage under at least one current configured
  profile—only `arm-gcc` in this campaign—with bounded per-function time and
  complete outcome retention. Four of eight candidates have completed an
  initial stage, one has a retained partial pass, two strict candidates remain
  untouched, and one review-exposed sibling remains calibration-only.
- [ ] Add independently sourced functional properties for the candidates that
  survive frontend/model triage and run WP without hiding unresolved goals.
- [ ] Classify every lead using the table above and publish false-positive and
  model-gap rates as well as confirmed defects.
- [x] For each confirmed lead, retain a concrete original-source witness and
  same-input fixed-source A/B; for zero confirmed leads, report zero plainly and
  choose the next batch from recorded coverage gaps.

No bug count or deadline is promised. The near-term goal is a trustworthy
search funnel whose first signal genuinely comes from Frama-C, not a guarantee
that a small batch contains an upstream-worthy defect.
