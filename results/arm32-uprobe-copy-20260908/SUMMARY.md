# ARM32 `arch_uprobe_copy_ixol()` checkpoint — 2026-09-08

Classification: `verified-no-finding-bounded-rte`.

New Linux bugs found by this checkpoint: **0**.

This is the fifth recent-risk ARM32 candidate to enter the search funnel. The
January 2026 trigger commit converted the temporary instruction-page mapping
from `kmap_atomic()` to `kmap_local_page()`. The current function's direct
pointer formation and byte-copy accesses are valid over a domain broader than
all of its in-tree callers. Mapping lifetime, cache visibility and concurrency
are deliberately outside this result.

## Analyzer-first source path

The first attempt used the exact configured
`arch/arm/probes/uprobes/core.c` translation unit and a driver derived from the
public declaration and generic callers before candidate-body review. Pinned
translation-unit and function provenance both passed. Frama-C then stopped
before the candidate at `include/linux/nodemask.h:253`, where Linux's `min()`
expansion contains `__auto_type`. This retained `tool-error` is a frontend gap,
not a kernel lead.

A compact slice then preserved the complete named declarator and body:

- function tokens: 76;
- function token SHA-256:
  `e3c5f3ace201c05fa6fe4f4e18426746805b77000f563297faae5193b1cb8ea7`;
- source-file SHA-256:
  `79bb32878baee8232f234a0a88f86738d28836b9b649223c73a74beb379e8454`;
- configured ARM32 `core.o` SHA-256:
  `8272f23bc1e632e4f6a7df0c3f0ec737e01ead58fd57ac2a60e56a2fcba40274`.

The driver supplies one live page, one writable 4 KiB mapping and a readable
source. Its `memcpy()` model is an explicit bounded C byte loop, so RTE/Eva
checks each source and destination access instead of trusting a library
summary. Mapping release, preemption and cache-flush helpers remain inert and
are recorded as assumptions.

## Result and sensitivity

| Case | Domain | Result |
| --- | --- | --- |
| Source-identical candidate | Any of 64 aligned 64-byte slots; length 0–64 | `calibration-passed`; 13 valid, zero unknown/invalid |
| Cross-page control | 65 bytes into the final 64-byte slot | destination assertion becomes invalid in the Eva log; fail-closed `incomplete` export |

The normal run retains exactly two Frama-C kernel warnings, both `using size of
'void'`. They identify the candidate's GNU `void *` byte arithmetic. Frama-C
uses a one-byte increment here, matching the GNU C behavior accepted by the
configured GCC build; the warnings are kept visible.

For the control, Eva reports
`arm32_uprobe_copy_destination_valid` as invalid when it reaches byte 65 and
stops propagation. The consolidated loop-wide property is exported as
`Unknown` because the preceding iterations are valid. The target therefore
remains incomplete rather than being mislabeled as a clean calibration pass.
It deliberately violates the real caller domain and is not a kernel defect.

## Caller boundary

ARM32 defines a 64-byte XOL slot. The generic allocator exposes 64 slots in a
4 KiB page and accepts only `slot_nr < UINSNS_PER_PAGE`. The two call shapes are
strictly smaller than the analyzed domain:

- the return-probe trampoline copies `UPROBE_SWBP_INSN_SIZE`, 4 bytes;
- normal out-of-line execution copies `sizeof(uprobe->arch.ixol)`, 8 bytes on
  ARM32 (`unsigned long ixol[2]`).

Thus the final allocated slot ends exactly at the page boundary and neither
in-tree caller crosses it. This does not establish safety for an arbitrary
future caller that passes an unchecked length.

## Retained local evidence

| Artifact | SHA-256 |
| --- | --- |
| Exact-TU summary | `3044d245ee584ef431a6c83988bd0f519c899b814c5a023c626a74d6e8c09d14` |
| Exact-TU target result | `82e50a4d2bd6d28943c8f2b1ad1ec1d21a62c3c81f3821757558a329c2254ef3` |
| Exact-TU analyzer log | `e0db7721d9b450129eb500d80b162621e1882acfcefdb5f8d8b0128d433af272` |
| Bounded-run summary | `ddedf9d8fa1a601c2dc264814c20342d57f48a144d5440f395482bfb23cc6710` |
| Bounded target result | `6741815d8b77c35cdb03f2b6c51a133e0a297c1d3199ff1ee7865b3a53216a1a` |
| Bounded analyzer log | `d0ab40194fa0236ca9b648f740ef92d0c73878fadade172a83f2bfde71858744` |
| Bounded property table | `84e9ec681e31dd7ca9ba7e53fc6bb3626ba47756ce3c7b047976483a27ffd5bc` |
| Control summary | `8af7de79435fb520a809fedaa51d6b8071820f3f69e0e76bb383dc4091df9117` |
| Control target result | `2f7a97237fb24e790e3f7c6d990f8b88f7596b91a2dd0cbeb20ac7d926208db6` |
| Control analyzer log | `f45c58b0de8addacb9f43402f3cabcd89fe6627c5818040bae1283c0d3b5b62b` |
| Control property table | `8e4b9abb92a7dcc46226c3ce4331ec03a4f491ba0dec11b4820f4face73330b1` |

Local output directories:

- `build/arm32-recent-search-20260908/uprobe-raw-tu-1`;
- `build/arm32-recent-search-20260908/uprobe-slice-final-1`;
- `build/arm32-recent-search-20260908/uprobe-cross-page-control-final-1`.

Next strict analyzer-first targets: `dma_cache_maint_page()` and
`__map_sg_chunk()` in `arch/arm/mm/dma-mapping.c`.

Regression: `python3 -m unittest discover -s tests -v` passed 1,100 tests with
20 skips. The local log SHA-256 is
`3e5fecc02c2306bcaecddc7656c75548e5acfeb409c99d4033f554f623e902e3`.
