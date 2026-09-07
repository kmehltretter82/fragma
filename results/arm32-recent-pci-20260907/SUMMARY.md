# ARM32 recent-risk checkpoint

Date: 2026-09-07
Kernel: `b9b3e33b70b71e516930117e21de3ad2a7723747`
Profile/build: `arm-gcc@arm-gcc-recent-v2` (`multi_v7_defconfig`, ARMv7,
little-endian, 32-bit `resource_size_t`)

This checkpoint demotes the generic eight-string search to frontend/driver
calibration and freezes eight recent architecture-specific candidates in
`config/bug-search-arm32-recent.json`. No Fragma-found kernel bug is confirmed.

## First candidate

`pcibios_align_resource()` is copied mechanically into a minimal analysis slice.
The provenance gate compares the complete declarator, parameter list and body
against the pinned Git blob:

- 124 source/harness tokens;
- token SHA-256
  `dfa41dbf6ffc59538c599a006fa963573c06fa052512dc7ac654833a45120b26`;
- identical declaration prefixes.

Six earlier attempts on the full pinned `bios32.c` translation unit are retained
locally under `build/arm32-recent-search-20260907/pci-raw-*`. They never reached
the candidate: Frama-C stopped in unrelated inferred-auto, MM padding,
constant-expression, sysfs, ratelimit, rbtree-latch and context-tracking header
constructs. These attempts are `model-or-contract-gap`, not kernel findings.

The first source-identical slice run exposed a project-model error: the modeled
host-bridge callback used a resource pointer where the real third parameter is
the scalar start address. Frama-C reported the resulting integer-to-pointer call.
After correcting the declaration from the pinned public header, the final run
completed with:

- status `calibration-passed`;
- 20 valid properties, zero unknown and zero invalid;
- zero analyzer warnings;
- all selected candidate RTE obligations valid.

Classification: `verified-no-finding`, limited to the bounded below-2-GiB driver,
valid local objects and the declared PCI dependency models. It is not a
functional proof, whole-translation-unit proof, or claim about real callback
implementations.

Local final output:
`build/arm32-recent-search-20260907/pci-slice-final-1`. Its summary, result and
analysis-log SHA-256 values are recorded in the campaign manifest.

Regression check: `python3 -m unittest discover -s tests` passed 1,071 tests
with 20 skips.

Next strict analyzer-first candidate: `module_frob_arch_sections()`. The sibling
`get_module_plt()` was exposed during dependency inspection before analysis, so
any later result from it is conservatively ineligible for the strict
`fragma-found` label.
