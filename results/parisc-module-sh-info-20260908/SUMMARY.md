# PA-RISC module `sh_info` A/B — 2026-09-08

Classification: supporting runtime confirmation for the
`fragma-found-confirmed` module relocation target-index finding. Frama-C found
the ARM32 instance. The PA-RISC result was added by source audit and does not
count as a second analyzer-found bug.

## Source and affected hooks

The test uses Linux commit
`28924df2a08f440c73991b83028032c901de2ae4` (`Merge tag
'perf-tools-fixes-for-v7.3-2026-09-07' of
git://git.kernel.org/pub/scm/linux/kernel/git/perf/perf-tools`). The early ELF
validity pass at this revision does not reject an out-of-range relocation
section `sh_info` value before `module_frob_arch_sections()` runs.

PA-RISC allocates `mod->arch.section` with `e_shnum` entries. When a SHT_RELA
section contains a relocation counted by `count_stubs()`, the hook uses
`sh_info` to read `stub_entries` and then to update it. The runtime witness
faulted on the read. The later store exists in the generated code but was not
reached by this witness.

A source audit of all 11 architecture hook definitions found early relocation
target indexing in exactly five architectures:

| Architecture | Early use | Evidence in this checkpoint |
| --- | --- | --- |
| ARM32 | Section-header pointer and `sh_flags` read | Same-input QEMU A/B |
| PA-RISC | Index into an `e_shnum`-sized heap array | Same-input QEMU A/B |
| ARM64 | Section-header pointer and `sh_flags` read | Source audit and full patched build |
| RISC-V | Section-header pointer and `sh_flags` read | Source audit and full patched build |
| LoongArch | Section-header pointer and `sh_flags` read | Source audit and full patched build |

ARC, Hexagon, PowerPC, s390 and SPARC do not consume `sh_info` in their early
hooks. Their later relocation handlers run behind the existing generic
out-of-range skip and are not instances of this ordering bug.

## PA-RISC same-input A/B

- Machine: QEMU 10.2.1 B160L, PA1.1, 256 MiB, TCG
- Kernel: 32-bit `generic-32bit_defconfig` with `MODULES=y` and
  `MODULE_UNLOAD=y`
- Compiler: `hppa-linux-gcc` 8.1.0 with GNU ld 2.30
- Configuration SHA-256, before and after:
  `d8db74478e88569d28f080622cb32176010aed5d89d357674e1a8b83e27af110`
- Shared initramfs SHA-256:
  `2f22700d7179eaced1c9ac2b70af6f5ef2663466ef7864d93e7c138e3ed61d39`

The control module contains an R_PARISC_PCREL17F relocation which
`count_stubs()` counts. The mutation rewrites only the four-byte, big-endian
`sh_info` field of section 4,
`.rela.text.unlikely.fragma_sh_info_init`, at file offset `0xae4`:

```text
00 00 00 03 -> 10 00 00 00
sh_info 3    -> 0x10000000
e_shnum      = 28
```

The field rewrite changes two byte positions because two bytes are zero on
both sides. No byte outside that four-byte field changes.

| Kernel | Control module | Malformed module |
| --- | --- | --- |
| Before fix | Load and unload return 0 | Data TLB miss at `module_frob_arch_sections()+0x11c`, followed by panic |
| After fix | Load and unload return 0 | Load returns -1 with `errno=8`; kernel prints target index 268435456; guest completes |

The pre-fix disassembly maps `+0x11c` to `ldw 4(ret0),r19`, the
`stub_entries` read used by `WARN_ON()`. The subsequent
`stw r20,4(ret0)` is at `+0x12c` and was not reached.

| Artifact | SHA-256 |
| --- | --- |
| Control module | `0e58fa885361336346ac6d04c84d8b82ce53de9a1b11e15b50e8af34377ebed1` |
| Malformed module | `9396cb24ae8a2689ab00e2c4ff5d76b429e230765652a7ac2e0ec3040d80ce14` |
| Mutation receipt | `d833def3dfbf13c1880d4fb6281878fde3eebf8d1e630cf79a04795ef477723a` |
| Pre-fix QEMU log | `caf09087aea111038b04769fbd161127d5d6eb082850690e12251d1f3aa744a8` |
| Post-fix QEMU log | `fbe54aea165390c18fd005acb54b3d5f0c43a8a67c69f9f837386d5f7bc24e8e` |
| Pre-fix `vmlinux` | `20678a04a7e4cb1117f97f306c9c999e5593a97e062da6ed115778afc6cf6a7e` |
| Post-fix `vmlinux` | `c3ccf22218395ad9e779a4b4a7dd43bb108de1f2bf650dfca2b005508da15d53` |

The reproducible harness is tracked in `harness/parisc-module-sh-info/`. Full
local evidence is retained under
`build/parisc-module-sh-info-qemu/`, including the kernels, configuration,
modules, mutation receipt, initramfs and serial logs.

## Other affected architecture builds

These are full patched `vmlinux` builds, not runtime A/B tests:

| Architecture and configuration | Toolchain | Configuration SHA-256 | `vmlinux` SHA-256 |
| --- | --- | --- | --- |
| ARM64 `defconfig` | GCC 15.2.0 | `eac183de8e37df409a95d82038c1ce2e00b26350a74a89717546a6942578d47f` | `01a0b3b56034fa36d45dc0b83a2bd19bd39820515b43d67905d3a30abb6091eb` |
| RISC-V `defconfig` plus `RELOCATABLE=y` and `MODULE_SECTIONS=y` | GCC 15.2.0 | `b5ce6c1e8b74c0cc8abbf588832fb0e99daf6b91bb7ce4c71e28070d7e1ee88a` | `901af8bbbd3470a17adf6668c78d2517dbd444ee9da585c3b63b33d76da31e98` |
| LoongArch `loongson64_defconfig` | LLVM 21.1.8 | `3f162efb9e3a039678cf746fe3ab3bc86b2b3921b1f7ef07ba9be5d2da775351` | `5f283958fabc2fa39f9b15db16dc1e2cef0e7652f00a75e43f551f700d07a46d` |

## Patch validation

- Canonical patch:
  `patches/confirmed/0001-module-reject-invalid-relocation-section-target-indices.patch`
- Patch SHA-256:
  `5839bc83c4bb9d872e4eed310633f5091812f440347052cb2feb43cdc1190e5f`
- Generated by `git format-patch` from commit
  `5b03c7c1271d14d9aede8e188794c597b0c7b873`
- `git apply --check`: passed at the declared base
- `git am`: passed in a fresh worktree and retained the exact code change
- `checkpatch.pl --strict`: zero errors, warnings and checks
- `git send-email --dry-run --confirm=never`: passed; no email was sent
- Project regression: 1,108 tests passed with 20 conditional skips
- Regression log SHA-256:
  `9690fe4f32449652af74b8e79585e2cd220dd436312eb639304ec99e26de0a2f`

The patch includes the ARM32 and PA-RISC A/B notes below the `---` cut. It
labels the ARM64, RISC-V and LoongArch results as build-only checks. No email
was sent by the project.
