# Module relocation `sh_info` multi-architecture A/B — 2026-09-08

Classification: runtime expansion of the existing
`fragma-found-confirmed` finding. Frama-C found the ARM32 instance. Source
review identified the four other affected architecture hooks. This checkpoint
does not count them as separate analyzer-found bugs.

## Scope

The current-base tests use Linux
`28924df2a08f440c73991b83028032c901de2ae4`. The original
`kernel/module/main.c` SHA-256 is
`251b3f2c3059f2396609c9f08f5d69a461696c6a054f54213597a922fab3a63b`.
The fixed source SHA-256 is
`b7c076a23738c72ddd8ded4c132e364e1259ecb3cb7a6bb56d4afac6e6b95aeb`.

A source audit found unsafe early relocation-target indexing in exactly five
architecture hooks:

| Architecture | Early use of unvalidated `sh_info` | Runtime evidence |
| --- | --- | --- |
| ARM32 | Section-header pointer and `sh_flags` read | Original fault, fixed rejection |
| ARM64 | Section-header pointer and `sh_flags` read | Original fault, fixed rejection |
| LoongArch | Section-header pointer and `sh_flags` read | Original fault, fixed rejection |
| PA-RISC | Index into an `e_shnum`-sized heap array | Original fault, fixed rejection |
| RISC-V | Section-header pointer and `sh_flags` read | Original fault, fixed rejection |

ARC, Hexagon, PowerPC, s390 and SPARC do not consume `sh_info` in their early
hooks. x86_64 was booted as a negative control for this ordering bug.

## Test input

The multi-architecture module puts an unused function in an executable
`.fragma_probe.text` section. The mutator changes only the four-byte `sh_info`
field of its relocation section header to `0x10000000`. The function is not
called, so the unchanged x86_64 loader can skip the invalid relocation and
still initialize the module. The mutation receipts verify that no byte outside
the `sh_info` field changes.

| Architecture | Relocation section | File offset | Old `sh_info` | `e_shnum` |
| --- | --- | ---: | ---: | ---: |
| ARM64 | `.rela.fragma_probe.text` | 37396 | 11 | 41 |
| RISC-V | `.rela.fragma_probe.text` | 4572 | 9 | 25 |
| LoongArch | `.rela.fragma_probe.text` | 4732 | 7 | 30 |
| x86_64 | `.rela.fragma_probe.text` | 5140 | 8 | 35 |

The existing ARM32 and PA-RISC harnesses use architecture-specific relocation
sections. Their exact mutations remain documented in the
[ARM32 record](../arm32-module-sh-info-20260908/SUMMARY.md) and
[PA-RISC record](../parisc-module-sh-info-20260908/SUMMARY.md).

## QEMU A/B results

The ARM64, RISC-V, LoongArch and x86_64 tests used QEMU 10.2.1 TCG at the
current base. For each architecture, the original and fixed kernels used
byte-identical configuration files and the same initramfs and module pair.

| Architecture and configuration | Original kernel | Fixed kernel |
| --- | --- | --- |
| ARM64 `defconfig`, GCC 15.2.0, `virt`/Cortex-A57 | Control loads and unloads. Malformed load raises a paging-request Oops at `module_frob_arch_sections()+0x110` and panics. | Control loads and unloads. Malformed load returns `ENOEXEC`, prints index 268435456 and completes. |
| RISC-V `defconfig` plus `RELOCATABLE=y`, GCC 15.2.0, `virt` | Control loads and unloads. Malformed load raises a paging-request Oops at `module_frob_arch_sections()+0xe4` and panics. | Control loads and unloads. Malformed load returns `ENOEXEC`, prints index 268435456 and completes. |
| LoongArch `loongson64_defconfig`, LLVM 21.1.8, `virt`/LA464 | Control loads and unloads. Malformed load raises a paging-request Oops at `module_frob_arch_sections()+0x1b8` and panics. | Control loads and unloads. Malformed load returns `ENOEXEC`, prints index 268435456 and completes. |
| x86_64 `x86_64_defconfig`, GCC 15.2.0, `pc`/qemu64 | Both control and malformed modules load and unload. No Oops occurs. | Control loads and unloads. Malformed load returns `ENOEXEC`, prints index 268435456 and completes. |

The x86_64 result is a negative control for the architecture-hook fault, not a
claim that the patch leaves malformed-module policy unchanged. It shows that
the test module is otherwise loadable when no early hook dereferences the bad
index. The generic fix deliberately rejects it before all architecture hooks.

ARM32 previously produced a paging-request Oops at
`module_frob_arch_sections()+0x160`. PA-RISC produced a Data TLB miss at
`module_frob_arch_sections()+0x11c` on the `stub_entries` read. Both fixed
kernels reject the same respective module with `ENOEXEC`. All five affected
architectures therefore have runtime original/fixed evidence.

No physical hardware or KASAN was tested.

## Current-base artifact identities

Full local evidence is retained under
`build/module-sh-info-qemu-multiarch/`. The build directory contains kernel
images, `vmlinux` files, byte-identical saved configurations, modules,
initramfs images, mutation receipts, `readelf` output, build logs and complete
serial logs.

| Architecture | Configuration | Control module | Malformed module |
| --- | --- | --- | --- |
| ARM64 | `eac183de8e37df409a95d82038c1ce2e00b26350a74a89717546a6942578d47f` | `f66c4ab91a151d3c614d48b2441da9d220f419cd8905dab08d9ccbda6f8a289e` | `94a6ea2ea7f6c190c9d5b095398fe46883ad60bcc3133d79edcfa5bb862da6aa` |
| RISC-V | `b5ce6c1e8b74c0cc8abbf588832fb0e99daf6b91bb7ce4c71e28070d7e1ee88a` | `6bf5c5f1e436b150090cec7c8a4b90d31367a023b5f6fe31acb25e5579c8337a` | `e2050e7abf63514e42b1aa91dbba157c3918445ea89944b3ba7038eaaed49deb` |
| LoongArch | `3f162efb9e3a039678cf746fe3ab3bc86b2b3921b1f7ef07ba9be5d2da775351` | `268bdd58655890f1aeb9481a663098e5a519251893306e737bb400d8877ad519` | `b39b4eb5f893aa7bdf831a4112cb364f1c0c26d154bade5190056a3558e2bb26` |
| x86_64 | `eec5afb2e91dcde5316569330ecc2a0af244ded509b984d31b83491cb700654e` | `66ab71e79b7a7ff9a0d0e94aa33fb982c3265efef6822ddbaf5aedc8ed7ecf85` | `766ff5ce0f6f9d006799e69e42e65641dc882e7cb48bba9670aa0ab30a95b99b` |

| Architecture | Original boot image | Fixed boot image | Original log | Fixed log |
| --- | --- | --- | --- | --- |
| ARM64 | `1bc6197d4418ba2877992be83750256c29b11b2ef752133f24985b61ae91044b` | `3d0bc67af996cffd6697c3aebd11c8cc31ed1bf200d4c9942509cc5ea72ec241` | `236ef60c510aca829803dddf421ca5f1df8e0a60941eea1c423927b9b6ddb432` | `248177492fd1d7bce5097a4846b42e54f6ff0c89bd47a97fc40a6166b3b716cb` |
| RISC-V | `6dbd280f6a1f1127e42b18386c7a1286553717b2704ee3acd9a172769f7758a3` | `40567a69c90a0427526f8c9117a87ffe7a908ad54c3d4f6865932cf46aa09576` | `e14b14b8591b4221e79716baabfb17a050821c4c78bc9e0d97a8b9aab574528d` | `d4048868add83a9f2320ca7a1c83e746ad75b0b53893326082f887112a43aaa9` |
| LoongArch | `73db2b4c867fe30a42da3e1918502d2a19a8aa9ddf58d9c1c735edcbc9f6851c` | `b8179458496fdff197f5fa5dd85489cda037041db0686d80ab25547ffb9a2c0d` | `4e78863942f09d7a09ac1b4283e7178084df025a22a1c29c9a7b0763acaf1c0a` | `20ecfa7fafabb31471d23bb8f82ea7cd5cba9352ed54f821936c14de765ae984` |
| x86_64 | `b7840678adddee60d5d8dfb48883ed2bc46c22fa0c492c2cd317de8a352919ce` | `ee3936bb32a3e2cdb905348209738aec5583071ae025f4ffd26ab7861c03c436` | `9e3c14d779899ccb05f174381f5e03bf6f056e04b9eb6d24899f2d538055b891` | `2b7a50baca2d63ec6b4eabfcbee8f9cb1efe8d877b819817e25fbde9924a0b4f` |

## Patch validation

- Canonical patch:
  `patches/confirmed/0001-module-reject-invalid-relocation-section-target-indices.patch`
- Generated commit: `469fb638e5f4662404e39e18d8d6efec9abc5a73`
- Patch SHA-256:
  `4a5691d975f1e15785d61fb868d5c8b6603174d716701341a7604c6817f3372f`
- Stable code patch-id:
  `736cba8706b2675d2a63878ddb54645307f4e532`
- `git am` on the declared base: passed in a fresh worktree
- `checkpatch.pl --strict`: zero errors, warnings and checks
- `git send-email --dry-run --confirm=never`: passed; no email was sent
- Project regression: 1,110 tests passed with 20 conditional skips
- Regression log SHA-256:
  `322d2088885bc13fe45858d0339d35d39cfa3965a6761bdaec0663dc70f5a126`

The patch notes name the five affected runtime tests and the x86_64 negative
control. The `To` and `Cc` headers cover the module maintainers and all five
affected architecture maintainer groups.
