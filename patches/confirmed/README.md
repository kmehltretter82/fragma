# Confirmed Linux kernel bug patches

Each file in this directory is a standalone email patch. Do not send the two
files as a series: they fix unrelated bugs in different subsystems.

| File | Status | Confirmation |
| --- | --- | --- |
| `0001-module-reject-invalid-relocation-section-target-indices.patch` | Ready for the submitter's final review | Frama-C lead plus original/fixed QEMU A/B on ARM32, ARM64, LoongArch, PA-RISC and RISC-V; x86_64 negative control |
| `0001-riscv-fix-load-unaligned-zeropad-fixup-for-rv32.patch` | Already sent by the submitter; retained here as the exact archive | RV32 KUnit/QEMU original/fixed A/B plus byte-identical RV64 object |

Both patches contain `From`, `To`, `Cc`, `Assisted-by: LLM`, and
`Signed-off-by: Karl Mehltretter <kmehltretter@gmail.com>`. Testing and A/B
evidence is below the `---` cut so it is available to reviewers without
becoming part of the permanent commit message.

The module patch was regenerated with `git format-patch`, applied with `git am`
in a fresh worktree, checked with strict checkpatch, and parsed successfully by
`git send-email --dry-run --confirm=never`. No email was sent.

After reviewing the file, the unsent module patch can be submitted directly:

```sh
git send-email /home/karl/linux-work/fragma/patches/confirmed/0001-module-reject-invalid-relocation-section-target-indices.patch
```

The ARM32 DMA lead is deliberately absent. It will be added only if the
original/fixed A/B and real-kernel caller/configuration checks confirm it.
