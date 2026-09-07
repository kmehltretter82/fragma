# Submission handoff

Status: **ready for human review and sending; no message has been sent**.

Patch:
[0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch](patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch)

Suggested routing from the recorded kernel tree:

- To: Paul Walmsley `<pjw@kernel.org>`, Palmer Dabbelt
  `<palmer@dabbelt.com>`, Albert Ou `<aou@eecs.berkeley.edu>`
- Cc: Alexandre Ghiti `<alex@ghiti.fr>`, Jisheng Zhang
  `<jszhang@kernel.org>`, `linux-riscv@lists.infradead.org`,
  `linux-kernel@vger.kernel.org`
- The patch body adds the author and `stable@vger.kernel.org` automatically.

The exact dry-run command that passed locally was:

```sh
git send-email --dry-run --confirm=never \
  --to='Paul Walmsley <pjw@kernel.org>' \
  --to='Palmer Dabbelt <palmer@dabbelt.com>' \
  --to='Albert Ou <aou@eecs.berkeley.edu>' \
  --cc='Alexandre Ghiti <alex@ghiti.fr>' \
  --cc='Jisheng Zhang <jszhang@kernel.org>' \
  --cc='linux-riscv@lists.infradead.org' \
  --cc='linux-kernel@vger.kernel.org' \
  riscv/rv32-zeropad/patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch
```

Before removing `--dry-run`, review the From identity, SMTP configuration,
recipient list, current RISC-V tree, and whether a newer upstream revision needs
one final apply/build check. Sending changes external state and is intentionally
left to an explicit user decision.

Test notes for a review reply or cover message:

```text
Tested on RV32 QEMU virt/TCG with a project-only KUnit guard-page test.
Before: page_end-{1,2,3} returned 0xa5, 0xa5a5, 0xa5a5a5 instead of
0x44, 0x4433, 0x443322; suite failed. After: all three cases and the
suite passed under the identical config. Built full RV32 Image and RV64
arch/riscv/mm/extable.o with GCC 15.2.0. Strict checkpatch clean. Patch
applies to v7.3-rc2 and next-20260904.
```
