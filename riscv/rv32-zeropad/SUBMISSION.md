# Submission handoff

Status: **ready for human review and sending; no message has been sent**.

Patch:
[0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch](patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch)

The patch carries this routing from the recorded kernel tree:

- To: Paul Walmsley `<pjw@kernel.org>`, Palmer Dabbelt
  `<palmer@dabbelt.com>`, Albert Ou `<aou@eecs.berkeley.edu>`
- Cc: Alexandre Ghiti `<alex@ghiti.fr>`, Jisheng Zhang
  `<jszhang@kernel.org>`, `linux-riscv@lists.infradead.org`,
  `linux-kernel@vger.kernel.org`
- `git send-email` also adds the author and `stable@vger.kernel.org` from the
  patch body automatically.

The exact dry-run command that passed locally was:

```sh
git send-email --dry-run --confirm=never \
  riscv/rv32-zeropad/patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch
```

After reviewing the dry-run envelope, the intended send command is simply:

```sh
git send-email \
  riscv/rv32-zeropad/patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch
```

Before removing `--dry-run`, review the From identity, SMTP configuration,
recipient list, current RISC-V tree, and whether a newer upstream revision needs
one final apply/build check. Sending changes external state and is intentionally
left to an explicit user decision.

The same test notes are already below the patch's `---` separator. They will be
visible to reviewers but excluded from the applied Git commit message:

```text
Tested on RV32 QEMU virt/TCG with a KUnit guard-page test.
Before, the last three offsets returned fill bytes from the previous word
(0xa5, 0xa5a5, and 0xa5a5a5) instead of the string tail (0x44, 0x4433, and
0x443322), and the suite failed. After, all three cases and the suite passed.
Built full RV32 Images for both sides with GCC 15.2.0. The complete RV64
extable.o is byte-for-byte identical before and after.
```
