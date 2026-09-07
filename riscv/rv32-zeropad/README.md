# RV32 `load_unaligned_zeropad()` wrong-result reproducer and fix

Status: **dynamically reproduced; fix A/B validated; patch send-ready; not sent**.

The RV32 exception-table handler rounds a faulting address down to an eight-byte
boundary even though `REG_L` and `unsigned long` are four bytes on RV32. For a
load beginning in the final one, two, or three bytes of a mapped page, it loads
an earlier word and uses an oversized shift. It then writes that unrelated value
to the destination register and advances the exception PC.

The proposed fix derives the mask from `sizeof(data)`. It changes RV32 alignment
to four bytes and leaves RV64's eight-byte behavior unchanged:

```diff
- offset = addr & 0x7UL;
- addr &= ~0x7UL;
+ offset = addr & (sizeof(data) - 1);
+ addr &= ~(sizeof(data) - 1);
```

## A/B result

The project-only KUnit test allocates exactly one `vmalloc()` page, confirms the
following guard page is unmapped, fills the preceding bytes with `0xa5`, and
calls `load_unaligned_zeropad()` from the final three byte positions. QEMU TCG
boots the image as `rv32imafdch`.

| Mapped bytes remaining | Expected zero-padded word | Unpatched result | Patched |
|---:|---:|---:|---|
| 1 | `0x00000044` | `0x000000a5` | pass |
| 2 | `0x00004433` | `0x0000a5a5` | pass |
| 3 | `0x00443322` | `0x00a5a5a5` | pass |

The A-side suite is `not ok`; the B-side suite and case are both `ok`. The full
configuration is byte-for-byte identical on both sides, SHA-256
`47d87fee06e6d1985f7f46059d69daebf301820e98e5a207af3cd309c19cfbd0`.
Both boots intentionally have no root filesystem and panic only after KUnit has
finished; that later panic is the test-termination mechanism, not a test result.

The compact [audit summary](../../results/rv32-zeropad-20260907/SUMMARY.md)
records all gates passing. Its machine-readable companion binds the raw local
images, configs, QEMU logs, compiled objects, patches, source commits, tool
versions, KUnit values, and all review gates by SHA-256 or exact value. Bulk
build artifacts and logs remain ignored local evidence.

## Exact scope and source identity

- Mainline base: `df2908090cda368b01ff43709f51890076c56157`
  (`v7.3-rc2`).
- Linux-next applicability: `af5f12805e5cefa4fe68d6127c7e1fb78cd5535c`
  (`next-20260904`). The buggy fragment is present and the patch applies cleanly.
- Introducing commit: `d0fdc20b0429150c9dd09111f9b1d9d48117b56f`.
- Diagnostic commit used for A: `04a5cfb10c0f82771f217c5bd6810573c348c367`.
- Tested fix commit used for B: `a815e79559d1f56683c5f534b067be42ed256298`.
- Submission commit: `7fe4d4e77ee4f57046785b82918ce72cce7507e5`.
- Tested and submission changes have the same stable patch-id:
  `1e15327041a5d49a362302ac8826bf9296aa6039`.

The separate [diagnostic patch](reproducer/0001-DO-NOT-SUBMIT-riscv-Add-RV32-unaligned-zeropad-repro.patch)
is deliberately marked `DO NOT SUBMIT`: it is only the KUnit instrument used to
produce the before/after evidence. The minimal
[submission patch](patches/0001-riscv-Fix-load_unaligned_zeropad-on-RV32.patch) is
the upstream candidate.

## Build and review checks

The tested host already had every required tool; no package was installed and
no `sudo` command was used.

- QEMU 10.2.1, `qemu-system-riscv32 -machine virt`, TCG.
- GCC 15.2.0 cross-compiler with RV32 ILP32 support.
- Full RV32 `Image` build before and after the fix.
- The final RV32 `vmlinux` and `extable.o` are ELF32 RISC-V.
- A separate fixed RV64 `defconfig` `arch/riscv/mm/extable.o` build is ELF64
  RISC-V.
- RV32 disassembly contains masks `3` and `-4` followed by the word shift.
- Strict `scripts/checkpatch.pl`: 0 errors, 0 warnings, 0 checks.
- Clean indexed apply checks against both recorded mainline and linux-next.
- `git send-email --dry-run`: `Result: OK`; no email was transmitted.
- All [905 project unit tests](../../results/tests-rv32-concurrency-20260907.log)
  pass, with 20 pre-existing conditional skips.

Run the read-only audit of the retained local evidence with:

```sh
python3 -m fragma rv32-zeropad-audit \
  --output results/rv32-zeropad-NEW
```

The auditor refuses to overwrite an existing result. To rebuild the entire A/B
experiment in a new directory, use:

```sh
riscv/rv32-zeropad/run-ab.sh /path/to/linux /path/to/new-work-dir 8
```

That script refuses an existing work path, clones from the supplied kernel tree,
builds and boots both sides, checks the exact wrong/pass outcomes, compares the
configs, builds the RV64 compile control, and runs the patch-review tools. It
does not install anything or send mail.

## Interpretation

This is a demonstrated RV32 kernel wrong-result defect, not merely a Frama-C
alarm or a planted calibration. The evidence shows the behavior under the
recorded QEMU/configuration and validates the minimal fix. It is not evidence
that every caller, RISC-V configuration, or physical implementation has been
tested, and it does not become an upstream report until the patch is actually
sent and reviewed.
