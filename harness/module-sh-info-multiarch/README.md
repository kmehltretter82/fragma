# Module relocation `sh_info` multi-architecture harness

This harness extends the ARM32 and PA-RISC reproductions to ARM64, RISC-V,
LoongArch and an unaffected x86_64 control.

`fragma_sh_info.c` puts an unused function in an executable
`.fragma_probe.text` section. This creates a relocation section that affected
architecture hooks inspect before the old generic loader validates its target.
Keeping the probe out of module init and exit also lets an unchanged x86_64
kernel skip the malformed relocation and load the module as a negative control.

`mutate_sh_info.py` supports 32-bit and 64-bit ELF objects in either byte
order. It selects a relocation section targeting executable code, changes its
four-byte `sh_info` field to an out-of-range value, verifies that no other byte
changed and prints a JSON receipt.

`init.c` is a nolibc PID 1. It loads and unloads `control.ko`, attempts to load
`evil.ko`, prints machine-readable `FRAGMA_` markers and reboots. Build the
initramfs with the kernel's `usr/gen_init_cpio` and `initramfs.list`, setting:

```text
FRAGMA_INIT=<architecture-specific static nolibc init>
FRAGMA_CONTROL_KO=<unmodified module>
FRAGMA_EVIL_KO=<module emitted by mutate_sh_info.py>
```

Use the same module pair, initramfs and configuration for the original and
fixed kernels. The expected affected-architecture result is an Oops in
`module_frob_arch_sections()` before the fix and `ENOEXEC` from the early ELF
validity pass after the fix. On the original x86_64 negative control, both
modules should load and unload.

The 2026-09-08 commands, hashes and QEMU outcomes are recorded in the
[multi-architecture evidence summary](../../results/module-sh-info-multiarch-20260908/SUMMARY.md).
Bulk kernels, modules, initramfs images and serial logs remain ignored under
`build/module-sh-info-qemu-multiarch/`.
