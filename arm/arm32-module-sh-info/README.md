# ARM32 module relocation target-index bug

Frama-C Eva identified an invalid section-table pointer in the unchanged
ARM32 `module_frob_arch_sections()` implementation when a relocation section's
untrusted `sh_info` field lies outside the ELF section table. An exact QEMU
A/B test confirmed that the original kernel faults and the proposed generic
module-loader validation rejects the same input with `ENOEXEC`.

A source audit found the same early indexing class in PA-RISC, ARM64, RISC-V
and LoongArch. PA-RISC now has its own same-input QEMU A/B. The other three
architectures have full patched builds and are described only as
source-exposed, not runtime-confirmed.

This is the project's first `fragma-found-confirmed` Linux kernel bug. The
earlier RV32 `load_unaligned_zeropad()` bug remains `review-found-confirmed`.

Artifacts:

- [submission patch](patches/0001-module-reject-invalid-relocation-section-target-indi.patch)
- [plain-text report](REPORT.txt)
- [evidence summary](../../results/arm32-module-sh-info-20260908/SUMMARY.md)
- [PA-RISC A/B and affected-hook matrix](../../results/parisc-module-sh-info-20260908/SUMMARY.md)

The patch is based on upstream commit
`28924df2a08f440c73991b83028032c901de2ae4` and includes `To`/`Cc`,
`Assisted-by: LLM`, and `Signed-off-by: Karl Mehltretter` headers/trailers.
The sign-off was added at the named submitter's explicit request so the
reviewed file can be passed directly to `git send-email`. Nothing was emailed
by this project.

The source reproducer remains local and ignored. It is available to the human
reporter for maintainer-requested private sharing, in line with current kernel
AI-reporting guidance.
