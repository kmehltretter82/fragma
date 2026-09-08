# ARM32 module `sh_info` finding — 2026-09-08

Classification: `fragma-found-confirmed`.

Frama-C Eva first reported that `sechdrs + s->sh_info` may not be an object
pointer and that the subsequent `dstsec->sh_flags` read may be invalid in the
unchanged, source-gated ARM32 `module_frob_arch_sections()` body. Manual review
then established that the generic loader permits this field through its early
ELF checks. A concrete malformed module and same-input original/fixed QEMU A/B
confirmed the lead.

## Source and analysis identity

- Analysis revision: `b9b3e33b70b71e516930117e21de3ad2a7723747`
- Source: `arch/arm/kernel/module-plts.c`
- Function-token SHA-256: `de47a9730cb8f64c06774efa24e7d5b4efcd69ad067f0cefcac50814033a6f1c`
- Analysis build: `arm-gcc-recent-2g-analysis-v2`
- Analysis configuration SHA-256: `7b328f1239b1b04e4e95af25b6cb70a9e15aba9f23fb5c0b64d158cd1484f39f`
- Build receipt SHA-256: `c370d80272d119d3643bb0394e567babba0c1f191ca5328f019c96e444b07baf`
- Real-header model gate: passed with no diagnostics

The general analyzer-first run retained 81 valid and two unknown properties.
The two unknowns are exactly the out-of-range pointer formation and its
`sh_flags` dereference. The concrete analyzer witness makes the pointer-value
alarm invalid and stops propagation at that operation, so its overall project
status is deliberately `incomplete`, not an accepted verification result.

| Artifact | SHA-256 |
| --- | --- |
| General run summary | `a4ef5c530402ec75284fbbdb6738a4838e0573794069492e87826710ff00d6fe` |
| General result | `0713ce25b1383b79c6c74e2f28ddb032507a39978987c5c73315598042c6e2e2` |
| General analyzer log | `01c6e89ab3f57ec96c42929d3cf4a5ef838d91977108c3f0ad1db2967427cb07` |
| Concrete run summary | `eab91084d8594f02cbfcca5a344036c4ffe33c826861838388803ef3ef5616a2` |
| Concrete result | `9f2a877919d9210a8d7f21ee6625918db1844cd556b249789bb9ad55ac10a8bd` |
| Concrete analyzer log | `0cf04a9ffc9459d51864a5d5141a9a67364cb3eabbd8f1d505c47b25cd0d8c4f` |

## Dynamic A/B

The local source reproducer builds a normal module and changes only two bytes
in its ELF section table, changing section 11 (`.rel.ARM.exidx.exit.text`)
`sh_info` from 10 to `0x10000000`. The source is retained locally and is not
published automatically under current kernel AI-reporting guidance.

- Machine: QEMU 10.2.1 `virt`, Cortex-A15, TCG
- Kernel configuration: `multi_v7_defconfig` plus `VMSPLIT_2G=y`
- Compiler: `arm-linux-gnueabi-gcc` 15.2.0
- Control module SHA-256: `824a243c3c6c676df343e5d398183ba241765ee93fefe1f7a3c8a5012c995643`
- Malformed module SHA-256: `334f7daf9f942071bc70dd5b8927c47337d419c1a8242f1b4178572ccd024492`

Before the fix, the control loads/unloads and the malformed module produces
`Unable to handle kernel paging request`, with the PC at
`module_frob_arch_sections+0x160/0x2b8`, followed by a kernel panic. After the
fix, the control still loads/unloads, the loader prints the invalid index, the
malformed load returns `errno=8` (`ENOEXEC`), and the witness completes.

| Artifact | SHA-256 |
| --- | --- |
| Pre-fix QEMU log | `40d8c8f1b9382fe727b49e113bbabf16b66a98f2e07441462e500c05d6cac59a` |
| Post-fix QEMU log | `efd9ddf2511c315502a1e8e470431b554eb25f1bc657a2dc2329b07fd5c63fdd` |
| Pre-fix zImage | `e2916f43eef00a9e367e259584b317ab6d89db0b279490601692c46e75a07e49` |
| Post-fix zImage | `b453107d90006b6b12ca662e8287258020d7a719cc6c690e2171705af375ce08` |

## Patch and current-tree check

The generic fix validates SHT_REL/SHT_RELA `sh_info` during the early ELF pass,
before architecture hooks. It is based on current upstream commit
`28924df2a08f440c73991b83028032c901de2ae4`, where the bug remains present and
the ARM function is unchanged from the analyzed revision.

- Patch: `arm/arm32-module-sh-info/patches/0001-module-reject-invalid-relocation-section-target-indi.patch`
- Patch SHA-256: `ad3d77f3f0278f6525eba16982a6ee5f7efdfa28a460d8b8d94497c516bdd859`
- Current-base configuration SHA-256: `76600c466a378e172779e7832b32114c5281c1d997677a226d07134b652919d9`
- Current-base full patched zImage SHA-256: `1385712a3b07b0c388e57aa0cfe628c3772c4b9fa0f77395baee270926bc27a3`
- `git apply --check`: passed against current upstream
- `checkpatch.pl --strict --ignore MISSING_SIGN_OFF`: zero errors, warnings,
  and checks. The omission is intentional: the human submitter must review and
  add their own DCO sign-off.
- Sparse: not claimed; installed sparse 0.6.4 is rejected as outdated by the
  current kernel build.

Threat classification: regular kernel robustness bug. The demonstrated input
requires module-loading privilege and permissive module-signature policy; it
does not grant an attacker a capability they did not already possess.
