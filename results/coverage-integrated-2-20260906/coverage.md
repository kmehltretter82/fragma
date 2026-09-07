# Coverage matrix

Checked: 2026-09-06T03:40:46.557353+00:00

Revision: `b9b3e33b70b71e516930117e21de3ad2a7723747`

16 of 24 distinct kernel functions have at least one current accepted contract variant. This is not full-API or caller coverage. Calibration and project witnesses are excluded.

## Architecture and profile inventory

| Architecture | Registered profiles | State | Architecture level |
| --- | --- | --- | --- |
| alpha | alpha-gcc | registered | not-assessed |
| arc | arc-gcc | registered | not-assessed |
| arm | arm-gcc | registered | not-assessed |
| arm64 | arm64-gcc | registered | not-assessed |
| csky | csky-gcc | registered | not-assessed |
| hexagon | hexagon-clang | registered | not-assessed |
| loongarch | loongarch64-gcc | registered | not-assessed |
| m68k | m68k-gcc | registered | not-assessed |
| microblaze | microblaze-gcc | registered | not-assessed |
| mips | mips-gcc | registered | not-assessed |
| nios2 | nios2-gcc | registered | not-assessed |
| openrisc | openrisc-gcc | registered | not-assessed |
| parisc | parisc-gcc | registered | not-assessed |
| powerpc | powerpc32-gcc | registered | not-assessed |
| riscv | riscv64-gcc | registered | not-assessed |
| s390 | s390x-gcc | registered | not-assessed |
| sh | sh-gcc | registered | not-assessed |
| sparc | sparc64-gcc | registered | not-assessed |
| um | um-x86_64-gcc | registered | not-assessed |
| x86 | x86_64-gcc | registered | not-assessed |
| xtensa | xtensa-gcc | registered | not-assessed |

## Configured model observations

| Profile | Registration | Latest dated model | Current dated model level | Undated observations |
| --- | --- | --- | --- | --- |
| um-x86_64-gcc | experimental | not supplied | none | 1 |
| arm-gcc | experimental | not supplied | none | 0 |
| powerpc32-gcc | experimental | not supplied | none | 0 |
| alpha-gcc | experimental | not supplied | none | 0 |
| m68k-gcc | experimental | not supplied | none | 0 |
| sh-gcc | experimental | not supplied | none | 0 |
| x86_64-gcc | experimental | passed / L1 / 2026-09-06T03:39:28.884528+00:00 | L1 | 0 |
| arm64-gcc | experimental | passed / L1 / 2026-09-06T03:39:28.884528+00:00 | L1 | 0 |
| riscv64-gcc | experimental | passed / L1 / 2026-09-06T03:39:28.884528+00:00 | L1 | 0 |
| s390x-gcc | experimental | passed / L1 / 2026-09-06T03:39:28.884528+00:00 | L1 | 0 |
| arc-gcc | planned | not supplied | none | 0 |
| csky-gcc | planned | not supplied | none | 0 |
| hexagon-clang | planned | not supplied | none | 0 |
| loongarch64-gcc | planned | not supplied | none | 0 |
| microblaze-gcc | planned | not supplied | none | 0 |
| mips-gcc | planned | not supplied | none | 0 |
| nios2-gcc | planned | not supplied | none | 0 |
| openrisc-gcc | planned | not supplied | none | 0 |
| parisc-gcc | planned | not supplied | none | 0 |
| sparc64-gcc | planned | not supplied | none | 0 |
| xtensa-gcc | planned | not supplied | none | 0 |

## Target outcomes

| Target | Profile | Role | Latest outcome | Completed | Freshness |
| --- | --- | --- | --- | --- | --- |
| arm64.cpuid | arm64-gcc | proof | unsupported | 2026-09-06T03:39:28.884528+00:00 | current |
| arm64.immediates | arm64-gcc | proof | inconsistent | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.s390.byte-order.eva | s390x-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.count_cutoff.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.early_nul.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.first_match.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.full_copy.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.no_copy_room.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.nul_conversion.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.truncation.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.string.zero_count.eva | x86_64-gcc | calibration | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.strlcat.naive.eva | x86_64-gcc | calibration | incomplete | 2026-09-06T03:39:28.884528+00:00 | current |
| calibration.strlcat.naive.wp | x86_64-gcc | calibration | inconsistent | 2026-09-06T03:39:28.884528+00:00 | current |
| mpi.rshift | x86_64-gcc | proof | unsupported | 2026-09-06T03:39:28.884528+00:00 | current |
| riscv.base-encoders | riscv64-gcc | proof | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| s390.tod_to_ns | s390x-gcc | proof | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| s390.unaligned24 | s390x-gcc | proof | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| s390.unaligned48 | s390x-gcc | proof | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| string.strlcat | x86_64-gcc | proof | inconsistent | 2026-09-06T03:39:28.884528+00:00 | current |
| string.strnchr | x86_64-gcc | proof | unsupported | 2026-09-06T03:39:28.884528+00:00 | current |
| string.verified.strlcat | x86_64-gcc | proof | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |
| string.verified.strnchr | x86_64-gcc | proof | accepted-current | 2026-09-06T03:39:28.884528+00:00 | current |

## Contract-variant property coverage

| Target / function | Kind | Runtime safety | Functional | Termination | Caller preconditions |
| --- | --- | --- | --- | --- | --- |
| arm64.cpuid / cpuid_feature_extract_signed_field_width | kernel | unresolved | not-claimed | not-claimed | unverified |
| arm64.cpuid / cpuid_feature_extract_unsigned_field_width | kernel | unresolved | not-claimed | not-claimed | unverified |
| arm64.immediates / aarch64_get_imm_shift_mask | kernel | unresolved | not-claimed | not-claimed | unverified |
| arm64.immediates / aarch64_insn_decode_immediate | kernel | unresolved | not-claimed | not-claimed | unverified |
| arm64.immediates / aarch64_insn_encode_immediate | kernel | unresolved | not-claimed | not-claimed | unverified |
| arm64.immediates / aarch64_insn_adrp_get_offset | kernel | unresolved | not-claimed | not-claimed | unverified |
| arm64.immediates / aarch64_insn_adrp_set_offset | kernel | unresolved | not-claimed | not-claimed | unverified |
| calibration.s390.byte-order.eva / __get_unaligned_be24 | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.s390.byte-order.eva / fragma_byte_order_calibration | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.count_cutoff.eva / strnchr | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.early_nul.eva / strnchr | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.first_match.eva / strnchr | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.full_copy.eva / strlcat | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.no_copy_room.eva / strlcat | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.nul_conversion.eva / strnchr | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.truncation.eva / strlcat | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.string.zero_count.eva / strnchr | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.strlcat.naive.eva / strlcat | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| calibration.strlcat.naive.wp / strlcat | calibration | not-applicable | not-applicable | not-applicable | not-applicable |
| mpi.rshift / mpihelp_rshift | kernel | unresolved | not-claimed | unresolved | unverified |
| riscv.base-encoders / rv_r_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / rv_i_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / rv_s_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / rv_b_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / rv_u_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / rv_j_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / rv_amo_insn | kernel | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_i | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_s | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_b | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_u | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_j | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| s390.tod_to_ns / tod_to_ns | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned24 / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned24 / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned24 / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned24 / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned24 / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned24 / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned48 / __get_unaligned_be48 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned48 / __put_unaligned_be48 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| s390.unaligned48 / fragma_roundtrip_be48 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| string.strlcat / strlcat | kernel | unresolved | not-claimed | not-claimed | unverified |
| string.strnchr / strnchr | kernel | unresolved | unresolved | unresolved | unverified |
| string.verified.strlcat / strlcat | kernel | accepted-current | accepted-current | accepted-current | unverified |
| string.verified.strnchr / strnchr | kernel | accepted-current | accepted-current | accepted-current | unverified |

All property claims remain conditional on each target's declared input domain and trusted assumptions. Output NUL termination is not function termination. Detailed identity failures, changed inputs, dated historical observations, unresolved dependencies, and explicit source receipts are retained in JSON.
