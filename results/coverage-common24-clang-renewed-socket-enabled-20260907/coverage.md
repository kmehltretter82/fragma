# Coverage matrix

Checked: 2026-09-07T00:23:07.635428+00:00

Revision: `b9b3e33b70b71e516930117e21de3ad2a7723747`

4 of 24 distinct kernel functions have at least one current accepted contract variant. This is not full-API or caller coverage. Calibration and project witnesses are excluded.

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
| um-x86_64-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.400977+00:00 | L1 | 1 |
| arm-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.052197+00:00 | L1 | 1 |
| powerpc32-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.052197+00:00 | L1 | 1 |
| alpha-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.400977+00:00 | L1 | 1 |
| m68k-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.052197+00:00 | L1 | 1 |
| sh-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.472929+00:00 | L1 | 1 |
| x86_64-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.400977+00:00 | L1 | 1 |
| arm64-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.472929+00:00 | L1 | 1 |
| riscv64-gcc | experimental | passed / L1 / 2026-09-07T00:19:41.472929+00:00 | L1 | 1 |
| s390x-gcc | experimental | passed / L1 / 2026-09-06T05:47:19.330286+00:00 | none | 1 |
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
| arm64.cpuid | arm64-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| arm64.immediates | arm64-gcc | proof | inconsistent | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.s390.byte-order.eva | s390x-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.count_cutoff.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.early_nul.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.first_match.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.full_copy.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.no_copy_room.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.nul_conversion.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.truncation.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.string.zero_count.eva | x86_64-gcc | calibration | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.strlcat.naive.eva | x86_64-gcc | calibration | incomplete | 2026-09-06T05:47:19.330286+00:00 | stale |
| calibration.strlcat.naive.wp | x86_64-gcc | calibration | inconsistent | 2026-09-06T05:47:19.330286+00:00 | stale |
| common.unaligned24.alpha | alpha-gcc | proof | accepted-current | 2026-09-07T00:19:41.400977+00:00 | current |
| common.unaligned24.arm | arm-gcc | proof | accepted-current | 2026-09-07T00:19:41.052197+00:00 | current |
| common.unaligned24.arm64 | arm64-gcc | proof | accepted-current | 2026-09-07T00:19:41.472929+00:00 | current |
| common.unaligned24.m68k | m68k-gcc | proof | accepted-current | 2026-09-07T00:19:41.052197+00:00 | current |
| common.unaligned24.powerpc32 | powerpc32-gcc | proof | accepted-current | 2026-09-07T00:19:41.052197+00:00 | current |
| common.unaligned24.riscv64 | riscv64-gcc | proof | accepted-current | 2026-09-07T00:19:41.472929+00:00 | current |
| common.unaligned24.sh | sh-gcc | proof | accepted-current | 2026-09-07T00:19:41.472929+00:00 | current |
| common.unaligned24.um-x86_64 | um-x86_64-gcc | proof | accepted-current | 2026-09-07T00:19:41.400977+00:00 | current |
| common.unaligned24.x86_64 | x86_64-gcc | proof | accepted-current | 2026-09-07T00:19:41.400977+00:00 | current |
| mpi.rshift | x86_64-gcc | proof | unsupported | 2026-09-06T05:47:19.330286+00:00 | stale |
| riscv.base-encoders | riscv64-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| s390.tod_to_ns | s390x-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| s390.unaligned24 | s390x-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| s390.unaligned48 | s390x-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| string.strlcat | x86_64-gcc | proof | inconsistent | 2026-09-06T05:47:19.330286+00:00 | stale |
| string.strnchr | x86_64-gcc | proof | unsupported | 2026-09-06T05:47:19.330286+00:00 | stale |
| string.verified.strlcat | x86_64-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |
| string.verified.strnchr | x86_64-gcc | proof | accepted-stale | 2026-09-06T05:47:19.330286+00:00 | stale |

## Contract-variant property coverage

| Target / function | Kind | Runtime safety | Functional | Termination | Caller preconditions |
| --- | --- | --- | --- | --- | --- |
| arm64.cpuid / cpuid_feature_extract_signed_field_width | kernel | accepted-historical-stale | not-claimed | not-claimed | unverified |
| arm64.cpuid / cpuid_feature_extract_unsigned_field_width | kernel | accepted-historical-stale | not-claimed | not-claimed | unverified |
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
| common.unaligned24.alpha / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.alpha / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.alpha / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.alpha / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.alpha / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.alpha / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm64 / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm64 / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm64 / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm64 / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm64 / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.arm64 / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.m68k / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.m68k / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.m68k / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.m68k / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.m68k / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.m68k / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.powerpc32 / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.powerpc32 / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.powerpc32 / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.powerpc32 / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.powerpc32 / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.powerpc32 / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.riscv64 / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.riscv64 / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.riscv64 / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.riscv64 / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.riscv64 / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.riscv64 / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.sh / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.sh / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.sh / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.sh / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.sh / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.sh / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.um-x86_64 / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.um-x86_64 / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.um-x86_64 / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.um-x86_64 / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.um-x86_64 / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.um-x86_64 / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.x86_64 / __get_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.x86_64 / __get_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.x86_64 / __put_unaligned_be24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.x86_64 / __put_unaligned_le24 | kernel | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.x86_64 / fragma_roundtrip_be24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| common.unaligned24.x86_64 / fragma_roundtrip_le24 | project-witness | accepted-current | accepted-current | accepted-current | unverified |
| mpi.rshift / mpihelp_rshift | kernel | unresolved | not-claimed | unresolved | unverified |
| riscv.base-encoders / rv_r_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / rv_i_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / rv_s_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / rv_b_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / rv_u_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / rv_j_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / rv_amo_insn | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_i | project-witness | unresolved | unresolved | unresolved | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_s | project-witness | unresolved | unresolved | unresolved | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_b | project-witness | unresolved | unresolved | unresolved | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_u | project-witness | unresolved | unresolved | unresolved | unverified |
| riscv.base-encoders / fragma_riscv_roundtrip_j | project-witness | unresolved | unresolved | unresolved | unverified |
| s390.tod_to_ns / tod_to_ns | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned24 / __get_unaligned_be24 | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned24 / __get_unaligned_le24 | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned24 / __put_unaligned_be24 | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned24 / __put_unaligned_le24 | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned24 / fragma_roundtrip_be24 | project-witness | unresolved | unresolved | unresolved | unverified |
| s390.unaligned24 / fragma_roundtrip_le24 | project-witness | unresolved | unresolved | unresolved | unverified |
| s390.unaligned48 / __get_unaligned_be48 | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned48 / __put_unaligned_be48 | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| s390.unaligned48 / fragma_roundtrip_be48 | project-witness | unresolved | unresolved | unresolved | unverified |
| string.strlcat / strlcat | kernel | unresolved | not-claimed | not-claimed | unverified |
| string.strnchr / strnchr | kernel | unresolved | unresolved | unresolved | unverified |
| string.verified.strlcat / strlcat | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |
| string.verified.strnchr / strnchr | kernel | accepted-historical-stale | accepted-historical-stale | accepted-historical-stale | unverified |

All property claims remain conditional on each target's declared input domain and trusted assumptions. Output NUL termination is not function termination. Detailed identity failures, changed inputs, dated historical observations, unresolved dependencies, and explicit source receipts are retained in JSON.
