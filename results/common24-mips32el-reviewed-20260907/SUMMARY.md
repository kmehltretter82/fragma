# MIPS32el common24 scoped L2 result

Result: **PASS**.

The fresh reviewed run at
`build/common24-mips-l2-reviewed-20260907/run-2` accepts
`common.unaligned24.mips32el` under the registered `mips32el-clang` profile at
Linux `b9b3e33b70b71e516930117e21de3ad2a7723747`. Bulk proof output remains
ignored local evidence; this tracked summary records its boundary and primary
file identities.

| Gate | Fresh result |
| --- | --- |
| Configured MT7621 model | L1, 19/19 checks |
| Ordinary WP goals | 94/94 valid |
| Selected consolidated properties | 82/82 Valid |
| Dependency inventory | Complete and unconditional; no issue or missing link |
| Warnings | 5/5 matched exact scoped reviews |
| Smoke probes | 12 inconclusive timeouts; 0 inconsistent; 0 waived |
| Compiler sensitivity | 22/22 mutations rejected; 25 commands checked |
| Fixture controls | Wrong type 5/5 errors; wrong inline 1/1 error |
| Positive compiler object | ELF32 little-endian MIPS, 8-byte definition |
| Final classification | accepted, verified, local policy passed, proof policy passed |

The compiler-object gate also checks the exact O32/MIPS32r2 flags and the
`.reginfo`, `.MIPS.abiflags` and empty `.llvm_addrsig` metadata. This is
container/ABI metadata, not an instruction, linker or runtime proof.

Primary retained identities:

| Raw artifact | SHA-256 |
| --- | --- |
| Suite `summary.json` | `85c070db021ef6fa64c27f4905f684b4d4c517290542d86e6a2768138cc07ed4` |
| Target `result.json` | `a7525613a39e7a902730f77b34bdb4793b950cd8260085790e2a36cc4872c014` |
| `analysis.log` | `09aa03499ca45bc6a9a34208063bfa00721c4de2edb8cfda38b3a717952c551e` |
| `wp.json` | `20156acbd4130ab6368d8a7b8681a05335fbb8f1239ed68be5647405b90a72dd` |
| `properties.tsv` | `19f31c29c14aaef9e322b03908712c051c0e97522adbcade95efe1f2da595149` |
| Compiler-calibration receipt | `b3849c9c1c523ea2100623f78f9684b2deff990a449b2480dfee629e31f5bea6` |
| Compiler-controls receipt | `2fa5a90ea3bc050fd94f19262d6e1b1840a27d412769c57b0b68ec0373f48b93` |
| Fresh profile receipt | `ea44910a1844cc52b00d09ef425f20ee780bc6e86448bb5d2e0e8f7c9de4eab6` |

The four kernel functions are `__get_unaligned_be24`,
`__get_unaligned_le24`, `__put_unaligned_be24` and
`__put_unaligned_le24`; the two `fragma_roundtrip_*24` functions are project
witnesses. The result establishes the declared sequential-C properties only.
It does not cover kernel callers, emitted instructions, target execution,
concurrency, big-endian MIPS, MIPS64, L3 or arbitrary MIPS code. It confirms no
kernel defect: these selected helpers passed their properties.

Reproduce into a new directory with:

```sh
python3 -m fragma run \
  --kernel /home/karl/linux-work/linux \
  --output build/common24-mips-l2-reviewed-NEW \
  --target common.unaligned24.mips32el \
  --timeout 1 --wall-timeout 600 --jobs 2
```

Why3 needs permission to create its private local Unix socket. No package was
installed and no `sudo` command was used. The checkpoint's
[full regression](../tests-mips-l2-arm32-freeze-20260907/SUMMARY.md) passes all
1,043 tests with 20 conditional skips.

The preceding `run-1` also passed, but its review document still contained a
Markdown trailing-space line break. Removing that whitespace changed the
review's bound SHA-256. The six exact bindings were updated and `run-2` was
executed from scratch; `run-1` remains preserved but is not the primary
checkpoint evidence.
