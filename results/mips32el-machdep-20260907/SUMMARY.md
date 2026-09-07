# MIPS32el machdep checkpoint

Result: **candidate calibrated; unregistered; not L1**.

This result remains historical. The later
[MT7621 L1 result](../mips32el-mt7621-l1-20260907/SUMMARY.md) uses a registered
profile and genuine configured kernel build; this receipt itself is unchanged.

The final local run completed at `2026-09-07T18:48:57.777250+00:00` with
`status=candidate-calibrated-not-L1`, `level=unregistered`,
`integration_eligible=false`, and `input_drift=false`. Its raw directory is
`build/mips32el-machdep-20260907/run-4`; bulk outputs remain ignored.

The adapter binds Clang 21.1.8 to little-endian O32 MIPS32r2, provisions 218
pinned musl 1.2.5 headers offline, runs the unchanged Frama-C 33.0 generator,
checks the emitted model, compiles an ELF32 MIPS calibration object, rejects
wrong-width and wrong-endian controls, and passes Frama-C parsing plus Eva with
zero alarms and 7/0/0 valid/unknown/invalid assertions.

Principal SHA-256 identities:

| Artifact | SHA-256 |
| --- | --- |
| Raw final receipt | `753aa203ab9af326d0bb887f162c82a4234f77fbaec2cd53935e3b2e9978bbb7` |
| Generated candidate | `dcbc18e07e17d215f13b01f3fd842e7ee0c6652fff0eee9e592b89dce6961ce9` |
| ELF32 calibration object | `c5ceb6d229f0a0d7cea7713bcabcdb73a9cf37bc5168cd0fb5db9b58ad77373c` |
| Sysroot receipt | `ca8baeb420dae5e955c464002a9b0e8469bfaaf336caf4090cdb047dbaf7c343` |
| Adapter | `82d091f8299acee229ae57388d7749faae213b95fae15fbe52a2a5711b6a56fb` |
| Sysroot provisioner | `751558ac493ba58a443930645a541246eb1e818931fbe4d5c0401fa89f9e1dec` |

The pinned kernel commit is
`b9b3e33b70b71e516930117e21de3ad2a7723747` with tree
`054b6818c409ab20ae89b1031a1a7c358f673d87`. The source archive SHA-256 is
`a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4`.
No network access, package installation, `sudo`, target execution, profile
registration, L1 or L2 acceptance occurred.

The checkpoint's complete project regression run passes 1,015/1,015 tests with
20 conditional skips. Its [log](../tests-mips-rv32-checkpoint-20260907.log) has
SHA-256
`6f92a38b20be924e873b392ff9c248aaca01258f4f7edd61d1c0fa0d6eecb0e0`.

See the [full handoff](../../profiles/MIPS32EL-MACHDEP-20260907.md) for the
header-order rationale, exact model boundary and reproduction commands.
