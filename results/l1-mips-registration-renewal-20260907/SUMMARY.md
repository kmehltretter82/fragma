# Configured-profile L1 renewal after MIPS registration

Result: **11/11 profiles passed; 201/201 checks passed**.

After the additive `clang-21` toolchain-lock entry and registration of
`mips32el-clang`, all ten preceding configured profiles were rerun into
`build/profile-checks/mips32el-registration-final-20260907`. The separate
MT7621 raw run is
`build/profile-checks/mips32el-mt7621-l1-20260907/run-3`. All eleven receipts
report `status=passed` and `level=L1`.

| Profile | Checks | Raw `profile.json` SHA-256 |
| --- | ---: | --- |
| `alpha-gcc` | 18 | `6e2e469479b8a5750c9c81bd65d1651dbb3e28f6642b677d148d2e1d0fbaf35c` |
| `arm-gcc` | 18 | `642d6a7521495bfd0a9b6cbb3106deccebf62ff4dde89e6b7f8b6b83fc6de44a` |
| `arm64-gcc` | 18 | `2fbeef9f510589f619711fc145f6d05ef9ed38acf78321a25cc6ef022b7bef1d` |
| `m68k-gcc` | 18 | `340ca13d82c466d9ff8e683ab1b06fc9068f217e2a69d20d9f8bfa0e466b97f6` |
| `powerpc32-gcc` | 18 | `75fe03e03c5e5e6cbe28658ab19c6569fac1f422f50143f587b9f00638017e02` |
| `riscv64-gcc` | 18 | `5a81ce13740da8f846ba400ebf1617ba1b1ad6b63e936f39577148b047e3409e` |
| `s390x-gcc` | 18 | `10ae70073ced7844c2e886b9f1575c510c978b7ff77ab767d46a3520349c6b5d` |
| `sh-gcc` | 18 | `f38313f3ab06fa55b73a36813f2e06070fe57fcb2d16ee55d57d5b87bb52d0d4` |
| `um-x86_64-gcc` | 18 | `c1fb663e142d31a60b10ee067387d6446a94820164ddc4412a40b033ac69ce81` |
| `x86_64-gcc` | 20 | `c2aeb4a502613d27777b56acd87c118753a617d5181434798276c3540ccefc35` |
| `mips32el-clang` | 19 | `95a399fd3f59eaf05c7913233fd81ca7c1723295dc7fb96251a0a7de77fc85b6` |

This is a model/configured-build renewal only. It does not replay any L2 proof,
change a proof verdict, establish target runtime behavior, or make all MIPS
variants equivalent to MT7621. Bulk run outputs remain ignored; the hashes above
bind the local raw receipts. No network, installation or `sudo` was used.
