# MIPS32el MT7621 L1 result

Result: **passed L1; 19/19 gates passed**.

The registered `mips32el-clang` profile completed its normal configured-kernel
check against Linux `b9b3e33b70b71e516930117e21de3ad2a7723747`. The raw run is
`build/profile-checks/mips32el-mt7621-l1-20260907/run-3`; bulk evidence remains
ignored. Its `profile.json` has SHA-256
`95a399fd3f59eaf05c7913233fd81ca7c1723295dc7fb96251a0a7de77fc85b6`
and fingerprint
`e36da20aae25ca79463d669d702bba26122ad549c7378910e99c8efee96ccd54`.

The run binds an automatically selected, hash-locked MT7621 SMP/CPS seed;
Clang/LLVM 21.1.8; authenticated MIPS musl generator headers; an independently
checked little-endian O32/MIPS32r2 machdep; negative width/endian/model controls;
Frama-C parsing and Eva; and the genuine configured `lib/string.c` Kbuild
command and object. The final object is ELF32 little-endian MIPS, machine 8,
flags `0x70001001`, SHA-256
`54fedb98a48054ccb22b1f3c6987c2eb51084d77fafafc91986c1c7d566aa180`.
Intermediate `run-2` failed closed on Kbuild's two identical
`-ffreestanding` arguments; the retained validator permits that one harmless
duplication and still rejects repeated ABI, endian, ISA or float-mode choices.

The normal locked-toolchain preflight also passes after the additive Clang
entry. No `sudo`, installation, network access, target execution, L2 proof or
L3 runtime claim occurred. See the [full handoff](../../profiles/MIPS32EL-MT7621-L1-20260907.md)
for reproduction, identities and exact scope.
