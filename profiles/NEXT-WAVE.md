# Remaining architecture toolchain work

Read-only local readiness check, 2026-09-06, for pinned Linux
`b9b3e33b70b71e516930117e21de3ad2a7723747`. Ten architecture families still
lack configured L1: `arc`, `csky`, `hexagon`, `loongarch`, `microblaze`,
`nios2`, `openrisc`, `parisc`, `sparc` and `xtensa`. Tool availability is not a
build, model or L2 claim. Ten architectures still lack a documented L2
baseline; MIPS now has one exact scoped common24 result.

The planned GCC executables for `arc`, `csky`, `loongarch`, `microblaze`,
`mips`, `nios2`, `openrisc`, `parisc`, `sparc` and `xtensa` were not found on
the inspected PATH or in the checked system/local compiler directories.
Additional toolchains and target generator headers are prerequisites, not
packages installed automatically by verification.

Clang 21.1.8 is present at `/usr/bin/clang` (resolved to
`/usr/lib/llvm-21/bin/clang`, SHA-256
`412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932`).
Its unflagged reported target is x86-64, not evidence of a configured Hexagon
profile. No kernel object or model was generated in this readiness check.

The later C3 IPC work now has one deliberately narrower exception to that
historical readiness result: a genuine `loongson64_defconfig` SMP
`ipc/util.o` is accepted as a source/compiler/disassembly mapping through the
explicit Clang/LLVM 21.1.8 target route. This does not provide generated
Frama-C target headers, machine-model calibration, L1, L2 or a general
LoongArch profile, so LoongArch remains in this architecture-support queue.

The earlier narrow exception for MIPS used a genuine little-endian
`malta_defconfig` MIPS32r2 SMP `ipc/util.o` is accepted for the C3 lifetime
mapping through Clang/LLVM 21.1.8. Its O32 ELF identity, configuration, Kbuild
command and LL/SC lowering are checked. A later, separately scoped
[MIPS32el candidate](MIPS32EL-MACHDEP-20260907.md) provisioned authenticated
generator headers and passed type/layout, parser and Eva calibration. The later
[MT7621 checkpoint](MIPS32EL-MT7621-L1-20260907.md) registers that exact route
and passes genuine configured-kernel L1. Its separate
[common24 result](../common/L2-MIPS32EL-20260907.md) supplies one narrow L2
scope. MIPS leaves the initial L1/L2 queues but remains in the caller, runtime
and variant queues; big-endian and 64-bit MIPS are still open.

The subsequent [LLVM metadata assessment](../build/llvm-readiness-20260906/REPORT.md)
confirms the installed compiler, linker and LLVM utility suite at version
21.1.8. Explicit target and empty-input macro queries succeed for the four
candidates below; the observed triples add the `unknown` vendor component.
Invocation aliases and resolved executable hashes are recorded separately.
These are compiler-default observations, not genuine kernel configurations or
validated target models. In particular, MIPS defaults to o32/hard-float and
the queried LoongArch route reports soft-float; neither may silently become the
planned profile. No kernel object, target program or new proof was produced.

## Implement the LLVM route explicitly

The [first Hexagon compiler-build milestone](LLVM-BUILD-20260906.md) now passes
genuine preparation and `lib/string.o` with an explicit LLVM 21.1.8/v68 suite.
The [build helper](../fragma/build.py) has an opt-in, strictly bounded LLVM route;
GCC behavior is preserved. This diagnostic does not activate a model/profile.
The subsequent [interface milestone](CLANG-INTERFACE-20260906.md) adds explicit
family/target/CPU queries and pinned Clang resource inventories to the
[model checker](../fragma/profiles.py) and [toolchain inventory](../fragma/toolchain.py),
with unchanged GCC commands and 182 fresh passing existing-model checks.
The production model generator's custom header path still only consumes its
reviewed RISC-V receipt. The separate
[Hexagon header milestone](HEXAGON-HEADER-PROVISION-20260906.md) now authenticates
the genuine Qualcomm musl archive against its exact Git tree and provisions all
217 target headers offline. Independent byte readback and actual header-order
diagnostics pass their stated scopes; no model is promoted. The new
[standalone adapter](HEXAGON-GENERATOR-ADAPTER-20260906.md) handles the macro and
probe issues, consumes the genuine header receipt and extracts a complete
candidate. Its [layout continuation](HEXAGON-LAYOUT-20260906.md) corrects the
source-derived `max_align_t` representation and executable/dialect confusion,
measures all twelve GNU alignment fields, and passes actual compiler/analyzer
layout comparison. The fresh 100-query generation still detects four emitted-
alignment contradictions and returns nonzero; all 891 regression tests pass.
The normal Clang profile gate remains closed pending extended-alignment
policy, production integration and full calibration. The standard RISC-V musl archive remains unsuitable for
Hexagon; host defaults or a weakened target comparison are not a replacement.

The pinned kernel's [Clang target routes](../build/sources/linux-b9b3e33b70b71/scripts/Makefile.clang)
include the following useful candidates:

| Candidate | Kernel target argument | Additional work |
| --- | --- | --- |
| Hexagon | `hexagon-linux-musl` | Compiler/build/header identities, full candidate generation and source-derived compiler/analyzer layout agreement exist. Resolve extended-alignment mismatch, integrate the profile route, then pass genuine-kernel L1/L2; requested/observed triples remain separately bound. |
| LoongArch | `loongarch64-linux-gnusf` | The distinct LLVM C3 IPC object mapping is now checked. Keep it separate from the planned GCC profile; add generated-header ABI/model calibration and genuine L1/L2 before general activation. |
| MIPS | `mipsel-linux-gnu` | MT7621 O32/little-endian MIPS32r2 passes registered genuine-kernel L1 and one four-helper scoped L2 result. Add callers/runtime separately; big-endian MIPS32 and MIPS64 remain separate profiles. |
| Sparc64 | `sparc64-linux-gnu` | The documented LLVM route also needs external GNU assembler support; that cross-prefix is missing locally. |

Continue from the Hexagon adapter's explicit extended-alignment gate through
profile integration and model calibration. For MIPS, continue from the
registered MT7621 L1 and common24 L2 scope to callers/runtime and separate ABI
variants;
LoongArch still needs its machine-model candidate. Preserve the planned GCC
routes as separate profile work. Required acceptance remains: compiler identity,
target-aware version/macros, pinned tools and generator headers, genuine build,
fresh machine/type/layout/parser/calibration evidence, and finally scoped proofs.
Additional configurations, compatibility layouts and runtime support remain
separate.

## Nios II requires a different compiler version

The installed primary GCC 15 release notes at
`/usr/share/doc/gcc-15/NEWS.html` state that Nios II support was removed in GCC 15
after being deprecated in GCC 14. Thus this architecture cannot inherit the
current default GCC 15.2.0 requirement. It needs an explicitly pinned supported
pre-15 toolchain (or a separately maintained port), compatible binutils and
headers, and its own calibration evidence. The architecture remains in this
pinned Linux roster; a missing toolchain is not grounds to count it as complete.

No download, installation, compiler build, target execution or support-level
promotion was performed for the original readiness assessment. Subsequent
milestones compile objects, run benign host build tools and prepare
workspace-local headers; the MT7621 continuation now awards exact L1 but does
not execute target objects or award L2. The currently configured profiles
can continue without `sudo`; provisioning missing future-port dependencies is
a separate setup step.
