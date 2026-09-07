# Architecture model calibration

`config/architectures.json` registers every architecture directory in the pinned
kernel revision. Additional ABIs and byte orders are listed as planned variants;
they do not inherit support from a working baseline profile.

`config/profiles.json` defines the active compiler profiles, with independent
kernel selectors and compiler targets. The common unsigned-char and short-wchar
settings follow the kernel Makefile, including on x86. RISC-V uses the kernel's
LP64 ABI, not the compiler's usual userspace LP64D ABI.

The configured broader-ABI profiles include ARMv7 AAPCS Linux (`multi_v7_defconfig`), 32-bit
big-endian PowerPC (`ppc6xx_defconfig`), Alpha (`defconfig`), m68k
(`virt_defconfig`, 68040), and SH4A (`sh7757lcr_defconfig`). Each selected compiler
must match its exact target/version requirement in `toolchain/lock.json`.
In particular, m68k uses two-byte long/pointer alignment: the sample structure
occupies ten bytes, compared with twelve on the ARM32 profile. Compiler and
Frama-C fixtures independently check this difference.

All ten configured profiles explicitly require
`analysis.runtime_checks.pointer_formation = "object-or-null"`; the existing
integer-arithmetic policy remains separate and unchanged. Parsing and EVA
commands request the flag, and the positive calibration retains an actual
correctness audit. The new `analysis-runtime-policy` gate validates that audit
instead of trusting command intent. All ten fresh configured L1 receipts are
indexed in [the current interface-compatibility renewal](../build/profile-checks/clang-interface-20260906/index.json):
18 checks per cross/UML profile and 20 for x86 with its native fixture.
Old receipts do not inherit this policy, and L1 still does not establish L2.
All ten configured profiles now also have current latest-dated suite-model
evidence in the [combined renewal matrix](../results/coverage-calibrations-clang-renewed-20260907/coverage.md).
The 28 dated observations comprise 15 current L1 and 13 stale observations;
the ten explicit standalone observations remain undated and current L1.

The hosted [UML x86-64 profile](UML.md) now has a separate configured L1
baseline. It uses `ARCH=um SUBARCH=x86_64`, its own compiler-derived machine
description, and a source-hash-bound review of UML's explicit x86 kernel-header
delegation. Its `-mcmodel=large` command is not the ordinary x86 kernel command.
L1 alone does not imply a UML proof baseline or runtime execution. The
separate [renewed common24 baseline](../common/L2-CLANG-RENEWAL-20260907.md) now
establishes scoped L2 for exactly four byte helpers using UML's own model,
genuine `-Os` command, frontend, compiler controls and complete proof gates.
No UML runtime execution is claimed.

Discover available prerequisites, including missing candidate compilers for
every remaining registered architecture, with:

```
python3 -m fragma.profiles --capabilities --output results/profile-capabilities.json
```

Availability is separate from support: a compiler executable alone does not
establish a configured profile or any verification level. Capability output
records the observed version/target, locked requirement, and emulator presence.
The [remaining-architecture readiness plan](NEXT-WAVE.md) records the eleven
unconfigured families, missing GCC cross tools, the explicit LLVM/tool-suite
work needed for Hexagon and other candidates, and Nios II's separate compiler
version requirement. These are setup/implementation prerequisites, not current
support claims; no installation is required for the ten existing profiles.

The [MIPS32el candidate checkpoint](MIPS32EL-MACHDEP-20260907.md) is a deliberate
step beyond compiler availability: an offline authenticated musl header sysroot,
the unchanged Frama-C generator, O32 little-endian compiler calibration, two
negative controls, parsing and Eva all pass. It remains absent from the profile
registry and central toolchain lock, so it is unregistered rather than L1. The
separate MIPS C3 IPC object mapping does not promote this general model.

The [Hexagon LLVM compiler-build milestone](LLVM-BUILD-20260906.md) passes
genuine v68 preparation and `lib/string.o`, with pinned tools and 37 new inert
build-path tests. The [target-aware Clang interfaces](CLANG-INTERFACE-20260906.md)
now add exact binary/resource/flag gates and 43 further mocked tests; the existing
ten models pass 182 fresh checks unchanged. The subsequent
[header milestone](HEXAGON-HEADER-PROVISION-20260906.md) authenticates the complete
Hexagon musl tree and provisions 217 workspace-local headers. The new
[generator adapter](HEXAGON-GENERATOR-ADAPTER-20260906.md) and
[layout continuation](HEXAGON-LAYOUT-20260906.md) now complete 100 compiler queries,
including all twelve GNU alignment fields and source-derived `max_align_t`.
Frama-C agrees on all 28 layout values and rejects three wrong representations;
the executable and literal Clang dialect remain separately recorded. All
891 regression tests passed at the September 6 shared-project identity; they
were not rerun as regression validation of the private providers. Four
emitted-alignment contradictions still block
integration. Extended-alignment policy, production integration and genuine-kernel
L1 remain open. No sudo or system installation was needed.
The [private alignment-provider candidate](../build/framac-alignment-provider-20260907/CANDIDATE-BUILD-20260907.md)
now builds and passes five early queries and one legacy core-only parse.
The installed provider is unchanged. A [fresh private context run](../build/framac-alignment-provider-20260907/PRIVATE-CONTEXT-20260907.md)
now completes all 55 opt-in pairs: 33 constant agreements, 21 corresponding
rejections and one compound-category mismatch. Fourteen additional controls
confirm missing-definition acceptance, double-VLA alignment and typed-arithmetic
gaps. A [fresh declaration candidate](../build/framac-alignment-provider-20260907/CANDIDATE-DECLARATION-20260907.md)
now builds and rejects all four missing-definition controls, preserving the
reverse-order cases and 55-pair results. The
[candidate-5 handoff](../build/framac-alignment-provider-20260907/CANDIDATE-VLA-ARITHMETIC-20260907.md)
retains candidate 4's VLA regression and fixes the saved-bound initializer in
fresh evidence. Basic double/int witnesses match `[8,8,4]`/`[4,4,4]`; the
55-pair summary remains 33 agreements, 21 rejection correspondences and one
compound mismatch. The 44-case raw batch has 156 executed queries, 66 skips,
eleven exit-zero and 33 exit-one initial outcomes per analyzer mode, and 22
successful reparses. Three expanded AST-check failures recover, but casts,
integer-constant-expression handling, static type queries and three valid
unsupported VLA controls remain open. Patch 009 is unapplied and unbuilt.
Full semantics and normal-pipeline integration remain open; no profile,
architecture level, accepted count or confirmed kernel-bug count changes.
Further Hexagon implementation is parked while the user's requested bounded
Linux kernel correctness review takes priority.

Run model calibration with:

```
python3 -m fragma.profiles --kernel /path/to/linux --profile s390x-gcc --output results/s390-model
```

The kernel checkout must contain the pinned git revision. It need not have that
revision checked out: header inputs are exported from pinned git objects and
hashed. Generation uses the installed Frama-C 33.0 `make_machdep.py` helper and
the selected cross compiler, preserving its flags, version, predefined macros,
and helper/input hashes. It requires Python PyYAML for that upstream helper;
the registry/validation API itself uses only the Python standard library.

RISC-V's kernel LP64 ABI can differ from an installed LP64D-only glibc sysroot.
Its generator therefore uses pinned musl 1.2.5 RISC-V headers, prepared separately:

```
curl --fail --location https://musl.libc.org/releases/musl-1.2.5.tar.gz -o /tmp/musl-1.2.5.tar.gz
python3 profiles/setup_musl.py --archive /tmp/musl-1.2.5.tar.gz --output build/profile-sysroots/riscv64-musl-1.2.5
```

Setup verifies the archive SHA256 recorded in the profile, invokes the upstream
header installation, and records every resulting header hash. The verification
step checks that receipt and never installs anything. Set
`FRAGMA_RISCV64_MUSL_SYSROOT` to relocate this header sysroot. The generator uses
GCC's own builtin headers first, so `-fshort-wchar` is preserved, and requests
POSIX.1-2008 metadata explicitly. These libc fields complete Frama-C's machine
description schema; actual kernel analysis still uses `-nostdinc` and pinned
Linux headers. No musl runtime, floating-point calling convention, or libc API
verification is claimed.

Generated machine descriptions are validated by independent target-compiler
assertions against pinned kernel headers, representative Frama-C parsing, and
EVA checks of arithmetic, conversions, memory byte order, and field layout.
The fixtures also compile wrong width and byte-order profiles and require their
rejection; these are controlled calibration errors. A compiled native check is
run only when the selected target actually matches the host. Cross-emulator
availability is reported separately and never replaced with host execution.
In the nine-profile common24 runs, hardware x86's benign model fixture uses
its separately recorded `-O2` context; it is not execution of the genuine
`-Os` common24 object, a kernel-helper runtime test or L3 corroboration.

These checks establish a scoped C model, not a complete kernel ABI. A profile
stays L0 unless a genuine kernel build is supplied and its configuration and
recorded compile command match the profile. L2 additionally requires source,
assumption, proof and calibration gates for a documented function set; L3
separately requires applicable target-runtime corroboration. See the renewed
[s390 pilot](../s390/L2-RENEWAL-20260907.md) and the
[nine freshly renewed common24 baselines](../common/L2-CLANG-RENEWAL-20260907.md) for exact
scopes. The current nine-profile acceptance/audit covers 164 L1 checks, 846
ordinary goals and 738 selected properties; 108 smoke outcomes remain inconclusive.
The earlier wave-three identity passed
[610 regression tests](../results/tests-common24-nine-reviewed-20260906.log).
The latest separate full regression passes
[891 tests](../results/tests-hexagon-gnu-model-20260906.log); this proof renewal
does not claim another test-suite run. The common24 proof audit
checks 5,155 file hashes without drift. The subsequent
[seven-target WP renewal](../docs/PROOF-RENEWAL-20260907.md) passes 74 model checks,
418 ordinary goals and 331 selected properties with 2,031 readback hashes
unchanged. Its ARM64, RISC-V, s390 and string proof scopes are current. The
[nine-calibration renewal](../docs/CALIBRATION-RENEWAL-20260907.md) adds 38 model
checks, 55 positive properties and revalidated retained native corroboration
for the nine unchanged false-specification observations. The
[current matrix](../results/coverage-calibrations-clang-renewed-20260907/coverage.md)
records 16 current proof variants, nine current calibrations and six legacy
nonpasses, covering 18 of 24 distinct kernel functions currently.
Earlier [six-profile evidence](../common/L2-WAVE2-20260906.md)
remains dated, not retroactively renewed. Nine freshly renewed common24 scopes plus
the separately renewed s390 pilot name ten current architecture baselines; eleven roster families
still have no L2 baseline. Neither the 21-entry roster nor these narrow scopes
means whole-architecture support, and no L3 has been established.
The s390 scope decision checks all four mandatory targets across two authentic
completed summaries; its revalidated finite QEMU `max` receipt is not full z13
fidelity or whole-pilot L3.

Packed scalar offsets are checked; bit-field allocation, assembly, concurrency,
MMIO and floating-point computation remain unsupported. Compatibility userspace
layouts are separate future work.

To add a port, register the architecture/profile/variants, select a real compiler
and kernel configuration, generate a target machine description, resolve every
generation warning, pass the common and architecture-specific fixtures, supply
the kernel build evidence, and add source-gated conditional proofs with declared
assumptions. Maintain failure evidence and update the level only from fresh
checks. No compiler, model, or configuration can be silently borrowed from the
host to fill a missing target setting.
