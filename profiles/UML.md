# UML x86-64: configured L1 model

On 2026-09-06, `um-x86_64-gcc` passed all 17 configured-profile checks against
kernel revision `b9b3e33b70b71e516930117e21de3ad2a7723747`. This is **L1 only**:
kernel configuration, a representative real kernel compilation, and a scoped
compiler/Frama-C model. There is no UML L2 proof baseline or L3 runtime result.

Recorded evidence:

- `build/kernel/um-x86_64-gcc/fragma-build.json`: fresh out-of-tree
  `x86_64_defconfig`, `prepare lib/string.o`, and compilation-database generation;
  all three commands returned zero. This is not a complete UML image build.
- `build/profile-checks/um-x86_64-gcc-configured/profile.json`: 17 passing checks,
  compiler and source identities, actual compilation command, generated-header
  hashes, and configured calibration dependencies.
- `build/profile-checks/um-x86_64-gcc-configured/um-x86_64-gcc.yaml`: independently
  generated machine description, SHA256
  `6495c3309060a7e7ad1a2d5844ebd2f58771c8e90edb39f9698ad2860bce3b90`.

The compiler is the existing locked GCC 15.2.0, target `x86_64-linux-gnu`.
No package installation, sudo operation, source-checkout modification, or model
copied from another profile was needed. Host build prerequisites present during
preparation included make, flex, bison, bc, binutils and libc development headers.
`pahole` was absent; the selected baseline did not require a BTF build.

## Kernel settings and measured model

The exact selectors are `ARCH=um SUBARCH=x86_64`, with
`arch/um/configs/x86_64_defconfig`. Required generated settings include
`CONFIG_UML=y`, `CONFIG_UML_X86=y`, `CONFIG_64BIT=y`, `CONFIG_X86_64=y`,
`CONFIG_X86_32=n`, and `CONFIG_SMP=n`.

The real `lib/string.c` command contains `-m64 -mcmodel=large -fno-builtin`,
`-D__arch_um__`, `-fno-PIE`, and
`-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx`. Kernel unsigned plain char,
two-byte wchar, GNU11, and no-strict-overflow/no-strict-aliasing settings are
preserved. The build gate requires the UML profile flags and exact recorded
selectors; ordinary x86 `-mcmodel=kernel` or `-mno-red-zone` settings are rejected.
The complete effective command, including UML symbol-renaming macros, remains
in the build and profile receipts.

Independent compiler assertions and Frama-C checks establish little endian,
short/int/long/long-long/pointer sizes of 2/4/8/8/8 bytes, unsigned plain char,
two-byte wchar, and eight-byte long/pointer/long-long alignment. Kernel integer
types and representative natural/packed structures are checked. EVA proves all
seven bounded arithmetic and memory-byte-order assertions with zero alarms.
Wrong pointer width, compiler-endian expectation, and Frama-C memory byte order
are independently rejected. The fixture is also compiled with the genuine
UML include paths, configuration and full `lib/string.c` compiler flags.

## Explicit kernel-header delegation

UML itself selects `HEADER_ARCH=x86` for `SUBARCH=x86_64`. Its Makefile adds
the x86 kernel/UAPI paths; the UML UAPI Kbuild is empty, and the generic-header
generator explicitly excludes UML from its mandatory-header fallback. Therefore
the profile declares `header_arch=x86`, with an individual rationale and exact
SHA256s for these pinned selection inputs:

- `arch/um/Makefile`
- `arch/um/include/uapi/asm/Kbuild`
- `scripts/Makefile.asm-headers`
- `arch/x86/um/Kconfig`

The exporter retains and checks all four inputs, the x86 kernel POSIX selector,
and the selected x86 UAPI definitions. Missing headers, changed reviewed source,
another SUBARCH, a generic fallback, and unreviewed architecture overrides fail.
No `/usr/include` kernel type is substituted. The separate configured compilation
also records the actual x86 type headers selected through UML's own include path.

## Reproducing the preparation and model checks

Use a fresh workspace/output: existing evidence is never overwritten. After
creating the pinned snapshot with the common runner, the following reproduces
the tool environment and preparation used for this baseline:

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" python3 - <<'PY'
from pathlib import Path
from fragma import build, profiles, toolchain
root = Path.cwd()
profile = profiles.load_profiles(root)["um-x86_64-gcc"]
env = profiles._environment(toolchain.prepare_environment(root))
source = root / "build/sources/linux-b9b3e33b70b71"
prepared = build.prepare_build(root, source, profile, env, jobs=4)
assert prepared["status"] == "prepared"
result = profiles.validate_profile(
    root, profile, kernel=root.parent / "linux", env=env,
    kernel_build=root / "build/kernel/um-x86_64-gcc",
    output=root / "build/profile-checks/um-x86_64-gcc-configured")
assert (result["status"], result["level"]) == ("passed", "L1")
PY
```

The selected environment strips ambient C/C++ include-injection variables while
preserving the locked Frama-C loader setup. For regression checks against current
evidence:

```sh
FRAGMA_UM_PROFILE_RESULTS=build/profile-checks/um-x86_64-gcc-configured \
  python3 -m unittest tests.test_profiles tests.test_um_profile
```

## Remaining scope

Host-facing UML translation units use distinct `USER_CFLAGS`, libc headers,
`__UM_HOST__`, and generated `user_constants.h`. Their signal, ptrace and host
structure layouts are not established by this kernel-side model. The host-offset
assembly generation occurs during preparation, but neither its complete hosted
dependency closure nor a running UML kernel is certified here.

The current whole-translation-unit preprocessing substitutions remain scoped to
`x86_64-gcc`. Initial UML L2 targets should therefore be source-gated standalone
pure helpers with explicit models, or wait for a separately reviewed UML input
path. UML symbol aliases, such as `strrchr` becoming `kernel_strrchr`, must retain
their source-to-analysis identity when such targets are introduced.

There is no host-native execution shortcut to L3: the ordinary x86 native model
fixture is not automatically run or reused for this UML profile. Assembly,
concurrency, MMIO, floating-point operations, host syscall behavior, 32-bit UML,
and a full hosted ABI remain separate work.
