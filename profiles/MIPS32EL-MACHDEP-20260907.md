# MIPS32el machine-model candidate

Status: **candidate calibrated; deliberately unregistered; not L1 or L2**.

This checkpoint adds a fail-closed adapter for one precise MIPS variant: O32,
little-endian MIPS32r2 with soft-float compiler selection and the Linux kernel's
unsigned-char and two-byte `wchar_t` semantics. It uses Clang 21.1.8 and the
unchanged Frama-C 33.0 machine-description generator. The final run returns
`candidate-calibrated-not-L1`, reports no input drift, and keeps
`integration_eligible` false.

The compact [result](../results/mips32el-machdep-20260907/SUMMARY.md) binds the
ignored raw run and its principal artifacts by SHA-256.

## Header inputs

The offline provisioner authenticates the exact musl 1.2.5 archive, rejects
unsafe or oversized tar members before extraction, and invokes musl's own
`install-headers` target with `ARCH=mips`. It verifies 218 installed headers and
keeps the archive, license, command log, header inventory and provider identity
in a receipt. It neither builds nor installs a C library.

The generator include order is intentional:

1. a generator-only `limits.h` overlay containing the three exact values read
   from pinned musl source;
2. Clang's authenticated builtin headers;
3. the authenticated MIPS musl headers.

Clang's builtin `stddef.h` must precede musl's generic `stddef.h` so
`-fshort-wchar` supplies the kernel-compatible `unsigned short` `wchar_t`.
Musl's MIPS `bits/alltypes.h` otherwise declares `wchar_t` as `int`. The overlay
only supplies `PATH_MAX=4096`, `TTY_NAME_MAX=32` and `HOST_NAME_MAX=255`; it is
not used as a kernel header substitute. The actual compiler calibration uses
separately exported UAPI headers from the pinned kernel tree, including MIPS
`sgidefs.h`.

## Final observations

- Compiler: `/usr/bin/clang-21`, version 21.1.8, resolved binary SHA-256
  `412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932`.
- Observed target: `mipsel-unknown-linux-gnu`; requested ABI flags include
  `-mabi=32 -EL -march=mips32r2 -msoft-float`.
- Kernel commit: `b9b3e33b70b71e516930117e21de3ad2a7723747`, tree
  `054b6818c409ab20ae89b1031a1a7c358f673d87`.
- Candidate SHA-256:
  `dcbc18e07e17d215f13b01f3fd842e7ee0c6652fff0eee9e592b89dce6961ce9`.
- Checked model: 32-bit pointers, `int` and `long`; 64-bit `long long`;
  little endian; unsigned plain `char`; two-byte `unsigned short` `wchar_t`;
  four-byte pointer/long alignment and eight-byte `long long` alignment.
- Compiler fixture: ELF32 little-endian MIPS, machine 8, flags `0x70001001`,
  SHA-256
  `c5ceb6d229f0a0d7cea7713bcabcdb73a9cf37bc5168cd0fb5db9b58ad77373c`.
- Wrong-pointer-width and wrong-endian controls both fail at their intended
  static assertions and emit no object.
- Frama-C parsing passes. Eva generates zero alarms and reports seven valid,
  zero unknown and zero invalid assertions. Its one informational signed-wrap
  warning follows the selected kernel arithmetic policy and is not an alarm.
- All mutable input classes are hashed again before acceptance; the final
  receipt records `input_drift: false`.

## Reproduce

Provision a fresh local header sysroot from the exact archive:

```sh
python3 profiles/setup_mips_musl.py \
  --archive /path/to/musl-1.2.5.tar.gz \
  --output build/profile-sysroots/mips32el-musl-1.2.5-NEW
```

Then generate and calibrate into a fresh result directory:

```sh
python3 -m fragma.mips_machdep \
  --sysroot build/profile-sysroots/mips32el-musl-1.2.5-NEW \
  --kernel /path/to/linux \
  --output build/mips32el-machdep-NEW
```

The archive must have SHA-256
`a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4`,
and the kernel repository must contain the pinned commit. Both commands are
workspace-local and need neither network access nor `sudo`.

## Remaining boundary

The adapter is not present in `config/profiles.json` or `toolchain/lock.json`.
It has not passed a configured genuine-kernel L1 translation-unit gate, a
scoped L2 proof, target execution, or a concurrency model. The separate C3 IPC
MIPS object mapping remains valid in its own narrow scope but does not promote
this model. Big-endian MIPS, MIPS64, other ISA revisions, hard-float ABIs and
compatibility layouts remain independent future profiles.
