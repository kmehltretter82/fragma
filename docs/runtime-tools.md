# Optional local runtime tools

Static proof runs do not require an emulator. Applicable compiled checks can
use an explicitly prepared emulator, without changing system packages, shell
startup files, services, or binary-format registrations.

The separate [runtime lock](../toolchain/runtime-lock.json) pins Ubuntu's
`qemu-user` package `1:10.2.1+ds-1ubuntu3.2`, its URL, size and SHA256. The hash
was taken from this machine's configured package index; this helper does not
independently reauthenticate upstream signatures. It does not alter the core
proof-toolchain lock or transfer any previous proof approval.

## Explicit setup

Preview the local setup; this command does not write or download anything:

```sh
python3 toolchain/setup_runtime.py --prefix "$PWD/toolchain/runtime-prefix"
```

Download the exact artifact URL shown in that plan into a new local file, then
explicitly apply the offline setup:

```sh
python3 toolchain/setup_runtime.py \
  --archive /path/to/qemu-user_10.2.1+ds-1ubuntu3.2_amd64.deb \
  --prefix "$PWD/toolchain/runtime-prefix" --apply
```

The setup verifies both size and SHA256 before reading package contents. It
extracts only package data through Python's safe archive filter into a new
prefix; package control scripts never run. Existing prefixes are rejected,
not upgraded or overwritten. The setup also checks the s390 executable's
version and absence of a dynamic ELF interpreter, and hashes every extracted
file. Package files under this prefix do not register host `binfmt` handlers.

The [current setup receipt](../toolchain/runtime-prefix/fragma-runtime.json)
records 119 installed data files. Its s390 emulator reports version 10.2.1 and
provides an explicit `z13` CPU model. Other supplied emulator binaries are
available as files only; their presence does not validate any target profile.

## Runtime evidence is separate

Invoke an emulator by its explicit local path; installation does not change
the shell's `PATH`. For example, `toolchain/runtime-prefix/usr/bin/qemu-s390x`
is the emulator selected for the bounded s390 calibration under development.

QEMU user mode translates a target process and its system calls; it does not
boot or verify the kernel. Select the CPU explicitly and record the compiled
target, compiler flags, native layout observations, emulator binary, target
runtime/link dependencies and exact output. See the upstream
[user-mode documentation](https://www.qemu.org/docs/master/user/main.html).

Emulator availability alone establishes no L2 or L3 claim. A completed compiled
check corroborates only its actual reached observations. It cannot replace an
unproved universal property, validate unrelated assembly/concurrency, or make
an arbitrary solver timeout into evidence of a false specification. Raw
analyzer outcomes and independently observed runtime facts remain separate.
