# Common explicit-byte helpers

The shared harness selects four genuine Linux 24-bit byte helpers and two
project round-trip witnesses. It preserves their full contracts and all 16
intermediate assertions. Adding profile variants does not add unique kernel
functions or count the witnesses as kernel code.

Nine GCC profile variants retain accepted normal runs and independent
retained-evidence/replay checks at their exact pre-MIPS project identity. The
[2026-09-07 L2 renewal](L2-CLANG-RENEWAL-20260907.md) covers exactly these four helpers
under ARM32, PowerPC32, m68k, ARM64, RISC-V64, SH, Alpha, hardware x86-64 and
UML x86-64. The final audit checks 846 ordinary goals, 738 selected properties
and 5,155 unique file hashes with zero drift; all 108 smoke outcomes remain
inconclusive. The source, full domains and existing scoped reviews are unchanged.
All 252 genuine-fixture/compiler observations and 36 helper/profile combinations
are checked. The [dated wave-three results](L2-WAVE3-20260906.md) and their
610-test pass remain preserved under their earlier identity.
All [891 current regression tests](../results/tests-hexagon-gnu-model-20260906.log)
pass after the subsequent Clang interfaces, offline Hexagon header setup and
standalone generator adapter with source-derived compiler/analyzer layout
calibration. Its extended-alignment gate remains closed.
Tests, header diagnostics and models alone do not renew proofs; the new normal
runs and audits supply the current acceptance. No whole-architecture,
kernel-caller or L3 claim follows. The
[current matrix](../results/coverage-calibrations-clang-renewed-20260907/coverage.md)
has 16 current proofs, nine current accepted Eva calibrations and six legacy
nonpasses. The [seven non-common proof renewals](../docs/PROOF-RENEWAL-20260907.md)
bring current distinct-function coverage to 18 of 24; the nine common variants
still cover the same four helpers, not nine new function sets. Original
[socket-denied attempts](RENEWAL-SOCKET-FAILURE-20260907.md) remain incomplete
outside matrix history. The preserved first coverage audit and its narrow
successor distinguish nine old contexts' unavailable current validation from
the new accepted proofs; see the [renewal record](L2-CLANG-RENEWAL-20260907.md).

A tenth registered variant, `common.unaligned24.mips32el`, now has a fresh
post-registration [scoped L2 result](L2-MIPS32EL-20260907.md). Its exact
MT7621 O32/little-endian MIPS32r2 run passes 19 L1 gates, 94 ordinary goals,
82 selected properties, 22 compiler mutations and both fixture controls. This
does not refresh the nine GCC receipts and does not add distinct kernel
functions.

The initial registered variants are `common.unaligned24.arm`,
`common.unaligned24.powerpc32`, and `common.unaligned24.m68k`. Their dated run
passed normal acceptance, including scoped assumption/warning reviews
and the [compiler-calibration provider](../docs/common24-compiler-calibration.md).
The [2026-09-06 L2 baselines](L2-20260906.md) document support for exactly
these four helpers under the three profiles, complete proof/replay readback,
556 then-passing tests and the remaining limitations. No L3 is established.
The [wave-two continuation](WAVE2-20260906.md) adds
`common.unaligned24.arm64`, `common.unaligned24.riscv64` and
`common.unaligned24.sh`. Their distinct scoped reviews and the source-derived
compiler assertion identities were tested by the then-current 580-test pass,
without skips. The dated [six-profile L2 run](L2-WAVE2-20260906.md) retained
normal acceptance and independently audited replay: 564 ordinary goals, 492
selected properties and 3,664 file hashes, with zero drift at that identity.
The [third wave](WAVE3-20260906.md) adds `common.unaligned24.alpha`,
`common.unaligned24.x86_64` and `common.unaligned24.um-x86_64`, with their own
assumptions and evidence, and renews the older six contexts. Source reuse does
not transfer earlier approval; the dated earlier records remain unchanged.
The [first registered integration run](INTEGRATION-20260906.md) completed all
94 ordinary goals and 82 selected properties per profile, with independent
readback and no input drift at that input identity. It predates the compiler
provider changes, and its unaccepted statuses are preserved.

Each target explicitly selects one closed frontend policy. ARM32 and m68k
select `no-instrument`, as do ARM64, RISC-V, SH, Alpha, hardware x86-64 and UML;
PowerPC32 selects `patchable-entry-0`. These are checked against the genuine
configured kernel headers, not inferred from the host or
architecture name. Missing or unknown policies fail. See the
[frontend policy](../docs/frontend-policy.md) for the command/artifact gates.

With the existing prepared builds and local toolchain, request a fresh run
from the project root (choose an output directory that does not already exist):

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" python3 -m fragma run \
  --kernel /home/karl/linux-work/linux \
  --target common.unaligned24.arm --target common.unaligned24.powerpc32 \
  --target common.unaligned24.m68k --target common.unaligned24.arm64 \
  --target common.unaligned24.riscv64 --target common.unaligned24.sh \
  --target common.unaligned24.alpha --target common.unaligned24.x86_64 \
  --target common.unaligned24.um-x86_64 \
  --target common.unaligned24.mips32el \
  --output results/common24-new-run \
  --timeout 1 --wall-timeout 600 --jobs 2
```

Use a new output directory for every run. The strategy has its own 1s/5s child
budgets; the global timeout does not replace them. No common24 object is
executed and no installation occurs. Hardware x86 separately builds and runs
the benign model-calibration fixture under its recorded `-O2` context; that is
not execution of the genuine `-Os` common24 object or UML runtime evidence.
No claim covers instrumentation, generated code, kernel callers, traps,
assembly, MMIO or concurrency.
Why3 requires local Unix-socket IPC permission; the successful renewal used a
separately authorized execution environment, without installing packages.

The earlier [ARM32/m68k](../build/common-byte-analysis-work/HANDOFF.md) and
[PowerPC32](../build/common-byte-ppc-analysis-work/HANDOFF.md) diagnostics each
closed 94 ordinary goals and 82 properties per profile, with 12 inconclusive
smoke checks each. Those are dated staged observations, not acceptance of the
new runner inputs. The [compiler-only sensitivity audit](../build/common-byte-calibration-work/AUDIT-20260906.md)
retains 22 fixed observations and 22 individually rejected wrong expectations
per profile. It is not runtime reachability, an ACSL proof, native-provider
evidence or L3 corroboration.

The [next-profile queue](NEXT-PROFILES.md) records these completed ports and
the narrowly reviewed Alpha metadata and genuine size-optimization changes.
Nine dated GCC common24 architecture scopes, the separately renewed s390 pilot,
and the new current MIPS32el scope make eleven documented named architecture
baselines, not eleven fully supported architectures. S390's three WP groups
and mandatory byte-order Eva case are separately rechecked; its runtime and
caller limitations remain. The
[ten unconfigured architectures](../profiles/NEXT-WAVE.md) have separate
toolchain and model prerequisites. Each needs fresh profile-specific gates and
a documented scope decision; availability or registration is not support.
