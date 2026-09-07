# Hexagon LLVM compiler-build milestone

2026-09-06, pinned Linux `b9b3e33b70b71e516930117e21de3ad2a7723747`.
The first genuine Hexagon compiler-build check passed. This is **not L1**, a
new configured registry profile, a whole-kernel build or target execution.
The registry remains ten configured profiles and eleven planned families.

## Delivered and verified

The opt-in [LLVM provider](../fragma/llvm_build.py), called by the existing
[build helper](../fragma/build.py), supports one explicit diagnostic route:
Clang/LLVM 21.1.8, Hexagon v68, integrated assembler. Its specification pins
all eleven target/host tool roles, their invocation aliases, resolved paths,
versions and binary hashes. Host linking uses the explicitly selected LLD
alias. Requested `hexagon-linux-musl` and observed
`hexagon-unknown-linux-musl` remain separate target-aware identities.
The existing GCC path and its command spelling are preserved.

The LLVM environment removes ambient header and make-flag injections. Readback
requires the exact configured CPU, source/cwd/output, retained Kbuild command,
target/CPU and kernel flags, and a bounded ELF32 little-endian Hexagon
relocatable container. Only Kbuild's exact dependency-only preprocessor
forwarding is admitted; conflicting selectors, response files, changed tools
and symlinked evidence artifacts fail. ELF tables are checked, not machine
instructions, relocation semantics or ABI execution. Unsupported versions,
targets and tool-path spellings require separate work, not fallback.

The [fresh run](../build/hexagon-llvm-bringup-20260906/run-1/result.json)
completed at 19:50:18 UTC. All three commands returned zero:

1. Genuine `olddefconfig`, using the retained minimal explicit v68 seed.
2. Genuine `make -j4 prepare lib/string.o` with the same pinned LLVM suite.
3. The pinned kernel's compilation-database generator.

This is not an unchanged `comet_defconfig` build. The resulting configuration
has Comet/MMU, SMP disabled, one CPU and 4-KiB pages. The actual string command
uses `-O2`, `--target=hexagon-linux-musl`, `-mv68`, `-nostdinc` and the original
kernel include/semantic flags. The object reports machine 164 and ELF flags
`0x68`; these observations do not establish an ISA or a runnable system.

The [independent build audit](../build/hexagon-llvm-build-audit-20260906/REPORT.md)
rechecks 1,496 run hashes, 434 retained regular files and 760 canonical source
files against the pinned Git blobs, with no new-run drift. The initial auditor
mistakenly compared 817 textual path aliases against canonical paths; its
failure and original checker remain preserved beside the corrected successful
audit. Source checks cover explicit snapshot paths in retained commands, not
a hermetic whole-build dependency closure.

All [647 regression tests](../results/tests-hexagon-llvm-build-20260906.log)
pass in 76.123 seconds, without skips. The 37 new tests comprise 20 LLVM gates
and 17 build integration/GCC compatibility tests, all with mocked external
commands. The [exact-command sidecar](../results/tests-hexagon-llvm-build-20260906.json)
records the stripped environment and explicit retained-evidence paths.

## Reproduce only the compiler-build check

From this workspace, choose a fresh run number:

```sh
env -i PATH=/usr/bin:/bin LANG=C PYTHONDONTWRITEBYTECODE=1 \
  python3 build/hexagon-llvm-bringup-20260906/run.py run-2
```

The [driver](../build/hexagon-llvm-bringup-20260906/run.py) refuses existing
outputs and checks the frozen prerequisite inventory. Its candidate is
deliberately outside `config/profiles.json`; ordinary profile/model commands
do not acquire Hexagon support from this build. No installation or `sudo` is
needed on the inspected machine. Kernel preparation builds and runs benign
host configuration tools; none of the generated Hexagon objects is executed.
No analyzer, proof or historical fault/trap/OOB harness was run for this step.

## Still required before Hexagon L1

- [ ] Select and pin a genuine Hexagon generator-header source, or explicitly
  review a distinct kernel-oriented generator adapter with no libc/runtime
  compatibility claim. The upstream musl 1.2.5 archive has no Hexagon port;
  LLVM builtin headers, the RISC-V sysroot and host Newlib are not validated
  substitutes. Bind archive, receipt, full header inventory and resource
  headers as absolute path/hash records.
- [ ] Extend toolchain inventory and model checks with family-specific version
  and target queries. Carry target/CPU flags through every generator, macro,
  fixture and standalone-preprocessor command. Do not use Clang's host default
  triple or GCC-only runtime-component discovery.
- [ ] Generate a complete warning-free machine description; independently
  check scalar/type/layout/alignment/endian behavior, wrong-model controls,
  genuine kernel headers and the actual analyzer pointer policy. No hand-filled
  machine fields or assumed alignments.
- [ ] Activate a separately identified profile only after fresh L1 gates;
  subsequently add scoped source/proof/calibration/review gates for L2.
- [ ] Resolve broader CPU/kernel compatibility separately. The upstream default
  is v2, which installed Clang rejects; silently dropping `-mv2` is not v2
  support. Modern configuration values also lack `ELF_CORE_EFLAGS` branches
  used by `ptrace.c` in this pin. The successful object scope does not repair
  that wider build limitation.

The [readiness audit](../build/hexagon-readiness-audit-20260906/REPORT.md)
records the source and empty-input evidence behind these boundaries.

## Existing-proof freshness

Changing the shared build helper changes a recorded input of the earlier
nine-profile runs. Their accepted dated results and scoped reviews are retained,
but current identity acceptance requires fresh runs. The
[new coverage matrix](../results/coverage-hexagon-llvm-build-20260906/coverage.md)
therefore reports zero accepted-current, 25 accepted-stale and six legacy
nonpasses across 31 targets and 24 distinct kernel functions. All ten standalone
model observations remain current L1; all thirteen dated model observations
are stale. Hexagon remains planned with no model or proof target.

The [coverage audit](../build/hexagon-llvm-coverage-audit-20260906/README.md)
checks all 3,697 generation inputs and 489 current-report artifact references
(468 unique paths), without drift. This is an inventory/freshness audit, not
renewed proof replay. No earlier receipt, review or dated L2 report was rewritten.
