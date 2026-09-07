# MIPS32 little-endian C3 IPC implementation mapping — 2026-09-07

Status: one genuine configured SMP MIPS32r2 `ipc/util.o` mapping is accepted
for the existing bounded IPC lifetime property. It is not accepted for the
bounded strong-CAS progress property, and it does not activate a general
Frama-C MIPS machine profile, L1/L2 support or whole-kernel verification.

The current full base is
[`concurrency-c3-ipc-refcount-20260907-13`](../results/concurrency-c3-ipc-refcount-20260907-13/SUMMARY.md).
It passes 1036/1036 checks across eleven architecture profiles. The follow-on
[`concurrency-c3-llsc-progress-20260907-07`](../results/concurrency-c3-llsc-progress-20260907-07/SUMMARY.md)
passes 609/609 checks across eight LL/SC-bearing profiles and promotes zero of
them. Independent byte readback found no mismatch across the base's 91 inputs
and 395 artifacts or the follow-on audit's 22 inputs and 35 artifacts.

## Exact configured route

The profile uses only tools already present on the machine:

- kernel revision `b9b3e33b70b71e516930117e21de3ad2a7723747`, tree
  `054b6818c409ab20ae89b1031a1a7c358f673d87`;
- `ARCH=mips`, `malta_defconfig`, `LLVM=1`, `LLVM_IAS=1` and
  `CC=/usr/bin/clang`;
- Ubuntu Clang/LLVM 21.1.8, compiler target query
  `--target=mipsel-linux-gnu -dumpmachine`, observed as
  `mipsel-unknown-linux-gnu`; and
- LLVM objdump's explicit `--disassemble-symbols=<function>` route.

The final configuration is SHA-256
`a45ad683e9c792341dbd8ae53afbfcd0ac919bcbaa3f34e988ff0b04fc3f7278`.
It requires 32-bit little-endian MIPS32r2, `CONFIG_MIPS_MT_SMP=y`, SMP,
SYSVIPC, tree RCU, `CONFIG_CPU_HAS_SYNC=y`, no LTO and
`CONFIG_CC_IS_CLANG=y`. Both `CONFIG_WEAK_ORDERING` and
`CONFIG_WEAK_REORDERING_BEYOND_LLSC` are absent in this selected build. The
generated object is ELF32 little-endian MIPS (machine 8, O32/MIPS32r2 flags),
12,608 bytes, SHA-256
`bfc8d8134c04b6b892deb8ccf4ccbf451d1435e3fbd13eb60878acbd09b77ff8`.
Its exact Kbuild command record is SHA-256
`3a50e9baf3ed7a327de55118b7992513a1b867c1e39601ef789303d6f828bc4e`.
Both configuration phases and the object build reported no undeclared
diagnostics.

The receipt binds the invoked compiler and disassembler, target-aware query,
Kbuild assignments, generated configuration, command record and emitted
object. As with the other object mappings, it is not a hermetic attestation of
every host dynamic library or LLVM auxiliary binary.

## Lowering and admission decision

The pinned source and emitted object agree on the selected operations:

| Helper | Emitted operation | Relevant decision |
| --- | --- | --- |
| `ipc_rcu_getref()` | MIPS `ll` / compare / `sc` with a failed-SC retry | valid atomic get-unless-zero lifetime mapping; no finite retry bound |
| `ipc_rcu_putref()` | MIPS `ll` / decrement / `sc` with a failed-SC retry and retained `call_rcu` relocation | valid atomic final-put lifetime mapping; no finite retry bound |

The source gate also pins the `kernel_uses_llsc` selection, the configured
`SC_BEQZ=beqz` retry branch, the LL/SC ordering boundary and the MIPS MT Kconfig
path that selects SMP. The lifetime property needs indivisible RMW behavior,
not termination of every possible reservation loop, so the mapping can be
accepted in that bounded scope.

The separate progress property remains restricted to the three checked
single-instruction strong-CAS profiles: native x86-64, s390x and UML x86-64.
MIPS is instead the eighth profile in the fail-closed LL/SC audit. Its source,
accepted object identity and full-object retry control flow all pass, but no
architecture-backed finite store-conditional failure guarantee is bound. The
decision is therefore `not_promoted`; a successful lifetime mapping is not
used as progress evidence.

## Boundaries and next architecture work

This milestone found no new Linux defect. It does not prove scheduler fairness,
lock-free or wait-free progress, RCU grace-period completion, allocator safety,
arbitrary IPC behavior or whole-kernel correctness. It also does not provide
Frama-C target headers or validate MIPS types, layout, bit-fields or compiler
semantics against Eva/WP.

General MIPS support still needs a separately registered LLVM profile (and any
distinct planned GCC profiles), authenticated target-header inputs, machine and
layout generation, parser and calibration gates, then scoped L1 and L2
evidence. Big-endian MIPS and 64-bit MIPS are separate configurations and gain
no support from this little-endian O32 result.

No package was installed, no `sudo` command was used, no target object was
executed and no running kernel was modified.
