# LoongArch64 C3 IPC implementation mapping — 2026-09-07

Status: one genuine configured SMP LoongArch64 `ipc/util.o` mapping is accepted
for the existing bounded IPC lifetime property. It is not accepted for the
bounded strong-CAS progress property, and it does not activate a general
Frama-C LoongArch machine profile, L1/L2 support or whole-kernel verification.

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
- `ARCH=loongarch`, `loongson64_defconfig`, `LLVM=1`, `LLVM_IAS=1` and
  `CC=/usr/bin/clang`;
- Ubuntu Clang/LLVM 21.1.8, compiler target query
  `--target=loongarch64-linux-gnusf -dumpmachine`, observed as
  `loongarch64-unknown-linux-gnusf`; and
- LLVM objdump's explicit `--disassemble-symbols=<function>` route.

The final configuration is SHA-256
`61662dbfd894d861f1a31bc1f9fdaafd4e74c34297a57ce583c3e8686e6c066e`.
It requires `CONFIG_LOONGARCH=y`, 64-bit Loongson, SMP, SYSVIPC, tree/preempt
RCU, `CONFIG_CPU_HAS_AMO=y`, `CONFIG_AS_HAS_SCQ_EXTENSION=y`, no LTO and
`CONFIG_CC_IS_CLANG=y`. The generated object is ELF64 little-endian LoongArch
(machine 258, soft-float object ABI), 24,232 bytes, SHA-256
`dfaec38ff50e09786c0b50fcada8fe33c0d76e1b432bc4624eb79b018921d96a`.
Both build phases and the object build reported no undeclared diagnostics.
The receipt binds the invoked compiler and disassembler plus the exact emitted
object; it is not a hermetic attestation of every host dynamic library or LLVM
auxiliary binary.

Schema 6 makes the Kbuild assignments, target-aware compiler query arguments
and per-objdump named-symbol option explicit for every profile. The nine GNU
profiles retain empty target arguments, empty extra Kbuild assignments and GNU
`--disassemble=<function>`; LoongArch and the later MIPS32 mapping use distinct
LLVM routes. This is an additive interface, not a silent global switch to LLVM.

## Lowering and admission decision

The pinned source and emitted object agree on the selected operations:

| Helper | Emitted operation | Relevant decision |
| --- | --- | --- |
| `ipc_rcu_getref()` | `ll.w` / compare / `sc.w` with a failed-SC retry, then `dbar 1792` | valid atomic get-unless-zero lifetime mapping; no finite retry bound |
| `ipc_rcu_putref()` | `amadd_db.w` decrement, successful-path `dbar 21`, `call_rcu` relocation | valid atomic final-put lifetime mapping |

The lifetime property needs indivisible RMW behavior, not termination of every
possible reservation loop, so this implementation mapping can be accepted in
that bounded scope. The separate progress property is restricted to the three
already checked single-instruction strong-CAS profiles: native x86-64, s390x
and UML x86-64. LoongArch is instead added to the fail-closed LL/SC audit. Its
source, accepted object identity and full-object retry control flow all pass,
but no architecture-backed finite store-conditional failure guarantee is
present. The decision is therefore `not_promoted`.

## Boundaries and next architecture work

This milestone found no new Linux defect. It does not prove scheduler fairness,
lock-free or wait-free progress, RCU grace-period completion, allocator safety,
arbitrary IPC behavior or whole-kernel correctness. It also does not provide
Frama-C target headers or validate LoongArch types/layout against Eva/WP.

General LoongArch support still needs a separately registered Clang profile (or
the independently planned GCC profile), authenticated target-header inputs,
machine/type/layout generation, parser and calibration gates, then scoped L1
and L2 evidence. Other Linux architectures remain in the queue; this one
successful translation-unit mapping must not be counted as all-architecture
completion. The later [MIPS mapping](CONCURRENCY-C3-MIPS-20260907.md) is a
separate object-level result and does not broaden this LoongArch claim.

No package was installed, no `sudo` command was used, no target object was
executed and no running kernel was modified.
