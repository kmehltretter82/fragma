# Independent s390 byte-order specification calibration

This optional witness corroborates two concrete assertions in the existing
`calibration.s390.byte-order.eva` target. It is not a universal proof, a kernel
defect report, an assembly proof, or certification of a complete architecture.
The only input is the valid three-byte array `{0x12, 0x34, 0x56}`. The actual
kernel helper returns `0x123456`; `decoded_be24` is observed true and the
deliberately false specification `byte_order_REFUTED` is observed false. Both
observations are reached, followed by normal process return with exit status 0.
An error exit, crash, timeout, missing event, or unreachable EVA assertion is
never substituted for the false-specification observation.

## Exact scope and separately trusted components

`fragma/s390_sensitivity.py` checks the original helper body against pinned
kernel revision `b9b3e33b70b71e516930117e21de3ad2a7723747`. The existing harness
and its two ACSL assertions are unchanged. A generated adapter adds narrowly
reviewed, side-effect-free scalar observations immediately after the assertions;
erasing only its tagged insertions must recover the original harness bytes and
tokens. The complete harness hash, exact entry-function token sequence, property
names, source lines, expected values, and input are bound by the observation map.
This is a fixed translation of those two predicates, not an ACSL interpreter.

The helper object uses the genuine configured s390 kernel compile command and
headers, including `-march=z13`, `-mpacked-stack`, `-mbackchain`, `-msoft-float`,
unsigned plain char, kernel arithmetic flags, and expoline mitigation flags.
The existing real-kernel type/model check is compiled with `-Werror`. Explicit
extra isolation flags disable inlining and two interprocedural optimizations and
enable per-function/data sections; they do not replace the original optimization,
ABI, arithmetic, or mitigation flags. This is not an unchanged optimization
pipeline. Link-time section collection removes unrelated functions.

The unchanged pinned `arch/s390/lib/expoline.S` is compiled with the genuine
kernel context plus `__ASSEMBLY__` and linked as separately trusted native
compiler/backend support. Its exact source and consumed headers are recorded.
Its actual return thunk must resolve from that object and appear in the runtime
execution trace. No theorem about the assembly is claimed.

The hosted observer is a separate translation unit. Its ordinary unpacked,
no-backchain stack frames are explicit; only integer/pointer arguments cross to
the kernel-flag object. The observer retains the scalar model flags but uses
hosted headers and the cross toolchain's static target CRT/libc. Complete consumed
header and static link-input inventories, including whole archive hashes, are
retained. The compiler, linker, static libc, emulator and host remain trusted.

## Requested z13 versus executed max CPU

The locally installed, hash-pinned QEMU user-mode binary is version 10.2.1. Its
CPU list advertises `z13`, but requesting that exact CPU fails before the guest
starts because this QEMU configuration lacks several requested facilities.
`build/s390-sensitivity/native-probe-3` preserves the initial failed attempt.
Every completed receipt repeats the exact `z13` startup check on the same guest
binary and retains its command, exit status, empty stdout and diagnostic.

The bounded witness instead executes explicitly with `-cpu max`, a different
supported QEMU model. Receipts distinguish `requested_cpu: z13`,
`compiler_cpu: z13`, and executed `cpu: max`. This is not full z13 emulation and
does not validate unrelated cryptographic, decimal-floating-point, timing, or
system facilities. It does not automatically promote an entire profile level.

The retained helper executes scalar byte loads, shifts, bit-selection/OR
operations, and a branch to the original return thunk. Its complete instruction
bytes must agree between the ELF executable segment, target disassembly, and
QEMU's actually entered translation block. The entry's direct call to the helper
and executed entries for the observer, calibration entry, helper, and backend
thunk are checked separately; symbol presence alone is insufficient.

A separate volatile native-memory observation stores the integer `0x01020304`
and reads bytes `[1, 2, 3, 4]`. That checks actual guest big-endian layout rather
than inferring native byte order from the helper's explicit-byte arithmetic.

## Reproduction and acceptance

After explicit local setup of the existing pinned cross compiler and optional
QEMU runtime, no sudo, system package installation or binfmt registration is
needed. The kernel checkout remains read-only and all outputs use a new directory.

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" python3 -m fragma.s390_sensitivity \
  --kernel-tree /home/karl/linux-work/linux \
  --profile-receipt "$PWD/build/profile-checks/pointer-policy-final-20260906/s390x-gcc/profile.json" \
  --output build/s390-sensitivity/native-new
FRAGMA_S390_NATIVE_RESULTS=build/s390-sensitivity/native-new \
  python3 -m unittest tests.test_s390_sensitivity -v
```

Choose an unused output directory. The [common24 integration refresh](../build/native-refresh-readback-20260906/READBACK.md)
records `native-5`; earlier receipts remain dated evidence. Further changes to
bound inputs require regeneration and validation, not rehashing an old receipt.

`validate_native_receipt(root, kernel, target, revision, freshmodel, build,
receipt_path)` performs read-only current-input validation. It reconstructs the
adapter and exact command plan, repeats source/body and dependency hash checks,
compares the current genuine build and freshly calibrated machine model, checks
every retained artifact and complete dependency inventory, and revalidates the
ordered JSON observations and instruction evidence. Malformed JSON, duplicate
keys, non-finite numbers, Boolean/integer/float confusion, omitted inventory
entries, changed inputs and contradictory command metadata fail closed. These
local receipts are not signed execution attestations.

The returned `native-specification-calibration` envelope includes exact target,
profile, kernel source/revision, entry, target digest, receipt hash, and property
file/line/function/predicate/expected/observed/reached bindings. Runtime metadata
includes the requested/executed CPU distinction, rejected-z13 diagnostic, ELF
identity, instruction trace evidence and native layout. Every consumed input and
artifact appears in `tracked_files` for a final drift check by the caller.

The suite must validate an explicitly supplied receipt against its fresh model
and proof inputs. Native evidence can corroborate only this exact reached false
predicate; it cannot mask a positive-property failure, another unresolved goal,
or a tool error. Raw EVA statuses remain unchanged, including its ambiguous
`Invalid or unreachable` label. Independent corroboration is reported separately.
