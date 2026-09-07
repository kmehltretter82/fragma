# RISC-V BPF JIT signed-left-shift-overflow — VERDICT: NOT A KERNEL BUG

## Final conclusion (after full static + dynamic investigation)
Frama-C proved `rv_i_insn`'s `imm11_0 << 20` is ISO C signed-left-shift
overflow (imm11_0 >= 0x800). That is TRUE under ISO C -- and IRRELEVANT to the
Linux kernel, which does NOT compile under ISO C semantics.

The kernel builds with **`-fno-strict-overflow`** (Makefile:1155), which makes
GCC treat signed overflow -- INCLUDING left-shift overflow -- as defined
(two's-complement wrap). Under that flag GCC:
  * does not consider the shift UB, and
  * omits the `-fsanitize=shift` (shift-base) instrumentation entirely.
So in the real kernel the expression is well-defined, produces the correct
instruction word, and can NEVER trigger UBSAN.

## How this was proven (not assumed)
Userspace, exact rv_i_insn path, gcc-15 -O2:
  * default flags               -> "left shift of 63488 by 20 places ..." FIRES
  * -fno-strict-overflow        -> NO error, correct result (insn=8002829b)
  * -fwrapv                     -> NO error
Kernel, 6 QEMU boots, UBSAN_SHIFT on, a seccomp filter that JITs
`addiw x15,x15,-2048` (== rv_i_insn(0xF800), confirmed in the bpf_jit_enable=2
image dump: bytes `9b 87 07 80`): the overflow expression DID execute, and NO
`shift-out-of-bounds` splat fired -- because GCC never emitted the check.

## Why the earlier "reachable/reportable" assessment was WRONG
  * Frama-C models ISO C; the kernel's -fno-strict-overflow changes the dialect.
  * The fan-out's "reachable via negative immediates" was static reasoning that
    never accounted for the build flags; the runtime repro is what caught it.
  * Precedent commits (cls_u32, fsl_sai, EDAC) fix shift-EXPONENT-too-large
    (a different, genuinely-UB class unaffected by -fno-strict-overflow), not
    shift-base overflow of a nonnegative value. Not comparable.

## Lesson for the fragma rig
To analyze kernel code without this false-positive class, configure WP/EVA to
match `-fno-strict-overflow`: treat signed arithmetic (and shift) overflow as
wrapping rather than UB (Frama-C: `-warn-signed-overflow` off / model signed
ops as modular). Otherwise every `u8/u16 << bigN` in the kernel is a phantom
alarm. The dynamic UBSAN repro is the correct arbiter and should gate any
"signed overflow" finding before it is ever mailed.

## Net
NO patch. NO report. The rig, the Frama-C proof, the fan-out, and the QEMU
UBSAN repro all WORKED -- and together they correctly concluded there is no
kernel bug here. That is the win: the pipeline rejected a false positive
instead of mailing it.
