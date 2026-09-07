# arch/riscv — RTE hunt log (recent code)

Tree: linux-7.2-rc4-clean (byte-identical to rc6 HEAD b9b3e33b70b71 for the
files below), build ~/linux-work/riscv-syz-nolto, riscv64 LP64 -> gcc_x86_64
machdep sound. Method: batch harness including the REAL decode macros.

## traps_misaligned.c decode arithmetic (annotated/insn_decode.sweep.c) — NO BUG

Recently churned file (319fafd9a374, d585018a9258 touched its speed-probe path).
The misaligned load/store handlers decode the faulting instruction to pick
access width, destination register, and sign-extension. Swept the arithmetic
core using the actual macros from arch/riscv/include/asm/insn.h (included, not
transcribed). RTE: **19/19 proved.**

Key results:
  * SECURITY property proved: REG_OFFSET(insn, SH_RD) and REG_OFFSET(insn,
    SH_RS2) are in [0,248] for ANY insn. The register selector is masked to
    REG_MASK (0xF8 on 64-bit), so a malicious instruction's 5-bit reg field
    can never push REG_PTR past pt_regs' 32-register block (offsets 0..248;
    status/badaddr live at >=256). No OOB register read/write.
    [REG_PTR itself casts ulong->pointer, which WP can't track; the integer
     REG_OFFSET bound is the checkable core of the same property.]
  * Load sign-extension `(long)(val << shift) >> shift`, shift =
    8*(sizeof(ulong)-len) with len in {2,4,8} -> shift in {0,32,48}: proved
    never >= 64, no shift-UB. Unsigned variants (LWU/LHU/C.LHU) correctly leave
    shift=0 (zero-extend); signed (LH/C.LH) use 48; verified by manual read.
  * RVC_RS2S(insn) << SH_RD re-encode + INSN_LEN(insn): well-defined for any
    insn (compressed re-encode has low bits 0 => INSN_LEN=2, correct).

Manual audit of both scalar handlers (load lines 220-331, store 333-424):
epc advance, width table, fp routing all correct. Careful code.

## Infra note (RISC-V whole-file parse)
Same __auto_type wall as arm64, here via KCSAN data_race() in rwsem.h (pulled
by mm.h). No clean shim for __auto_type -> batch harness is the path. bits.h
override in riscv/override lets asm/insn.h be included standalone.
