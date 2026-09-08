# ARM32 BPF JIT `build_insn()` checkpoint — 2026-09-08

Classification: `partial-no-finding`.

This is the third candidate to enter the frozen recent-risk ARM32 search
funnel. It is architecture-specific code changed in April 2026, not part of
the generic string calibration. The first direct-operation Eva/RTE pass found
no reachable candidate alarm, and 88 concrete JIT results matched their C
oracles under QEMU. This is useful negative evidence, but it does not close
the candidate: source-gated emitter/helper bodies, a live output buffer and
broader BPF conformance coverage remain open.

## Analyzer-first ordering and source identity

The candidate was frozen from commit
`b9b3e33b70b71e516930117e21de3ad2a7723747` before its body was reviewed. The
first usable analyzer result was retained before manual diagnosis. The slice
then passed the function provenance gate against the pinned Git blob:

- source: `arch/arm/net/bpf_jit_32.c`;
- complete named declarator/body: 2,797 tokens;
- token SHA-256:
  `49454fa5f56c2c4d80dcb579384cbaa438f8fcda8f72b9c95a95fd446d5f9aa1`;
- source-file SHA-256:
  `db6a06715406e2277966729b0d65503763ac6ffc4b218dda621ac5046685c42b`;
- the only declared difference is removal of the `static` prefix so the
  separate driver can call the function.

Eleven exact whole-translation-unit attempts stopped in unrelated transitive
headers before completing candidate analysis. The failures progressed through
GNU inferred temporaries, cache-line markers, fortified declarations,
configuration assertions, runtime-indexed `offsetof()` and invalid
return-expression constructs in `dma-mapping.h`. They are retained locally as
frontend/model gaps under `build/arm32-recent-search-20260908/`; temporary
header adapters used to diagnose the boundary were not added to the public
project interface.

## Direct-operation Eva/RTE pass

The compact three-instruction fake-pass driver ranges over every 8-bit opcode,
external BPF registers 0 through 10, every 32-bit immediate, verifier-valid
MOVSX widths and one valid conditional branch. The JIT output pointer is null,
as in the kernel's instruction-counting pass. Emitters, register-transfer
helpers and branch-offset helpers are deliberately inert in this stage.

The final run completed with 197 valid properties, three dead properties and
zero warnings. All reachable direct C operations are valid in this scope. The
three dead properties are the read/alignment/object-pointer obligations for
the `default` arm of an inner `switch (BPF_SRC(code))`; its enclosing cases
admit only the two values handled by the preceding `BPF_X` and `BPF_K` arms.
The report remains `incomplete` rather than converting dead obligations or
modeled dependencies into a verification claim.

Frama-C 33 also exported repeated rows when the same source expression was
reached from several implicit call sites. The report parser now aggregates
same-status selected rows while retaining their exporter row numbers, and
fails closed on conflicting statuses. This run records 12 identical groups,
16 extra exporter rows and zero conflicting groups.

| Artifact | SHA-256 |
| --- | --- |
| Run summary | `64e255c24a83555e0e9973b50a27584164de29a1e22a72919eb6659b098b8604` |
| Target result | `e760a6278a0ba4192af2f28e5fa241f61135ca31455e896767be4d8181d0ff0b` |
| Analyzer log | `144dfcab7842262f80a30a0fa91fb14d6baf6a1f7a00f7010bfe72dce213c1c0` |

Local output:
`build/arm32-recent-search-20260908/build-insn-slice-final-2`.

## QEMU semantic matrix

`harness/arm32_bpf_jit_semantics.c` loads raw socket-filter BPF programs with
the `bpf()` syscall and checks the returned value against an independent C
oracle. It covers LDIMM64 halves, 64-bit register arithmetic, the 0/1/31/32/33/63
shift boundaries, MOVSX widths 8/16/32, signed DIV/MOD including zero and
`INT64_MIN / -1`, every supported signed/unsigned 32/64-bit comparison, and a
64-bit stack store/load.

High halves are exposed through a 64-bit stack store followed by a 32-bit load
at the little-endian high-word offset. They are therefore not observed through
another right shift that could mask paired arithmetic/code-generation errors.

The kernel configuration contains `BPF=y`, `BPF_SYSCALL=y`, `BPF_JIT=y` and
`BPF_JIT_ALWAYS_ON=y`, so a successfully loaded program cannot fall back to
the interpreter. QEMU 10.2.1 ran the ARMv7 kernel on `virt`/Cortex-A15 with
TCG. All 88 checks passed. The subsequent PID-1 exit panic is expected and
occurs after the test summary.

| Artifact | SHA-256 |
| --- | --- |
| Runtime source | `33512d0ac368264230f221faa0c52aa566b011934d5f935e7d7333ec423a53a7` |
| ARM static test binary | `e9d4c07f3232af21b916d03fffa00d5dbbd23cd0d81a9f616cdd15ac412b697e` |
| Initramfs | `ebbbd4e1d0f84953d0c5e35509842c0c1947106250f7ab230af5902059b460fc` |
| Kernel configuration | `7b328f1239b1b04e4e95af25b6cb70a9e15aba9f23fb5c0b64d158cd1484f39f` |
| zImage | `b453107d90006b6b12ca662e8287258020d7a719cc6c690e2171705af375ce08` |
| Full local QEMU log | `f479e4ea5e865c180e0eaaeeaa55d388823b96097dada7e60dbd7ad8561d6837` |
| Tracked result lines | `4a8c8265c69e6e50cc19408ea97e17251f19174da1a41f8a50d09cf65d431e34` |

No kernel bug is claimed from this candidate at this checkpoint. The next
primary target is `__sync_icache_dcache()`, whose April 2026 change fixed a
real `PG_dcache_clean` race and therefore gives Mthread plus Eva a much more
interesting concurrency/state transition than a mature string primitive.

Regression: `python3 -m unittest discover -s tests` passed 1,085 tests with 20
skips. The local log SHA-256 is
`c4ace7b407f2cdcfb9fac7b48b88a2ea91028c0520045e9ddc4c09d1917e20db`.
