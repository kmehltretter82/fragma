# ARM64 cpuid scalar-helper review

Scope: the existing `arm64.cpuid` runtime-safety contract variant, pinned Linux
`b9b3e33b70b71e516930117e21de3ad2a7723747`, configured `arm64-gcc` LP64
little-endian profile, GCC 15.2.0, and Frama-C 33 Typed integer model. No kernel
caller coverage, full architecture support level, native runtime result, or
new functional contract is claimed. The existing harness and its C tokens,
contracts, function-pointer declarations and full argument domains are unchanged.

## Source and concrete model checks

The original source file is `arch/arm64/include/asm/cpufeature.h`, SHA-256
`e292d3d4aa4da4293cd0244b692abc033104e117b40260c266d4894d41eb34af`.
The existing harness has SHA-256
`0642417abb3e112498f8779ca60bb9788409160a2669d7a28f297b8fab0bc41a`.
The baseline source gate confirms identical named declarators and complete
function bodies. It explicitly reports the omitted `inline`, `__always_inline`
and `__attribute_const__` declaration modifiers; they are not silently treated
as equal declarations.

`annotated/cpuid-kernel-model-check.c` includes real `<linux/types.h>` and
`<asm/cpufeature.h>`, compiled using the configured kernel's genuine
`lib/string.c` argument vector, with `-Werror` and dependency recording. It does
not include harness typedefs or substitute kernel headers. `fixture-2/receipt.json`
records successful compilation, an empty diagnostic log, and 197 consumed input
records. Every source-tree header is compared with the pinned Git blob; generated
headers remain tied to the actual configured build receipt.

The fixture verifies exact `u64 == unsigned long long` and
`s64 == signed long long` type identity, their 64-bit widths, 32-bit `int` and
`unsigned int`, the type of literal `64`, both real function signatures, and the
exact current inline/always-inline/const macro expansions. The first diagnostic
attempt in `fixture-1/kernel-model.log` rejected signatures that omitted the
const function attribute. The successful fixture preserves that attribute in
the expected signature: this is evidence for explicitly reviewing its omission,
not a reason to weaken signature checking.

Compiler constant-expression checks also cover signed high-bit conversion,
arithmetic right shifts of negative `s64`, and signed/unsigned narrowing into
the 32-bit return types. These are implementation-model checks, not a universal
proof of the compiler and not execution on an ARM64 processor. The independently
generated ARM64 machine description and profile arithmetic checks are required;
the historical harness comment claiming x86 width equivalence is not used.

## Guard and declaration reasoning

The domain is exactly `width >= 1`, `field >= 0`, and mathematical
`field + width <= 64`. Therefore `1 <= width <= 64`, `0 <= field <= 63`,
`0 <= 64-width <= 63`, and `0 <= 64-width-field <= 63`. Both integer
subtractions are representable in the configured 32-bit `int`. All feature
values retain their complete `u64` domain. There is no extra `width <= 32`
restriction, despite the 32-bit return types.

The first shift's operand is unsigned `u64` in both helpers, so there is no
signed left-shift operation. The signed helper then converts to `s64` and
right-shifts according to the selected GCC/Frama-C arithmetic-right-shift model;
its eventual `int` return conversion is modelled, not assumed value-preserving.
The unsigned helper narrows to `unsigned int` modulo its width. Neither function
dereferences a pointer, accesses an object, calls another function, divides,
allocates, loops, traps or uses inline assembly. Global function-pointer
initializers take addresses only; they do not constitute indirect calls.

The omitted inline/always-inline/const modifiers concern optimizer/linkage
metadata for these pure scalar leaves. The body-level proof does not claim
machine-code equivalence, function-address identity, instrumentation behavior,
or preservation under arbitrary linking. Exact parameter and return types are
checked with the real declarations; the limited sequential body semantics and
absence of effects are visible directly and supported by assigns proofs.

Consequently the four exact global WP warnings can be narrowly reviewed for
these two selected functions: alignment and function-pointer guards have no
applicable operations, signed-overflow omission is covered by the explicit
count bounds and unsigned left shifts, and the umbrella missing-guards warning
is restricted to those reviewed causes. No unknown frontend attribute diagnostic
is waived because the current standalone harness emits none.

## Proof evidence and outstanding sensitivity work

The full baseline receipt at
`results/all-registered-baseline-20260906/arm64.cpuid/result.json` retains all
6 ordinary WP goals Valid (four shift guards and two assigns properties), all
10 selected TSV properties Valid, and no unresolved dependencies. Two smoke
attempts remain inconclusive; this is not a consistency proof. A concrete valid
domain witness is `(features=0, field=0, width=1)`. The baseline overall status
was unsupported because its assumption was pending and the warnings lacked
scoped reviews, not because any of these ordinary obligations was unresolved.

The registered target retains the existing `arm64.cpuid` ID and unchanged
harness. Its two scoped assumptions and four exact warning reviews are in
[the target manifest](../config/arm64-cpuid-targets.json). The real-header
[compiler fixture](annotated/cpuid-kernel-model-check.c) runs as a required
integrated gate; it is not substituted for the kernel implementation.

The staged candidate and compiler-negative receipts remain dated review
evidence under `build/arm64-cpuid-review/`. Promotion of metadata alone grants
no acceptance: a fresh run must pass source, configured model, fixture,
assumption, raw proof/dependency and final input-integrity checks together.
Use `python3 -m fragma run --target arm64.cpuid` and consult the resulting
summary. Current run status is recorded separately in [PROGRESS.md](../PROGRESS.md)
so updating status cannot silently change the reviewed inputs.

Helper-specific sensitivity calibration is still missing. The existing generic
profile arithmetic fixtures do not establish discrimination of these helpers'
bit extraction or 64-to-32-bit return conversion. A useful next bounded batch
would retain exact helper bodies and valid inputs, checking:

- `features=1ULL<<63, field=63, width=1`: signed -1 and unsigned 1;
- `features=0x80000000ULL, field=0, width=32`: signed INT_MIN and unsigned
  0x80000000;
- `features=~0ULL, field=0, width=64`: signed -1 and unsigned UINT_MAX;
- a zero field and an ordinary four-bit field away from bit zero.

Each case should have named positive assertions and one deliberately false
specification on the same valid execution, with independent exact observation
mapping when EVA's terminal false row is `Invalid or unreachable`. No invalid
shift, weakened precondition, defect reproducer, or inferred kernel bug is needed.
That batch would be specification/model calibration, not universal functional
proof or caller-precondition coverage. Historical manual caller notes are not
promoted to proved caller coverage by this review.
