# Reviewed string contracts

This is a new, separate specification variant for Linux revision
`b9b3e33b70b71e516930117e21de3ad2a7723747`, configured `x86_64-gcc` only.
The historical `string.acsl.c`, `string.eva.c` and `specs.h` are unchanged.
`string.verified.c` is the complete pinned `lib/string.c` plus ACSL comments:
the whole-translation-unit token hash is
`76eeed733c04e8f1f133dfda2cc9061985b4e35e79b4ec82fbbd17dbd6ae5d2d`.
Both function bodies and declaration prefixes pass the pinned source gate.

The contracts prove sequential C properties under the listed input, frontend,
machine and external-function assumptions. They do not prove kernel callers,
architecture assembly implementations, concurrency, a different configuration,
or arbitrary trap behavior. Reviewed assumptions are not implementation proofs.

## What `strlcat` guarantees

Let `d` and `n` be the first-NUL lengths of the original destination and source,
and `capacity` the original count. The accepted domain requires positive
writable capacity, `d < capacity`, a readable source through its first NUL, and
separation between the source string and the entire destination capacity.
These are caller obligations; no kernel caller has been verified here.

With `copied = min(n, capacity - d - 1)`, the postconditions establish:

- The returned attempted length is `(unsigned long)(d + n)`.
- Every byte before the original destination NUL is preserved.
- Exactly the first `copied` source bytes occur after that preserved prefix.
- The first resulting NUL is at `d + copied`, inside capacity.
- No memory outside the destination capacity is modified.

The cast in the return contract is deliberate. On this checked 64-bit profile,
the returned value is the mathematical sum modulo `2^64`; it equals the sum
without reduction when the sum fits. There is no artificial no-overflow bound
on the sum of two independent lengths. Each individual string length is less
than `SIZE_MAX`, leaving storage for its terminator. The resulting output
length is bounded by `capacity - 1` and does not wrap.

The `BUG_ON(dsize >= count)` condition is excluded by this valid API domain and
the assumed exact `strlen` result. The contract does not convert the kernel's
guard into a permissive userspace-style `strlcat` contract for an unterminated
or undersized destination. The historical weakened-domain and deliberately
false contracts remain separate calibration experiments.

All local assertions are proved obligations, not admitted lemmas. The
first-NUL predicate and minimum function are definitions, not axioms. The
initial proof of the exact resulting first-NUL length timed out until explicit
length-uniqueness and copied/nonzero-prefix assertions exposed the intermediate
facts; those intermediate assertions now prove independently too.

## What `strnchr` accepts

`fragma_scan_readable` admits zero count without any readable object (including
a null pointer). For positive count, either the whole count-byte range is
readable, or a shorter readable prefix contains a NUL. This broadens the old
full-count-readable precondition while proving every actual byte access.

The result is the first matching byte after the C conversion `(char)c`, before
count exhaustion or an earlier NUL. Searching for NUL is supported: comparison
precedes the early-termination check, so a converted zero returns the NUL's
address. The checked kernel compiler uses unsigned plain `char`; the model
preserves that conversion, including integer arguments outside `[0,255]`.
Zero count returns null and dereferences nothing, despite the C unsigned
post-decrement of count wrapping when its old value is zero.

One intentional domain restriction remains: a buffer with neither count
readable bytes nor a readable NUL prefix is not admitted merely because an
early non-NUL match would stop this particular call. A character-dependent
minimum-access domain could be specified later; it has not been claimed here.
The `\from` clause gives an overapproximate result-dependency range, not a
requirement that every byte in that range is accessed or an information-flow
certificate. Memory framing, all functional properties, loop invariants,
termination and actual reads are the proved claims.

## Trusted calls and exceptional control flow

`specs.verified.h` makes the following modular assumptions explicit:

- `strlen` terminates, writes nothing, and returns the first-NUL length for a
  readable string. Its generic C body is present in this configured TU but is
  not selected for proof. Its implementation correctness remains trusted.
- `memcpy` terminates, copies the exact prestate source bytes into a writable
  disjoint destination, preserves memory outside its footprint, and returns
  the destination. Empty ranges allow zero-byte copies without dereferences.
  Its architecture implementation is not proved by this analysis.
- The replacement `fragma_unreachable` may diverge: `terminates \false`,
  `exits \false`, `ensures \false`, `assigns \nothing`. This combination is
  consistent; it does not simultaneously demand termination and forbid all
  exits. Nevertheless it is only accepted here because the call is proved
  unreachable, not as an implementation-equivalent model of a real trap.

The selected `.config` has `CONFIG_BUG=n`. Importantly, the existing x86 header
override unconditionally replaces the architecture `BUG()` body, even in that
configuration. Its removal of UD2 is therefore reviewed on the proved-dead
`strlcat` path only. Possible trap handlers, externally visible effects,
abnormal termination, or different configurations remain outside this proof.

The whole-TU report includes unknown global `strlen`/`memcpy` preconditions:
their unselected callers are not analysed. Every precondition instance at the
two selected `strlen` calls and the selected `memcpy` call is `Valid`. These
global rows must not be mistaken for proved implementations or silently
reclassified as proved caller coverage.

## Exact smoke and diagnostic reviews

In the fresh native-preprocessing run, two smoke goals report the same unreachable guard
statement at `string.verified.c:274`:

- `typed_fragma_unreachable_wp_smoke_dead_call_s4355`
- `typed_strlcat_wp_smoke_dead_code_s4355`

Both are individually reviewed in `config/string-verified-targets.json`, bound
to the source, specification and build hashes. The first-NUL uniqueness and
destination-fits facts imply the guard is false before any assumed trap
postcondition can be used. Target termination also proves. The associated TSV
row has function `fragma_unreachable`, kind `user assertion`, text `\false`,
and the ambiguous status `Invalid or unreachable`; it is smoke/dead-path
evidence, not a kernel defect or a proved ordinary property. No other failed
smoke test is waived. Smoke timeouts mean only that no contradiction was found,
not that specification consistency was proved.

The following global WP diagnostics have target-specific reviews:

- Skipped alignment guards: actual selected-function accesses and the modeled
  copy footprint are bytes with alignment one. No multibyte access is covered.
- Skipped function-pointer guards: there are no indirect calls in the selected
  bodies. The only direct calls are the three models listed above.
- Signed-overflow option warning and `Missing RTE guards`: the real compiler's
  `-fno-strict-overflow` is reflected in the calibrated profile flags. These
  bodies perform size arithmetic in unsigned long and no signed arithmetic
  needing an overflow guard. Unsigned wrap/conversion is intentional. All
  emitted memory guards prove; no division or shift operations are present.

Other frontend diagnostics are retained. Their exact affected symbols were
reviewed against the selected call closure, not assumed supported globally:

| Diagnostic | Scope checked |
| --- | --- |
| `__gnu_inline__` ignored | `offset_to_ptr` and header inline declarations; not the selected global function bodies. |
| `nocf_check` ignored | IBT declarations such as `is_endbr`; not called. |
| `__alloc_size__` ignored | User-copy allocation declarations; not called. |
| `__error__` ignored | Wrong-size cmpxchg diagnostic declarations; not called. |
| `__externally_visible__` ignored | Unselected `memcmp` definition. |
| Unexpected statement attribute `cold` | Branch-layout hint; the selected BUG branch is independently dead. No C memory/control-flow operation is removed by ignoring a cold hint. |
| Undeclared `__builtin_{mul,add,sub}_overflow` | Unselected `size_mul`, `size_add`, `size_sub` helpers. |
| Undeclared `__builtin_clz`, `clzl`, `clzll`, `ctzl` | Unselected bitops/scheduler helpers. |
| Implicit void-pointer conversions | Unselected little-endian bitops wrappers. |

The compatibility `asm_inline` spelling and C23-to-`typeof` changes occur in
unselected assembly/memset helpers. Command-line `__signed__` removal is not a
general signed-type equivalence assertion: the selected declarations use plain
char, int and unsigned-long size_t, whose identities are independently checked.
Builtin copy substitution and the unreachable replacement have separate models.
Changing the selected functions, configuration, preprocessing command or
consumed headers requires a new review; this is not a blanket warning filter.

## Fresh evidence and remaining work

`build/string-verified/final/strnchr` and `.../strlcat` contain the durable
preprocessed inputs, complete commands, logs, WP JSON, consolidated property
TSV, and receipts. Each receipt includes 146 consumed-file hashes, actual
kernel build/compiler flags and a passing pinned whole-TU source gate. The
mutable kernel checkout differs from the pinned revision; preprocessing uses
the checked immutable snapshot, not that checkout.

| Selected function | Ordinary valid WP goals | Selected TSV rows, all Valid | Smoke evidence |
| --- | ---: | ---: | --- |
| `strnchr` | 47/47 | 18 | 5 inconclusive |
| `strlcat` | 59/59 | 23 | 8 inconclusive; 2 individually reviewed dead-path findings |

These are fresh runs with `-wp-cache none` before the `-then -report` phase,
`-wp-rte -wp-split`, the generated configured x86-64 machine model, the profile's
arithmetic flags, and explicit Alt-Ergo 2.6.3 / Z3 4.13.4 via the isolated
verified toolchain. The analysis process and preprocessing each exit zero.
Do not use WP's combined printed goal fraction as the ordinary proof count;
it mixes smoke/termination bookkeeping with ordinary goals.

CVC5 is intentionally not in these commands: its standalone Why3 calibration
passes, but the attempted Frama-C WP integration emitted `anomaly: Not_found`.
That integration issue remains open and must not be hidden by portfolio
success. The earlier exploratory evidence is retained separately under
`build/string-verified/initial` and `refined1`.

The target manifest still requires root-level dependency, model, toolchain,
warning-review and source-hash gates. Passing these selected goals alone is not
a complete suite certificate. Caller proofs and controlled property-sensitivity
calibrations are separate work; this document does not mark all of PLAN phase 3
complete. No claimed portability follows from an x86-64-only proof.

### Native annotation preprocessing review

The integrated runner now invokes Frama-C native `-pp-annot`, not just the
compiler-only `.i` used by the first proof. The separate fresh run under
`build/string-verified/native-review` checked this change with the complete
target compiler command and retained Frama-C's actual `.pp` stream. Its
`equivalence.json` records exact C-token/declaration equality for `strnchr`,
`strlcat` and the modular `strlen` body against the preceding proof input.
All selected consolidated property formulas are unchanged; all 106 ordinary
goals and all 41 selected property rows still prove. The smoke statement ID
changes from `s4354` to `s4355`, so the manifest names only the newly observed
IDs instead of weakening ID matching.

`review_context.preprocessing` binds the exact compiler command, native
annotation mode, input mode and extra arguments. Existing compiler macro
redefinition diagnostics from annotation preprocessing are not automatically
waived by this command-equivalence check. They remain visible and require any
additional warning-policy review individually. The compiler-only `input.i`
remains an audit comparison artifact; it is not called the analyzer's input.
