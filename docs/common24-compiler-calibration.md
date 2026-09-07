# Common24 compiler calibration

The nine registered common24 targets explicitly request
`common24-fixed22`. This is a compiler check of the four selected byte helpers,
not a native test, an ACSL proof, or an architecture-support award. The suite
requires it before running their WP analysis. Existing targets without this
setting do not inherit compiler evidence.

## What runs

Each profile uses its checked compiler and genuine configured `lib/string.c`
command. No object or generated kernel program is executed.

| Stage | Commands | Required observation |
| --- | ---: | --- |
| Genuine-header fixture | 1 | Exact types, signatures and selected inline spelling compile; retained ELF data agrees. |
| Fixture controls | 2 | Wrong C type gives exactly five intended static-assert errors; opposite inline policy gives exactly one. Neither produces an object. |
| Fixed-input calibration | 3 | Positive compilation, macro dump and preprocessing succeed without diagnostics. |
| Individual expectation controls | 22 | Each one-bit wrong expectation gives its sole intended error and no object. |

The positive calibration covers both decoding orders, both stores, round trips,
maximum byte values, discarded upper bits and the model's native byte order.
Its local arrays are initialized before reading. The C source is fixed by hash;
the controls change expected facts, not helper bodies or pointer validity.
These finite observations do not replace the full-domain proof contracts.

The genuine base command must contain exactly one `-O2` or `-Os` option.
Hardware x86-64 and UML retain their configured `-Os`; it is not replaced with
`-O2`. Positive macro readback requires `__OPTIMIZE__` exactly once with value
1, and `__OPTIMIZE_SIZE__` exactly once with value 1 for `-Os` or absent for
`-O2`. Conflicting modes, unsupported modes, optimization-macro overrides and
malformed or duplicate macro definitions fail. See the
[wave-three scoped review](../common/REVIEW-WAVE3-20260906.md).

The expected error symbol is derived from the successful positive preprocessed
calibration function before any wrong-expectation command starts. The checker
requires all 22 known case labels in order, canonical unique consecutive symbol
suffixes and exactly one matching direct call per declaration. It does not assume
that kernel headers leave `__COUNTER__` at zero: the configured RISC-V headers
consume two values, so that profile's symbols run from 2 through 23. Negative
diagnostics cannot select their own expected identity. Readback independently
rederives the mapping from checked bytes; malformed positive mappings stop the
run before any negative command. See the [scoped parser review](../common/REVIEW-WAVE2-20260906.md).

The object reader requires a nonempty defined calibration function in a
file-backed executable section and checks ELF table bounds, symbol definitions
and relocations. The narrow ARM unwind-metadata allowance is explicit. Alpha
function metadata is admitted only as exact `0x80`/`0x88` on bounded defined
local/global functions in ELF64 little-endian EM_ALPHA with zero header flags
and nonwritable executable file-backed storage. The required calibration
function remains global. Observations preserve the metadata; mixed visibility,
unknown values, marked weak functions and executable relocations are not added
to the allowed set. Object
metadata and function-byte hashes do not establish instruction semantics,
compiler correctness, runtime reachability or instrumentation behavior.

## Retained evidence

Each target retains sibling `compiler-controls` and `compiler-calibration`
directories. The latter has 25 command records and exactly 52 artifacts besides
its receipt; the former has two command records and four diagnostic streams
besides its receipt. Both record invocation intents before starting commands,
timeouts, outcomes, input hashes and failure information.

The compiler environment is reconstructed exactly: `PATH=/usr/bin:/bin`,
`LC_ALL=C`, `TZ=UTC`, and `TMPDIR` set to the corresponding output directory.
Parent search-path overrides are not inherited. Recomputing an altered
environment's digest does not make it acceptable.

Validation rechecks the current registered target/profile, model-policy audit,
compiler, generated build files, pinned source dependencies, implementation,
positive genuine-header gate, every command and every raw artifact. Input files
must be regular before hashing; artifact and receipt symlinks are rejected.
Missing controls, extra diagnostics, absent objects or conflicting inventories
cannot be replaced by a saved success label.

The normal target's integrity inventory must include the compiler receipts and
all their tracked files. A scoped review must also bind the calibration setting,
environment policy and implementation hashes. Passing compiler checks does not
approve the two common24 assumptions or any frontend/RTE warning. Smoke checks
remain individually reported; inconclusive smoke results are not consistency
proofs.

## Replay boundary

Compiler readback currently requires unchanged current inputs and their original
bound paths. It does not certify arbitrary stale historical receipts or relocate
them automatically. Logical comparison normalizes verified commands and known
paths and excludes transient receipt/model digests, but that normalization does
not bypass current-input validation. Compare fresh independently validated runs;
do not rewrite old receipts into new successes.

Use the [common harness instructions](../common/README.md) for a fresh suite
run. The [first integrated proof run](../common/INTEGRATION-20260906.md) predates
this compiler-provider integration and remains a dated, unaccepted result.
The subsequent [reviewed L2 baselines](../common/L2-20260906.md) pass all three
fresh registered targets, including their own compiler receipts, full proofs,
scoped reviews and retained-evidence replay validation. That combined evidence,
not compiler checks alone, supports the documented four-helper/profile scope.
The [wave-two record](../common/WAVE2-20260906.md) separately retains ARM64,
RISC-V and SH evidence, the initial RISC-V checker failure, and its corrected
fresh run. Provider changes require fresh normal acceptance for the original
profiles as well; old receipts are never rewritten to adopt a new symbol map.
The [six-profile L2 run](../common/L2-WAVE2-20260906.md) supplied that acceptance
at the wave-two identity. The subsequent Alpha/`-Os` provider changes require
another explicit review and fresh acceptance for all nine common24 profiles.
Earlier compiler failures and unaccepted normal runs remain unchanged.
The [nine-profile L2 renewal](../common/L2-WAVE3-20260906.md) now supplies that
fresh acceptance and independently audited replay: all 252 common24
fixture/compiler commands pass alongside the complete proofs. This does not
change the finite-calibration or runtime boundaries.

The enclosing hardware x86 L1 model runner also executes its separate benign
model-calibration program under its recorded `-O2` context. That is not execution
of a common24 calibration object, genuine `-Os` helper runtime corroboration,
UML execution or L3 evidence. The compiler-only stages described here execute
no generated objects.
