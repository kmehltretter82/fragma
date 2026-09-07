# Independent native string witnesses

The [native helper](../fragma/native_sensitivity.py) corroborates the eight
[bounded specification-sensitivity cases](STRING-SENSITIVITY.md) by compiling
and executing them on the configured x86-64 host. All inputs are valid API
inputs. The intended negatives are false specifications, not kernel defects.

Current evidence: [native-6 receipt](../build/string-sensitivity/native-6/receipt.json).
All eight executions return normally with exit status 0 and empty stderr.
The 22 named positive properties evaluate true; all eight deliberately false
properties evaluate false. Each run records the complete small array state
and the returned length or pointer offset, as well as named observations.

The original EVA TSV remains `Invalid or unreachable`. A native observation
does not rewrite that status: it is separate evidence that the same bounded
input reaches a named false-spec observation. Neither these witnesses nor the
EVA cases add universally verified kernel functions or automatically promote
an architecture support level.

## What actually executes

The helper compiles the whole, source-gated
[kernel translation-unit copy](string_calibration.c) using the genuine pinned
`lib/string.c` compilation command. All configured compiler flags and real
kernel headers remain present. There are no Frama-C header overrides, trap
substitutions, function-body rewrites, or weakened kernel conditions in this
native object. Only `-ffunction-sections` and `-fdata-sections` are added to
enable removal of unrelated functions at link time.

The configured GCC lowers `__builtin_memcpy` in `strlcat` to inline native
instructions. No substitute copy implementation is supplied. The link retains
`--wrap=memcpy` without a wrapper definition: if this compiler path unexpectedly
needs an external copy, linking fails rather than silently selecting libc.
The real trap guard is compiled and never executed by these valid inputs.

A [linker visibility script](native_sensitivity.symbols) keeps executable
definitions local. This prevents kernel strings from interposing on the hosted
observer's libc and allows unrelated kernel functions to be discarded.
The final symbol table and linker definition traces bind `strlcat`, `strnchr`,
and `strlen` to the exact kernel object. The ELF header confirms an x86-64,
little-endian, non-PIE executable. No relocation or model flags are silently
removed if compilation or linking fails.

The hosted observation adapter is compiled separately with the same relevant
integer/character/wrapping flags, the userspace stack ABI, and explicit layout
assertions. The kernel object keeps its original kernel ABI flags. Its
compiler, assembler/linker components, runtime libraries, host headers, startup
link inputs, generated adapter, objects, executable, and all logs are hashed.

## Original driver identity and bounded translations

The [mapping inventory](../config/string-native-observations.json) pins the
entire original driver hash. The generator inserts observation calls at the
existing ACSL assertion comments and verifies that deleting only the inserted
blocks restores the original driver bytes and C tokens. It does not replace
the original calls, arguments, arrays, or control flow. Changing the driver
requires an explicit mapping review and a fresh native run.

Ordinary side-effect-free predicates are evaluated as C expressions in their
original local scope; ACSL null becomes a C null pointer. Every positive
observation is checked before the next one. A failed positive stops the run,
so a later dependent pointer dereference cannot turn an earlier mismatch into
a falsely successful witness. A matching false-spec observation continues,
and an explicit normal-return marker is required afterwards.

Four logical readability predicates need explicit bounded translations:
three compare the known live local array extent with the requested byte count;
the remaining one observes the known-null pointer. These translations are
justified only by the frozen declarations and preceding observations. They
are not a generic pointer-validity checker. No out-of-bounds pointer or memory
access is evaluated to corroborate the false readability claims.

## Receipt and acceptance interface

`run_native` writes a version-1 `fragma-native-spec-sensitivity` receipt with:

- exact target digests, pinned source gates, driver/specification/mapping and
  generator identities;
- configured model, machine-description, compiler, build/configuration, and
  consumed-input hashes;
- original and effective compile/link/execute commands, symbol owners, binary
  identity, and explicit native deviations;
- per-case source file, line, function, property name, ACSL predicate, native
  expression and translation reason, observed/expected Boolean values,
  bounded state, normal return, process status, stdout and stderr;
- complete artifact hashes and a final input-drift check.

The read-only API is:

```python
validate_native_receipt(root, kernel, target, revision, freshmodel, build,
                        receipt_path)
```

It regenerates the adapter and mappings, rechecks current source/model/build
identity and all recorded files, then parses the actual stdout again. Missing,
duplicate, reordered, malformed, type-confused, mismatching, or nonreturning
events fail. A nonzero process status alone is never a false-spec observation.
Only the explicitly requested matching case is returned in a
`native-specification-calibration` envelope with source locations and tracked
files for the caller's final integrity check.

An integrated evaluator may use that envelope only for an exact named
calibration negative whose raw EVA status is `Invalid or unreachable`, while
preserving that raw status and exposing the separate native observation.
It must still require all positive EVA properties, current source/model and
assumption gates, and ordinary warning policy. This mechanism must not waive
an arbitrary unknown goal, solver timeout, unrelated invalidity, or proof
target. Receipt selection should be explicit, never automatic stale reuse.

These are inspectable local execution records, not cryptographically signed
attestations. As with analyzer reports, arbitrary malicious fabrication of
both artifacts and metadata is outside the local integrity model. Compiler,
hardware, OS/loader, and observation runtime correctness remain trusted.
The result covers these eight concrete executions, not all caller inputs,
large-length wraparound, concurrency, or other architectures.

## Reproduce

Choose a new output directory; the helper refuses to overwrite evidence:

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" python3 -m fragma.native_sensitivity \
  --kernel-tree /path/to/linux \
  --profile "$PWD/build/profile-checks/pointer-policy-final-20260906/x86_64-gcc/profile.json" \
  --output "$PWD/build/string-sensitivity/native-new"

FRAGMA_STRING_NATIVE_RESULTS=build/string-sensitivity/native-new \
  python3 -m unittest tests.test_native_sensitivity
```

`native-1` retained a failed link caused by unrelated exported kernel symbols.
`native-2` through `native-8` are earlier successful development receipts, not
current-input certificates. The [common24 integration refresh](../build/native-refresh-readback-20260906/READBACK.md)
validates `native-9` with the current generator/validator and explicit model.
After further bound-input changes, regenerate into another new directory;
do not copy acceptance or update hashes in a historical receipt.
