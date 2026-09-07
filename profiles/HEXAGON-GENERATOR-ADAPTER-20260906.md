# Hexagon generator adapter: complete extraction, alignment gate closed

2026-09-06. The [adapter](../fragma/hexagon_machdep.py) consumes the
[authenticated headers](HEXAGON-HEADER-PROVISION-20260906.md) and extracts a
complete candidate from the pinned compiler. Its actual result is
**blocked-object-alignment**, not L1 or an activated profile. No Linux kernel
bug is claimed.

## Reviewed changes

The installed Frama-C helper, schema and all 67 original C/header probes remain
unchanged. Their exact hashes are checked before use. The adapter reads the
pinned helper's 52-entry standard probe inventory without executing that Python
helper, then makes a separate retained copy. Only three sources change, with
the complete [patch](../build/hexagon-generator-adapter-20260906/run-1/probe-changes.patch)
retained:

- `sanity_check.c` returns zero explicitly, including under `-ffreestanding`.
- `wordsize.c` emits an explicit marker when `__WORDSIZE` is undefined.
  An empty field is accepted only from that successful observation, never from
  a failed/missing probe. No macro or pointer width is injected.
- `max_align_t.c` gives its aligned-16 fallback struct a distinct tag. The
  original probe had an unintended redefinition error alongside legitimate
  assertion failures; checking only warnings would have missed that error.

All eight macro probes and the final predefined-macro query now omit `-c`.
Target, CPU, freestanding, short-wchar and header-selection flags are preserved.
Includes remain target musl first, then pinned Clang resources under `-nostdinc`,
with the explicit POSIX feature macro.

Values must come from the expected primary assertion diagnostic, not a source
excerpt or unrelated error. Warnings, fatal errors, ambiguous observations,
incomplete macro fields and transport failures are rejected. `max_align_t`
intentionally selects the first alignment-equivalent candidate, retaining the
original algorithm and its four legitimate matching assertions. This does not
establish actual libc type or size equivalence.

Validation requires all 66 nonoptional schema fields, permits the 12 optional
GCC alignment fields, rejects unknown/wrongly typed fields, and additionally
checks macro-mapping values where the installed schema is insufficient.
Missing validation dependencies fail; no default fields or YAML repairs are used.

## Actual run and alignment contradiction

The [invocation](../build/hexagon-generator-adapter-20260906/invocation-1/receipt.json)
and [adapter receipt](../build/hexagon-generator-adapter-20260906/run-1/receipt.json)
record the fresh run. Its generator interval was 22:24:03–22:24:09 UTC.
All 84 commands completed: 41 returned zero and 43 returned the expected
compile-time assertion/alignment rejection. No compiler warnings or unrelated
errors remained. All required fields were extracted, with `wordsize` explicitly
observed undefined.

Compiler exit success disagrees with the emitted alignment of the unchanged
`int _Alignas(ALIGN_TEST) x = 42` fixture:

| Requested alignment | Compiler result | Emitted alignment | Observation |
| --- | --- | --- | --- |
| Powers of two from 16 through 268,435,456 | Zero, empty stderr | Matches request | Honored in these objects |
| 536,870,912 through 4,294,967,296 | Zero, empty stderr | 4 | Four contradictions |
| 8,589,934,592 | One named alignment-limit error | No object | Explicit rejection |

The adapter checks ELF32 little-endian Hexagon/v68 identity, the global four-byte
`x` symbol, its initializer, section and alignment. No object executes. Padded
alignment objects are retained with bounded streaming hashes, not truncated.

The [candidate YAML](../build/hexagon-generator-adapter-20260906/run-1/candidate.yaml)
keeps the upstream exit-status-derived `max_extended_alignment=4294967296`.
It is **not replaced by 268435456** or approved because its schema passes.
The contradiction makes both the adapter and its recorded invocation return
nonzero. `integration_eligible` remains false; even hypothetical extraction
without a contradiction cannot award L1 without separate profile calibration.

The earlier type fixture observed 16-byte genuine libc `max_align_t`, versus an
eight-byte `long long`. The generator's alignment-equivalent representation is
not interchangeable with that libc type. The previous libc `WCHAR_MAX` versus
kernel short-wchar mismatch also remains explicit, not a broader ABI claim.

## Evidence and regression

The run binds 3,007 explicit input files plus the compiler identity and 297
builtin-resource files before/after execution. All 67 adapted sources are also
compared before/after; 438 output artifacts are retained. No input drift was
observed. This includes the interpreter and PyYAML/jsonschema source trees, not
a complete hermetic Python/dynamic-library closure. Registry, tool lock, shared
profile/build/toolchain providers, old models and old proof receipts are unchanged.

The [independent retained-evidence audit](../build/hexagon-generator-adapter-20260906/EVIDENCE-AUDIT.md)
checks all 84 command/stream inventories, 31 objects and 438 artifacts, then
rehashes 3,757 bound paths without drift. Its own random-access ELF reader
confirms all 29 successful alignment trials. It imports neither the adapter nor
the shared ELF reader, and launches no external program. Comparison with the
preserved musl-first YAML finds only the candidate name and equivalent flag-list
tokenization changed; no measured field changed. No new per-source header-trace
replay is claimed by this milestone.

All [802 regression tests](../results/tests-hexagon-adapter-20260906.log) pass in
84.536 seconds, without skips. The [actual-command record](../results/tests-hexagon-adapter-20260906.json)
preserves the previous invocation/environment with only a fresh output log.
The 82 new tests are inert: 50 source/parser/schema/ELF checks and 32
transport/control-flow checks. Compiler, analyzer and native executions are
mocked in these tests; the real 84-command generator run is separate.

To repeat the diagnostic, choose a fresh output beneath an existing parent:

```sh
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  python3 -m fragma.hexagon_machdep \
  --sysroot build/profile-sysroots/hexagon-musl-6d7621470acf-1 \
  --output build/hexagon-generator-adapter-20260906/run-2
```

With these inputs, expect nonzero status for the alignment contradiction, not
support activation. No download, installation, make, analyzer, kernel rebuild or
target/native execution occurs in this diagnostic.

## Next acceptance gate

Resolve the compiler/model extended-alignment mismatch and document a calibrated
`max_align_t` representation policy. A smaller hand-filled field or unexplained
suppression is not a fix. Then integrate the adapter and its absolute-path
header/resource evidence into the normal profile pipeline, preserving GCC
commands and complete before/after input checks.

A fresh genuine build must match the intended profile ID and explicit v68
configuration; the old diagnostic build cannot be relabeled. Full kernel
type/layout, parsing, arithmetic/byte-order and policy calibration must pass
before registration, followed by scoped L2 proofs. The default-v2/modern-CPU
mismatch and wider `ELF_CORE_EFLAGS` limitation remain open.

Inventory at this dated milestone was unchanged: ten configured/current L1 models, eleven planned
profiles, 31 targets and 24 distinct kernel functions. Earlier proof acceptances
remain stale; this adapter neither renews them nor establishes a Hexagon baseline.
No sudo or system package installation was needed.
