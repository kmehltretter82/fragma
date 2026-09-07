# Maintaining the verification suite

The acceptance unit is a particular source revision, build profile, contract,
analysis policy and set of required properties—not a function name or green
process exit. [PLAN.md](../PLAN.md) defines the broader milestones;
[PROGRESS.md](../PROGRESS.md) links dated evidence and outstanding work.

## Add a target without losing its scope

1. Choose a small kernel function and its real API domain. Identify conditional
   compilation, actual declarations, macros/types, external calls, assembly and
   exceptional paths before choosing a harness. Record unverified callers.
2. Add a unique ID to `config/targets.json` or a `config/*-targets.json` fragment
   with `schema_version: 1` and the same full `kernel_revision`. Declare source,
   harness, profile, analysis, functions, required properties, claims and
   assumptions. Keep an existing ID when only promoting its reviewed metadata;
   use a distinct variant when changing its contract or modeled domain.
3. Use `provenance.mode: functions` for an exact extracted standalone body or
   `translation-unit` for a comments-only whole translation unit. Neither gate
   proves substituted headers/types. Use a real-header `kernel_model_check`
   fixture to check those against the actual configured kernel compiler.
   Whole-kernel-TU preparation is currently x86-specific; a registered profile
   alone does not implement that path for another architecture.
4. Name every required functional property. Select direct helper dependencies
   together through `analysis_functions` when appropriate. List project-only
   witnesses under `project_functions`; do not count them as kernel functions.
   The RISC-V encoder manifest shows this distinction. An assigns proof alone
   does not establish an encoder's functional behavior.
5. Add tests for exact extraction, required property inventory, input domain,
   scoped model checks and expected failure modes. Preserve full input domains
   unless an API-backed restriction is explicitly reviewed. Keep malformed or
   unsupported inputs as failures, not empty successful extractions.
6. Run the target in a new output directory. Inspect ordinary goals, selected
   consolidated dependencies, warnings, smoke results, consumed headers and
   final integrity checks—not only aggregate counts. Add bounded, valid-input
   specification calibrations separately; a solver timeout does not establish
   that a false claim was detected.

For example, from the project root with the prepared ARM64 build:

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" \
  python3 -m fragma run --target arm64.cpuid \
  --output results/arm64-cpuid-new-review --timeout 5 --wall-timeout 180 --jobs 2
```

This example verifies the currently registered runtime-safety contract, not a
new functional specification. The [ARM64 review](../arm64/CPUID.md) explains its
two trusted assumptions, unchanged domains and missing behavioral calibration.

## Review an assumption or diagnostic

Keep each assumption in the ledger with a stable ID, kind, scope, justification,
source/configuration dependencies, review evidence and explicit status. A
`reviewed-assumption` is still trusted; do not set `implementation_proved` merely
because a caller passed using its contract. External implementations, callers
and architecture-specific backend code need separate evidence.

A warning/smoke review must bind the exact functions, diagnostic or dead-path
identity, relevant files and hashes, source revision, configured model, analysis
settings, preprocessing and any proof strategy. Explain why it applies to those
operations. The runner checks these bindings again; changing a review input
requires re-review rather than copying an earlier acceptance flag.

Particularly important boundaries:

- An inconclusive smoke attempt does not prove consistency. A dead trap branch
  under one contract does not justify eliminating it under a broader domain.
- Normal return, abnormal exit and divergence are different. Review `ensures`,
  `exits`, `terminates` and nonreturning declarations together.
- Pointer formation is separate from readable/writable access and alignment.
  Record effective analyzer options. Silencing a diagnostic is not evidence
  that the compiler semantics have been modeled.
- A runtime observation corroborates only its reached assertion and actual
  execution environment. Preserve raw `Invalid or unreachable` and keep
  independent reachability/falsity evidence separate. Never override an
  unresolved positive dependency with a native observation.

## Update a kernel revision or toolchain

Work in an isolated project/build location and keep prior receipts immutable.
Select the complete Git commit explicitly; the checkout's current HEAD does not
replace the pin. Recompute its architecture roster with `git ls-tree`, update
the architecture/profile/target revision declarations together, and compare
selected bodies, declarations, macros, generated configuration and headers.
Removed architectures remain historical, not current supported profiles.

Create a fresh source snapshot and configured builds using the documented CLI:

```sh
python3 -m fragma snapshot --kernel /path/to/linux --output /new/project/build/sources/linux-pinned
python3 -m fragma prepare --profile s390x-gcc --source /new/project/build/sources/linux-pinned
```

Run these from the new project root after its pins/profile build paths have been
reviewed. `prepare` uses the selected profile's configuration and output recipe;
it is not a way to overwrite arbitrary directories. Do not manually relabel an
old build receipt or machine description as current.

For tool changes follow [the locked setup/update procedure](toolchain.md): use
a new installation prefix, verify artifacts and complete package definitions,
inspect the candidate lock, then rerun model checks and clean proofs. Same
version text does not erase differing binary/library hashes. Cross-compilers,
runtime tools and the RISC-V generator-only sysroot have separate requirements.
No verification command installs or upgrades them.

## Local automation and baseline review

`ci/check.py` runs the unit suite followed by the common proof runner. It writes
logs and a driver receipt under a new explicit output directory:

```sh
FRAGMA_TOOLCHAIN_PREFIX="$PWD/toolchain/verified-prefix" \
  python3 ci/check.py --mode core --output results/ci-core-new \
  --native-evidence "$PWD/build/string-sensitivity/native-9/receipt.json" \
  --native-evidence "$PWD/build/s390-sensitivity/native-5/receipt.json" \
  --timeout 1 --wall-timeout 600 --jobs 2
```

`core` selects both the actual `core` and `calibration` suites, including their
unresolved legacy cases. It is not a green-only subset: it currently must fail
until those cases are resolved. `extended` selects the extended suite;
`all` selects all three suites. The calibration suite currently includes s390
as well as strings, so both `core` and `all` need the two explicit native
receipts shown above. `extended` currently contains proof targets only and
does not need a native receipt. Supply only relevant, explicit receipts.
Receipts are revalidated against current inputs and may need regeneration.

The unit suite must pass before proofs start. A missing/incomplete/mismatched
proof summary or nonzero child exit makes the automation fail. Retain both
failed and successful logs. Analyzer wall caps and per-solver attempts remain
separate; runtime checks are not silently provisioned or executed by this driver.
There is no hosted CI service, automatic baseline approval or proof cache yet.

Before accepting an intentional baseline update:

1. Record old/new pins and all source, model, contract, review, tool and analysis
   changes. Explain each missing/new property, status change and dependency—not
   just a changed goal total. Keep unsupported cases in the selection.
2. Run the affected targets, plus dependants of changed contracts/assumptions.
   Shared model/toolchain changes or uncertain impact require the full supported
   matrix and registered suite. Automatic dependency-based scheduling is not
   implemented; current shared-input hashing deliberately invalidates broadly.
3. Repeat clean runs and use `python3 -m fragma compare` on the explicit retained
   summaries. Input, execution-limit and outcome equality are distinct; a
   relocated run needs fresh path/build review and cannot inherit acceptance
   just because property counts agree. See [replay policy](replay.md).
4. Generate `python3 -m fragma coverage` from explicit completed summaries and
   profile evidence. Include newer failures. Publish accepted-current,
   historical/stale and unresolved coverage separately, excluding calibration
   cases and project wrappers from unique-kernel-function counts.
5. Update the dated progress/baseline explanation with evidence links, timing,
   scope, unresolved obligations and reviewer identity. Do not mark an L2/L3
   milestone from registration, compiler availability or a single passing leaf.

The existing [baseline triage](baseline-20260906.md) is a dated example, not a
permanent approval. See [result semantics](results.md) for partial-run handling.
The newer [seven-helper s390x baseline](../s390/PILOT-20260906.md) records the
separate conditional L2 scope decision after a complete all-target run and
exact pilot evidence audit. It leaves unrelated CI failures and broader
runtime/trap/caller milestones open; the auditor itself awards no level.
