# Comparing independent runs

The read-only comparison command checks retained artifacts and distinguishes
semantic inputs, execution budgets and outcomes:

```sh
python3 -m fragma compare results/first/summary.json results/second/summary.json \
  --output results/first-versus-second.json
```

It does not run analyzers, modify the original reports, accept a proof cache,
or need today's target registry to match a historical registry. The optional
comparison output must be a new file. Exit status is zero only for two distinct,
accepted executions with matching inputs, known execution limits and outcomes.
Comparing a receipt to itself does not establish reproducibility.

Two independent runs on 2026-09-06 pass this comparison:
[run A](../results/replay-strings-a-20260906/SUMMARY.md),
[run B](../results/replay-strings-b-20260906/SUMMARY.md), and their
[comparison receipt](../results/replay-strings-a-versus-b-20260906.json).
Both selected the stronger `strnchr` and `strlcat` variants and passed all
106 ordinary goals and 41 selected consolidated dependency rows. They used
the same clean 91-package toolchain with a stripped environment, 20-second
solver limits, 600-second analyzer limits and four jobs. Input, execution-limit
and outcome comparisons all agree; the retained executions are distinct.
This establishes same-workspace clean replay for these two targets, not a
relocated-workspace or full-suite result.

A subsequent [relocated-project experiment](../build/relocation-review/handoff-20260906/RESULTS.md)
also completed two clean runs, each with 106 ordinary goals and 41 selected
properties Valid. It exported a fresh pinned kernel snapshot and generated a
new configured build at `/tmp/fragma-relocation-review.WgbrJEVI/fresh-project`,
using the same explicitly selected clean toolchain prefix. All 19 model checks
passed. The [independently rechecked A/B comparison](../results/relocation-replay-recheck-20260906.json)
is `replay-passed` within that relocated workspace.

The new exact preprocessing/build identities required a fresh scoped review;
the initial linked-build attempt correctly failed before proof. Comparison
with the old workspace remains `inputs-changed`, including changed review
identities in the policy outcome. This establishes clean relocated execution,
not automatic no-manual-path-edit relocation, a new toolchain installation,
or same-input cross-workspace replay. Full artifacts remain at their recorded
`/tmp` paths; the project handoff copies are archive mirrors, not new runs.

The versioned `fragma-replay-v1` view retains actual compiler/prover/library
hashes, configurations, source/header/specification/model inputs, trusted
assumptions, declared review context and proof-search settings. It verifies
the retained analyzer/preprocessor reports, rederives property/diagnostic facts
and recomputes the result policy. Changing a binary or a reviewed input changes
the association even if all property outcomes happen to agree.

Timings, a winning solver's incidental identity and audited temporary source
locations are not semantic properties. The comparator normalizes recognized
preprocessor linemarker filenames only; it does not rewrite C/ACSL expressions,
string literals, opaque compiler definitions, warning text or property names.
It retains multiplicity and exported-identity ambiguities rather than converting
property or warning lists to sets.

## Explicit corresponding locations

Both sides default to this repository as their `project` root. For corresponding
retained locations, supply explicit roles independently:

```sh
python3 -m fragma compare /old/results/run/summary.json /new/results/run/summary.json \
  --left-root project=/old --right-root project=/new \
  --left-root switch=/old-tools/opam/fragma \
  --right-root switch=/new-tools/opam/fragma
```

The `run` role comes from each summary's actual directory. Unknown absolute
locations remain literal inputs, not silently matched by filename. More
specific nested roles can describe the pinned kernel snapshot, build directory
or native tool prefix. Identical path roles do not erase differing file hashes.

## Acceptance limits

The historical and clean-rebuilt string runs agree on their checked outcomes,
but their actual tool binaries differ. They correctly report `inputs-changed`,
not same-input reproducibility. Historical inputs not needed to reparse reports
are identified by their recorded hashes, not claimed currently rerunnable.

Raw build/review/native receipt hashes remain conservative anchors. Relocated
review approval is not automatically inherited: commands and build identities
must still be independently checked at the new location. This is not yet a
general solution for relocated-workspace acceptance or incremental cache reuse.

New runs record separate solver and analyzer wall limits. Unrecognized legacy
receipts with missing limits cannot pass the clean-replay criterion. Each
comparison reports input, execution and outcome differences separately, so a
matching goal count alone cannot conceal a lost property or changed dependency.

Historical assertion labels use a narrowly recognized compatibility rule:
three exact recorded parser hashes from the inspected string/core receipts
mapped only the declaration line. The comparator reconstructs that convention
for those receipts; new runs also map a multiline predicate's exact start line.
All recovered rows must still match the saved rows. Unknown parser identities
do not receive a blanket permission to drop or invent labels, and no historical
approval is transferred to current changed code.

Current pointer-policy envelopes are rederived from the actual command and
byte-bound audit for both target analysis and model calibration. A saved
`status: checked` is insufficient. Model, pipeline and review identity comparisons
preserve JSON types; missing or contradictory settings fail closed.

The pre-pointer-policy replay examples above remain historical. Only three
explicitly inspected runner/profile hash pairs receive the separate
`legacy-observed` interpretation, with the recorded disabled-pointer audit and
no new policy declaration. That compatibility path never inserts a default or
upgrades an old run. Comparisons expose legacy versus current policy scope;
historical replay success does not establish current pointer-checked coverage.
