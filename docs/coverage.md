# Explicit-evidence coverage matrix

`fragma.coverage.generate_matrix(root, summary_paths, profile_paths=(), checked_at=None)`
is a read-only inventory. Supply completed `summary.json` paths explicitly; it
does not search result directories or choose convenient historical successes.
`render_markdown(matrix)` renders the same inventory. The standalone command
creates a new output directory and refuses to overwrite an existing one:

```sh
python3 -m fragma coverage \
  --summary results/all-registered-baseline-20260906/summary.json \
  --profile-evidence build/profile-checks/um-x86_64-gcc-configured/profile.json \
  --output results/coverage-example
```

Exit status zero means the report was generated, not that its proof targets
pass. Omit evidence options for an inventory explicitly marked not run; there
is no implicit search for receipts. The standalone `python3 -m fragma.coverage`
interface remains available for an explicit alternate project root.

The JSON includes every architecture in the pinned roster, every registered or
planned profile, every target and its kernel/project function references. It
records manifest hashes, supplied evidence paths and hashes, dates, individual
identity failures, changed inputs, retained-artifact checks, assumptions and
unresolved dependencies. Its generation inputs are checked again before return.
The current kernel snapshot is checked against the original pinned git-blob hash;
this does not relabel the original source as consumed when analysis used a
source-equal annotated translation unit.

For each target, the latest explicitly supplied completion wins regardless of
success. Missing selected results are `not-produced`. An undated terminal
preflight failure blocks current acceptance because it cannot safely be ordered
before a success. Equally dated observations are ambiguous, not a tie broken in
favor of success. Minimal unsuccessful records remain reportable without the
artifact fields produced only by successful analyses.

Historical acceptance and current eligibility are separate. A changed input,
target definition, source identity, profile, or retained proof artifact prevents
current acceptance; its dated reported outcome remains visible. The generator
checks recorded byte hashes for analyzer logs, audits and retained actual
preprocessing. Older WP JSON/TSV outputs lack original byte digests, so their
reparsed goals/properties must equal the saved summary rows; current byte hashes
are recorded without pretending they were captured during the original run.
Accepted proof rows also pass a fresh application of the report policy.

Current acceptance also requires revalidated target and model pointer-policy
envelopes, reconstructed from actual commands and retained byte-bound audits.
The declared pipeline and hash-bound review must agree. Old policy receipts
may remain valid historical observations, including explicitly supported legacy
replay, but cannot become `accepted-current` by adding defaults or copying a
saved approval field. A shared policy change requires fresh configured models,
renewed reviews, affected native witnesses and proof/calibration runs.

Counts deduplicate `(revision, source path, kernel function)`. Calibration rows
and project witnesses never increase kernel counts. Different contract/config
variants remain separate rows, with their own declared claims and observed
preconditions. One accepted variant does not mean the full API or all callers
are covered. The four dimensions are runtime safety, functional behavior,
termination, and caller preconditions. Only exact declared claim categories
count: output NUL termination is not termination of execution. Caller closure
has no accepted evidence schema yet and is never inferred from a conditional
function proof or a project witness.

Model observations are separate from proof outcomes. The latest dated model
failure is not replaced by an older L1 success; undated standalone profile
receipts remain explicitly undated observations. This module never awards L2 or
L3 from a proof subset, model calibration, or the presence of an emulator.

This inventory trusts local runner receipts; it is neither an independent proof
replay nor a tamper-resistant signature. Registry/provenance policies and all
declared external assumptions still bound every claim. Strict JSON parsing
rejects duplicate keys, non-finite numbers, and Boolean schema versions.
