# Common24 renewal: interrupted sandbox attempts

Recorded 2026-09-07. This is an execution-failure record, not a proof acceptance
or a kernel-defect report. Original artifacts have not been relabeled or replaced.

The three normal renewal batches started on 2026-09-06 at approximately
23:44:20 UTC. Their exact commands, clean environments, input hashes and budgets
are retained by the [original launcher](../build/common24-clang-renewal-20260906/run_batch.py)
and its invocation records. Each selected three existing common24 WP targets,
with a one-second prover timeout, a 600-second analyzer wall timeout, two jobs
and the existing Alt-Ergo/Z3 selection. No contracts, source bodies, compiler
flags, reviews or model policies were relaxed.

## Observed result

All nine model validations passed: 164/164 named checks. In every started proof
analysis, Why3 reported that connecting to its local Unix-domain socket was
denied with `Operation not permitted (connect,)`. The first analysis in each
batch reached its analyzer wall timeout and recorded `tool-error` with
`accepted: false`. The next analysis in each batch showed the same socket error.

| Batch | Completed target outcome | Interrupted analysis | Not yet analyzed |
| --- | --- | --- | --- |
| wave1 | ARM: tool-error / analyzer timed out | PowerPC32 | m68k |
| wave2 | ARM64: tool-error / analyzer timed out | RISC-V64 | SH |
| wave3 | Alpha: tool-error / analyzer timed out | x86-64 | UML x86-64 |

The completed first targets had passed their compiler calibration. Model and
compiler successes do not turn the unavailable prover results into acceptance.
There are zero accepted renewed proofs from these attempts.

## Termination and retained evidence

The root agent used an approved, narrowly scoped process inspection outside the
sandbox to identify the three known Python wrappers. Before signaling, it opened
process handles and checked each exact command line and working directory.
SIGINT was sent only to those wrappers. Their existing cleanup handlers killed
their owned child process groups, waited for the children and wrote failed
invocation receipts. All three original tool-session handles then returned
terminal exit code 1; no retry was started while they remained live.

Each receipt records child return code -9, `KeyboardInterrupt`, and no input
drift. The recorded completion times are all 2026-09-07 at 00:01:02 UTC:

| Batch | Terminal invocation receipt | Receipt SHA-256 |
| --- | --- | --- |
| wave1 | [receipt](../build/common24-clang-renewal-20260906/invocation-wave1/receipt.json) | `16b69ed02a43770faddc3d6655656ba7459239df67e3a1a0fd35fcd273ff65bd` |
| wave2 | [receipt](../build/common24-clang-renewal-20260906/invocation-wave2/receipt.json) | `3175fcb3646b91e64c0aa5a49dacdcd8718cabeff83045c8f093a31981b9e8c3` |
| wave3 | [receipt](../build/common24-clang-renewal-20260906/invocation-wave3/receipt.json) | `2d81701e90dd3424d1bb086c6b14902d1381eceaadce81916383856615c27e87` |

The root's post-termination readback checked each receipt's 52 initial input
hashes plus its stdout, stderr and partial-summary hashes: 55 comparisons per
batch, with no mismatches. This was a read-only check reported by the execution
tool, not an independently generated audit artifact or a full dependency-closure
claim.

The original suite summaries remain exactly as interrupted:
[wave1](../results/common24-clang-renewed-wave1-20260906/summary.json),
[wave2](../results/common24-clang-renewed-wave2-20260906/summary.json), and
[wave3](../results/common24-clang-renewed-wave3-20260906/summary.json).
They still say `running` and lack suite completion dates. The separate terminal
invocation receipts establish that these processes have stopped; they do not
make the partial suites complete. The coverage collector rejects such running
summaries, so they must not be silently treated as valid coverage inputs or
rewritten to pass ingestion.

## Continuation boundary

Any retry must use unused output paths, preserve these failed attempts, keep the
same proof scope and budgets, and obtain permission for the required local
solver IPC. No package installation or `sudo ... install` command is needed.
Fresh acceptance still requires normal source/model/review/compiler gates,
complete proof and dependency results, and retained-evidence validation.

The [published coverage](../results/coverage-clang-model-interface-20260906/coverage.md)
still has zero accepted-current targets, 25 accepted-stale targets and six legacy
nonpasses. No fresh coverage or architecture promotion follows from this failure
record. No historical fault/trap/out-of-bounds harness or common24 object was
executed. Hardware x86 model validation includes only its existing benign native
model fixture, independently of these WP targets.
