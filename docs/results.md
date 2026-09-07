# Reading verification results

The common runner writes versioned JSON records (`schema_version: 1`) and a
human-readable `SUMMARY.md` into a new run directory. Existing run directories
are never overwritten. Reports are evidence about their recorded inputs and
execution, not certificates for later edits or arbitrary kernel callers.

## Run and target records

`summary.json` records the pinned kernel revision, ordered selected target IDs,
start and completion dates, output directory, explicit native receipt paths,
checked profile receipts, shared input hashes, target records and status counts.
`toolchain.json` records the actual compiler/analyzer/prover versions, binary
hashes, dependency inventory, environment and setup failures. Each target has a
separate `TARGET_ID/result.json` matching its entry in the summary.

Successful target records additionally retain:

- The complete target declaration: kernel source/functions, harness and any
  driver, selected analysis scope, required properties, calibration expectations,
  claims, input domain references and caller-coverage declaration.
- Source identity, actual prepared input and compiler/preprocessor commands,
  the configured machine model, kernel-header checks, assumptions and scoped
  warning/dead-path review evidence.
- The actual analyzer command and completion status, its raw diagnostics,
  ordinary and smoke proof goals, consolidated dependency/property rows,
  optional independently validated native observations, and the final evaluation.
- Input-integrity records and the final drift-check outcome. A source, model,
  contract, tool, review or recorded native input change invalidates acceptance.

The recorded solver timeout, analyzer wall limit and job count are separate.
Declared proof strategies may contain their own bounded prover attempts; their
source and options are also evidence inputs. A solver timeout is not a wall-clock
suite limit, and a wall timeout is never interpreted as invalidity evidence.

Current records additionally contain `validated_analysis_policy`, derived from
the declared model/pipeline, actual analyzer argv and retained correctness audit.
The explicit `runtime_checks.pointer_formation = "object-or-null"` setting is
separate from the unchanged integer-arithmetic flags. Configured model receipts
retain their own `validated_model_policy`, byte-bound `analysis_policy_audit`
and `analysis-runtime-policy` check. These envelopes validate settings, not
proof completeness: raw properties, dependencies and all other gates remain
required. See [the scoped policy review](pointer-policy-review.md).

For the pinned EVA version, an explicit builtin map is audited as
`@default,` followed by that map; this empty override category is distinct from
automatic builtin replacement. The checker requires the exact recorded
representation and canonical command controls, not a generic prefix-removal
rule. The [investigation and preserved first failure](../build/pointer-formation-review/builtin-audit-review.md)
explain why old tool-error receipts were not retroactively accepted.

## Terminal versus partial results

The normal aggregate status is `passed` only if every selected target is
accepted, otherwise `incomplete`. A failed toolchain check is `preflight-failed`:
each selected target receives `preflight-blocked`, a completion date and durable
JSON/Markdown output, without attempting profile or proof execution. Expected
environment/setup exceptions use this same failure path.

An in-progress run is `running`, without a final completion date. Abruptly
terminated processes can leave such partial artifacts; they must not be treated
as completed evidence. Coverage and replay reject unfinished runs. A profile
failure can instead produce a completed `profile-blocked` target; a preparation
or analyzer failure produces an explicit error record with whatever evidence
was available before the failure. Missing success-only fields never imply that
an unsuccessful target passed.

## Proofs, calibration and unresolved results

`passed` on a proof-role target requires both ordinary proof goals and the
selected consolidated dependencies to satisfy policy, plus source, model,
assumption, diagnostic and final input checks. An analyzer's exit status zero,
a count of goals, or a downstream theorem using an unproved assertion is not
sufficient. Trusted external implementations remain assumptions.

`calibration-passed` is different: a controlled false specification was
distinguished as intended, including its positive dependencies. It adds no
verified kernel function. Native observations cannot substitute for failed
positive properties, arbitrary unknown goals or analyzer errors. Raw EVA
`Invalid or unreachable` status remains unchanged; independently established
reachability and falsity are separate fields, never relabelled kernel defects.

`unsupported`, `inconsistent`, `unknown`, `timeout`, review requirements and
tool errors remain distinct issues in the evaluation. The single target status
summarizes those issues, not their complete explanation. In particular a smoke
result can identify a contradictory assumption or a dead path needing scoped
review; an inconclusive smoke test is not a consistency proof.

TSV rows retain file, line, function, property kind, text and raw status. Named
assertions are mapped to exact source declaration/predicate-start lines, not
nearby text. The exporter's omitted source columns can make *unselected*
callsites ambiguous; those rows retain multiplicity and an ambiguity marker.
Selected ambiguity is rejected. `report_row` is a physical file position, not a
logical property identifier.

## Coverage and reproducibility are separate checks

[Coverage](coverage.md) uses explicit completed receipts and current input
hashes. It keeps dated successes but does not keep current acceptance after
required evidence changes or a newer supplied failure. Function counts exclude
calibrations and project witnesses; each contract/configuration variant and its
unverified caller preconditions remains separate.

[Replay](replay.md) compares two independently executed runs after validating
retained artifacts, with separate input, execution-limit and outcome identities.
It is not cache authorization. Neither report generation nor replay silently
installs tools, executes target programs, or awards an architecture level from
the presence of an emulator.
