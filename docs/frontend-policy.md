# Explicit target-local preprocessing policies

The common24 target family uses one shared harness with a closed selector:

```json
"frontend_policy": {
  "schema_version": 1,
  "kind": "common24-inline",
  "variant": "no-instrument"
}
```

`no-instrument` selects `FRAGMA_COMMON24_INLINE_POLICY=1`;
`patchable-entry-0` selects `=2`. There are no arbitrary definitions, undefines,
compiler flags or architecture-based defaults in this interface. The genuine
kernel fixture and standalone harness are mandatory paired inputs. Legacy
targets without this policy keep their existing commands and evidence shape;
they do not acquire an implicitly checked frontend envelope.

The runner uses the same selector exactly once in dependency preprocessing,
Frama-C's native ACSL preprocessor command and the genuine-header compiler
fixture. The selected model's compiler flags are unchanged. The fixture checks
the real kernel types, byte alignment, promotion range, signatures and expanded
inline spelling using genuine headers and the model-bound kernel build command.

`validated_frontend_policy` is a separate versioned result envelope. It checks
the actual recorded commands and retained ACSL-preprocessed `.pp` stream, not
only the requested manifest. All four helper bodies, both project witness bodies
and their declaration prefixes must agree with the source and selected policy.
The actual stream must preserve the ordered 24 ACSL blocks: comparison ignores
formatting whitespace but preserves token boundaries and quoted literal bytes.
Both raw and preprocessed inputs must have the exact two reviewed typedefs.

The compiler fixture's relocatable ELF object must have the model's class and
byte order and both named inline-metadata symbols with the expected contents.
The checker records the observed machine identifier without claiming ISA or
generated-code verification. Its empty diagnostics, complete dependency list,
object, headers and source identities remain bound evidence. An attribute
retained by Frama-C is not a modeled instrumentation effect.

The separate common24 source/inventory gate requires the complete six annotated
functions and reviewed strategy, all 94 ordinary goal identities, all 82 selected
source-located properties, and the 12 smoke categories. Missing obligations do
not make a smaller report pass. A complete inventory does not approve warnings,
pending assumptions, compiler calibration or smoke-test consistency.

Scoped warning reviews must additionally bind the explicit frontend policy,
its implementation and inline header, along with the existing harness,
strategy, fixture, pinned source, configured build, machine description and
analysis-policy identity. No s390 review or native receipt is transferred.
The first common24 run retained pending assumptions. The subsequent
[scoped review](../common/REVIEW-20260906.md) and integrated compiler checks
supported the [first three-profile L2 baselines](../common/L2-20260906.md).
Those approvals do not transfer to another profile or changed inputs.
The separate [wave-two review](../common/REVIEW-WAVE2-20260906.md) covers ARM64,
RISC-V and SH, all with their genuine `no-instrument` spelling. Their type and
frontend assumptions have separate IDs and exact reviewed-profile lists.
ARM64/RISC-V are LP64 and SH is ILP32; the wrong-type fixture still checks all
five intended type/signature errors, without redefining genuine `u32`.
The same supplement explicitly reviews the source-derived compiler assertion
identities for all six targets. It supplies neither a proof nor a smoke waiver;
fresh current-input acceptance is required after updating the review bindings.
The subsequent [six-profile run](../common/L2-WAVE2-20260906.md) completes those
fresh gates, full proof/dependency acceptance and retained-evidence replay.

The [wave-three review](../common/REVIEW-WAVE3-20260906.md) separately covers
Alpha, hardware x86-64 and UML x86-64. All use their own checked LP64 model and
genuine `no-instrument` spelling. UML retains its own configured header route;
sharing a compiler binary does not transfer the hardware x86 context. Its
independent assumption pair does not inherit either earlier wave's approval.
The same supplement reviews the exact Alpha ELF metadata and genuine `-Os`
compiler-policy changes for all nine profiles. Earlier results remain dated
until new normal runs pass under the explicitly renewed contexts.
The [nine-profile renewal](../common/L2-WAVE3-20260906.md) completes those
normal gates and independent retained-evidence/replay checks for all nine;
all 108 smoke outcomes remain inconclusive.

Replay and coverage rederive the envelope after checking actual stream bytes.
An opted-in result without the envelope is incomplete, not legacy-compatible.
Replay compares normalized stream contents and mapped commands separately;
random temporary paths and raw `.pp` hashes are artifact identities, not opaque
path-independent input keys. Binary compiler outputs are hashed as bytes.
Full replay still requires reviewed assumptions; a pending-review run can have
checked frontend/inventory observations while remaining incomparable for replay.

Changing shared runner code or adding the new manifest invalidates conservative
current-coverage bindings of older suite results. Retain those files as dated
evidence and run fresh checks; never rehash an old receipt into approval.
