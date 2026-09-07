# Exact 24-bit byte proofs

The [proof-only harness](unaligned.verified.c) preserves every C token of the six
kernel helpers and three project round-trip witnesses in `unaligned.acsl.c`.
Its function contracts and accepted domains are unchanged. Sixteen additional
ACSL assertions expose intermediate facts; they are obligations, not assumptions.
The 48-bit helpers remain unresolved and are not included in the completed
individual 24-bit results below.

All four 24-bit helpers have complete focused WP/dependency results on the actual
configured s390x **z13** model, using the pinned Linux revision
`b9b3e33b70b71e516930117e21de3ad2a7723747` and clean workspace toolchain.

| Focused evidence under `build/s390-pilot/byte-work/` | Ordinary WP | Selected property TSV |
| --- | --- | --- |
| `put-be24-2` | 18 Valid | 12 Valid |
| `put-le24-1` | 18 Valid | 12 Valid |
| `get-be24-3` | 13 Valid | 15 Valid |
| `get-le24-1` | 13 Valid | 15 Valid |

These receipts include actual source-gate results, configured kernel-header
checks, compiler preprocessing, retained parsed streams, commands, tool/input
hashes, WP JSON, and consolidated property TSV. Focused experiments used an
isolated working copy; their exact annotation streams are retained with the
receipts. The fresh combined replay of the final proof-only harness,
[byte24-final-2](../../build/s390-pilot/byte24-final-2/receipt.json), closes **all 82
ordinary WP goals and all 70 selected property/dependency TSV entries**, including
both full-domain round trips. Its twelve smoke attempts time out inconclusively;
no failed-smoke warning is waived. These totals exclude termination/exit and
default-behavior bookkeeping from the ordinary goal count.

## Proof structure

For an unsigned store input `v`, the assertions establish the quotient/remainder
decompositions at byte boundaries, beginning with
`v = (v & 255) + 256 * (v >> 8)`. The corresponding decompositions at shifts 8
and 16 let ordinary integer reasoning prove every stored byte equals the exact
specified quotient modulo 256. No restriction such as `v < 2^24` is added.

For decoding, the assertions first establish these generic decompositions for
the packed bitwise value, then prove each extracted byte equals its original
input byte. The [strategies](byteproof.h) use Frama-C's existing checked mask,
shift, range, conversion, and bitwise-equality tactics. Every side condition
remains a proof obligation. The weighted byte sum and bound then follow by
arithmetic. Valid readable/writable three-byte regions are the only pointer
preconditions; no extra alignment or byte-value restrictions are introduced.

The assertion order matters to proof search, not to C behavior. Extracting the
bytes first causes simplification to replace masks with known byte values,
leaving the mask-to-modulo tactic without its target. The rejected `get-be24-1`
and `get-be24-2` experiments retain their unresolved intermediate dependencies;
their locally Valid final postconditions were not treated as complete proofs.

Frama-C 33 also has the already documented trivial-child bookkeeping limitation:
an initially true tactic child can lack a recorded verdict, leaving its parent
Unknown. In extraction range subgoals, applying mask-to-modulo before BitRange
avoids the trivial constant-mask positivity child. No tool installation, tactic
implementation, or result file was patched to force success. There are no new
axioms, admitted lemmas, manual verdicts, or weakened contracts.

## Smoke routing and caller scope

Frama-C 33's `ProofStrategy.hints` deliberately excludes smoke goals from default
strategies. A tip-only invocation can therefore leave a requires smoke with
`verdict: none` and emit `Failed smoke-test`. The rejected `put-be24-1` evidence
retains this condition. Explicitly scheduling `tip,alt-ergo,z3` gives the smoke
goals actual external attempts. Their timeouts are inconclusive consistency
checks, never successful ordinary proofs or a proof of satisfiable contracts.

The first combined replay, `build/s390-pilot/byte24-final`, proved all 82 ordinary
goals, but its TSV still had an Unknown generic getter precondition. That status
came from the unselected project-only EVA calibration caller copied into the
harness. It was not ignored. The final proof-only variant omits only that
project calibration definition; the original calibration and its deliberately
false byte-order assertion remain unchanged in `unaligned.acsl.c`, selected
separately by the calibration manifest. No kernel function or round-trip body
was removed. The fresh `byte24-final-2` replay closes the entire selected
call/dependency graph; the earlier partial replay remains available for review.

## Warning-review scope

Any common-suite warning review must be bound to this precise source, strategy,
real-header fixture, configured machine/build, toolchain lock, and preprocessing
policy. For this 24-bit group only:

- Every accessed object is a byte or byte array, with alignment one checked by
  the genuine kernel-header fixture. The unsupported generic alignment warning
  does not remove an applicable stricter-alignment obligation.
- Calls occur only in the two project round-trip witnesses and are direct calls
  to the four selected, source-checked helpers. There are no function pointers,
  external function contracts, assembly, concurrency, or MMIO.
- Promoted decoder bytes are in `[0,255]`; constant shifts by 8 and 16 produce at
  most `16711680`, within signed 32-bit range. Stores use unsigned 32-bit inputs
  and constant valid right shifts. The signed-overflow diagnostic is reviewed
  against those exact operations and the proved range properties, not silenced
  as a general policy.
- `__gnu_inline__` affects linkage/inlining of these explicit sequential helper
  bodies. Their signatures and effective macro expansion are checked against
  the genuine configured headers. No address-dependent or instrumented behavior
  is claimed.

The global `Missing RTE guards` diagnostic can be scoped only together with the
exact companion warnings and all generated ordinary/runtime/dependency results.
This review does not extend to the unselected 48-bit helpers or future targets.

Standalone receipts always record `certified: false`: the common suite still
must enforce its complete provenance, toolchain, assumption, model, warning and
integrity policy. Kernel callers remain unverified. These explicit-byte helpers
do not independently corroborate native endianness, nor do these proofs provide
actual s390 hardware/emulator execution evidence.

Run the preservation and local-progress tests with:

```sh
python3 -m unittest tests.test_s390_byte_annotations tests.test_s390_proof_progress tests.test_s390_targets
```

Reproduce the complete local group after its target-manifest promotion with a
fresh output directory (options precede positional arguments):

```sh
python3 s390/prove.py --strategy fragma_byte_decompose --timeout 1 --wall-timeout 600 s390.unaligned24 build/s390-pilot/byte24-new-run
```

The common runner's independent integrated replay remains required for an
accepted target result; the standalone experiment never awards an L2 certificate.
