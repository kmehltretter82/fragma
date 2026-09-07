# Bounded string specification sensitivity

These eight local cases exercise concrete functional and domain facts behind
the strengthened [string contracts](../annotated/string.verified.c). They do
not change kernel code, reproduce a vulnerability, or count as additional
verified kernel functions. The deliberately false claims are in the driver.

The [target fragment](../config/string-sensitivity-targets.json) keeps every
case in the calibration role with no universal correctness claims. Each
entry runs separately: all named positive assertions precede one deliberately
false assertion. The exact source locations and expected names are inventory
checked by [the tests](../tests/test_string_sensitivity.py).

| Entry suffix | Valid bounded example and positive facts | Deliberately false claim |
| --- | --- | --- |
| `truncation` | Append `cdef` to `ab`, capacity 5: attempted length 6, exact `abcd\0`, unchanged prefix/source and outside-capacity sentinel | Return equals stored length 4 |
| `no_copy_room` | Append `cd` to `ab`, capacity 3: attempted length 4, unchanged `ab\0` | Every nonempty source adds a byte |
| `full_copy` | Append `cd` to an empty capacity-4 destination: exact `cd\0`, untouched tail | Reversed bytes are equivalent |
| `first_match` | Search `aba\0` for `a`: first pointer, matching byte | The later matching pointer is the first |
| `nul_conversion` | Search a two-byte `A\0` object with count 8 and character 256: converted character is NUL and terminator is found | NUL never matches |
| `early_nul` | Search the same short object for absent `B`: readable two-byte prefix and null result | All eight bytes must be readable |
| `zero_count` | Search a null pointer with count 0: null result without a read | Count zero still requires readable storage |
| `count_cutoff` | Search readable `abc` with count 2 for `c`: null result | Search ignores the count |

The early-NUL and zero-count negative properties query logical readability;
they do not dereference invalid addresses. No input-memory fault is introduced.
The examples test only small nonwrapping lengths. The full modulo-2^64
attempted-length theorem remains the responsibility of the separate WP target;
these bounded cases cannot instantiate every unsigned-length combination.

## Independent source and model

[string_calibration.c](string_calibration.c) is a whole-translation-unit copy
of pinned `lib/string.c` at
`b9b3e33b70b71e516930117e21de3ad2a7723747`. Its C tokens, including declarations
and bodies, must equal that pinned source. Only two small ACSL safety checks
are added: the valid append domain before `BUG_ON`, and a null-or-readable
search result. Neither imports the strong quantified WP contracts.

The [minimal model header](specs.sensitivity.h) gives an explicit byte-copy
contract and a coherent nonreturning trap model. Genuine configured x86 kernel
headers and compile arguments establish `size_t`, character signedness, and
the selected implementation. Existing GNU/frontend and x86 header substitutions
remain trusted, consumed inputs with recorded hashes. The trap call is excluded
by the valid-domain assertion in all three append samples; no trap or inline
assembly behavior is certified.

Automatic EVA builtins are disabled, so the generic kernel `strlen` C body
executes. Only `memcpy:Frama_C_memcpy` is selected explicitly. The kernel's
assembly copy implementation and the analyzer builtin's own implementation
are not proved here. The assumption entries in the target fragment expose
these limitations. The unrelated whole-TU functions are not selected claims.

## Fresh evidence and acceptance boundary

The raw run is in
[baseline-3](../build/string-sensitivity/baseline-3/summary.json). Each entry
has its exact command, current configured profile, build receipt, source gate,
compiler dependencies, Frama-C consumed-source audit, retained native
preprocessing files, SHA-256 hashes, analyzer log, red-status export, and
consolidated property TSV. Frama-C performs native `-pp-annot` preprocessing
with the actual configured compiler command; the compiler-only `.i` is an
additional audit artifact, not substituted for the analyzer's own input.

The analyzer reports each negative locally as invalid and stops propagation
at that deliberately false assertion. Its consolidated TSV status is
`Invalid or unreachable`, **not unconditional `Invalid`**. This raw EVA
evidence alone therefore remains **incomplete**. Likewise, unselected entries'
`Dead` properties are unreachable, not
independent invalidity evidence. A reported nonterminating driver after the
false assertion describes propagation stopping, not kernel nontermination.
Frontend attribute and annotation-preprocessing warnings are retained too;
this raw evidence is not a waiver of the integrated runner's warning policy.

Completion requires a separately checked concrete reachability witness tied to
the same named negative, positive facts, source/driver hashes, and compiler
profile—such as a bounded native execution with observed outputs. An unknown,
timeout, red-property export alone, or unreachable status must not silently
be relabelled as a refutation. These cases also do not establish caller coverage
or prove that a strengthened contract is maximally general.

The separate [native corroboration helper](NATIVE-STRING-SENSITIVITY.md) now
provides such bounded reached-state observations with a read-only revalidation
API. Native evidence must be selected and validated explicitly; it does not
change any raw EVA status or bypass the other regression gates.

The [integrated eight-case run](../results/string-sensitivity-integrated-2-20260906/SUMMARY.md)
passes with the explicit `native-6` receipt and the clean local toolchain.
All positive EVA properties are valid, and each negative retains its raw
`Invalid or unreachable` status alongside one exact native reached-false
observation. Source/model/assumption and final drift gates also pass. No kernel
defect, universal proof, or extra verified kernel function is inferred.

The earlier integrated attempt is retained as a parser failure: two unselected
`memcmp` callsites have distinct source columns but the same exported TSV
identity. The parser now preserves and flags all such unselected occurrences;
it still rejects selected or contradictory duplicate identities. The row
number distinguishes recorded occurrences only, not logical property identity.

The earlier `probe-1` run used the strengthened quantified contracts directly:
EVA left several of those contracts unknown, despite validating the driver
facts. `probe-2` evaluated the independent minimal view. `baseline-1` was an
incomplete artifact-retention attempt. `baseline-2` exposed two multiline
assertion-label/source-location mismatches; both labels now share their
expression's line. Use `baseline-3` for current complete raw receipts.
Historical attempts are retained, not overwritten or accepted.

Run inventory/source tests with:

```sh
python3 -m unittest tests.test_string_sensitivity
```

To additionally verify the current raw evidence and its explicit nonacceptance:

```sh
FRAGMA_STRING_SENSITIVITY_RESULTS=build/string-sensitivity/baseline-3 \
  python3 -m unittest tests.test_string_sensitivity
```

The fragment's entries use the normal regression runner's `driver`, `entry`,
`eva_auto_builtins`, and `eva_builtins` fields. They are calibration evidence,
not an exemption from any provenance, input-integrity, or outcome gate.
