# Private alignment candidate: build and core parse, 2026-09-07

The patched private Frama-C candidate now builds and passes five early
version/resource-path queries plus one core-only C parse. This establishes an
executable development candidate, **not validated Hexagon alignment semantics,
plugin loading, production integration, L1 or L2**. The installed analyzer,
original baseline, existing profiles and proof results remain unchanged.

## Successful build and preserved failure

[Candidate build 2](candidate-build-2/receipt.json) ran from
03:30:24.024532 to 03:33:05.193000 UTC. Dune returned zero after 154.062 seconds
of monitored build time; the original process group was terminal with its
leader reaped, no leftover members and no cleanup signal. Source and selected
dependencies did not drift. No compiler warning/error diagnostics were found
in its 334,489-byte stderr; stdout is empty.

The source is the pinned upstream archive plus exactly
[policy v2](patches/0002-alignment-attribute-policy-v2.patch),
[alignment consumers](patches/0003-clang-alignment-consumers.patch) and
[typing corrections](patches/0004-clang-alignment-typing.patch): nine changed
files and 39 exact hunks across 11,511 source entries. The full source is retained
separately in `worktree-2`, with an authenticated original preparation inventory.
The opt-in behavior and remaining limitations are described in the
[typing review](patches/ALIGNMENT-TYPING-REVIEW-20260907.md) and
[next context controls](CONTEXT-NEXT.md).

[Candidate build 1](candidate-build-1/receipt.json) is preserved as a failure,
03:25:53.878019–03:27:36.070350 UTC, Dune exit 1, clean process termination and
no input drift. One source defect produced bytecode/native compiler diagnostics:
`open Machdep` imports a nested datatype module also named `Machdep`, hiding the
outer module when the new validator is qualified. Policy v2 changes exactly
`Machdep.validate_alignment_attribute_policy` to the already-opened
`validate_alignment_attribute_policy`. The old patch, recorder, source tree and
failed artifacts were not edited. The complete source inventories differ in
only that one-line `machine.ml` correction.

Independent read-only replay checked exact argv/environment/stdin/process
identity, all build artifacts, source, selected dependencies and baseline
dependency equality, plus archive/patch reconstruction. It rehashed 37,487
unique regular paths with zero drift. That audit returned zero and wrote no
sidecar or other artifact. The build receipt inventories 19,337 artifact entries
excluding itself: 12,351 regular files, 796 directories and 6,190 symlinks,
915,950,420 regular-file bytes. Adding the receipt gives 19,338 entries and
920,166,642 regular-file bytes; symlink targets are recorded as link text.

The private native executable is
`candidate-build-2/dune-build/default/src/init/boot/empty_file.exe`,
43,211,520 bytes, mode 0555. Neither it nor its plugins are installed.

## Successful runtime checks and preserved recorder error

[Runtime 2](candidate-runtime-2/receipt.json) ran from
03:35:13.846580 to 03:35:24.843838 UTC, exit zero. All six direct queries returned
zero with terminal process groups and empty stderr. Before/after input snapshots
are byte-identical. The status is
`private-early-paths-and-legacy-core-parse-checked-not-alignment-validated`.

The first five queries check `-version`, `-print-config`, `-print-share-path`,
`-print-lib-path` and `-print-plugin-path`. All reported Frama-C sites are under
the private build; the explicit OCaml dependency environment still uses the
existing switch. Early path output does not prove plugin loading/isolation.

The sixth query uses `-no-autoload-plugins -machdep x86_64 -print -ocode printed.c core.i`.
Its complete inert input is `int fragma_private_core_constant = 7;`. It reports
`Parsing core.i (no preprocessing)` and prints that exact declaration with the
normal generated-file comment. It does not preprocess, execute the declaration,
load analysis plugins, run WP/Eva, or test the opt-in Hexagon model. Root readback
checked all six raw outputs, empty stderr, command-result equality, group gates,
the exact printed declaration and equal input snapshots.

A separate read-only audit checked all 42 retained runtime entries plus the
receipt, all six command/result/environment/output records, and the current
build/source/dependency closure with zero mismatches. The runtime tree remained
identical across readback; the private temporary directory is empty. It also
revalidated all 26 retained entries plus the failed runtime-1 receipt without
changing that failure. No audit-side compiler/analyzer or other subprocess ran,
and no audit sidecar was written.

[Runtime 1](candidate-runtime-1/receipt.json) remains failed after three
exit-zero early queries, 03:33:49.686297–03:34:00.299509 UTC. Its recorder wrongly
expected a trailing newline after a path. The path was correct; both the
unchanged baseline output and `special_hooks.ml` explicitly establish no
trailing newline. The successor recorder changes only this exact expectation.
It reruns all six queries into a fresh output; the failed receipt is not
reclassified, and no parser was reached in that failed attempt.

## Invocation and safety scope

The successful build used [build_candidate_v2.py](build_candidate_v2.py),
`--output .../candidate-build-2`, and explicit SHA arguments for all three
patches. Its complete direct command and environment are retained in
[intent.json](candidate-build-2/intent.json). It runs only the existing Dune
`build --release --build-dir ... -j2 --promote-install-files=false
--disable-promotion --cache=disabled --display=short @install` route, with
separately authorized local Unix-socket IPC. `@install` builds install-tree
artifacts; it does not perform `dune install` or a package operation.

The monitored build deadline is 1,800 seconds, with inventory/scheduling latency;
512 MiB child files, periodic 8 GiB/100,000-entry checks and bounded original-
group cleanup remain explicit. The recorder pins and compares baseline
dependencies, retains exact source reconstruction and hashes before/after.
This is selected-input and original-process-group evidence, not a hermetic
host/library closure or attestation of descendants escaping that group.

The runtime launch used [check_candidate_runtime_v2.py](check_candidate_runtime_v2.py),
explicit build-recorder/receipt/binary hashes, and `--output .../candidate-runtime-2`.
Complete arguments are retained in its [request](candidate-runtime-2/request.json)
and each command intent. It uses the default sandbox, a clean explicit
environment, six fixed queries, 30 seconds per query and a 300-second query
budget. Cleanup and input hashing can finish after the query deadline.
Both recorders state the cancellation sample boundary before final receipt
serialization and require a nonzero exit for later observed cancellation;
their actual terminal exit codes were checked separately.

Neither recorder requests a network operation, package installation, kernel
build, target execution, historical native fault harness or production-provider
change. No such operation was invoked directly in this work.
The latest completed project regression run remains the earlier 891-test pass;
it has not been rerun against this private provider.

## Next gate remains open

The subsequent [private context continuation](PRIVATE-CONTEXT-20260907.md)
executes all 55 unchanged compiler/analyzer pairs with the same private build
and [single-field opt-in YAML](candidate-policy.yaml): 33 constant agreements,
21 corresponding rejections and one compound-category mismatch. That YAML
retains the original measured representation, fields and maximum. A separate
14-case run confirms missing-definition, double-VLA and typed-arithmetic gaps.
Correct those measured gaps in fresh successor sources, and complete the
additional controls in [CONTEXT-NEXT.md](CONTEXT-NEXT.md). Do not replace valid
controls with expected rejections.
Typed attribute arithmetic, complete redeclaration/pragma semantics, expression
provenance, ACSL/bitfields, max_align_t regressions, genuine-kernel L1, existing-
profile regressions and production integration remain required.

Current accepted-target/function/architecture counts do not increase from this
private build milestone. No reportable Linux kernel defect is established.

| Artifact | SHA256 |
| --- | --- |
| Policy v2 patch | `b7c995ec09d85356865f6ab799f4f2002140fe496a2b25e146ac34479fa730c9` |
| Consumer patch | `3dcd00320b8a07ac01879376bec8b4ee02ded8cd4b0646103fa926d30b2c8f49` |
| Typing patch | `970278b7dfd73a2206649583b2743b93f6bde6a349364c16c145b7370b0edc37` |
| Build v2 recorder | `e9210a6a2d08e6c2d1783a8fc3d9d45a98145eda1b46168bc1a3486c5b8b2869` |
| Failed build 1 receipt | `f2572b2dd06c531db92ffa84565a6620962bd3bc9d70923b4aead02bcb8ceadd` |
| Successful build 2 receipt | `8153590cfd0613d22663f743b2fd382ad2663cb49ff3546803eae33d401bdb10` |
| Private executable | `d8435871161925515ef043ee9e88138b40b64becc9e453a90525658076d770ed` |
| Failed runtime 1 receipt | `0004785a1160de584ab42cbc0117f8616da8fb4dd590b506795c61a82f2c8cd2` |
| Runtime v2 recorder | `a094b0ee274ac66e5e4e62e823e5543803ba92c3340c3595292431536556af06` |
| Successful runtime 2 receipt | `8773296cb124904b6c0944e22576392ffbd78a799883601d934ace2399209082` |
