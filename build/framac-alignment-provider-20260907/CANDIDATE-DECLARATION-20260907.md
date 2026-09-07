# Private declaration correction: built and observed, 2026-09-07

The new private candidate rejects all four previously accepted missing-`_Alignas`
definition controls. The reverse-order controls remain unchanged, as does the
55-case context matrix. This validates the correction on those measured cases,
**not full redeclaration semantics, Hexagon support, L1/L2 or integration**.
The double-VLA mismatch, typed GNU arithmetic and compound-error recovery remain
open. No reportable Linux kernel defect is established.

## Exact successor source and build

[Preparation 3](worktree-3/preparation.json) creates a new source tree from the
same authenticated archive and four ordered patches: policy-v2, consumers,
typing, and [0005](patches/0005-c11-missing-definition.patch). Patch 0005 adds
nine lines before canonical declaration merging. It checks the original C11
specifier's presence, including zero and ignored high requests, only under the
explicit private policy. It does not change legacy behavior or the numerical
alignment policy. Tentative and initialized definitions remain distinct.

The [new preparer](prepare_candidate_v3.py) verifies all patches in memory
before extraction and writes only the nine changed files in the fresh tree.
It retains full original/final inventories and before/after inputs. Preparation
completed at 04:43:09.258259 UTC with no drift and no subprocesses. The source
has 11,511 entries: 10,893 files and 618 directories, with nine changed files
and 40 hunks against the archive. Compared with candidate 2, the only source
change is the nine-line guard in `cabs2cil.ml`.

Independent preparation readback freshly hashes 21,798 unique regular paths
without drift, reconstructs the archive and exact four-patch chain, checks all
ten input pins and the retained preparation artifact inventory. The preparation
receipt is 7,191,389 bytes; its enlarged bounded reader is explicitly 16 MiB.

The [V3 build recorder](build_candidate_v3.py) independently reconstructs that
same ordered patch chain, including patch 0005 consuming patch 0004's output
with exact coordinates and no fuzz. [Build 3](candidate-build-3/receipt.json)
ran 04:44:57.503123–04:47:40.533566 UTC and returned zero. Monitored Dune time was
155.859 seconds; the original process group was terminal and reaped without
leftovers or cleanup signals. Source and selected dependency hashes did not
drift. Its native development executable is 43,212,432 bytes, mode 0555.
No compiler warning/error diagnostic patterns were found in the retained log.

Independent build/runtime readback twice rehashes the complete build tree
(12,352 files, 6,190 symlinks, 796 directories), complete runtime tree
(36 files, seven directories), all 11,511 source entries, all four selected
dependency trees (14,602 entries), 13 dependency files and 13 selected inputs.
All match their recorded inventories without drift. It separately reconstructs
the exact archive/patch chain and checks the build and six runtime command
identities, environments, outputs, process closure and inert parse artifacts.

The ordinary private build used separately approved local Dune IPC permission.
It did not install packages or replace the installed analyzer. Builds 1/2,
their failures and source trees remain unchanged.

## Private runtime and unchanged matrix

The [V3 runtime checker](check_candidate_runtime_v3.py) differs from its frozen
predecessor only in the builder path. [Runtime 3](candidate-runtime-3/receipt.json)
passes five version/resource-path queries and one inert legacy x86_64 core-only
parse, completing 04:49:14.669106 UTC without drift. Plugin autoloading is off;
these six checks alone do not establish alignment semantics or plugin support.

The reviewed [V3 context recorder](diagnose_candidate_context_v3.py) then runs
all 55 unchanged pairs against this candidate with the same opt-in YAML and
V2 classifier. [Context run 3](context-run-3/receipt.json) completed
04:50:33.543244 UTC, terminal exit 1, with no input drift:

| Observation | Count |
| --- | ---: |
| Constant witnesses agree | 33 |
| Named rejection categories correspond | 21 |
| Compound rejection-category mismatch | 1 |
| Unresolved observations | 0 |
| Unexpected negative-control acceptance | 0 |

The above-maximum/missing-definition compound case still has two compiler
categories but only the first analyzer error. Patch 0005 does not reproduce
Clang's error recovery after discarding an invalid attribute. The remaining
one-category mismatch is preserved, not converted into agreement.

Independent context/extra-run readback freshly hashes 2,983 unique regular
paths without drift and verifies all 142 command records, 69 preprocessing
commands and 207 linemarkers. All 55 matrix comparisons exactly equal the prior
run, including all 628 compiler/analyzer constants. The current matrix tree
contains 949 files and 280 directories (27,252,673 bytes); the extra tree has
260 files and 75 directories (24,385,621 bytes). This readback rehashes current
runs, selected inputs, fixtures, prior context/extra runs, runtime artifacts,
compiler resources, private libc targets and executable; full nested build/
source/dependency records are compared as recorded. The separate build/runtime
audit above performs the fresh full-tree rehashes.

## Four corrected controls and remaining limitations

The [extra V2 recorder](diagnose_candidate_extra_context_v2.py) retains and
verifies the prior raw run and executes all 14 unchanged extra pairs.
[Extra context run 2](extra-context-run-2/receipt.json) completed
04:50:21.122001 UTC without drift. Exit zero denotes complete raw observation
collection only; its receipt remains explicitly unclassified and ineligible
for support.

Only analyzer return codes 004, 006, 008 and 010 change from the preceding extra
run, from acceptance to rejection. Each has the exact new missing-definition
diagnostic and empty stderr. Their compiler counterparts still reject the same
independent invalid condition:

| Source sequence | Requests | New measured result |
| --- | --- | --- |
| Aligned extern, then bare tentative definition | 16, 0, 2^29 | Both reject missing `_Alignas` on the definition. |
| Aligned extern, then bare initialized definition | 16 | Both reject missing `_Alignas` on the definition. |
| Bare tentative definition, then aligned extern | 16, 0, 2^29 | Both remain accepted. |
| Bare initialized definition, then aligned extern | 16 | Both remain rejected. |

The analyzer now has five successes and nine rejections across these 14 cases;
Clang remains at six successes and eight rejections. These totals are not a
semantic pass rate. The valid `double` VLA still reports `[4,8,4]` instead of
Clang's `[8,8,4]`; the `int` companion remains `[4,4,4]`. Valid GNU `8 + 8`
remains unsupported by the analyzer. Unsigned wrap-to-zero, negative and
nonpower arithmetic still produce unsupported analyzer outcomes, not validated
matching language rejections. The reverse tentative-16 expression/storage
alignment distinction documented in [the prior milestone](PRIVATE-CONTEXT-20260907.md)
also remains open.

## Scope and next work

Each matrix run consists of two versions, 55 textual LLVM IR emissions and 55
core-only parses; the extra run is two versions plus 14 pairs. Their explicit
preprocessor descendants are additional. Per-command original process groups,
generated headers, actual preprocessing argv, retained files and full selected
before/after snapshots remain checked. These are not hermetic-host or escaped-
descendant attestations. No target program, kernel build or WP/Eva proof ran.

The [VLA typed-origin proposal](VLA-PROVENANCE-PROPOSAL-20260907.md) and
[GNU typed-arithmetic proposal](patches/TYPED-GNU-ALIGNMENT-REVIEW-20260907.md)
are reviewed separately; neither is part of candidate 3 or behaviorally validated
by these runs. Both currently target candidate 2 source coordinates and need
exact rebasing/composition after patch 0005, without fuzzy application. They
need fresh integration, compiler/runtime checks and discriminating
controls, including source-syntax decay, unevaluated expressions, bound effects,
target-C integer types and print/reparse. The remaining controls and full
integration gates in [CONTEXT-NEXT.md](CONTEXT-NEXT.md) still apply. Policy/legacy
regressions, complete redeclarations/pragma semantics, `max_align_t`, genuine-
kernel L1, existing-profile regressions and normal-pipeline integration remain
required before registration or support promotion.

Current acceptance stays at 25/31 registered targets, 18/24 distinct functions
and ten named scoped architecture baselines; eleven families still lack one.
The earlier 891-test project regression result is not a candidate-3 regression
pass. No system installation is needed for this immediate work.

## Retained identities

| Artifact | SHA256 |
| --- | --- |
| Preparation recorder | `6551226822dce69c90af64714fe321ef0df222305e0f0031c390d1669a777451` |
| Preparation 3 receipt | `c9b4a378958dd8200f16ed2bd1dd37ee392497e91fe93161868bdf341ad094de` |
| Missing-definition patch | `1a7ab19aaff5d3d8785bc73d838e54bbd0273c60844bf5f9336f44eb357aaa29` |
| Build V3 recorder | `e1f9c310040ecf2588da7648de9a490e277926b9116096e39c714bbe53a98668` |
| Build 3 receipt | `d54d44216ef6f61902935441887e94025f6dbd328ca72b3d353018f497950832` |
| Private executable | `c514f183fb4eb4f6d225396ce94da37c75c40116d6d472935a4169ac88bc37bd` |
| Runtime V3 checker | `5a4f760ac76c858a16e662ac4bac8b455c621c60642df7fd24160b0fb7bc133b` |
| Runtime 3 receipt | `3a3ce8c1dddd2ff6f88cb8876858fbc7d79f23dba3fe9a792387154f8c38aad2` |
| Context V3 recorder | `6f58a09cfb9b78b9ebca5b1a34c014eecdd19b9d67311cb4327da990f78447eb` |
| Context run 3 receipt | `2c7d6f9a56cee476948162ea1125528b962589a4e1ace41ff5c8233ab08eabae` |
| Extra V2 recorder | `2c18e3c754d29acb55e2b1030ca46d8e55a1130680926f25938afd6856693d36` |
| Extra run 2 receipt | `51afd1958922a9daccd60ae0b2ada84a7acd49ad8363c7ef52ffe26eaac47e5e` |
