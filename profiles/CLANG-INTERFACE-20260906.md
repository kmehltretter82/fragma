# Target-aware Clang interfaces and GCC model renewal

2026-09-06. Compiler/model interface work is delivered and tested; **Hexagon
model generation remains closed**. No new configured profile, Hexagon L1,
libc compatibility, whole-kernel support or L2 proof result is awarded here.

## Implemented gates

The [toolchain inventory](../fragma/toolchain.py) now has an explicit Clang
family branch for the selected LLVM 21.1.8/Hexagon v68 candidate. It requires
both an executable hash and a complete builtin-include-tree hash. The exact
target arguments are `--target=hexagon-linux-musl -mv68`; the expected reported
triple remains `hexagon-unknown-linux-musl`. Version, target and resource queries
retain their observations. Binary/alias identity is checked before execution,
after the version query, and after target/resource probing.

Resource discovery uses the target-aware `-print-resource-dir` query. It hashes
all files, directories and confined symlink identities, rejects escaping/cyclic
links and special files, and checks repeat-read stability. The runtime inventory
rehashes these resources without issuing GCC-only `cc1`, assembler or linker
queries to Clang. A failed selected required compiler remains a failure; an
unavailable optional compiler does not block unrelated profiles. Existing GCC
tool records and commands retain their prior behavior.

The [profile interface](../fragma/profiles.py) distinguishes compiler families,
parses Clang's version format, checks exact tool/profile requirements and carries
the target/CPU prefix with all model compiler flags. That prefix reaches the
generator, macros, fixtures and stored standalone-preprocessor flags in the
intended pipeline. Conflicting selectors and unbound compiler configuration,
resource/include/driver/plugin forwarding routes are rejected. A planned row
with an optional Clang lock returns a prerequisite mismatch, not an exception
or host-default availability claim. Selected invocation aliases must agree.

Genuine Clang build matching revalidates the [LLVM build provider](../fragma/llvm_build.py)
against the exact source and retained validation envelope, then requires every
declared model compiler flag in the real TU. A model-only enum/packing flag
cannot silently inherit the earlier genuine build. The current unconditional
generator-header gate rejects all Clang header settings until a reviewed target
route exists; neither host nor RISC-V headers can open it.

`config/profiles.json` and `toolchain/lock.json` are unchanged. These opt-in
interfaces do not install tools or register the diagnostic candidate.

## Actual verification

- All [690 regression tests](../results/tests-clang-model-interface-20260906.log)
  pass in 75.666 seconds, without skips. This includes 16 new toolchain tests and
  27 new profile tests, with external commands mocked. The
  [exact-command sidecar](../results/tests-clang-model-interface-20260906.json)
  preserves the environment and retained-evidence paths. No historical native
  fault/trap/OOB harness was executed by those tests.
- The [actual legacy preflight](../results/preflight-clang-model-interface-20260906.json)
  passes all 18 locked tools with no issues. The configured lock still contains
  no Clang record. Plugin/prover listing, GCC component metadata and dependency
  inventories were queried; no proof, kernel, target program or installation
  was run by preflight.
- [Real Clang metadata](../build/profile-checks/clang-interface-20260906/clang-metadata.json)
  passes the three version/target/resource queries. The installed resource tree
  has 297 files, 310 entries and 15,520,436 file bytes. Its tree SHA-256 is
  `deb75785057f7fa7d497414c903e9c03a6d7005c84999204b21be6001e66b24c`.
  This pin was first observed locally for the diagnostic, not obtained from a
  signed upstream resource manifest. Builtin resources are not target libc headers.
- The [fresh ten-profile model renewal](../build/profile-checks/clang-interface-20260906/index.json)
  passes all 182 L1 checks: 20 for hardware x86-64, 18 for each other profile.
  Every generated machine description and declared compiler flag list matches
  the previous configured model. This was a fresh normal compiler/Frama-C run,
  not relabeling old models. Only hardware x86 executes the separate benign
  model-calibration fixture; cross objects and historical fault/trap/OOB
  harnesses are not executed.

The [independent audit](../build/clang-interface-audit-20260906/REPORT.md)
rehashes all 771 recorded renewal inputs and 284 retained files. It verifies
the ten unchanged YAML byte streams, 182 checks and 133 logged command/complete
log comparisons against previous models, normalizing only exact output roots.
It independently reconstructs the Clang resource-tree hash. The total audit
closure is 956 textual paths/955 resolved files, with no drift. Raw model logs
do not independently encode every process exit/stream; the structured runner
outcomes remain part of the trusted evidence. No compiler/analyzer was rerun
by this audit.

## Resolved source selection; remaining Hexagon work

The [header-source research](HEXAGON-HEADERS-20260906.md) identifies Qualcomm's
genuine Hexagon musl fork and resolves the pinned toolchain recipe's annotated
tag to commit `6d7621470acf277cbb00550655ed7140d3e4cff9`. The three public recipe/tag
documents are [retained](../build/hexagon-header-source-metadata-20260906/capture-1/receipt.json).
The tag is unsigned; no archive checksum, installed sysroot, verified header
closure or compiler compatibility is inferred from it. No source archive or
SDK was downloaded, and no headers were installed.

Next, authenticate that exact source and inspect the header-only build closure.
Review `__WORDSIZE`, `__WCHAR_TYPE__`, required POSIX fields and header ordering
under unchanged `-ffreestanding`/`-fshort-wchar` flags. Provision the target
headers separately, bind all source/generated/resource inputs, and require
warning-free generation plus full independent model/calibration checks before
opening the Clang gate. Do not fabricate missing fields or switch to hosted
compiler semantics. Broader CPU/kernel compatibility remains separate.

## Freshness and scope

The [new coverage matrix](../results/coverage-clang-model-interface-20260906/coverage.md)
contains 31 targets, 24 distinct kernel functions and all 21 architecture
families: zero accepted-current, 25 accepted-stale and six legacy nonpasses.
The ten explicitly supplied fresh standalone models are current L1; all thirteen
historical dated suite-model observations remain stale. Hexagon stays planned
without model or target evidence. Fresh standalone model files do not replace
dated suite observations or renew function proofs.

For each earlier nine-profile common24 run, the exact changed shared inputs are
now `fragma/build.py`, `fragma/profiles.py` and `fragma/toolchain.py`. Original
acceptances, reviews and artifacts remain intact. The
[independent coverage audit](../build/clang-interface-coverage-audit-20260906/README.md)
checks 3,703 generation inputs, 489 artifact references, 31 result equalities,
13 dated model equalities and four Markdown tables, without drift. This is
inventory/freshness readback, not renewed proof replay.
