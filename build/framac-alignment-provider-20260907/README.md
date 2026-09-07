# Private Frama-C build baseline, 2026-09-07

The pinned, **unmodified** Frama-C 33.0 source now builds in a private workspace
directory. Five subsequent early version/resource-path queries also pass. This
establishes a build path for the [alignment-context corrections](../../profiles/HEXAGON-CONTEXT-20260907.md),
not those corrections, analysis correctness, plugin isolation, Hexagon L1 or L2.

## Completed build

[build_baseline.py](build_baseline.py) ran once from 01:39:36.855209 to
01:42:38.123677 UTC. The [receipt](baseline-1/receipt.json) records exit 0,
confirmed child termination, no cancellation and no source/dependency drift.
Its status remains `unmodified-private-build-complete-not-runtime-validated`.

The cached upstream archive matches the SHA256 in the existing toolchain lock:
`9c1cbffd28bb33c17a668107e39c96e4ae7378a3d8249f69b47afc7ee964e9b8`.
Extraction permits only the fixed 10,893 regular files and 619 directories,
49,657,870 source bytes, with no links, special files or path traversal. All
extracted source bytes and the selected build dependencies remain unchanged.
The archive, retained source and installed versions of the six principal
alignment-consumer/interface files also matched in a separate read-only check.

The one direct child is Dune `build --release ... @install`, with two jobs,
promotion/cache disabled, a separate build directory and private temporary/cache
directories. Its normal OCaml/C compiler and configuration descendants are build
tools, not target programs. `@install` builds the package/install-tree targets;
no `dune install`, opam operation, package installation, test suite, analyzer
parse, proof or kernel build was invoked by this recorder. Local Dune Unix-socket
IPC was explicitly authorized. No change to `verified-prefix` was requested or
observed in the selected dependency trees.

The build has a 1,800-second child deadline, a 512 MiB per-file child limit and
periodic 8 GiB/100,000-entry workspace checks. Live quota checks tolerate Dune's
RPC socket and disappearing temporary files; the final inventory is strict.
These are bounded checks, not an instantaneous filesystem quota or hermetic
host/descendant-process attestation. Selected dependency trees are switch
`bin`/`lib` and prefix `include`/`lib`, with 13 additional metadata/tool files.
System libraries and the entire host environment are not claimed as a closure.

The receipt contains 30,847 artifact entries: 23,241 files, 1,416 directories and
6,190 symlinks, with 964,503,808 regular-file bytes. Its private native executable
is `baseline-1/dune-build/default/src/init/boot/empty_file.exe`, SHA256
`e14caa0a3b5938a70ade4d85942444bbf73532a2a0a2c323b6d181246dd122ef`.
Symlink targets are retained as link text, not counted as additional file bytes.

## Completed early runtime checks

[check_runtime.py](check_runtime.py) ran from 02:00:10.450111 to
02:00:15.979615 UTC. Its [receipt](runtime-1/receipt.json) records five exit-zero,
terminal queries, exact output agreement and no input drift. Every completed
build artifact and the selected build dependencies were rechecked before/after.

The five queries are `-version`, `-print-config`, `-print-share-path`,
`-print-lib-path` and `-print-plugin-path`. They exit during the early command
stage, before plugin loading or C analysis. The uninstalled executable's Dune
site placeholders require the explicit environment retained in each
[command intent](runtime-1/command-01/intent.json); running the bare executable
without it is not the checked invocation. OCaml dependencies still come from
the existing switch, while all three reported Frama-C sites are private:

```text
baseline-1/dune-build/install/default/share/frama-c/share
baseline-1/dune-build/install/default/lib/frama-c/lib
baseline-1/dune-build/install/default/lib/frama-c/plugins
```

These path results do not prove which plugins/libraries a later analysis loads.
The separate status is `private-early-runtime-paths-checked-not-analysis-validated`;
the original build receipt is preserved unchanged. Neither receipt activates a
profile or alters the candidate machine description.

## Recorded invocations and next work

Working directory was `/home/karl/linux-work/fragma`:

```sh
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B build/framac-alignment-provider-20260907/build_baseline.py \
  --output /home/karl/linux-work/fragma/build/framac-alignment-provider-20260907/baseline-1
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B build/framac-alignment-provider-20260907/check_runtime.py \
  --output /home/karl/linux-work/fragma/build/framac-alignment-provider-20260907/runtime-1
```

These are completed invocation records, not commands to overwrite their outputs.
The runtime reader deliberately pins this particular build receipt and helper.

Next, use a new authenticated source/build location for an explicitly selected
alignment policy and the typing/query corrections; do not patch this completed
baseline or the verified installation. Preserve source attributes and the
unchanged local-static-initializer case. Validate actual private parsing/plugin
selection, diagnostic controls, the full context matrix, `max_align_t` controls
and genuine-kernel model checks before normal-pipeline integration and proofs.
No alignment semantics have yet been changed by this build milestone.

| Record | SHA256 |
| --- | --- |
| Build recorder | `3181b7c935cc03b31ba9c4232176b5e7e4fda794c0f013f31692cfe1f4e3e7c7` |
| Build receipt | `deb25b14d6add7d7f01bf0a10e52bbe53ff6864e69a051ad68eb0d07ba111836` |
| Runtime reader | `a3efe12a4c1b5d61cadc4c7d3b19646979d4d3524547928a008e2db127de8862` |
| Runtime receipt | `70bb175d11c4454cabf6443fa0a1516f1c2b52ce0cc7ea9a893523f19d98b591` |
