# Hexagon target-header provisioning and generator compatibility

2026-09-06. This continues the [source-selection research](HEXAGON-HEADERS-20260906.md)
and [Clang interface milestone](CLANG-INTERFACE-20260906.md). Header-source identity
is now verified beyond the earlier tag metadata, and 217 genuine headers have
been provisioned and independently checked. Real compiler diagnostics identify
the remaining generator-portability work. Hexagon remains
unconfigured; no L1, L2, libc runtime or whole-kernel support follows from this work.

## Source authentication

The [acquisition record](../build/hexagon-header-bringup-20260906/acquisition-1/receipt.json)
retains a source archive addressed by the exact musl commit
`6d7621470acf277cbb00550655ed7140d3e4cff9`, the corresponding Git object, and
Qualcomm's toolchain recipe at `690674c053a1cded5d4fc8db9864fdb073299a1b`.
The source archive SHA-256 is
`0e481938549bdabd255240b44b8f442c2e4fbd3fc19981dcf44c09ffa8488c1f`.
Its compressed size is 1,109,702 bytes. No complete SDK or binary toolchain was
downloaded.

The raw Git commit rehashes to the selected commit ID and names root tree
`bb4f49744f8862407ae88046d3f5228175d3068f`. An
[independent archive audit](../build/hexagon-header-bringup-20260906/source-audit-1.json)
compares every archive file's Git blob identity and executable flag with
`git ls-tree` at that exact commit. All 2,658 files and 229 directory entries
match; uncompressed file bytes total 3,592,282. There are no links or special
files. The executable sources are `configure`, `testing/test.sh`, and
`tools/install.sh`; their presence is not authorization to run all three.

The selected tag and commit provide no verified release signature. A
`Signed-off-by` line is not a cryptographic signature. The recorded archive
SHA-256 binds the actual retained bytes; Git object/tree checks bind their
contents to the observed pinned upstream selection. This is not a signed
toolchain-release or compiler-compatibility claim.

## Header-only build closure

The exact musl `Makefile`, `tools/install.sh`, `tools/mkalltypes.sed`, Hexagon
templates and common templates were inspected before source execution.
`ARCH=hexagon install-headers` requires no `configure`, compiler, linker,
libc objects, runtime, or full Qualcomm build script. It selects common headers,
Hexagon-specific `bits` headers ahead of generic ones, and these generated files:

- `bits/alltypes.h`: Hexagon and common templates processed by `mkalltypes.sed`.
- `bits/syscall.h`: the Hexagon syscall template plus its `SYS_` aliases.

The reviewed execution closure is GNU make, the shell and ordinary file tools
(`mkdir`, `sed`, `cp`, plus `cat`, `chmod`, `mv` and the temporary-file `rm` trap
in `install.sh`). The full recipe's `make clean`, SDK/kernel/runtime builds,
QEMU build and system/sysroot links are outside this header-only operation.
The [offline provisioner](setup_hexagon_musl.py) uses fresh private workspace
paths and a clean explicit environment, retaining source, generated files,
tools, commands and both output streams. Normal verification never provisions
or fetches headers implicitly.

The [actual two-stage run](../build/hexagon-header-bringup-20260906/provision-run-1/receipt.json)
completed with both commands returning zero and no input drift. The original
extraction remains pristine; installation used a separate source copy under
`build/profile-sysroots/hexagon-musl-6d7621470acf-1`. The
[sysroot receipt](../build/profile-sysroots/hexagon-musl-6d7621470acf-1/fragma-sysroot.json)
binds 217 headers, two generated headers, 55 generated directories, the complete
original source manifest and nine host tool identities. `make install-headers`
returned zero with empty stderr, running from 21:44:51 to 21:44:56 UTC.

The [independent header audit](../build/hexagon-header-bringup-20260906/header-audit-1.json)
reconstructed both generated headers in Python and every source-copy selection
directly from the authenticated archive, without importing the provisioner or
executing make. All 217 installed headers, totaling 461,704 bytes, match in
names, contents and file modes. There is no drift. Tool hashes/aliases do not
constitute a complete dynamic-library or hermetic build attestation.

The two explicit offline setup commands are:

```sh
python3 profiles/setup_hexagon_musl.py --extract-only \
  --archive build/hexagon-header-bringup-20260906/acquisition-1/musl-source.tar.gz \
  --commit-raw build/hexagon-header-bringup-20260906/acquisition-1/commit.raw \
  --output build/hexagon-header-bringup-20260906/extracted-1
python3 profiles/setup_hexagon_musl.py --install-headers \
  --extracted build/hexagon-header-bringup-20260906/extracted-1 \
  --output build/profile-sysroots/hexagon-musl-6d7621470acf-1
```

Those paths now contain retained evidence and cannot be reused as outputs.
Choose fresh paths for a repeat. The actual clean environment, exact absolute
argv, Python identity and streams are retained by the
[invocation recorder](../build/hexagon-header-bringup-20260906/provision.py).
This installs only workspace-local headers, not system packages or a libc.

## Compatibility findings from the exact source

The selected twelve-header generator closure genuinely provides the required
types and POSIX limits when `_POSIX_C_SOURCE=200809L` is explicit. The candidate
order is target-musl includes before Clang resources under `-nostdinc`, while
retaining `--target=hexagon-linux-musl`, `-mv68`, `-ffreestanding`,
`-fshort-wchar` and the selected kernel type/code-generation flags. No host
headers, hosted-mode switch or hand-filled machine fields are permitted.

Two source findings require explicit treatment before a model can be accepted:

1. The selected `include`, `arch/hexagon` and `arch/generic` trees have no
   `__WORDSIZE` definition or eligible `bits/reg.h`. Frama-C's `machdep.mli`
   defines this field as the macro's expansion, empty when undefined; it is not
   a synonym for pointer width. The unmodified generator currently reports a
   missing field before filling its default. Injecting `__WORDSIZE=32` would
   invent a macro rather than measure it.
2. Hexagon's type template derives `wchar_t` from `__WCHAR_TYPE__`, so it can
   preserve the kernel's short-wchar type. Its `stdint.h` and `wchar.h` nevertheless
   contain 32-bit `WCHAR_MIN/MAX` expressions. The upstream machine generator
   probes the type, not those two macros. Successful core type extraction would
    therefore not establish complete target-libc header/API compatibility.

The installed generator's `--check` flag is declared but unused. Its
`--check-only` schema construction also requires twelve optional GCC alignment
fields omitted for Clang. Diagnostic validation must independently check all
66 nonoptional fields and distinguish a structurally valid YAML file from
successful, warning-free field extraction. Raw per-probe compiler diagnostics
must remain available; the generator's own stderr does not contain every
underlying compiler warning.

## Actual generator and compiler diagnostics

The [diagnostic recorder](../build/hexagon-header-bringup-20260906/diagnose.py)
runs the unchanged, hash-pinned helper with transparent per-command transport
recording. It retains the unmodified YAML, every exit status and stdout/stderr,
and copies newly emitted objects before temporary files disappear. It explicitly
closes the helper's buffered output file, matching normal process-exit behavior.
Each run has a shared 180-second deadline, ten-second individual calls and
separate caps of 96 generator calls and 56 dependency/fixture calls.

Both [musl-first](../build/hexagon-header-bringup-20260906/musl-first-1/receipt.json)
and [builtin-first](../build/hexagon-header-bringup-20260906/builtin-first-1/receipt.json)
diagnostics completed: 84 generator calls and 56 additional calls each, in
12.776 and 11.822 seconds respectively. They use the same target/CPU and
kernel flags; only the two explicit `-isystem` directory positions change.
The existing genuine `lib/string.c` command contains every selected model flag.
Input inventories remain unchanged before/after. No object or target program
was executed, and no Frama-C proof or model calibration was run.

The header-order comparison observes these differences in otherwise identical
generator output:

| Field | Target musl first | Clang builtins first |
| --- | --- | --- |
| `host_name_max` | `255` | missing, defaulted empty |
| `path_max` | `4096` | missing, defaulted empty |
| `tty_name_max` | `32` | missing, defaulted empty |
| `int_fast16_t` | `int` | `short` |
| `uint_fast16_t` | `unsigned int` | `unsigned short` |
| `mb_cur_max` | `((size_t)4)` | `((size_t)1)` |

Musl-first passes the [compile-only type/layout fixture](../build/hexagon-header-bringup-20260906/types.c)
with `-Werror` and empty stderr. The object is ELF32 little-endian, machine 164,
flags `0x68`. Its retained constants show two-byte `wchar_t`, four-byte
`size_t`, eight-byte `time_t`, four-byte fast16 types, and eight-byte
long-long/max-align alignment. The actual target-libc `WCHAR_MAX` is
`4294967295`, versus compiler `__WCHAR_MAX__=65535`. The separate
[wide-character limit control](../build/hexagon-header-bringup-20260906/wchar-mismatch.c)
fails its sole named static assertion, with no object. Builtin-first fails the
type/layout fixture with six diagnostics and also retains the intended
wide-character-limit rejection. These observations do not alter either header.

All 53 distinct helper source files and the combined type fixture have
separate preprocessing/header-trace replays. Every observed include stays within
the authenticated sysroot, pinned helper files or Clang resources. The
wide-character control does not have an additional independent `-H` replay;
its source and full sysroot are bound, not a separately traced per-control graph.

Both YAML files satisfy the independently checked 66-required/12-optional-field
schema, but **neither passes the warning-free generation gate**. Musl-first
reports missing `wordsize`; builtin-first additionally reports the three POSIX
limits above. Raw compiler output also reveals ten warnings per run which the
upstream helper does not surface: a missing return in its freestanding sanity
probe, and nine uses of `-c` together with preprocessing-only `-E`. Generator
exit zero and schema validity are therefore not model acceptance.

The [independent retained-evidence audit](../build/hexagon-header-bringup-20260906/EVIDENCE-AUDIT.md)
verifies both full 140-call inventories, exact compiler outputs and warning
classes, all 54 dependency replays per run, the six YAML differences and the
two expected wide-character control failures. Its separate ELF reader confirms
the positive fixture's 48-byte constant array. It rehashes 4,584 bound paths
without drift, including 600 musl-first and 598 builtin-first retained files.
The audit executes no make, compiler, analyzer or target program. It validates
these diagnostic observations, not a supported machine model.

## Regression and next gate

All [720 regression tests](../results/tests-hexagon-headers-20260906.log) pass
in 85.011 seconds with no skips. The
[exact-command record](../results/tests-hexagon-headers-20260906.json) preserves
the prior evidence-backed environment and new frozen source/test identities.
Thirty new tests cover offline source/header provisioning with inert synthetic
archives and mocked commands. Six separate
[recorder tests](../build/hexagon-header-bringup-20260906/transport-tests-2.json)
cover transport, interruption and buffered output, without compiler execution.
The actual compiler diagnostics above are separate from those regressions.

Next, implement and review an explicit generator adapter that distinguishes an
observed undefined macro from a failed probe, uses preprocessing-only commands
without `-c`, and makes the freestanding sanity probe return explicitly. Keep
the installed upstream helper/schema and these raw baseline outputs unchanged;
do not inject a word size, switch to hosted semantics, suppress unexplained
diagnostics or rewrite YAML fields. Then integrate the authenticated target
header receipt and require full genuine-kernel L1 calibration before registration,
followed by scoped L2 proofs. The libc wide-character API limitation remains
explicitly outside the kernel model's claim.

No registry, tool lock, shared model provider or old proof receipt changed in
this milestone. The ten existing models and current coverage inventory remain
as recorded in the preceding interface milestone: 10 configured profiles,
11 planned, 31 targets, zero current proof acceptances and 25 dated acceptances.
Header preparation does not renew those proofs or establish Hexagon L1.
