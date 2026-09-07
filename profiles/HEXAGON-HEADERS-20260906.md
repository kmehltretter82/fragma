# Hexagon generator-header research — 2026-09-06

Status: a genuine Hexagon libc source selection is resolved to an exact commit,
but its source/header closure and compatibility with the pinned Frama-C generator
are not yet validated. This note does not activate a profile or award L1/L2/L3.
Official recipe/tag metadata was fetched read-only. No source archive or binary
toolchain was downloaded, no headers were installed, and no compiler, analyzer,
or target program was run for this research.

## Preferred source route and provenance limits

Qualcomm maintains [quic/musl](https://github.com/quic/musl), a musl fork for
Hexagon. Qualcomm's current [toolchain build recipe](https://github.com/qualcomm/toolchain_for_hexagon/blob/main/build-toolchain.sh)
contains a separate `build_musl_headers` stage: configure for `hexagon`, then
`make install-headers`. Its Linux target sysroot is
`target/hexagon-unknown-linux-musl/usr`. This is a target-libc header route, not
host ABI substitution or the commercial QuRT SDK.

The [v21.1.8 release listing](https://github.com/qualcomm/toolchain_for_hexagon/releases)
links toolchain-recipe commit `690674c053a1cded5d4fc8db9864fdb073299a1b`.
Its [pinned Dockerfile](https://github.com/qualcomm/toolchain_for_hexagon/blob/690674c053a1cded5d4fc8db9864fdb073299a1b/Dockerfile),
subsequently retrieved read-only after browser cache misses, selects
`https://github.com/quic/musl/archive/hexagon-v1.2.4-dec-2025.tar.gz`.
The official [tag reference](https://api.github.com/repos/quic/musl/git/ref/tags/hexagon-v1.2.4-dec-2025)
resolves to annotated tag object `25ad729940d704662790093c65175db497d98827`;
the [tag object](https://api.github.com/repos/quic/musl/git/tags/25ad729940d704662790093c65175db497d98827)
selects musl commit `6d7621470acf277cbb00550655ed7140d3e4cff9`; the tagger timestamp
is 2025-12-15T16:46:16Z. The API reports no verified signature (`verified: false`,
reason `unsigned`). This establishes the observed upstream source selection,
not cryptographic release-signature verification or archive-byte authentication.

The source archive and complete selected header closure have **not** been fetched
or validated. There is no archive checksum or installed sysroot receipt yet.
The installed system LLVM 21.1.8 and Qualcomm's complete v21.1.8 toolchain are not
assumed interchangeable merely because their LLVM version numbers match.

The three HTTP-200 metadata responses are retained in
[`capture-1`](../build/hexagon-header-source-metadata-20260906/capture-1/receipt.json),
received 2026-09-06 20:39:02 UTC. Independent readback matched these SHA-256 values:

| Retained input | SHA-256 |
| --- | --- |
| `Dockerfile` | `5cad5009955db742feda2288cf981e7b464394b6a3c4b78b64270208e985128c` |
| `tag-ref.json` | `3fde4f335ca8b107a1b1a4a49c9288d9e50efea473a7cad7e9605bec4612c38c` |
| `tag-object.json` | `895c7b68ccc9afc73613d94dd6380f464d3cdbf14f241a0ace564f748a72c044` |
| `receipt.json` | `3e88b660380f9a28b052842e1f17c62ff5fae094bd3964a7983b66a35e995b20` |
| `../capture.py` | `b4d7d6a306c68c7fb0ee004e5c1f504d6cf08a83e41785c7bb496f63b8db8966` |

The inspected capture script fetches only those three documents, checks the
recipe/tag linkage, and records the no-archive/no-install/no-execution boundary.
These local hashes authenticate the retained observations, not an upstream
signature or the still-unfetched source archive.

There is an independently attributable historical musl pin:
`aff74b395fbf59cd7e93b3691905aa1af6c0778c`. It appears in Qualcomm maintainer
Brian Cain's [2021 toolchain manifest](https://lists.gnu.org/archive/html/qemu-devel/2021-07/msg04801.html)
and QEMU's [former Hexagon header-build recipe](https://lists.gnu.org/archive/html/qemu-devel/2022-12/msg03775.html).
Those references establish historical provenance, not suitability of that older
revision for this workspace's LLVM 21.1.8 generator context.

The fork's [Makefile](https://github.com/quic/musl/blob/master/Makefile) separates
`install-headers` from libc objects. Header construction combines common headers,
architecture-specific and generic `bits` headers, and generated `alltypes.h` and
`syscall.h`. The exact selected source must be inspected and authenticated before
implementing a workspace-local header-only provisioner; running the complete
toolchain build script is not required for this proposed scope.

## Installed generator requirements

The inspected installed helper is
`toolchain/verified-prefix/opam/fragma/lib/frama-c/lib/make_machdep/make_machdep.py`
(481 lines), SHA-256
`889d3ca26ea964aebcc2e9a1c2fe5ccab3f064b29fd8c69f7c90678d7b2dd6bf`.
Its schema is
`toolchain/verified-prefix/opam/fragma/share/frama-c/share/machdeps/machdep-schema.yaml`,
SHA-256 `ce8de93d93cc3bfbd8ad843bd6b44dd3f89ac5bd981f48b93433006b1fa34400`.

The fixed standard probe inventory includes these twelve headers:

`errno.h`, `features.h`, `limits.h`, `signal.h`, `stddef.h`, `stdint.h`,
`stdio.h`, `stdlib.h`, `sys/types.h`, `time.h`, `unistd.h`, `wchar.h`.

Type/layout probes require genuine declarations, including `ssize_t`, `time_t`,
`wint_t`, `sig_atomic_t`, and integer typedefs. Macro probes use preprocessing;
the generator does not execute target programs. Its only optional schema fields
are twelve GCC-specific alignment entries. There is no kernel-only probe mode.
`--from-file` recovers compiler/architecture settings, not supplied replacement
values for missing probes. Manual YAML editing is mentioned upstream, but is
not compiler-derived evidence and does not satisfy this project's current gate.

Schema permission for an empty non-POSIX field is not equivalent to successful
generation: an absent macro generally leaves its field unset, and helper lines
473–479 issue a missing-field warning before filling defaults. The project rejects
generator stderr. Likewise, `wordsize.c:9` unconditionally includes `features.h`;
its optional `bits/reg.h` inclusion cannot rescue a missing top-level header.

## Concrete issues to resolve before provisioning or promotion

1. Preserve the selected recipe/tag metadata above, then authenticate the source
   archive against the resolved musl commit and inspect the complete twelve-header
   and generated-header dependency closure. The release's compiler version alone
   is insufficient source provenance; a resolved tag does not authenticate an
   unexamined archive or header installation.
2. Establish `__WORDSIZE` from that genuine source. The published
   [Hexagon port RFC](https://www.openwall.com/lists/musl/2023/08/30/3) lists no
   added `bits/reg.h`, and the local standard musl 1.2.5 archive contains no generic
   `bits/reg.h`. This is a prerequisite to inspect, not proof that the current
   Qualcomm fork lacks every possible definition. Do not synthesize a value just
   to suppress a generator warning.
3. Review the actual compiler/header ordering under unchanged kernel flags.
   Installed Clang 21 `include/limits.h:24` and `include/stdint.h:24` only use
   `include_next` when `__STDC_HOSTED__` is true. With `-ffreestanding`, copying the
   existing GCC/RISC-V builtin-first route hides target POSIX limits, uses Clang's
   own fast-integer typedefs, and gives builtin `MB_LEN_MAX` a default of 1.
   Simply adding `_POSIX_C_SOURCE` does not change that header selection.
4. Target-musl-first ordering may preserve `-fshort-wchar` without an adapter:
   the original Hexagon port conditionally derives `wchar_t` from
   `__WCHAR_TYPE__`, as shown in the [primary maintainer discussion](https://www.openwall.com/lists/musl/2020/09/17/2).
   Confirm this in the exact selected revision rather than assuming generic musl
   behavior or transferring a historical header implementation unchanged.
5. Require retained, warning-free generator output and independently checked
   model fields, then fresh genuine configured-kernel type/layout calibration.
   Keep the generator-only libc metadata scope separate from actual kernel
   analysis, which uses pinned kernel headers with `-nostdinc`; no libc runtime,
   QuRT, whole-kernel, or hardware claim follows.

## Alternatives not cleared

The locally pinned standard musl 1.2.5 archive has no Hexagon architecture.
Installed Clang builtin headers alone do not supply the twelve-header inventory.
The installed Newlib 4.6.0 headers have `sys/features.h`, but no top-level
`features.h` and no authenticated Hexagon target-header provision receipt.
Feature-test macro definitions do not fix that missing include. These local
routes are not substitutes for an authenticated Hexagon libc header set.

A kernel-only generator would be new, separately reviewed model-generation work:
the installed upstream helper provides no such route, and dropping POSIX probes
or borrowing host fields would not be a faithful use of its current pipeline.
The intentional Clang generator-header gate remains closed pending the work above.
