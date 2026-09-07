# Locked toolchain and preflight

The accepted dependency inventory is [lock.json](../toolchain/lock.json).
It pins Frama-C 33.0, Why3 1.8.2, Alt-Ergo 2.6.3, CVC5 1.3.4,
Z3 4.13.4, opam 2.5.0, OCaml 5.2.1, and GCC 15.2.0. The full
[historical opam export](../toolchain/opam-switch.export) pins all 90 originally
installed packages. The original installation failed its `conf-graphviz.0.1`
post dependency because `dot` was unavailable. The separate
[complete export](../toolchain/opam-switch.complete.export) pins those same
packages plus that post dependency for a clean 91-package installation. Both
exports embed package definitions, source URLs, archive checksums and build
instructions. Preflight recognizes only those two exact package sets and
reports `historical-analysis` or `complete`; extra packages do not silently pass.

Preflight is read-only and never installs anything:

```sh
python3 -m fragma.toolchain
python3 -m fragma.toolchain --switch-prefix '/path/to/installed switch'
python3 -m unittest discover -s tests -p test_toolchain.py -v
```

The JSON output reports every tool's resolved path, command, version, executable
SHA-256 and status, required Frama-C components, the entire installed opam
package set, package-definition hashes, full-export hash, and effective search
paths. Its runtime receipt hashes native shared libraries, compiler frontends,
assemblers/linkers, and every installed Frama-C/Why3 support file. A missing tool,
wrong version/target, changed prebuilt binary, changed
package set, missing component, or missing/modified export produces failure.
Cross-compilers are optional capabilities at global preflight; the selected
architecture profile must separately require its compiler.

Discovery first honors `--switch-prefix` / `FRAGMA_SWITCH_PREFIX`, then checks
the workspace installation at `toolchain/prefix/opam/fragma`, and finally the
historical named switch at `$HOME/.opam/fragma`. Set `FRAGMA_TOOLCHAIN_PREFIX`
to choose a GMP/prover prefix. An explicit selection does not fall back to a
different switch. `FRAGMA_TOOL_FRAMA_C`, `FRAGMA_TOOL_GCC`, and the equivalent
uppercase, underscore-separated executable variables select individual binaries;
they still have to pass the lock checks. The parent process environment is
copied, never changed. Shell evaluation of `opam env` is unnecessary.

For Python callers:

```python
from pathlib import Path
import subprocess
from fragma.toolchain import inventory, prepare_environment

root = Path('/path/to/fragma')
env = prepare_environment(root)
checked = inventory(root, env)
if not checked['ok']:
    raise RuntimeError(checked['issues'])
subprocess.run([checked['tools']['frama-c']['path'],
               '-wp-why3-config', str(root / 'toolchain/why3.conf'),
               '-wp-no-why3-detect', '-wp-list-provers'],
               env=env, check=True)
```

Use the checked [Why3 configuration](../toolchain/why3.conf) with
`-wp-why3-config /path/to/fragma/toolchain/why3.conf -wp-no-why3-detect` for WP.
This selects the actual pinned versions and resolves commands using the checked
`PATH`. Preflight verifies the configuration hash and required prover visibility.
It never changes a user's global Why3 configuration. Overrides of solver binary
paths that do not match the commands on `PATH` are rejected.

Why3 1.8.2 automatic CVC5 detection expects the old `This is cvc5 version`
banner and versions 1.0–1.2. Installed CVC5 1.3.4 uses `cvc5 1.3.4`, so automatic
detection omits it from WP. The explicit configuration uses the existing `cvc5`
driver with the actual version. The bounded [driver calibration](../toolchain/prover-calibration.mlw)
returned `Valid` for `x + 1 > x` and `Unknown (sat)` for the deliberately false
`x + 1 = x`. The latter is the driver's classification of a satisfiable negation,
not a kernel defect or a timeout. Compatibility beyond this small calibration
remains an explicit tool assumption. Direct Why3 execution uses a local Unix
socket; an environment that prohibits it must report that runtime restriction.

## Setup at another location

The bootstrap currently supports a Linux x86_64 host; analysis targets may use
cross-compilers. Python 3.12+, the pinned host GCC, make, pkg-config, patch,
tar, bzip2, unzip, git, dpkg-deb, and the native development dependencies needed by opam
packages must be installed first. System-package installation is explicit and
outside this bootstrap. The original host's distribution package versions and
runtime-library hashes are recorded in the lock.

Preview the exact paths, artifact URLs and hashes, and installation stages:

```sh
./toolchain/install.sh --prefix /scratch/fragma-tools \
  --build-dir /scratch/fragma-build --download-cache /scratch/fragma-downloads
```

Then run the same command with `--apply` to install. `--kernel /path/to/linux`
optionally checks source availability; setup does not modify kernel sources.
`--jobs` sets build parallelism. All destinations are configurable without
editing a script. Existing nonempty install prefixes are rejected; use a new
prefix for updates. Failed downloads/builds are retained for diagnosis. The
matching `--resume --apply` command resumes only a prefix carrying a setup marker
for the same accepted lock. It refuses arbitrary existing installations or a
lock that changed since the attempt. Commands and outputs are retained in the
build attempt's `setup.log`; successful setup writes `setup-report.json` in the
installation prefix.

Setup verifies SHA-256 before executing or extracting downloaded artifacts,
builds and tests GMP 6.3.0 using GNU C17, creates a separate opam root, and imports
the complete export with `--require-checksums --no-depexts`. It uses an empty local
repository: every required package definition comes from the pinned full export,
so setup does not depend on a moving repository index. An optional
`--opam-download-cache /path/to/existing/download-cache` copies source archives
read-only into the new opam root; opam still verifies their checksums. Setup
extracts six pinned Ubuntu Graphviz artifacts inside the prefix solely to
provide `dot -V` for `conf-graphviz`. The native host must meet their listed libc,
expat, libltdl and zlib dependencies. Graph rendering plugins are not included or
claimed functional. Setup does not edit shell
startup files or upgrade a user's existing switch. Its final check is the same
preflight used for analysis. To use the resulting installation:

```sh
FRAGMA_TOOLCHAIN_PREFIX=/scratch/fragma-tools \
  python3 -m fragma.toolchain
```

The wrapper and discovery tests exercise paths containing spaces. A complete
native/opam rebuild in a prefix containing spaces has not been validated;
upstream package build scripts can impose additional restrictions.

## Updating a pin

Build and validate a new, isolated toolchain. Export it with opam's
`switch export --full --readonly` and review the replacement of
`toolchain/opam-switch.export`. Run `python3 toolchain/capture-lock.py
--switch-prefix /path/to/new/switch` to print a candidate lock; this command
does not replace the accepted lock. Review versions, complete package set,
source definitions, URLs/checksums, compiler targets, and limitations before
accepting changes. Refresh bootstrap URLs in the capture script when versions
change. Re-run a clean full proof suite and explain changed obligations before
accepting a new proof baseline. Actual binary and package-definition hashes
belong in every run identity, even when a same-version rebuild is expected.

## Current limits

The observed local download hashes pin bytes but have not been independently
authenticated against upstream signatures. The export embeds all package
definitions but does not vendor every source archive. Host compiler versions
are enforced and executable/library hashes are recorded; a hermetic operating
system image and all compiler source/build dependencies are not yet supplied.
Rebuilt OCaml executables can differ because they contain build paths, so only
prebuilt opam/CVC5/Z3 require exact executable hash matches. Installed package
definitions are hashed as run inputs; their raw formatting can differ after
an opam import and is not compared byte-for-byte with the original installation.

The initial preflight passed against the existing toolchain on 2026-09-05.
On 2026-09-06, a clean 91-package installation completed at
`toolchain/verified-prefix`, using verified source archives and the complete
export. The [setup report](../toolchain/verified-prefix/setup-report.json) and
[persistent build log](../toolchain/verified-build/fragma-setup-1n1vr87d/setup.log)
record the result. GMP's tests reported 177 passes, one skipped native helper
test, and no failures/errors; see [the test receipt](../toolchain/gmp-check.reference.json).

A second [preflight with a stripped environment](../toolchain/verified-prefix/clean-environment-report.json)
passed without the old switch or user-local binaries on `PATH`. The
[clean solver calibration](../toolchain/verified-prefix/clean-prover-calibration.json)
matched the historical positive/negative results. This establishes the clean
toolchain installation and bounded driver check. Replay of the full selected
kernel suite under that installation is a separate acceptance check; these
artifacts do not establish every kernel proof's reproducibility.
