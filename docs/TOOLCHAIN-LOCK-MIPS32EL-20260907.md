# Toolchain-lock extension for MIPS32el

Status: **additive lock extension checked; normal preflight passed**.

Registering `mips32el-clang` changes the central lock identity from
`0d3557b20e4a0ed16e6a4fe8622aa3ecd1572b9b30d490c7c69b4be82d7f47cb` to
`9dd17cba107f42c860360d693dbb8e8d956d9c22197ae753154b2d6f97377fe5`.
A structural comparison against the preceding Git revision found exactly one
new key, `clang-21`: all 18 preceding tool records are byte-for-byte equal,
with no changed or removed record. The new entry binds Clang 21.1.8, its
resolved binary and resource-header tree, and the exact little-endian O32
MIPS32r2 soft-float target arguments.

The normal workspace-local preflight returns `ok: true`, no issues, and the
new lock hash. The target-review manifests now bind that hash so future proof
runs cannot silently use the old context. This is a metadata re-attestation of
an additive lock delta, not a replay of prior proofs: retained proof results
continue to carry their original target definitions and project identity and
must be rerun before a current-identity coverage matrix can call them fresh.

No compiler, analyzer, package or system file was installed, and no `sudo`
command was used.
