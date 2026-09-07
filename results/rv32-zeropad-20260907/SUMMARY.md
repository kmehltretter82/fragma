# RV32 `load_unaligned_zeropad()` A/B audit

Overall audit: **PASS**

The unpatched kernel returned bytes from the preceding word in all three
guard-page cases. The patched kernel passed the same KUnit case under a
byte-identical configuration.
All 98 recorded checks passed.

| Remaining mapped bytes | Expected | Before | Before status | After status |
|---:|---:|---:|---|---|
| 1 | `0x44` | `0xa5` | fail | pass |
| 2 | `0x4433` | `0xa5a5` | fail | pass |
| 3 | `0x443322` | `0xa5a5a5` | fail | pass |

A-side suite: **not ok**; B-side suite: **ok**.

Base: `df2908090cda368b01ff43709f51890076c56157` (v7.3-rc2)
Submission commit: `7fe4d4e77ee4f57046785b82918ce72cce7507e5`
Stable patch-id: `1e15327041a5d49a362302ac8826bf9296aa6039`

The submission patch passes strict `checkpatch.pl`, applies cleanly to the
recorded mainline and linux-next commits, and has an RV64 compile control.
The later no-rootfs panic in each log occurs after KUnit and is not a test
failure. Raw images, configurations, logs, objects, and the source clone
remain local; their pinned SHA-256 identities are in `pilot-audit.json`.
The patch is send-ready but has not been emailed or maintainer-acknowledged.
