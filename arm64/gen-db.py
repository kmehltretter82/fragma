#!/usr/bin/env python3
"""arm64 whole-file compile-db generator for the broad RTE sweep.

    gen-db.py <tree-relative source.c> [...]

Pulls each target's real cross-compile command from compile_commands.raw.json
(generated from ~/linux-work/arm64-build), injects the same Frama-C 33 shims +
override headers used by the lib/string.c rig, and writes arm64/sweep-db.json.

Note: arm64 Linux is LP64, so `-machdep gcc_x86_64` (also LP64) models every
integer width identically; the only ABI difference is char signedness, which
none of the u32/u64 bit-arithmetic targets depend on.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
fragma = os.path.dirname(HERE)
shared = os.path.join(fragma, "annotated")
db = json.load(open(os.path.join(HERE, "compile_commands.raw.json")))

SHIMS = (" -D__builtin_memcpy=memcpy"
         " -D__typeof_unqual__=__typeof__"
         " -D__restrict__=restrict"
         " -D__SIZEOF_INT128__=16"
         " -D__signed__="
         " -D__builtin_unreachable=fragma_unreachable"
         " -D__aarch64__"
         " -D__uint128_t=unsigned __int128"
         " -D__int128_t=__int128"
         " -std=gnu11")

def entry_for(target):
    e = next((x for x in db if x["file"].endswith(target)), None)
    if e is None:
        sys.exit(f"no compile command for {target}")
    cmd, src = e["command"], e["file"]
    idx = cmd.index(" -I")
    cmd = cmd[:idx] + f" -I{os.path.join(HERE, 'override')}" + cmd[idx:]
    cmd += (f" -include {os.path.join(shared, 'specs.h')}"
            f" -include {os.path.join(shared, 'compat.h')}")
    cmd += SHIMS
    return {"directory": e["directory"], "command": cmd, "file": src}

out = [entry_for(t) for t in sys.argv[1:]]
with open(os.path.join(HERE, "sweep-db.json"), "w") as f:
    json.dump(out, f, indent=1)
print(f"wrote arm64/sweep-db.json ({len(out)} target(s))")
