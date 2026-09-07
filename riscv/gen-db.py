#!/usr/bin/env python3
"""riscv whole-file compile-db generator for the RTE sweep.

    gen-db.py <basename-or-suffix source.c> [...]

Pulls each target's real cross-compile command from compile_commands.raw.json
(generated from ~/linux-work/riscv-syz-nolto, source tree linux-7.2-rc4-clean),
injects the Frama-C 33 shims + override headers, writes riscv/sweep-db.json.

riscv64 Linux is LP64 => -machdep gcc_x86_64 models integer widths exactly.
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
         " -D__uint128_t=unsigned __int128"
         " -D__int128_t=__int128"
         " -D__riscv"
         " -D__riscv_xlen=64"
         " -std=gnu11")

def entry_for(target):
    e = next((x for x in db if x["file"].endswith(target)), None)
    if e is None:
        sys.exit(f"no compile command for {target}")
    cmd, src = e["command"], e["file"]
    idx = cmd.index(" -I")
    cmd = cmd[:idx] + f" -I{os.path.join(HERE, 'override')}" \
                    + f" -I{os.path.join(fragma, 'arm64', 'override')}" + cmd[idx:]
    cmd += (f" -include {os.path.join(shared, 'specs.h')}"
            f" -include {os.path.join(shared, 'compat.h')}")
    cmd += SHIMS
    return {"directory": e["directory"], "command": cmd, "file": src}

out = [entry_for(t) for t in sys.argv[1:]]
with open(os.path.join(HERE, "sweep-db.json"), "w") as f:
    json.dump(out, f, indent=1)
print(f"wrote riscv/sweep-db.json ({len(out)} target(s)); src {out[0]['file']}")
