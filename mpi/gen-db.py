#!/usr/bin/env python3
"""Generic annotated-TU compile-db generator.

    gen-db.py <tree-relative-or-absolute source.c> [<source2.c> ...]

For each target, take the kernel's real compile command from
../compile_commands.json and produce an entry that:
  * points at the annotated copy under mpi/annotated/<basename> if one exists,
    else at the original tree file (RTE-only mode needs no annotations);
  * injects the front-end overrides and Frama-C 33 shims (shared with the
    lib/string.c rig; see ../annotated/gen-db.py for the rationale of each).
Writes mpi/compile_commands.json.
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
fragma = os.path.dirname(HERE)
db = json.load(open(os.path.join(fragma, "compile_commands.json")))
shared = os.path.join(fragma, "annotated")   # reuse specs.h/compat.h/override

SHIMS = (" -D__builtin_memcpy=memcpy"
         " -D__typeof_unqual__=__typeof__"
         " -D__restrict__=restrict"
         " -D__SIZEOF_INT128__=16"
         " -D__signed__="
         " -D__builtin_unreachable=fragma_unreachable"
         " -std=gnu11")

def entry_for(target):
    e = next((x for x in db if x["file"].endswith(target) or x["file"] == target),
             None)
    if e is None:
        sys.exit(f"no compile command for {target}")
    cmd, src = e["command"], e["file"]
    base = os.path.basename(src)
    annotated = os.path.join(HERE, "annotated", base)
    use = annotated if os.path.exists(annotated) else src
    cmd = cmd.replace(src, use)
    # override include dir must precede the kernel arch includes
    idx = cmd.index(" -I")
    cmd = cmd[:idx] + f" -I{os.path.join(shared, 'override')}" + cmd[idx:]
    cmd += (f" -include {os.path.join(shared, 'specs.h')}"
            f" -include {os.path.join(shared, 'compat.h')}")
    cmd += SHIMS
    return {"directory": e["directory"], "command": cmd, "file": use}

out = [entry_for(t) for t in sys.argv[1:]]
with open(os.path.join(HERE, "compile_commands.json"), "w") as f:
    json.dump(out, f, indent=1)
print(f"wrote mpi/compile_commands.json ({len(out)} target(s))")
for o in out:
    print("  ->", o["file"])
