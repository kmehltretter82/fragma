#!/usr/bin/env python3
"""Generate annotated/compile_commands.json: take the kernel's real compile
command for lib/string.c from ../compile_commands.json, retarget it at the
annotated copy, force-include specs.h (extern-function contracts) and
compat.h (front-end shims), and add Frama-C 33 compatibility flags."""
import json, os

fragma = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db = json.load(open(os.path.join(fragma, "compile_commands.json")))
entry = next(e for e in db if e["file"].endswith("lib/string.c"))

annotated = os.path.join(fragma, "annotated", "string.acsl.c")
specs = os.path.join(fragma, "annotated", "specs.h")
compat = os.path.join(fragma, "annotated", "compat.h")
override = os.path.join(fragma, "annotated", "override")

cmd = entry["command"]
src = entry["file"]
assert src in cmd, f"source path {src} not in command"
cmd = cmd.replace(src, annotated)

# Header override dir (doctored asm/string_64.h: C23 "auto" -> __typeof__)
# must be searched BEFORE the kernel's arch include dirs.
idx = cmd.index(" -I")
cmd = cmd[:idx] + f" -I{override}" + cmd[idx:]

cmd += f" -include {specs} -include {compat}"
# Frama-C 33 front-end compatibility shims for kernel-used GCC/C23 features:
#  __builtin_memcpy -> memcpy            so the ACSL contract in specs.h applies
#  __typeof_unqual__ -> __typeof__       only re-adds qualifiers (conservative)
#  __restrict__ -> restrict              spelling Frama-C accepts
#  __SIZEOF_INT128__                     machdep value doesn't survive -undef;
#                                        needed for the kernel's u128 typedefs
#  -std=gnu11                            kernel dialect; Frama-C's own -std=c11
#                                        would disable ", ## arg" comma deletion
cmd += (" -D__builtin_memcpy=memcpy"
        " -D__typeof_unqual__=__typeof__"
        " -D__restrict__=restrict"
        " -D__SIZEOF_INT128__=16"
        " -D__signed__="
        " -D__builtin_unreachable=fragma_unreachable"
        " -std=gnu11")

out = [{"directory": entry["directory"], "command": cmd, "file": annotated}]
# same flags for the generated analysis variants (see gen-variants.sh)
for v in ("string.eva.c", "string.fault.c"):
    vpath = os.path.join(fragma, "annotated", v)
    out.append({"directory": entry["directory"],
                "command": cmd.replace(annotated, vpath), "file": vpath})
with open(os.path.join(fragma, "annotated", "compile_commands.json"), "w") as f:
    json.dump(out, f, indent=1)
print("wrote annotated/compile_commands.json")
