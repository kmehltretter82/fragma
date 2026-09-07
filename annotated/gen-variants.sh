#!/bin/bash
# Generate analysis variants of the annotated TU (never edited by hand):
#   string.eva.c   - naive_no_truncation ensures stripped, so EVA harness runs
#                    aren't emptied by reduction over a known-false postcondition
#   string.fault.c - same, PLUS the BUG_ON guard in strlcat removed:
#                    fault injection to prove the guard is load-bearing
set -eu
cd "$(dirname "$(readlink -f "$0")")"

# strip the 2-line naive ensures clause (name + existential body)
sed '/naive_no_truncation:/,+1d' string.acsl.c > string.eva.c

# additionally remove the BUG_ON guard (fault injection), and the helper
# asserts guard_passed/copy_fits: unproven asserts are still ASSUMED by the
# goals after them, so leaving them in would absorb the collapse we want to
# demonstrate.
python3 - <<'PYEOF'
import re
src = open('string.eva.c').read()
src = src.replace('\tBUG_ON(dsize >= count);\n', '')
# drop the whole /*@ ... */ block containing these named asserts
for name in ('guard_passed', 'copy_fits'):
    src = re.sub(r'\t/\*@(?:[^*]|\*(?!/))*?assert ' + name + r'(?:[^*]|\*(?!/))*?\*/\n', '', src)
open('string.fault.c', 'w').write(src)
PYEOF

for v in string.eva.c string.fault.c; do
    grep -q naive_no_truncation $v && { echo "BAD: naive survived in $v"; exit 1; }
done
grep -q 'BUG_ON(dsize >= count)' string.eva.c   || { echo "BAD: eva variant lost BUG_ON"; exit 1; }
grep -q 'BUG_ON(dsize >= count)' string.fault.c && { echo "BAD: fault variant kept BUG_ON"; exit 1; }
echo "variants OK: string.eva.c (naive stripped), string.fault.c (naive+BUG_ON stripped)"
