#!/bin/bash
# Compare the complete C preprocessing-token stream and require exactly one
# definition of each intended function. Missing/invalid input fails closed.
# KERNEL_REVISION selects an immutable git blob; omit it to check working files.
set -euo pipefail
HERE=$(dirname "$(readlink -f "$0")")
TREE=${TREE:-${KERNEL_TREE:-$HERE/../../linux}}
revision_args=()
if [[ -n ${KERNEL_REVISION:-} ]]; then
    revision_args=(--revision "$KERNEL_REVISION")
fi
exec python3 "$HERE/../fragma/provenance.py" \
    --kernel-tree "$TREE" --root "$HERE" \
    --source lib/string.c --harness string.acsl.c \
    --mode translation-unit --function strnchr --function strlcat \
    "${revision_args[@]}"
