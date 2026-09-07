#!/bin/bash
# Verify named declarators and full bodies, including nested braces, against
# the working source. TREE retains its historical meaning: the MPI directory.
# KERNEL_REVISION selects immutable git source from the containing kernel tree.
set -euo pipefail
HERE=$(dirname "$(readlink -f "$0")")
TREE=${TREE:-${KERNEL_TREE:-$HERE/../../linux}/lib/crypto/mpi}
revision_args=()
source_prefix=
if [[ -n ${KERNEL_REVISION:-} ]]; then
    kernel_root=$(git -C "$TREE" rev-parse --show-toplevel)
    mpi_relative=$(git -C "$TREE" rev-parse --show-prefix)
    TREE=$kernel_root
    source_prefix=$mpi_relative
    revision_args=(--revision "$KERNEL_REVISION")
fi

check() {
	local name=$1 tree_file=$2 harness=$3
	python3 "$HERE/../fragma/provenance.py" \
		--kernel-tree "$TREE" --root "$HERE" \
		--source "$source_prefix$tree_file" --harness "annotated/$harness" \
		--mode functions --function "$name" "${revision_args[@]}"
}

check mpihelp_rshift generic_mpih-rshift.c mpih-rshift.acsl.c
if [[ -f "$HERE/annotated/mpih-lshift.acsl.c" ]]; then
	check mpihelp_lshift generic_mpih-lshift.c mpih-lshift.acsl.c
fi
