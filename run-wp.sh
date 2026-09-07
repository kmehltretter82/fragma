#!/bin/bash
# Uniform Frama-C invocation for the annotated kernel TU.
#   run-wp.sh                          -> parse only
#   run-wp.sh strnchr,strlcat         -> WP + RTE on those functions
#   run-wp.sh strlcat -wp-prop=xyz ... -> extra args passed through
#
# -cpp-extra-args=-std=gnu11 is LOAD-BEARING: frama-c's -compilation-db only
# extracts -I/-D/-include from the db command, and frama-c's own -std=c11
# disables GNU ", ## arg" comma deletion, which x86 rmwcc.h relies on.
set -eu
cd "$(dirname "$(readlink -f "$0")")"
export PATH=$HOME/.local/bin:$PATH LD_LIBRARY_PATH=$HOME/.local/lib
eval "$(opam env --switch=fragma --set-switch)"

FC=(frama-c -compilation-db annotated/compile_commands.json
    -machdep gcc_x86_64 -cpp-extra-args=-std=gnu11
    ${FRAGMA_FILE:-annotated/string.acsl.c})

if [ $# -eq 0 ]; then
    exec "${FC[@]}" -print -ocode /dev/null
fi

FCT=$1; shift
exec "${FC[@]}" -wp -wp-fct "$FCT" -wp-rte -wp-split \
     -wp-prover alt-ergo,cvc5 -wp-timeout 45 -wp-par 8 "$@"
