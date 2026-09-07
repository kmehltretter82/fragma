#!/bin/sh
# Explicit, isolated setup. With no --apply, print the plan without writing.
set -eu
FRAGMA_SETUP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$FRAGMA_SETUP_DIR/setup.py" "$@"
