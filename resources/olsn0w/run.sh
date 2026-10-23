#!/bin/sh
set -eu
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
    sh "$source_dir/setup.sh" --host-only
fi
exec python3 "$source_dir/olsn0w.py" "$@"
