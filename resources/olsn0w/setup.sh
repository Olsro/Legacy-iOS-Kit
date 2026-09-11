#!/bin/sh
set -eu
kit=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 -c 'import sys; sys.exit("olsn0w requires Python 3.8 or newer") if sys.version_info < (3, 8) else None'
runtime="$kit/saved/olsn0w/runtime"
python3 -m venv "$runtime"
"$runtime/bin/python" -m pip install -r "$kit/resources/olsn0w/requirements.txt"
