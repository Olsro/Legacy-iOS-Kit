#!/bin/sh
set -eu
/usr/local/libexec/olsn0w/guard-target.sh
exec /private/var/aquila/aquila "$@"
