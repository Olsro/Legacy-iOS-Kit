#!/bin/sh
# Restart bounded probes when GraphicsServices has not published capabilities.
set -eu
probe_file=/private/var/run/olsn0w-gssc.$$.txt
trap '/bin/rm -f "$probe_file"' EXIT
attempt=0
while [ "$attempt" -lt 60 ]; do
    /usr/bin/gssc > "$probe_file" 2>&1 &
    probe_pid=$!
    /bin/sleep 1
    ready=0
    case "$(/bin/cat "$probe_file")" in \{*) ready=1;; esac
    kill -TERM "$probe_pid" 2>/dev/null || :
    wait "$probe_pid" 2>/dev/null || :
    [ "$ready" = 0 ] || exit 0
    attempt=$((attempt+1))
done
echo 'olsn0w: GraphicsServices readiness timed out' >&2
exit 1
