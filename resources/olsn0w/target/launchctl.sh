#!/bin/sh
# The untether invokes this after its kernel and shared-cache corrections.
if { [ "$#" = 2 ] && [ "$1" = load ] && [ "$2" = /Library/LaunchDaemons ]; } ||
   { [ "$#" = 3 ] && [ "$1" = load ] && [ "$2" = -D ] && [ "$3" = all ]; }; then
    # EverUntether makes /private world-writable during its first installation.
    # Restore the prepared ancestor mode before SSH checks authorized_keys.
    /bin/chmod 755 /private || exit 1
    result=0
    # Pangu's `load -D all` only needs to register newly installed third-party
    # jobs here. System jobs were registered by PID 1 before the untether ran.
    for directory in /olsn0w/late-jobs /Library/LaunchDaemons; do
        set -- "$directory"/*.plist
        [ -f "$1" ] || continue
        /olsn0w/load-jobs "$@" || result=1
    done
    exit "$result"
fi
exec /bin/launchctl "$@"
