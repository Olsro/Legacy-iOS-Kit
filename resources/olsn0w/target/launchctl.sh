#!/bin/sh
# The untether invokes this after its kernel and shared-cache corrections.
if { [ "$#" = 2 ] && [ "$1" = load ] && [ "$2" = /Library/LaunchDaemons ]; } ||
   { [ "$#" = 3 ] && [ "$1" = load ] && [ "$2" = -D ] && [ "$3" = all ]; }; then
    # EverUntether makes /private world-writable during its first installation.
    # Restore the prepared ancestor mode before SSH checks authorized_keys.
    # Pangu runs with the stock read-only root, whose prepared /private is
    # already 0755. EverUntether can make it writable and world-writable.
    # Accept a failed chmod only when the existing read-only metadata is the
    # exact safe mode; otherwise keep failing closed for SSH StrictModes.
    if ! /bin/chmod 755 /private 2>/dev/null; then
        case "$(/bin/ls -ld /private)" in
            drwxr-xr-x*) ;;
            *) exit 1 ;;
        esac
    fi
    result=0
    # Pangu's `load -D all` only needs to register newly installed third-party
    # jobs here. System jobs were registered by PID 1 before the untether ran.
    for directory in /olsn0w/late-jobs /Library/LaunchDaemons; do
        set -- "$directory"/*.plist
        [ -f "$1" ] || continue
        /olsn0w/load-jobs "$@" || result=1
    done
    [ "$result" = 0 ] || exit "$result"
    printf '%s\n' ready > /var/run/olsn0w-untether-ready || exit 1
    exit "$result"
fi
exec /bin/launchctl "$@"
