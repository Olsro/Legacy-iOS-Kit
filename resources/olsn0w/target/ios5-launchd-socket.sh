#!/bin/sh
# iOS 5 launchctl empties /var/tmp AFTER launchd.conf has opened this socket.
# Keep its inode alive across that cleanup (as in the Kit's g1lbertJB path).
set -eu
live=/private/var/tmp/launchd/sock
saved=/private/var/lib/olsn0w/launchd-socket/sock
case "${1:-}" in
    save)
        [ -S "$live" ]
        /bin/mkdir -p -m 700 /private/var/lib/olsn0w/launchd-socket
        /bin/ln -f "$live" "$saved"
        ;;
    restore)
        [ -S "$saved" ]
        /bin/mkdir -p -m 700 /private/var/tmp/launchd
        /bin/mv -f "$saved" "$live"
        ;;
    *) exit 2 ;;
esac
