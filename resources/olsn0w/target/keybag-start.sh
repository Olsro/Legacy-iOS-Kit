#!/bin/sh
set -eu
/usr/local/libexec/olsn0w/guard-target.sh
. /usr/local/libexec/olsn0w/target.conf
if [ ! -s /private/var/keybags/systembag.kb ]; then
    /usr/local/libexec/olsn0w/fixkeybag
    /bin/sync
fi
[ -s /private/var/keybags/systembag.kb ]
exec "${AG_KEYBAG_PROGRAM:-/usr/libexec/keybagd}" "$@"
