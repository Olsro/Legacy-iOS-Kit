#!/bin/sh
set -eu
/usr/local/libexec/olsn0w/guard-target.sh --keybag-init
. /usr/local/libexec/olsn0w/target.conf
if [ ! -s /private/var/keybags/systembag.kb ]; then
    /usr/local/libexec/olsn0w/fixkeybag
    /bin/sync
fi
[ -s /private/var/keybags/systembag.kb ]
if [ ! -e /private/var/lib/olsn0w/generation ]; then
    /bin/tar -xzpf /usr/local/share/olsn0w/data-firstboot.tar.gz -C /private/var
    /bin/tar -xpf /usr/local/share/olsn0w/data-personalization.tar -C /private/var
    /bin/sync
    printf '%s\n' "$AG_GENERATION" > /private/var/lib/olsn0w/generation.new
    /bin/mv /private/var/lib/olsn0w/generation.new /private/var/lib/olsn0w/generation
fi
exec "${AG_KEYBAG_PROGRAM:-/usr/libexec/keybagd}" "$@"
