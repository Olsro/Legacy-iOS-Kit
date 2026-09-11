#!/bin/sh
set -eu
/usr/local/libexec/olsn0w/guard-target.sh --initialize
/usr/local/libexec/olsn0w/keybag-init
. /usr/local/libexec/olsn0w/target.conf
if [ ! -e /private/var/lib/olsn0w/generation ]; then
    [ -s /private/var/keybags/systembag.kb ]
    /bin/tar -xzpf /usr/local/share/olsn0w/data-firstboot.tar.gz -C /private/var
    /bin/tar -xpf /usr/local/share/olsn0w/data-personalization.tar -C /private/var
    /bin/sync
    printf '%s\n' "$AG_GENERATION" > /private/var/lib/olsn0w/generation.new
    /bin/mv /private/var/lib/olsn0w/generation.new /private/var/lib/olsn0w/generation
fi
/bin/sync
