#!/bin/sh
# iOS 6 launchd.conf runs this before Aquila and before Data-backed jobs.
set -eu
/usr/local/libexec/olsn0w/guard-target.sh --keybag-init
. /usr/local/libexec/olsn0w/target.conf
if [ ! -s /private/var/keybags/systembag.kb ]; then
    /usr/local/libexec/olsn0w/keybag-init
    /bin/sync
fi
[ -s /private/var/keybags/systembag.kb ]
if [ ! -e /private/var/lib/olsn0w/generation ]; then
    /bin/tar -xzpf /usr/local/share/olsn0w/data-firstboot.tar.gz -C /private/var
    /bin/tar -xpf /usr/local/share/olsn0w/data-personalization.tar -C /private/var
    /usr/local/libexec/olsn0w/protection-probe d "/private/var/lib/olsn0w/fresh-$AG_GENERATION"
    /usr/local/libexec/olsn0w/protection-probe f /private/var/lib/olsn0w/protection-class-d
    /bin/sync
    printf '%s\n' "$AG_GENERATION" > /private/var/lib/olsn0w/generation.new
    /bin/mv /private/var/lib/olsn0w/generation.new /private/var/lib/olsn0w/generation
fi
/usr/local/libexec/olsn0w/guard-target.sh
