#!/bin/sh
# Release staging space only after protected initialization and the root remount.
set -eu
/usr/local/libexec/olsn0w/guard-target.sh
[ -s /private/var/keybags/systembag.kb ]
/bin/rm -f /usr/local/share/olsn0w/data-firstboot.tar.gz /usr/local/share/olsn0w/data-personalization.tar
/bin/sync
