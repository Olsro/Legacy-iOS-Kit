#!/bin/sh
set -eu
/usr/local/libexec/olsn0w/guard-target.sh
/usr/local/libexec/olsn0w/keybag-init
[ -s /private/var/keybags/systembag.kb ]
/bin/sync
