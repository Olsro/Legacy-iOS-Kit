#!/bin/sh
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
/usr/local/libexec/olsn0w/guard-target.sh
/usr/local/libexec/olsn0w/wait-graphics.sh
[ -s /private/var/keybags/systembag.kb ]
# The iOS 7 Pangu path deliberately leaves the System volume read-only until
# its untether has completed.  Both SSH files were installed and read back
# while the image was built, so first boot must only validate them here.
[ -s /usr/local/share/olsn0w/sshd_config ]
[ -s /etc/ssh/sshd_config ]
sync
