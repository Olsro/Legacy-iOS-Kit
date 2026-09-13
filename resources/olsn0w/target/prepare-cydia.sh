#!/bin/sh
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
/usr/local/libexec/olsn0w/guard-target.sh
# iOS 7 and 8 install the guarded launchctl endpoint used by their untethers.
# Do not let Cydia's RunAtLoad job race the kernel/shared-cache handoff: that
# can leave the reduced early-admission libmis selected for ordinary services.
if [ -x /olsn0w/lctl ]; then
    attempts=0
    . /usr/local/libexec/olsn0w/target.conf
    while :; do
        marker=$(cat /var/run/olsn0w-untether-ready 2>/dev/null || true)
        mounts=$(/sbin/mount)
        case "$mounts" in
            "$AG_ROOT_DEVICE on / (hfs,"*)
                case "$mounts" in
                    "$AG_ROOT_DEVICE on / (hfs,"*read-only*) ;;
                    *) [ "$marker" = ready ] && break ;;
                esac
                ;;
        esac
        attempts=$((attempts+1))
        [ "$attempts" -lt 300 ] || exit 1
        sleep 1
    done
fi
/usr/local/libexec/olsn0w/wait-graphics.sh
[ -s /private/var/keybags/systembag.kb ]
# The iOS 7 Pangu path deliberately leaves the System volume read-only until
# its untether has completed.  Both SSH files were installed and read back
# while the image was built, so first boot must only validate them here.
[ -s /usr/local/share/olsn0w/sshd_config ]
[ -s /etc/ssh/sshd_config ]
sync
