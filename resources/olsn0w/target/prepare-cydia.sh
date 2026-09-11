#!/bin/sh
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
/usr/local/libexec/olsn0w/guard-target.sh
/usr/local/libexec/olsn0w/wait-graphics.sh
[ -s /private/var/keybags/systembag.kb ]
mkdir -p /usr/share/olsn0w
dpkg-divert --local --add --divert /etc/ssh/sshd_config.distrib /etc/ssh/sshd_config
# Some legacy dpkg-divert builds rename the existing file even without an
# explicit --rename. Keep the active per-image key configuration at its
# canonical path so a restarted sshd does not fall back to ~/.ssh.
cp -p /usr/local/share/olsn0w/sshd_config /etc/ssh/sshd_config
chown 0:0 /etc/ssh/sshd_config
chmod 0600 /etc/ssh/sshd_config
dpkg-divert --local --add --divert /usr/share/olsn0w/com.openssh.sshd.plist /Library/LaunchDaemons/com.openssh.sshd.plist
sync
