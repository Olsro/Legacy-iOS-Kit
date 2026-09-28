#!/bin/sh
# Preserve Apple's other dirhelper duties; only repair the boot-time socket.
result=0
if [ -x /usr/local/libexec/olsn0w/dirhelper.stock ]; then
    /usr/local/libexec/olsn0w/dirhelper.stock "$@"
    result=$?
fi
if [ "${1:-}" = -machineBoot ]; then
    /bin/sh /usr/local/libexec/olsn0w/ios5-launchd-socket.sh restore || exit 1
fi
exit "$result"
