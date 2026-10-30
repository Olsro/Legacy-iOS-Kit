#!/bin/sh
# iOS 6 Aquila runs from launchd.conf, before notifyd and backboardd exist.
# Load package daemons only after GraphicsServices has been published.
/bin/sh /usr/local/libexec/olsn0w/wait-graphics.sh || :
exec /bin/launchctl load /Library/LaunchDaemons
