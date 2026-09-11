#!/bin/sh
# The generated configuration belongs to this prepared system image.
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
. /usr/local/libexec/olsn0w/target.conf
[ "$(sysctl -n hw.model)" = "$AG_BOARD" ]
[ "$(sysctl -n kern.osversion)" = "$AG_BUILD" ]
case "$(mount)" in *"$AG_ROOT_DEVICE on / ("*) ;; *) exit 80;; esac
case "$(mount)" in *"$AG_DATA_DEVICE on /private/var ("*) ;; *) exit 81;; esac
if [ "${1:-}" = --keybag-init ]; then
    # The generation file is protected and cannot be read until the native
    # keybag has been initialized. This directory is the offline volume marker.
    [ -d "/private/var/lib/olsn0w/fresh-$AG_GENERATION" ]
    data_mount=$(mount)
    data_mount=${data_mount#*"$AG_DATA_DEVICE on /private/var ("}
    data_mount=${data_mount%%)*}
    case ", $data_mount," in *", protect,"*) ;; *) exit 82;; esac
elif [ "${1:-}" = --initialize ] && [ ! -e /private/var/lib/olsn0w/generation ]; then
    [ -d "/private/var/lib/olsn0w/fresh-$AG_GENERATION" ]
    data_mount=$(mount)
    data_mount=${data_mount#*"$AG_DATA_DEVICE on /private/var ("}
    data_mount=${data_mount%%)*}
    case ", $data_mount," in *", protect,"*) ;; *) exit 82;; esac
else
    [ "$#" = 0 ] || [ "$1" = --initialize ]
    [ "$(cat /private/var/lib/olsn0w/generation)" = "$AG_GENERATION" ]
fi
