#!/bin/sh
# Rearm normal iBoot only after the selected target has a stable SpringBoard.
set -eu
PATH=/bin:/sbin:/usr/bin:/usr/sbin
. /usr/local/libexec/olsn0w/target.conf
/usr/local/libexec/olsn0w/guard-target.sh
marker=/private/var/lib/olsn0w/boot-success
/bin/rm -f "$marker" "$marker.new"
/usr/local/libexec/olsn0w/wait-graphics.sh

state=/private/var/run/olsn0w-boot-success.$$.txt
trap '/bin/rm -f "$state"' EXIT

springboard_pid() {
    /bin/launchctl list > "$state"
    while read pid status label; do
        if [ "$label" = com.apple.SpringBoard ]; then
            case "$pid" in
                ''|*[!0-9]*) return 1 ;;
                *) printf '%s\n' "$pid"; return 0 ;;
            esac
        fi
    done < "$state"
    return 1
}

# Five consecutive observations avoid acknowledging a SpringBoard which only
# appeared briefly during a failing boot. The outer bound keeps launchd retryable.
attempt=0
stable=0
previous=
while [ "$attempt" -lt 300 ]; do
    current=$(springboard_pid || true)
    if [ -n "$current" ] && [ "$current" = "$previous" ]; then
        stable=$((stable+1))
    else
        stable=0
    fi
    [ "$stable" -lt 5 ] || break
    previous=$current
    attempt=$((attempt+1))
    /bin/sleep 1
done
[ "$stable" -ge 5 ] || exit 1

# CrashHousekeeping normally runs only once, before olsn0w's boot relay and
# untether handoff have finished. Run the Apple executable again
# after the target is demonstrably usable so it can acknowledge the PMU boot
# failure and panic counters through IOPMUBootErrorClear.  Without this late
# acknowledgement, one later interrupted boot can make iBoot force Recovery
# even though the preceding target boot completed successfully.
housekeeper=/usr/libexec/CrashHousekeeping.backup
if [ ! -x "$housekeeper" ]; then
    housekeeper=/usr/libexec/CrashHousekeeping
    # iOS 8 and Aquila reuse Apple's launch-once path for the untether and
    # preserve the real program as .backup. Never relaunch that symlink here.
    [ -x "$housekeeper" ] && [ ! -h "$housekeeper" ] || exit 1
fi
"$housekeeper"

/usr/sbin/nvram auto-boot=true
set -- $(/usr/sbin/nvram auto-boot)
[ "$#" -eq 2 ] && [ "$1" = auto-boot ] && [ "$2" = true ]

printf '%s\n' "$AG_GENERATION" > "$marker.new"
/bin/chmod 644 "$marker.new"
/bin/mv -f "$marker.new" "$marker"
/bin/sync
