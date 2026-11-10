"""Stash an already restored olsn0w target with Cydia's own relocation script."""
import subprocess

from external_ssh import candidates, check_target, connect, device_info

# The directories relocated by /usr/libexec/cydia/free.sh (Cydia 1.1.30).
DIRECTORIES = ('/Applications', '/Library/Wallpaper', '/Library/Ringtones',
               '/usr/include', '/usr/share')
LOG = '/private/var/lib/olsn0w/stash.log'
PATH = 'PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH\n'

STATE = ('for d in '+' '.join(DIRECTORIES)+'; do '
         'if [ -h "$d" ]; then if [ -d "$d/" ]; then s=stashed; else s=broken; fi; '
         'elif [ -d "$d" ]; then s=directory; '
         'elif [ -e "$d" ]; then s=other; else s=missing; fi; '
         'echo "$s $d"; done')

# Cydia must have finished its first start on this generation, and the device
# must carry the relocation helpers installed with the olsn0w bootstrap.
READY = ('set -eu\n'
         '[ "$(/bin/cat /var/lib/olsn0w/cydia-ready)" = "$(/bin/cat /var/lib/olsn0w/generation)" ] || '
         '{ echo "Cydia preparation has not completed on this device" >&2; exit 1; }\n'
         'for name in free.sh move.sh du setnsfpn; do\n'
         '    [ -x /usr/libexec/cydia/$name ] || '
         '{ echo "Missing Cydia helper: $name" >&2; exit 1; }\n'
         'done\n')

# Only tools present on every target are used: the bootstrap has no tail, head or wc.
# Output goes to a device log and HUP/PIPE are ignored, so an interrupted USB
# link cannot stop a directory relocation halfway. The lock names this boot:
# a process identifier alone could match an unrelated daemon after a reboot.
RUN = ('set -eu\n'+PATH+
       'lock=/private/var/run/olsn0w-stash.lock\n'
       'boot=$(sysctl -n kern.boottime)\n'
       'if [ -s "$lock" ]; then\n'
       '    read pid previous < "$lock" || true\n'
       '    case "$pid" in\n'
       "        ''|*[!0-9]*) ;;\n"
       '        *) if [ "$previous" = "$boot" ] && kill -0 "$pid" 2>/dev/null; then\n'
       '               echo "Stashing is already running on this device" >&2; exit 75\n'
       '           fi ;;\n'
       '    esac\n'
       'fi\n'
       'echo "$$ $boot" > "$lock"\n'
       "trap '/bin/rm -f \"$lock\"' 0\n"
       "trap '' 1 13\n"
       '/sbin/mount -u -w /\n'
       'cd /\n'
       '/usr/libexec/cydia/free.sh < /dev/null > '+LOG+' 2>&1 || '
       '{ /bin/sync; echo "Cydia relocation failed:" >&2; /bin/cat '+LOG+' >&2; exit 1; }\n'
       '/bin/sync\n')


def read_state(connection):
    state = {}
    for line in connection.run(STATE).decode().splitlines():
        status, _, directory = line.partition(' ')
        state[directory] = status
    if tuple(state) != DIRECTORIES:
        raise RuntimeError('Cannot read the stashing state of the device')
    return state


def stash(product, udid, ecid=None, bundle=None, progress=print, timeout=3600):
    info = device_info(udid, product, ecid)
    # An old session can match hardware/build while holding another generation's
    # keys. Authenticate and check the installed generation before any write.
    selected = None
    for folder, report in candidates(info, bundle):
        try:
            with connect(udid, folder) as connection:
                check_target(connection, report)
            selected = folder, report
            break
        except (RuntimeError, ValueError, subprocess.TimeoutExpired):
            continue
    if selected is None:
        raise RuntimeError('Cannot authenticate the installed target with the saved olsn0w keys')
    folder, report = selected
    with connect(udid, folder) as connection:
        check_target(connection, report)
        connection.run('/bin/sh -s', READY.encode())
        before = read_state(connection)
        unexpected = [d for d, s in before.items() if s == 'other']
        if unexpected:
            raise ValueError('Unexpected non-directory on the device, nothing was changed: '+
                             ', '.join(unexpected))
        if all(s == 'stashed' for s in before.values()):
            progress('This installation is already stashed; nothing was changed.')
            return
        progress('Moving '+', '.join(d for d, s in before.items() if s != 'stashed')+
                 ' to the Data partition.')
        progress('This can take several minutes. Keep the device connected and do not use Cydia.')
        try:
            connection.run('/bin/sh -s', RUN.encode(), timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError('Stashing is still running on the device after '+str(timeout)+
                               ' seconds. Leave it powered on, then select this option again '
                               'to read the result. Device log: '+LOG) from error
        after = read_state(connection)
        try:
            usage = connection.run(PATH+'df -h / /private/var').decode().rstrip()
        except (RuntimeError, subprocess.TimeoutExpired):
            usage = ''  # The space summary is informative only.
        if usage:
            progress(usage)
        moved = [d for d in DIRECTORIES if before[d] != 'stashed' and after[d] == 'stashed']
        if moved:
            progress('Stashed: '+', '.join(moved))
        remaining = [d for d, s in after.items() if s != 'stashed']
        if remaining:
            raise RuntimeError('Not stashed, left unchanged on the System partition: '+
                               ', '.join(remaining)+'. Cydia skips a directory larger than the '
                               'free space of the Data partition. Free some space on the device, '
                               'then select this option again. Device log: '+LOG)
        progress('Stashing completed. Restart the device before installing packages.')
