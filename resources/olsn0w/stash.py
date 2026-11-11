"""Stash an already restored olsn0w target with Cydia's own relocation script."""
import subprocess
import uuid

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


FSTAB = '/private/etc/fstab'


def suid_fstab(data):
    """Let stashed setuid applications keep their privileges on the Data volume.

    The stock policy mounts Data nosuid, which silently disables root helpers of
    applications relocated to /var/stash (iFile, iCleaner). The Kit's regular
    jailbreaks drop that option too. Every other option and line is retained.
    """
    lines, found = data.decode('ascii').split('\n'), 0
    for index, line in enumerate(lines):
        fields = line.split()
        if not fields or fields[0].startswith('#') or len(fields) < 4 or fields[1] != '/private/var':
            continue
        options = fields[3].split(',')
        if len(fields) != 6 or fields[2] != 'hfs' or 'rw' not in options:
            raise ValueError('Unexpected Data mount in the device fstab; nothing was changed')
        found += 1
        if 'nosuid' in options:
            fields[3] = ','.join(option for option in options if option != 'nosuid')
            lines[index] = ' '.join(fields)
    if found != 1:
        raise ValueError('Unexpected Data mount in the device fstab; nothing was changed')
    return '\n'.join(lines).encode('ascii')


def allow_suid(connection):
    """Return True when the fstab was changed; a restart then applies it."""
    original = connection.read(FSTAB)
    updated = suid_fstab(original)
    if updated == original:
        return False
    # Same transaction as the SSH configuration: keep the original on Data,
    # stage beside the destination, rename, read back, and restore on mismatch.
    backup = '/var/lib/olsn0w/stash-fstab-'+uuid.uuid4().hex
    pending = FSTAB+'.'+backup.rsplit('-', 1)[1]
    connection.run('umask 077; /bin/mkdir '+backup+' && /bin/cp -p '+FSTAB+' '+backup+'/original')
    if connection.read(backup+'/original') != original:
        raise RuntimeError('Backup readback failed; the device fstab was left unchanged')
    restore = '/bin/cp -p '+backup+'/original '+FSTAB+'\n/bin/sync\n'
    script = ('set -eu\n/sbin/mount -u -w /\n'
              'test ! -e '+pending+' && test ! -L '+pending+'\n'
              "trap '/bin/rm -f "+pending+"' 0\n"
              '/bin/cp -p '+FSTAB+' '+pending+'\n'
              '/bin/cat > '+pending+'\n'
              '/bin/mv -f '+pending+' '+FSTAB+'\n/bin/sync\n')
    try:
        # The script itself is the remote command so that stdin carries the file.
        connection.run(script, updated)
        if connection.read(FSTAB) != updated:
            raise RuntimeError('The device fstab readback differs')
    except Exception:
        connection.run('/bin/sh -s', ('set -e\n'+restore).encode())
        raise
    return True


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
        restart = 'Restart the device before installing packages.'
        remounted = allow_suid(connection)
        if remounted:
            progress('Data partition: removed the nosuid mount option from '+FSTAB+
                     ' so stashed root applications keep working.')
            restart = 'Restart the device now: root applications such as iFile need it.'
        if all(s == 'stashed' for s in before.values()):
            progress('This installation is already stashed; no directory was moved.'+
                     (' '+restart if remounted else ''))
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
        progress('Stashing completed. '+restart)
