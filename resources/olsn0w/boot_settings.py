"""Prepare the installed compact layout's native NVRAM boot settings."""
import os
from pathlib import Path
import plistlib
import stat
import tempfile
import uuid

from restore import checkpoint

OVERRIDES = ('boot-ramdisk', 'boot-partition', 'boot-args')
READ = '/usr/sbin/nvram -x -p'


class PrivateBackupError(RuntimeError):
    pass


def read_settings(ram):
    raw = ram.run(READ)
    settings = plistlib.loads(raw)
    if not isinstance(settings, dict):
        raise ValueError('NVRAM did not return a property-list dictionary')
    return raw, settings


def write_backup(folder, raw):
    path = Path(folder) / ('nvram-before-' + uuid.uuid4().hex + '.plist')
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            info = os.fstat(output.fileno())
            # Verify privacy before writing identifiers from the full NVRAM.
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise PrivateBackupError('NVRAM backup requires private file permissions')
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if path.read_bytes() != raw:
            raise RuntimeError('NVRAM backup readback differs')
    except Exception:
        path.unlink()
        raise
    return path


def backup_settings(bundle, raw):
    try:
        return write_backup(bundle, raw)
    except PrivateBackupError:
        # A Kit on exFAT/NTFS cannot always enforce mode 0600. Keep a durable
        # private backup on the host's local temporary filesystem instead.
        folder = Path(tempfile.mkdtemp(prefix='olsn0w-boot-settings-', dir='/tmp'))
        try:
            return write_backup(folder, raw)
        except Exception:
            folder.rmdir()
            raise


def prepare_normal_boot(ram, bundle, progress=print):
    """Back up, remove only old boot overrides, and verify before any reboot.

    Call only after installing and verifying the selected compact layout.
    Stock iBoot's USB setenv whitelist excludes boot-ramdisk/boot-partition;
    use the authenticated rescue's native nvram tool while RAM is still held.
    """
    bundle = Path(bundle)
    ram.guard()
    raw, before = read_settings(ram)
    backup = backup_settings(bundle, raw)
    removed = [key for key in OVERRIDES if key in before]
    state = dict(kind='normal-boot-settings', complete=False,
                 backup=str(backup.resolve()), overrides_present=removed)
    journal = bundle / 'boot-settings.json'
    checkpoint(journal, state)
    progress('Preparing normal boot settings. Private NVRAM backup: ' + str(backup))
    try:
        for key in removed:
            ram.run('/usr/sbin/nvram -d ' + key)
        ram.run('/usr/sbin/nvram auto-boot=true')
        _, after = read_settings(ram)
        remaining = [key for key in OVERRIDES if key in after]
        if remaining:
            raise RuntimeError('Old boot overrides remain: ' + ', '.join(remaining))
        if after.get('auto-boot') not in ('true', b'true', True):
            raise RuntimeError('Could not verify auto-boot=true')
        state.update(complete=True, auto_boot_verified=True, removed_variables=removed)
        checkpoint(journal, state)
    except Exception as error:
        state['error'] = str(error)
        checkpoint(journal, state)
        raise
    progress('Normal boot settings verified.')
    return state
