"""Reapply a saved official activation record without repeating a restore."""
import plistlib
import subprocess
import time

from common import profile, tools
from external_ssh import candidates, check_target, connect, device_info
from saved_activation import backup_path, install, load


def recover(product, udid, ecid=None, bundle=None, progress=print, timeout=60):
    info = device_info(udid, product, ecid)
    identity = dict(product=product, ecid=info['ecid'])
    archive = backup_path(identity)
    if not archive.exists():
        raise ValueError('No saved activation archive found at '+str(archive)+
                         '. Use the original Kit folder containing this device\'s backup.')
    record, _ = load(archive, identity, udid)
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
        progress('Restoring the saved official activation record from '+str(archive))
        install(connection.prefix, record, has_baseband=profile(product)['has_baseband'])
        progress('Waiting for iOS to validate the restored record.')
        deadline = time.monotonic()+timeout
        while True:
            # Simple lockdown works before activation and after pairing records
            # have been invalidated by an erase. It also tolerates daemon reload.
            try:
                result = subprocess.run([str(tools()/'ideviceinfo'), '-u', udid, '-s', '-x'],
                                        capture_output=True, timeout=20)
            except subprocess.TimeoutExpired:
                result = None
            if result is not None and result.returncode == 0:
                values = plistlib.loads(result.stdout)
                if (values.get('UniqueDeviceID', '').lower() != udid.lower() or
                        values.get('UniqueChipID') != identity['ecid'] or
                        values.get('ProductType') != product or
                        values.get('ProductVersion') != info['version'] or
                        values.get('BuildVersion') != info['build']):
                    raise ValueError('Activation readback belongs to a different target')
                if values.get('ActivationState') == 'Activated':
                    progress('Saved official activation accepted by iOS. Continue Setup Assistant on the device.')
                    return
            if time.monotonic() >= deadline:
                raise RuntimeError('The record was restored, but iOS has not reported Activated. '
                                   'Keep the original backup and collect the restoration activation.log '
                                   'and device lockdownd logs before retrying. No erase was performed.')
            time.sleep(2)
