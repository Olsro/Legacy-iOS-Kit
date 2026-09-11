"""Prepare the Kit's signed-base restore with a RAM handoff before reboot."""
import copy
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import uuid
import zipfile

from archives import members
from common import KIT, digest, run, tools
from firmware import acquire, extract
from hfs import HFS
from img3 import img3
from rescue_prepare import RAM_VOLUME_BYTES, RECIPE_VERSION
from restore import checkpoint
from progress import activity, copy_stream

HANDOFF = 'olsn0w-restore-handoff'


def handoff_sleep():
    """The SSH rescue package has bash but no sleep utility."""
    package = KIT/'resources/jailbreak/freeze.tar.gz'
    matches = [data for item, data in members(package)
               if item.name == 'bin/sleep' and item.isfile()]
    if len(matches) != 1:
        raise ValueError('Kit handoff sleep utility missing or ambiguous')
    from signing import verify
    verify(matches[0])
    return matches[0]


def reboot_hook(token):
    if not re.fullmatch(r'[0-9a-f]{32}', token):
        raise ValueError('Expected an unambiguous handoff token')
    return ('''#!/bin/bash
set -e
/usr/sbin/nvram {variable}={token}
# The restore RAM can be read-only. Keep the handoff outside its filesystem.
# The host invokes the preserved reboot only after verification/installation.
while :; do /bin/sleep 1; done
'''.format(variable=HANDOFF, token=token)).encode()


def read_handoff(ram):
    value = ram.run('/usr/sbin/nvram ' + HANDOFF).decode().split()
    if len(value) != 2 or value[0] != HANDOFF or not re.fullmatch(r'[0-9a-f]{32}', value[1]):
        raise ValueError('Unexpected restore handoff marker')
    return (value[1] + '\n').encode()


def require_completed_restore(returncode, output, observed, token):
    """A reboot request alone may also mean a failed restore: require both."""
    if not re.fullmatch(r'[0-9a-f]{32}', token):
        raise ValueError('Invalid handoff token')
    if returncode != 0 or not any(line.strip() == 'DONE' for line in output.splitlines()):
        raise ValueError('The Kit restore did not confirm successful completion')
    if observed != (token+'\n').encode():
        raise ValueError('Restore RAM handoff does not belong to this run')


def copy_ipsw(source, output, replacements):
    """Copy all stock members, replacing only explicitly selected components."""
    with zipfile.ZipFile(source) as incoming:
        names = incoming.namelist()
        if len(set(names)) != len(names) or not set(replacements).issubset(names):
            raise ValueError('Ambiguous or missing IPSW components')
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Unsafe IPSW member path')
        def size(info):
            replacement=replacements.get(info.filename)
            if replacement is None:return info.file_size
            return replacement.stat().st_size if isinstance(replacement,Path) else len(replacement)
        total=sum(size(info) for info in incoming.infolist())
        with activity('Assembling firmware',total) as update, zipfile.ZipFile(output,'x',allowZip64=True) as outgoing:
            done=0
            def transfer(original,target):
                nonlocal done
                for chunk in iter(lambda:original.read(1024**2),b''):
                    target.write(chunk);done+=len(chunk);update(done)
            for info in incoming.infolist():
                with outgoing.open(copy.copy(info),'w',force_zip64=True) as target:
                    if info.filename in replacements:
                        replacement=replacements[info.filename]
                        if isinstance(replacement,Path):
                            with replacement.open('rb') as original:transfer(original,target)
                        else:
                            target.write(replacement);done+=len(replacement);update(done)
                    else:
                        with incoming.open(info) as original:transfer(original,target)
    with zipfile.ZipFile(output) as result, zipfile.ZipFile(source) as original:
        if result.namelist() != original.namelist():
            raise ValueError('Output IPSW member set differs')
        for info in result.infolist():
            if info.filename in replacements:
                replacement = replacements[info.filename]
                if isinstance(replacement, Path):
                    import hashlib
                    checksum = hashlib.sha256()
                    with activity('Checking assembled firmware',info.file_size) as update, result.open(info) as stream:
                        done=0
                        for chunk in iter(lambda: stream.read(1024**2), b''):
                            checksum.update(chunk);done+=len(chunk);update(done)
                    matches = info.file_size == replacement.stat().st_size and checksum.hexdigest() == digest(replacement)
                else:
                    matches = result.read(info) == replacement
                if not matches:
                    raise ValueError('IPSW replacement readback differs')
            else:
                old = original.getinfo(info.filename)
                if (info.CRC, info.file_size) != (old.CRC, old.file_size):
                    raise ValueError('Unmodified stock IPSW component changed')


def prepare(session, destination, ipsw=None, keys=None):
    session, destination = Path(session).resolve(), Path(destination).resolve()
    record = json.loads((session/'device.json').read_text())
    selected = record['identity']
    rescue = json.loads((session/'rescue-preparation.json').read_text())
    if (rescue.get('recipe_version') != RECIPE_VERSION or rescue.get('product') != selected['product']
            or rescue.get('build') != '12H321' or rescue.get('automatic_disk_mounts') is not False):
        raise ValueError('Prepare the current selected-device RAM rescue first')
    for name, expected in rescue['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or (session/name).is_symlink() or digest(session/name) != expected:
            raise ValueError('Prepared RAM rescue changed')
    if destination.exists():
        raise ValueError('Preserve the earlier provisioning bundle')
    source, metadata, _, identity = acquire(selected['product'], '8.4.1', ipsw, keys, '12H321')
    firmware, _ = extract(selected['product'], '8.4.1', source, keys, '12H321')
    destination.mkdir(parents=True, mode=0o700)
    token = uuid.uuid4().hex
    image_path = destination/'restore-ram.hfs'
    shutil.copyfile(session/'rescue-ram.hfs', image_path)
    image = HFS(image_path)
    if image.info()['bytes'] != RAM_VOLUME_BYTES:
        raise ValueError('Restore RAM allocation differs from the qualified rescue')
    from asr_patch import patch as patch_asr
    from signing import resign, verify
    asr_original = image.read('/usr/sbin/asr')
    asr, asr_report = patch_asr(asr_original)
    asr_file = destination/'asr.patched'
    asr_file.write_bytes(asr)
    resign(asr_file, verify(asr_original)['entitlements'])
    image.rename_file('/usr/sbin/asr', '/usr/sbin/asr_olsn0w_original')
    image.add('/usr/sbin/asr', asr_file.read_bytes(), 0o755)
    if image.read('/usr/sbin/asr') != asr_file.read_bytes():
        raise ValueError('Patched ASR readback differs')
    original = image.read('/sbin/reboot')
    # Rename the stock compressed record, as the Kit's reboot hook does.
    # Replacing its data fork would leave its decmpfs metadata behind.
    image.rename_file('/sbin/reboot', '/sbin/reboot_olsn0w')
    image.add('/sbin/reboot', reboot_hook(token), 0o755)
    sleep = handoff_sleep()
    image.add('/bin/sleep', sleep, 0o755)
    if image.read('/bin/sleep') != sleep:
        raise ValueError('RAM handoff wait utility readback differs')
    if image.read('/sbin/reboot_olsn0w') != original:
        raise ValueError('Original RAM reboot executable was not preserved')
    # Leave the flashable boot chain untouched. Only the restore iBEC receives
    # debug/AMFI boot arguments; futurerestore applies its own RSA patch later.
    run([tools()/'iBoot32Patcher', firmware/'iBEC.raw', destination/'iBEC.patched',
         '--debug', '-b', 'rd=md0 -v amfi=0xff cs_enforcement_disable=1'],
        destination/'ibec-patch.log', patcher=True)
    run([tools()/'xpwntool', destination/'iBEC.patched', destination/'iBEC.img3', '-t', firmware/'iBEC.orig'])
    run([tools()/'xpwntool', image_path, destination/'Ramdisk.img3', '-t', session/'Ramdisk.img3'])
    replacements = {}
    for component, name, kind in [('iBEC','iBEC.img3','ibec'),('RestoreRamDisk','Ramdisk.img3','rdsk')]:
        blob = (destination/name).read_bytes()
        actual, tags, data = img3(blob)
        if actual != kind or 'KBAG' in tags:
            raise ValueError('Unexpected encrypted restore component')
        if component == 'RestoreRamDisk' and data != image_path.read_bytes():
            raise ValueError('Restore RAM packing readback differs')
        replacements[identity['Manifest'][component]['Info']['Path']] = blob
    from filevault import decrypt
    os_member = identity['Manifest']['OS']['Info']['Path']
    os_keys = [key for key in metadata['keys'] if key['image'] == 'RootFS']
    if len(os_keys) != 1 or Path(os_member).name != os_keys[0]['filename']:
        raise ValueError('System image/key identity mismatch')
    encrypted = destination/'system.encrypted.dmg'
    plaintext = destination/'system.asr.dmg'
    with zipfile.ZipFile(source) as archive, archive.open(os_member) as incoming, encrypted.open('xb') as outgoing:
        copy_stream(incoming,outgoing,archive.getinfo(os_member).file_size,'Extracting signed system image')
    decrypt(encrypted, plaintext, os_keys[0]['key'])
    verified = destination/'system.verify.hfs'
    run([tools()/'dmg', 'extract', plaintext, verified], destination/'system-verify.log', timeout=600)
    if digest(verified) != digest(firmware/'rootfs.hfs'):
        raise ValueError('Plaintext ASR image differs from the original filesystem')
    verified.unlink()
    encrypted.unlink()
    replacements[os_member] = plaintext
    pending = destination/'base8.pending.ipsw'
    copy_ipsw(source, pending, replacements)
    pending.rename(destination/'base8.ipsw')
    names = ['asr.patched','base8.ipsw','restore-ram.hfs','Ramdisk.img3','iBEC.img3','system.asr.dmg']
    report = dict(kind='signed-base-restore-handoff',identity=selected,product=selected['product'],
                  build='12H321',reboot_token=token,rescue_session=str(session),
                  stock_system_preserved=True,device_modified=False,physical_restore_verified=False,
                  asr_patch=asr_report,asr_source='original-udif-without-filevault-envelope',
                  stock_hfs_sha256=digest(firmware/'rootfs.hfs'),handoff_storage='nvram',
                  handoff_package_sha256=digest(KIT/'resources/jailbreak/freeze.tar.gz'),
                  files={name:digest(destination/name) for name in names},stock_ipsw_sha256=digest(source))
    checkpoint(destination/'manifest.json', report)
    return report
