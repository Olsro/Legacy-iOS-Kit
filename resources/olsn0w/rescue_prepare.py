"""Build the selected stock 8.4.1 RAM rescue from Kit inputs on either host."""
import json
from pathlib import Path
import plistlib
import shutil
import tempfile
import zipfile

from archives import members, write_tar
from common import KIT, MODELS, digest, run, tools
from firmware import acquire, extract
from hfs import HFS
from img3 import img3
from restore import checkpoint
from signing import resign, verify
from system import entry, add_parents

RECIPE_VERSION = 3
RAM_VOLUME_BYTES = 64000000
MAINTENANCE = '/olsn0w-maintenance'
DISK_ENTITLEMENTS = {'com.apple.private.security.disk-device-access': True,
                     'com.apple.rootless.restricted-block-devices': True}
START_SERVICE = b'#!/bin/sh\n/sbin/sshd\nexec /usr/local/bin/restored_external_o\n'
# rc.boot must return before launchd can register the stock restore jobs.
# The service wrapper is entered through com.apple.restored_external.plist.
RC_BOOT = b'#!/bin/sh\nexit 0\n'


def unmount_payload():
    root = Path(__file__).parent
    report = json.loads((root/'target/rescue-unmount.json').read_text())
    required = {'target/rescue-unmount', 'native/target/rescue_unmount.c',
                'native/target/build-rescue.sh'}
    if set(report['files']) != required:
        raise ValueError('Incomplete rescue unmount provenance')
    for name, expected in report['files'].items():
        if digest(root/name) != expected:
            raise ValueError('Rescue unmount source or executable changed')
    data = (root/'target/rescue-unmount').read_bytes()
    if verify(data)['entitlements'] != DISK_ENTITLEMENTS:
        raise ValueError('Unexpected rescue unmount entitlements')
    return data


def ssh_config():
    return b'''Protocol 2
Port 22
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_rsa_key
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/olsn0w_authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePrivilegeSeparation no
UseDNS no
PidFile /var/run/sshd.pid
Subsystem sftp /usr/libexec/sftp-server
'''


def prepare(session, ipsw=None, keys=None, port=6414):
    session = Path(session).resolve()
    record = json.loads((session/'device.json').read_text())
    selected = record['identity']
    board, chip, board_id = MODELS[selected['product']]
    if (selected['board'], selected['chip'], selected['board_id']) != (board, chip, board_id):
        raise ValueError('Selected rescue hardware identity differs')
    if not 1024 <= port <= 65535:
        raise ValueError('Expected an unprivileged local USB port')
    if (session/'rescue-preparation.json').exists():
        raise ValueError('Preserve the existing rescue before preparing another')
    inputs, metadata, manifest, identity = acquire(selected['product'], '8.4.1', ipsw, keys, '12H321')
    firmware, _ = extract(selected['product'], '8.4.1', inputs, keys, '12H321')
    out = Path(tempfile.mkdtemp(prefix='rescue-pending-', dir=session))
    # Failed preparation stays private for inspection; nothing is sent to USB.
    with zipfile.ZipFile(inputs) as archive:
        component = identity['Manifest']['RestoreRamDisk']['Info']['Path']
        matching = [k for k in metadata['keys'] if k['image'] == 'RestoreRamdisk']
        if len(matching) != 1 or Path(component).name != matching[0]['filename'] or archive.namelist().count(component) != 1:
            raise ValueError('Restore ramdisk key/component identity mismatch')
        key = matching[0]
        (out/'RestoreRamdisk.orig').write_bytes(archive.read(component))
    run([tools()/'xpwntool', out/'RestoreRamdisk.orig', out/'RestoreRamdisk.dec',
         '-iv', key['iv'], '-k', key['key'], '-decrypt'])
    run([tools()/'xpwntool', out/'RestoreRamdisk.dec', out/'rescue-ram.hfs'])
    image = HFS(out/'rescue-ram.hfs')
    # Keep the allocation size qualified with the stock 8.4.1 boot chain.
    # Growing to 64 MiB can load successfully yet panic before RAM services.
    if image.info()['bytes'] > RAM_VOLUME_BYTES:
        raise ValueError('Stock restore RAM volume exceeds the qualified rescue size')
    image.grow(RAM_VOLUME_BYTES)
    ssh_package = KIT/'resources/sshrd/ssh.tar.gz'
    freeze = KIT/'resources/jailbreak/freeze.tar.gz'
    payload = {m.name:(m, data) for m, data in members(ssh_package)}
    sysctls = [data for m, data in members(freeze) if m.name == 'usr/sbin/sysctl' and m.isfile()]
    if len(sysctls) != 1:
        raise ValueError('Kit sysctl utility missing or ambiguous')
    utilities = {'sysctl':sysctls[0], 'dd':payload['bin/dd'][1],
                 'gptfdisk':payload['usr/bin/gptfdisk'][1],
                 'mount_hfs':image.read('/System/Library/Filesystems/hfs.fs/Contents/Resources/mount_hfs')}
    utilities['unmount'] = unmount_payload()
    for name, data in utilities.items():
        path = out/name
        path.write_bytes(data)
        if name != 'unmount':
            entitlements = verify(data)['entitlements']
            entitlements.update(DISK_ENTITLEMENTS)
            resign(path, entitlements)
        verify(path.read_bytes())
        payload[MAINTENANCE[1:]+'/'+name] = entry(MAINTENANCE[1:]+'/'+name, path.read_bytes(), 0o755)
    for name in ('rescue-client', 'ssh_host_rsa_key'):
        run(['ssh-keygen','-q','-t','rsa','-b','2048','-m','PEM','-N','','-f',out/name])
    for name, data, mode in [
        ('private/etc/ssh/sshd_config',ssh_config(),0o600),
        ('private/etc/ssh/ssh_host_rsa_key',(out/'ssh_host_rsa_key').read_bytes(),0o600),
        ('private/etc/ssh/olsn0w_authorized_keys',(out/'rescue-client.pub').read_bytes(),0o600),
        ('private/etc/rc.boot',RC_BOOT,0o755)]:
        payload[name] = entry(name,data,mode)
    # The Kit's generic rc.boot writes NVRAM and removes files. Replace it
    # with a returning stub, then let Apple's launchd job start the wrapper.
    add_parents(payload)
    write_tar(out/'rescue-overlay.tar',payload.values())
    image.command('untar',out/'rescue-overlay.tar')
    original = image.read('/usr/local/bin/restored_external')
    service = plistlib.loads(image.read('/System/Library/LaunchDaemons/com.apple.restored_external.plist'))
    if (service.get('Label') != 'com.apple.restored_external' or
            service.get('ProgramArguments') != ['/usr/local/bin/restored_external'] or
            service.get('RunAtLoad') is not True):
        raise ValueError('Stock restore service launch definition differs')
    image.add('/usr/local/bin/restored_external_o',original,0o755)
    image.command('rm','/usr/local/bin/restored_external')
    image.add('/usr/local/bin/restored_external',START_SERVICE,0o755)
    for path in ('/','/private','/private/etc','/private/etc/ssh'):
        image.command('chmod','0755',path)
        image.command('chown','0:0',path)
    with image.path.open('rb') as stream:
        stream.seek(1024)
        if stream.read(2) == b'HX': image.normalize_root()
    for name, (_,data) in payload.items():
        if data is not None and image.read('/'+name) != data:
            raise ValueError('Rescue payload readback differs: '+name)
    if image.read('/usr/local/bin/restored_external') != START_SERVICE or image.read('/usr/local/bin/restored_external_o') != original:
        raise ValueError('Restore service wrapper readback differs')
    run([tools()/'xpwntool',out/'rescue-ram.hfs',out/'Ramdisk.img3','-t',out/'RestoreRamdisk.dec'])
    run([tools()/'iBoot32Patcher',firmware/'iBSS.raw',out/'pwnediBSS','--rsa'],out/'ibss-patch.log',patcher=True)
    run([tools()/'iBoot32Patcher',firmware/'iBEC.raw',out/'iBEC.patched','--rsa','--debug','-b',
         'rd=md0 -v amfi=0xff cs_enforcement_disable=1'],out/'ibec-patch.log',patcher=True)
    run([tools()/'xpwntool',out/'iBEC.patched',out/'iBEC.img3','-t',firmware/'iBEC.orig'])
    run([tools()/'xpwntool',firmware/'DeviceTree.raw',out/'DeviceTree.img3','-t',firmware/'DeviceTree.orig'])
    shutil.copyfile(firmware/'Kernelcache.img3',out/'Kernelcache.img3')
    for name, kind in [('Ramdisk.img3','rdsk'),('iBEC.img3','ibec'),('DeviceTree.img3','dtre'),('Kernelcache.img3','krnl')]:
        actual,tags,data = img3((out/name).read_bytes())
        if actual != kind or 'KBAG' in tags:raise ValueError('Unexpected encrypted rescue component: '+name)
        if name == 'Ramdisk.img3' and data != image.path.read_bytes():raise ValueError('RAM image packing differs')
    from restore_run import target_prefix
    # target_prefix pins the standard key filenames, so publish a dedicated
    # rescue key under that name without sharing it with the target image.
    shutil.copyfile(out/'rescue-client',out/'ssh_client_rsa')
    published = ['iBEC.img3','DeviceTree.img3','Kernelcache.img3','Ramdisk.img3','rescue-ram.hfs',
                 'ssh_client_rsa','ssh_host_rsa_key.pub','pwnediBSS']
    if any((session/name).exists() for name in published):
        raise ValueError('Session contains earlier rescue artifacts; preserve them first')
    for name in published: shutil.copyfile(out/name,session/name)
    (session/'ssh_client_rsa').chmod(0o600)
    checkpoint(session/'ssh-prefix.json',target_prefix(session,port))
    record['rescue_maintenance'] = MAINTENANCE
    checkpoint(session/'device.json',record)
    report = dict(recipe_version=RECIPE_VERSION,product=selected['product'],build='12H321',
                  ram_root='md0',automatic_disk_mounts=False,device_modified=False,physical_boot_verified=False,
                  files={name:digest(session/name) for name in published},
                  packages={str(p.relative_to(KIT)):digest(p) for p in (ssh_package,freeze)},
                  tools={name:digest(out/name) for name in utilities})
    checkpoint(session/'rescue-preparation.json',report)
    return report
