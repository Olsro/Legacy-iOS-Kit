"""Build the selected RAM writer while retaining the signed 8.4.1 base."""
import json
from pathlib import Path
import plistlib
import shutil
import tempfile
import zipfile

from archives import members, write_tar
from common import KIT, MODELS, digest, profile, run, tools
from firmware import acquire, extract
from hfs import HFS
from img3 import img3
from restore import checkpoint
from signing import resign, verify
from system import entry, add_parents
from restore_environment import checked_build, selected_build

RECIPE_VERSION = 7
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


def decrypt_restore_ramdisk(source, metadata, identity, output, stem):
    """Extract one firmware-bound restore ramdisk into a regular HFS image."""
    output=Path(output)
    with zipfile.ZipFile(source) as archive:
        component=identity['Manifest']['RestoreRamDisk']['Info']['Path']
        matching=[k for k in metadata['keys'] if k['image']=='RestoreRamdisk']
        if (len(matching)!=1 or Path(component).name!=matching[0]['filename'] or
                archive.namelist().count(component)!=1):
            raise ValueError('Restore ramdisk key/component identity mismatch')
        key=matching[0]
        (output/(stem+'.orig')).write_bytes(archive.read(component))
    run([tools()/'xpwntool',output/(stem+'.orig'),output/(stem+'.dec'),
         '-iv',key['iv'],'-k',key['key'],'-decrypt'])
    run([tools()/'xpwntool',output/(stem+'.dec'),output/(stem+'.hfs')])
    return output/(stem+'.hfs')


def prepare(session, ipsw=None, keys=None, port=6414, *, environment_build=None, ram_ipsw=None):
    session = Path(session).resolve()
    record = json.loads((session/'device.json').read_text())
    selected = record['identity']
    environment_build = checked_build(selected['product'],
        environment_build if environment_build is not None else selected_build(selected['product']))
    native6 = environment_build == '10B329'
    board, chip, board_id = MODELS[selected['product']]
    if (selected['board'], selected['chip'], selected['board_id']) != (board, chip, board_id):
        raise ValueError('Selected rescue hardware identity differs')
    if not 1024 <= port <= 65535:
        raise ValueError('Expected an unprivileged local USB port')
    if (session/'rescue-preparation.json').exists():
        raise ValueError('Preserve the existing rescue before preparing another')
    inputs, metadata, manifest, identity = acquire(selected['product'], '8.4.1', ipsw, keys, '12H321')
    base_firmware, _ = extract(selected['product'], '8.4.1', inputs, keys, '12H321')
    selected_profile=profile(selected['product'])
    if native6:
        # Legacy iOS Kit's 4S gas-gauge recipe deliberately restores 8.4.1
        # through the 6.1.3 restore environment. Reuse the component recipe
        # for A5 iOS 6 Data without claiming those models need multipatch.
        # Keep the signed base and ticket at 8.4.1 in both cases.
        ram_inputs, ram_metadata, _, ram_identity = acquire(
            selected['product'],'6.1.3',ram_ipsw,build='10B329')
        firmware, _ = extract(selected['product'],'6.1.3',ram_inputs,
                              build='10B329')
    else:
        ram_inputs,ram_metadata,ram_identity=inputs,metadata,identity
        firmware=base_firmware
    out = Path(tempfile.mkdtemp(prefix='rescue-pending-', dir=session))
    # Failed preparation stays private for inspection; nothing is sent to USB.
    decrypt_restore_ramdisk(ram_inputs,ram_metadata,ram_identity,out,'RestoreRamdisk')
    (out/'RestoreRamdisk.hfs').rename(out/'rescue-ram.hfs')
    image = HFS(out/'rescue-ram.hfs')
    donor_rc = (image.read('/private/etc/rc.boot')
                if native6 else None)
    if native6:
        base_ram=HFS(decrypt_restore_ramdisk(inputs,metadata,identity,out,'BaseRestoreRamdisk'))
        library=base_ram.read('/usr/lib/libutil.dylib')
        (out/'bootstrap-libutil.dylib').write_bytes(library)
        options='/usr/local/share/restore/options.'+board[:-2]+'.plist'
        option_data=base_ram.read(options)
        plistlib.loads(option_data)
        if any(item['name']==Path(options).name for item in image.ls(str(Path(options).parent))):
            image.command('rm',options)
        image.add(options,option_data,0o644)
        if image.read(options)!=option_data:
            raise ValueError('Multipatch target restore options readback differs')
    # Keep the allocation size qualified with the stock 8.4.1 boot chain.
    # Growing to 64 MiB can load successfully yet panic before RAM services.
    if image.info()['bytes'] > RAM_VOLUME_BYTES:
        raise ValueError('Stock restore RAM volume exceeds the qualified rescue size')
    image.grow(RAM_VOLUME_BYTES)
    ssh_package = KIT/'resources/sshrd/ssh.tar.gz'
    freeze = KIT/'resources/jailbreak/freeze.tar.gz'
    payload = {m.name:(m, data) for m, data in members(ssh_package)}
    if native6:
        # The shared SSH payload contains Legacy Kit's generic shell rc.boot.
        # Gas-gauge multipatch must retain the native iOS 6 Mach-O instead: it
        # initializes root_device before invoking restored_external.
        if payload.pop('private/etc/rc.boot',None) is None:
            raise ValueError('Kit SSH payload lacks its expected rc.boot')
    sysctls = [data for m, data in members(freeze) if m.name == 'usr/sbin/sysctl' and m.isfile()]
    if len(sysctls) != 1:
        raise ValueError('Kit sysctl utility missing or ambiguous')
    mount_path=('/sbin/mount_hfs' if any(item['name']=='mount_hfs' for item in image.ls('/sbin'))
                else '/System/Library/Filesystems/hfs.fs/Contents/Resources/mount_hfs')
    utilities = {'sysctl':sysctls[0], 'dd':payload['bin/dd'][1],
                 'gptfdisk':payload['usr/bin/gptfdisk'][1],
                 'mount_hfs':image.read(mount_path)}
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
    configuration = [
        ('private/etc/ssh/sshd_config',ssh_config(),0o600),
        ('private/etc/ssh/ssh_host_rsa_key',(out/'ssh_host_rsa_key').read_bytes(),0o600),
        ('private/etc/ssh/olsn0w_authorized_keys',(out/'rescue-client.pub').read_bytes(),0o600)]
    if not native6:
        configuration.append(('private/etc/rc.boot',RC_BOOT,0o755))
    for name, data, mode in configuration:
        payload[name] = entry(name,data,mode)
    # For the regular iOS 8 restore environment, replace the Kit's generic
    # rc.boot with a returning stub and let launchd start the wrapper. The
    # multipatch branch removed that tar member above to retain native rc.boot.
    add_parents(payload)
    write_tar(out/'rescue-overlay.tar',payload.values())
    image.command('untar',out/'rescue-overlay.tar')
    original = image.read('/usr/local/bin/restored_external')
    if native6:
        # Keep the native Mach-O rc.boot: besides launching this service it
        # performs the iOS 6 root-device initialization required by ASR. This
        # is the exact Legacy iOS Kit restored_external replacement used by
        # --multipatch for the iPhone 4S gas-gauge path.
        original = (KIT/'resources/patch/re').read_bytes()
        if original[:4] != b'\xce\xfa\xed\xfe':
            raise ValueError('Kit multipatch restore service is not ARM Mach-O')
    if native6:
        # iOS 6 rc.boot is the service launcher. Reject a donor whose native
        # launch contract no longer contains the expected executable.
        if (donor_rc[:4] != b'\xce\xfa\xed\xfe' or
                donor_rc.count(b'/usr/local/bin/restored_external\0') != 1):
            raise ValueError('Multipatch rc.boot launch contract differs')
    else:
        service = plistlib.loads(image.read(
            '/System/Library/LaunchDaemons/com.apple.restored_external.plist'))
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
    # Initial external A5 pwnDFU always receives the signed-base 8.4.1 iBSS,
    # matching Legacy iOS Kit's patch_ibss default.  The multipatch restore
    # components themselves remain the checked 6.1.3 set below.
    run([tools()/'iBoot32Patcher',base_firmware/'iBSS.raw',out/'pwnediBSS','--rsa'],out/'ibss-patch.log',patcher=True)
    restore_bootargs='rd=md0 -v nand-enable-reformat=1 amfi=0xff amfi_get_out_of_my_way=1 cs_enforcement_disable=1 pio-error=0'
    run([tools()/'iBoot32Patcher',firmware/'iBSS.raw',out/'restore-iBSS.patched',
         '--rsa','--debug','-b',restore_bootargs],
        out/'restore-ibss-patch.log',patcher=True)
    run([tools()/'xpwntool',out/'restore-iBSS.patched',out/'iBSS.img3','-t',firmware/'iBSS.orig'])
    run([tools()/'iBoot32Patcher',firmware/'iBEC.raw',out/'iBEC.patched','--rsa','--debug','-b',
         restore_bootargs,
         *(['--ticket'] if native6 else [])],out/'ibec-patch.log',patcher=True)
    run([tools()/'xpwntool',out/'iBEC.patched',out/'iBEC.img3','-t',firmware/'iBEC.orig'])
    run([tools()/'xpwntool',firmware/'DeviceTree.raw',out/'DeviceTree.img3','-t',firmware/'DeviceTree.orig'])
    shutil.copyfile(firmware/'Kernelcache.img3',out/'Kernelcache.img3')
    for name, kind in [('Ramdisk.img3','rdsk'),('iBSS.img3','ibss'),('iBEC.img3','ibec'),('DeviceTree.img3','dtre'),('Kernelcache.img3','krnl')]:
        actual,tags,data = img3((out/name).read_bytes())
        if actual != kind or 'KBAG' in tags:raise ValueError('Unexpected encrypted rescue component: '+name)
        if name == 'Ramdisk.img3' and data != image.path.read_bytes():raise ValueError('RAM image packing differs')
    from restore_run import target_prefix
    # target_prefix pins the standard key filenames, so publish a dedicated
    # rescue key under that name without sharing it with the target image.
    shutil.copyfile(out/'rescue-client',out/'ssh_client_rsa')
    published = ['iBSS.img3','iBEC.img3','DeviceTree.img3','Kernelcache.img3','Ramdisk.img3','rescue-ram.hfs',
                 'ssh_client_rsa','ssh_host_rsa_key.pub','pwnediBSS']
    if native6:published.append('bootstrap-libutil.dylib')
    if any((session/name).exists() for name in published):
        raise ValueError('Session contains earlier rescue artifacts; preserve them first')
    for name in published: shutil.copyfile(out/name,session/name)
    (session/'ssh_client_rsa').chmod(0o600)
    checkpoint(session/'ssh-prefix.json',target_prefix(session,port))
    record['rescue_maintenance'] = MAINTENANCE
    checkpoint(session/'device.json',record)
    report = dict(recipe_version=RECIPE_VERSION,product=selected['product'],build='12H321',
                  restore_environment_build=environment_build,
                  multipatch=bool(selected_profile.get('multipatch')),
                  bootstrap_library_build='12H321',
                  ram_root='md0',automatic_disk_mounts=False,device_modified=False,physical_boot_verified=False,
                  files={name:digest(session/name) for name in published},
                  packages={str(p.relative_to(KIT)):digest(p) for p in (ssh_package,freeze)},
                  tools={name:digest(out/name) for name in utilities})
    checkpoint(session/'rescue-preparation.json',report)
    # Successful publication makes the private construction directory wholly
    # redundant. Failed preparation still retains it for diagnosis.
    shutil.rmtree(out)
    return report
