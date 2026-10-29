"""Prepare the Kit's signed-base restore with a RAM handoff before reboot."""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import uuid
import zipfile

from archives import members
from common import IMAGE_TIMEOUT, KIT, MODELS, baseband_strategy, digest, integer, profile, run, tools
from firmware import acquire, extract
from hfs import HFS
from img3 import img3
from integrity import require_same_file
from rescue_prepare import RAM_VOLUME_BYTES, RECIPE_VERSION
from restore_environment import report_build
from restore import checkpoint
from progress import activity

HANDOFF = 'olsn0w-restore-handoff'
MULTIPATCH_BOOTARGS = ('rd=md0 -v nand-enable-reformat=1 amfi=0xff '
                       'amfi_get_out_of_my_way=1 cs_enforcement_disable=1 pio-error=0')


def configure_baseband(image, product):
    """Disable modem flashing in restored's own options for preserved modems.

    The legacy host's --no-baseband alone does not stop iOS 8 restored from
    requesting BasebandData. Match the Kit's ramdisk UpdateBaseband override.
    """
    strategy=baseband_strategy(product)
    if strategy!='preserve':return dict(strategy=strategy)
    directory='/usr/local/share/restore'
    board=MODELS[product][0]
    names={item['name'] for item in image.ls(directory)}
    name='options.'+board[:-2]+'.plist'
    if name not in names:
        if 'options.plist' not in names:
            raise ValueError('Missing restore options for modem preservation')
        name='options.plist'
    path=directory+'/'+name
    original=image.read(path)
    options=plistlib.loads(original)
    if not isinstance(options,dict):raise ValueError('Expected a restore options dictionary')
    options['UpdateBaseband']=False
    fmt=plistlib.FMT_BINARY if original.startswith(b'bplist00') else plistlib.FMT_XML
    data=plistlib.dumps(options,fmt=fmt,sort_keys=False)
    image.add(path,data,0o644)
    if image.read(path)!=data:
        raise ValueError('Modem preservation options readback differs')
    return dict(strategy=strategy,update_baseband=False,options_path=path,
                options_sha256=hashlib.sha256(data).hexdigest())


def require_baseband_policy(report):
    """Reject older cellular-iPad bundles before any DFU or erase operation."""
    if baseband_strategy(report['product'])!='preserve':return
    policy=report.get('baseband_policy',{})
    if not isinstance(policy,dict):
        raise ValueError('Invalid modem preservation policy; no erase started')
    board=MODELS[report['product']][0]
    paths={'/usr/local/share/restore/options.'+board[:-2]+'.plist',
           '/usr/local/share/restore/options.plist'}
    if (policy.get('strategy')!='preserve' or policy.get('update_baseband') is not False
            or policy.get('options_path') not in paths
            or not isinstance(policy.get('options_sha256'),str)
            or not re.fullmatch(r'[0-9a-f]{64}',policy.get('options_sha256',''))):
        raise ValueError('Prepare the current modem-preserving restore RAM first; no erase started')


def multipatch_iboot_flags(component):
    """Leave RSA/ticket admission to futurerestore exactly once."""
    if component == 'iBSS':
        return []
    if component == 'iBEC':
        return ['--debug', '-b', MULTIPATCH_BOOTARGS]
    raise ValueError('Unsupported multipatch boot component')


def multipatch_key_metadata(base, donor):
    """Serve donor restore-component keys under the signed-base build route."""
    if (base.get('identifier') != donor.get('identifier') or
            base.get('buildid') != '12H321' or donor.get('buildid') != '10B329'):
        raise ValueError('Unexpected multipatch firmware-key identity')
    output=copy.deepcopy(base)
    for image in ('DeviceTree','Kernelcache'):
        target=[item for item in output.get('keys',[]) if item.get('image')==image]
        source=[item for item in donor.get('keys',[]) if item.get('image')==image]
        if len(target)!=1 or len(source)!=1:
            raise ValueError('Missing unique multipatch firmware key: '+image)
        for field in ('iv','key'):
            if not source[0].get(field):raise ValueError('Incomplete multipatch firmware key: '+image)
            target[0][field]=source[0][field]
    return output


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


def copy_ipsw(source, output, replacements, additions=()):
    """Copy all stock members, replacing only explicitly selected components."""
    with zipfile.ZipFile(source) as incoming:
        names = incoming.namelist()
        additions=set(additions)
        if (len(set(names)) != len(names) or additions & set(names) or
                set(replacements)-additions-set(names) or
                additions != set(replacements)-set(names)):
            raise ValueError('Ambiguous or missing IPSW components')
        for name in names+sorted(additions):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Unsafe IPSW member path')
        def size(info):
            replacement=replacements.get(info.filename)
            if replacement is None:return info.file_size
            return replacement.stat().st_size if isinstance(replacement,Path) else len(replacement)
        total=sum(size(info) for info in incoming.infolist())+sum(
            p.stat().st_size if isinstance(p,Path) else len(p)
            for name,p in replacements.items() if name in additions)
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
            for name in sorted(additions):
                info=zipfile.ZipInfo(name);info.compress_type=zipfile.ZIP_STORED
                with outgoing.open(info,'w',force_zip64=True) as target:
                    replacement=replacements[name]
                    if isinstance(replacement,Path):
                        with replacement.open('rb') as original:transfer(original,target)
                    else:
                        target.write(replacement);done+=len(replacement);update(done)
    with zipfile.ZipFile(output) as result, zipfile.ZipFile(source) as original:
        if result.namelist() != original.namelist()+sorted(additions):
            raise ValueError('Output IPSW member set differs')
        for info in result.infolist():
            if info.filename in replacements:
                replacement = replacements[info.filename]
                if isinstance(replacement, Path):
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


def multipatch_manifest(data, product, donor):
    """Route the erase identity to the complete 6.1.3 restore component records."""
    document=plistlib.loads(data);board,chip,board_id=MODELS[product]
    matches=[item for item in document['BuildIdentities']
             if item['Info'].get('DeviceClass')==board
             and item['Info'].get('RestoreBehavior')=='Erase'
             and integer(item['ApChipID'])==chip and integer(item['ApBoardID'])==board_id]
    if document.get('ProductBuildVersion')!='12H321' or product not in document.get('SupportedProductTypes',[]) or len(matches)!=1:
        raise ValueError('Unexpected signed-base manifest for multipatch')
    donor_matches=[item for item in donor['BuildIdentities']
                   if item['Info'].get('DeviceClass')==board
                   and item['Info'].get('RestoreBehavior')=='Erase'
                   and integer(item['ApChipID'])==chip and integer(item['ApBoardID'])==board_id]
    if donor.get('ProductBuildVersion')!='10B329' or len(donor_matches)!=1:
        raise ValueError('Unexpected multipatch restore donor manifest')
    manifest=matches[0]['Manifest'];donor_manifest=donor_matches[0]['Manifest']
    for component,path in (('RestoreDeviceTree','Downgrade/RestoreDeviceTree'),
                           ('RestoreKernelCache','Downgrade/RestoreKernelCache')):
        # In particular, the 6.1.3 kernel PartialDigest tells futurerestore how
        # to personalize the donor IMG3. Keeping the 8.4.1 component record
        # makes it transmit a different kernel image that old A5 iBEC rejects.
        manifest[component]=copy.deepcopy(donor_manifest[component])
        manifest[component]['Info']['Path']=path
    fmt=plistlib.FMT_BINARY if data.startswith(b'bplist00') else plistlib.FMT_XML
    output=plistlib.dumps(document,fmt=fmt,sort_keys=False)
    checked=plistlib.loads(output)
    selected=[item for item in checked['BuildIdentities'] if item['Info'].get('DeviceClass')==board and item['Info'].get('RestoreBehavior')=='Erase']
    if (len(selected)!=1 or selected[0]['Manifest']['RestoreDeviceTree']['Info']['Path']!='Downgrade/RestoreDeviceTree' or
            selected[0]['Manifest']['RestoreKernelCache']['Info']['Path']!='Downgrade/RestoreKernelCache'):
        raise ValueError('Multipatch manifest encoding failed')
    return output


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
    base_firmware, _ = extract(selected['product'], '8.4.1', source, keys, '12H321')
    firmware=base_firmware
    selected_profile=profile(selected['product'])
    multipatch=bool(selected_profile.get('multipatch'))
    native6=report_build(rescue)=='10B329'
    if rescue.get('multipatch') is not multipatch:
        raise ValueError('RAM rescue multipatch policy differs from selected model')
    destination.mkdir(parents=True, mode=0o700)
    token = uuid.uuid4().hex
    image_path = destination/'restore-ram.hfs'
    shutil.copyfile(session/'rescue-ram.hfs', image_path)
    image = HFS(image_path)
    if image.info()['bytes'] != RAM_VOLUME_BYTES:
        raise ValueError('Restore RAM allocation differs from the qualified rescue')
    baseband_policy=configure_baseband(image,selected['product'])
    from asr_patch import patch as patch_asr
    from signing import resign, verify
    asr_original = image.read('/usr/sbin/asr')
    if native6:
        # Match Legacy iOS Kit --multipatch: the 6.1.3 restore environment
        # receives its checked replacement ASR instead of the iOS 8 patch.
        asr=(KIT/'resources/patch/asr').read_bytes()
        verify(asr)
        asr_report=dict(method='legacy-kit-multipatch-asr',sha256=digest(KIT/'resources/patch/asr'))
    else:
        asr, asr_report = patch_asr(asr_original)
    asr_file = destination/'asr.patched'
    asr_file.write_bytes(asr)
    if not native6:
        resign(asr_file, verify(asr_original)['entitlements'])
    elif asr_file.read_bytes() != (KIT/'resources/patch/asr').read_bytes():
        # Legacy iOS Kit's gas-gauge path installs this already-signed ASR
        # byte-for-byte.  Re-signing it adds a second code directory and no
        # longer reproduces the multipatch restore environment exercised by
        # the Kit on A5 hardware.
        raise ValueError('Multipatch ASR differs from the checked Kit binary')
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
    if native6:
        # The RAM rescue carries already-admitted iBSS/iBEC images because it
        # sends them directly.  The IPSW passed to futurerestore must not: its
        # --use-pwndfu path applies RSA and the iBEC ticket patch itself.
        # Repack an unpatched iBSS and an iBEC containing boot arguments only,
        # both from the checked 6.1.3 multipatch restore environment.
        restore_inputs,restore_keys,restore_manifest,restore_identity=acquire(
            selected['product'],'6.1.3',build='10B329')
        restore_firmware,_=extract(selected['product'],'6.1.3',restore_inputs,
                                   build='10B329')
        restore_key_metadata=multipatch_key_metadata(metadata,restore_keys)
        (destination/'futurerestore-keys.json').write_text(
            json.dumps(restore_key_metadata,indent=2,sort_keys=True)+'\n')
        # The 6.1.3 components are only the native Data/gas-gauge-safe restore
        # environment.  Legacy iOS Kit deliberately keeps the selected signed
        # system image itself at 8.4.1.
        technical=destination/'signed-technical';technical.mkdir()
        signed_root=HFS(base_firmware/'rootfs.hfs')
        technical_names=['System/Library/CoreServices/SystemVersion.plist',
                         'System/Library/Caches/com.apple.kernelcaches/kernelcache']
        for name in technical_names:
            data=((base_firmware/'Kernelcache.img3').read_bytes()
                  if name=='System/Library/Caches/com.apple.kernelcaches/kernelcache'
                  else signed_root.read('/'+name))
            if not data:raise ValueError('Empty signed technical artifact: '+name)
            path=technical/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        run([tools()/'xpwntool',restore_firmware/'iBSS.raw',destination/'iBSS.img3',
             '-t',restore_firmware/'iBSS.orig'])
        run([tools()/'iBoot32Patcher',restore_firmware/'iBEC.raw',destination/'iBEC.patched',
             *multipatch_iboot_flags('iBEC')],destination/'ibec-patch.log',patcher=True)
        run([tools()/'xpwntool',destination/'iBEC.patched',destination/'iBEC.img3',
             '-t',restore_firmware/'iBEC.orig'])
    else:
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
    additions=set();multipatch_manifest_sha256=None
    if native6:
        components=(('iBSS','iBSS.img3','ibss',None),
                    ('RestoreDeviceTree','DeviceTree.orig','dtre','Downgrade/RestoreDeviceTree'),
                    ('RestoreKernelCache','Kernelcache.orig','krnl','Downgrade/RestoreKernelCache'))
        for component,name,kind,downgrade_path in components:
            source_file=(destination/name if component=='iBSS' else restore_firmware/name)
            blob=source_file.read_bytes();actual,tags,_=img3(blob)
            encrypted=component!='iBSS'
            if actual!=kind or ('KBAG' in tags) is not encrypted:
                raise ValueError('Unexpected multipatch restore component encoding: '+component)
            path=downgrade_path or identity['Manifest'][component]['Info']['Path']
            replacements[path]=blob
            if downgrade_path:additions.add(path)
        with zipfile.ZipFile(source) as archive:
            changed_manifest=multipatch_manifest(
                archive.read('BuildManifest.plist'),selected['product'],restore_manifest)
        replacements['BuildManifest.plist']=changed_manifest
        multipatch_manifest_sha256=hashlib.sha256(changed_manifest).hexdigest()
    target_os_member=identity['Manifest']['OS']['Info']['Path']
    if native6:
        # Legacy Kit's multipatch starts from a custom IPSW: it decrypts the
        # selected filesystem and rebuilds a plain UDIF before handing it to
        # the older restore ASR. The stock FileVault member cannot be opened
        # by iOS 6 ASR and fails source validation with Authentication error.
        rebuilt=destination/'system.asr.dmg'
        run([tools()/'dmg','build',base_firmware/'rootfs.hfs',rebuilt],
            destination/'system-build.log',timeout=IMAGE_TIMEOUT)
        verified=destination/'system.verify.hfs'
        run([tools()/'dmg','extract',rebuilt,verified],
            destination/'system-verify.log',timeout=IMAGE_TIMEOUT)
        require_same_file(base_firmware/'rootfs.hfs', verified,
                          'Rebuilt multipatch ASR image differs from signed base',
                          destination/'system-integrity.json',
                          inputs=dict(source_image=rebuilt, dmg_tool=tools()/'dmg'))
        verified.unlink()
        replacements[target_os_member]=rebuilt
        asr_source='rebuilt-udif-from-signed-base-hfs'
        transient_system=rebuilt
    else:
        from filevault import decrypt_stream
        os_keys = [key for key in metadata['keys'] if key['image'] == 'RootFS']
        if len(os_keys) != 1 or Path(target_os_member).name != os_keys[0]['filename']:
            raise ValueError('System image/key identity mismatch')
        plaintext = destination/'system.asr.dmg'
        with zipfile.ZipFile(source) as archive, archive.open(target_os_member) as incoming:
            decrypt_stream(incoming,archive.getinfo(target_os_member).file_size,
                           plaintext,os_keys[0]['key'])
        verified = destination/'system.verify.hfs'
        run([tools()/'dmg', 'extract', plaintext, verified], destination/'system-verify.log', timeout=IMAGE_TIMEOUT)
        require_same_file(base_firmware/'rootfs.hfs', verified,
                          'Plaintext ASR image differs from the original filesystem',
                          destination/'system-integrity.json',
                          inputs=dict(source_image=plaintext, dmg_tool=tools()/'dmg'))
        verified.unlink()
        replacements[target_os_member] = plaintext
        asr_source='original-udif-without-filevault-envelope'
        transient_system=plaintext
    pending = destination/'base8.pending.ipsw'
    copy_ipsw(source, pending, replacements,additions)
    pending.rename(destination/'base8.ipsw')
    # copy_ipsw checked the replacement inside the completed archive; the
    # standalone plaintext image is no longer an input to restoration.
    if transient_system is not None:transient_system.unlink()
    names = ['asr.patched','base8.ipsw','restore-ram.hfs','Ramdisk.img3','iBEC.img3']
    if native6:
        names+=['iBSS.img3','futurerestore-keys.json']
        names += [str(path.relative_to(destination)) for path in
                  (destination/'signed-technical').rglob('*') if path.is_file()]
    report = dict(kind='signed-base-restore-handoff',identity=selected,product=selected['product'],
                  build='12H321',reboot_token=token,rescue_session=str(session),
                  stock_system_preserved=True,multipatch=multipatch,
                  baseband_policy=baseband_policy,
                  stock_system_member_preserved=not native6,
                  restore_filesystem_build='12H321',
                  restore_environment_build=rescue.get('restore_environment_build'),
                  restore_component_policy=('legacy-kit-4s-multipatch' if multipatch else
                                            'native6-ram-writer' if native6 else 'signed-base'),
                  multipatch_component_metadata_build=('10B329' if native6 else None),
                  multipatch_restore_component_encoding=(
                      'encrypted-donor-for-libipatcher' if native6 else None),
                  restore_key_policy=('signed-base-with-10B329-restore-components'
                                      if native6 else 'signed-base'),
                  restore_bootchain_policy=('futurerestore-unpatched-rsa' if native6
                                            else 'futurerestore-stock-rsa'),
                  multipatch_manifest_sha256=multipatch_manifest_sha256,
                  device_modified=False,physical_restore_verified=False,
                  asr_patch=asr_report,asr_source=asr_source,
                  stock_hfs_sha256=digest(base_firmware/'rootfs.hfs'),
                  restore_hfs_sha256=digest(base_firmware/'rootfs.hfs'),handoff_storage='nvram',
                  handoff_package_sha256=digest(KIT/'resources/jailbreak/freeze.tar.gz'),
                  files={name:digest(destination/name) for name in names},stock_ipsw_sha256=digest(source))
    checkpoint(destination/'manifest.json', report)
    return report
