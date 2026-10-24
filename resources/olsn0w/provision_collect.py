"""Collect newly restored signed firmware while the original RAM stays alive."""
from collections import Counter
import io
import json
from pathlib import Path
import plistlib
import zipfile

from common import baseband_files, baseband_strategy, digest, profile
from device import same_hardware
from img3 import img3
from layout import HFS_TYPE, inspect
from provision import read_handoff, require_completed_restore
from restore import checked_manifest, checkpoint
from restore_environment import report_build

KERNEL='System/Library/Caches/com.apple.kernelcaches/kernelcache'


def modem_components(product):
    selected=profile(product)
    if not selected['has_baseband']:return None,()
    if baseband_strategy(product)=='preserve':return None,()
    family=selected['baseband_family']
    return 'usr/local/standalone/firmware/Baseband/'+family+'/',baseband_files(family)


def personalized_modem(data, names, *, optional=()):
    """Read required runtime files, allowing explicitly named restore-only files."""
    expected=set(names)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        counts=Counter(archive.namelist())
        missing=expected-set(counts)
        unexpected=set(counts)-expected-set(optional)
        duplicates={name for name,count in counts.items() if count>1}
        if missing or unexpected or duplicates:
            details='; '.join(label+': '+(', '.join(map(repr,sorted(values))) or 'none')
                             for label,values in (('missing',missing),('unexpected',unexpected),
                                                  ('duplicate',duplicates)))
            raise ValueError('Personalized modem archive has an unexpected component set ('+details+')')
        result={name:archive.read(name) for name in names}
    if any(not value for value in result.values()):
        raise ValueError('Personalized modem archive contains an empty component')
    return result


def collect(bundle, ram, destination):
    bundle,destination=Path(bundle),Path(destination)
    report=checked_manifest(bundle)
    native6=report_build(report)=='10B329'
    state=json.loads((bundle/'run.json').read_text())
    if not same_hardware(report['identity'],ram.identity) or not state.get('complete') or state.get('stage')!='authenticated-ram-handoff':
        raise ValueError('A completed selected-device restore handoff is required')
    require_completed_restore(state.get('returncode'),(bundle/'restore.log').read_text(errors='replace'),
                              read_handoff(ram),report['reboot_token'])
    if destination.exists():raise ValueError('Preserve the earlier technical collection')
    # Restore may already have unmounted both stock volumes. Only its known
    # mount points can be detached; never force an unmount or clear NVRAM.
    mounts=ram.run('/sbin/mount').decode().splitlines()
    internal=[line.split(' (',1)[0] for line in mounts if line.startswith(('/dev/disk','/dev/rdisk'))]
    allowed={'/dev/disk0s1s1 on /mnt1','/dev/disk0s1s2 on /mnt2'}
    if not set(internal).issubset(allowed):raise ValueError('Unexpected restored-volume mounts')
    ram.guard(internal)
    for line in reversed(internal):ram.run(ram.tool('unmount')+' '+line.split(' on ')[1])
    ram.guard()
    primary,secondary=ram.table();_,parts=inspect(primary,secondary)
    if len(parts)!=2 or [p['index'] for p in parts]!=[1,2] or any(p['type']!=HFS_TYPE for p in parts):
        raise ValueError('Expected a freshly restored stock HFS partition table')
    destination.mkdir(parents=True,mode=0o700)
    (destination/'gpt-primary.bin').write_bytes(primary);(destination/'gpt-secondary.bin').write_bytes(secondary)
    ram.run(ram.tool('mount_hfs')+' -o rdonly /dev/disk0s1s1 /mnt1')
    ram.guard(['/dev/disk0s1s1 on /mnt1'])
    files={name:dict(bytes=(destination/name).stat().st_size,sha256=digest(destination/name))
           for name in ('gpt-primary.bin','gpt-secondary.bin')}
    try:
        names=['System/Library/CoreServices/SystemVersion.plist',KERNEL]
        modem,modem_files=modem_components(report['product'])
        if modem:names += [modem+name for name in modem_files]
        packed_modem={}
        if modem and native6:
            family=profile(report['product'])['baseband_family']
            packed=ram.run('cat /mnt1/'+modem+family+'-personalized.zip')
            # Mav5's personalized restore ZIP retains RestoreSBL1. The loose
            # runtime set used by the iOS 8 collector does not include it;
            # collect the same runtime payload on the native iOS 6 path.
            optional=('restoresbl1.mbn',) if family=='Mav5' else ()
            packed_modem=personalized_modem(packed,modem_files,optional=optional)
        carrier_version=ram.run('cat /mnt1/'+names[0])
        carrier=plistlib.loads(carrier_version)
        expected_carrier=('8.4.1','12H321')
        if (carrier['ProductVersion'],carrier['ProductBuildVersion'])!=expected_carrier:
            raise ValueError('Unexpected newly restored carrier system version')
        for name in names:
            modem_name=(name[len(modem):] if modem and name.startswith(modem) else None)
            seeded=native6 and modem_name is None
            data=(packed_modem[modem_name] if modem_name in packed_modem else
                  (bundle/'signed-technical'/name).read_bytes() if seeded else
                  ram.run('cat /mnt1/'+name))
            if not data:raise ValueError('Empty signed-base artifact: '+name)
            path=destination/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            files[name]=dict(bytes=len(data),sha256=digest(path))
        version=plistlib.loads((destination/names[0]).read_bytes())
        if (version['ProductVersion'],version['ProductBuildVersion'])!=('8.4.1','12H321'):
            raise ValueError('Unexpected newly restored system version')
        kind,tags,_=img3((destination/KERNEL).read_bytes())
        if kind!='krnl':
            raise ValueError('Newly restored kernel has an unexpected image type')
    finally:
        ram.run(ram.tool('unmount')+' /mnt1')
    ram.guard()
    if ram.table()!=(primary,secondary):raise ValueError('Partition table changed during collection')
    checkpoint(destination/'modem-files.json',
               {n:v for n,v in files.items() if modem and n.startswith(modem)})
    checkpoint(destination/'collection.json',dict(
        identity=ram.identity,source='completed-signed-base-restore',build='12H321',
        restore_filesystem_build=report.get('restore_filesystem_build','12H321'),
        technical_source=('verified-signed-base-bundle' if native6
                          else 'restored-system-volume'),
        activation_collected=False,files=files))
    return destination
