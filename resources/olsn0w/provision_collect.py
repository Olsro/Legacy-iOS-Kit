"""Collect newly restored signed firmware while the original RAM stays alive."""
import json
from pathlib import Path
import plistlib

from common import digest
from device import same_hardware
from img3 import img3
from layout import HFS_TYPE, inspect
from provision import read_handoff, require_completed_restore
from restore import checked_manifest, checkpoint

KERNEL='System/Library/Caches/com.apple.kernelcaches/kernelcache'
MODEM='usr/local/standalone/firmware/Baseband/Mav5/'
MODEM_FILES=('apps.mbn','bbticket.der','dsp1.mbn','dsp2.mbn','dsp3.mbn','rpm.mbn','sbl1.mbn','sbl2.mbn')


def collect(bundle, ram, destination):
    bundle,destination=Path(bundle),Path(destination)
    report=checked_manifest(bundle)
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
        if report['product']!='iPad3,4':names += [MODEM+name for name in MODEM_FILES]
        for name in names:
            data=ram.run('cat /mnt1/'+name)
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
    checkpoint(destination/'modem-files.json',{n:v for n,v in files.items() if n.startswith(MODEM)})
    checkpoint(destination/'collection.json',dict(identity=ram.identity,source='completed-signed-base-restore',
        build='12H321',activation_collected=False,files=files))
    return destination
