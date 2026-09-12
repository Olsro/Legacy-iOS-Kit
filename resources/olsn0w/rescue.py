"""Load a selected RAM rescue using Legacy iOS Kit's host-specific DFU tools."""
import json
from pathlib import Path
import platform
import re
import subprocess
import time

from common import KIT, digest, profile, tools
from device import recheck_recovery
from restore import Rescue, checkpoint


def unique_usb_target(ecid):
    # libusb works on Linux and macOS; no system_profiler/ioreg dependency.
    import usb.core
    import usb.util
    devices=[d for d in usb.core.find(find_all=True,idVendor=0x05ac)
             if 0x1220 <= d.idProduct <= 0x12ff]
    if len(devices)!=1 or devices[0].idProduct!=0x1227:
        raise ValueError('Connect only the selected device in DFU before loading the rescue')
    try:
        serial=usb.util.get_string(devices[0],devices[0].iSerialNumber)
        match=re.search(r'ECID:([0-9a-fA-F]+)',serial or '')
        if not match or int(match[1],16)!=ecid:raise ValueError('DFU USB identity differs from session')
    finally:
        usb.util.dispose_resources(devices[0])


def boot(session, *, progress=print, pwned=False):
    session=Path(session).resolve()
    identity=json.loads((session/'device.json').read_text())['identity']
    report=json.loads((session/'rescue-preparation.json').read_text())
    if report.get('automatic_disk_mounts') is not False or report.get('ram_root')!='md0':
        raise ValueError('Rescue must boot RAM without automatically mounting internal volumes')
    required={'iBEC.img3','DeviceTree.img3','Kernelcache.img3','Ramdisk.img3'}
    if not required.issubset(report['files']):raise ValueError('Incomplete RAM rescue')
    for name,expected in report['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or digest(session/name)!=expected:
            raise ValueError('RAM rescue component changed')
    state=dict(stage='verified',ram_boot_requested=False,persistent_storage_commands_sent=False)
    checkpoint(session/'rescue-run.json',state)
    def run(argv,label,timeout=45):
        state['stage']=label;checkpoint(session/'rescue-run.json',state);progress(label)
        r=subprocess.run(list(map(str,argv)),cwd=session,capture_output=True,timeout=timeout)
        (session/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode:raise RuntimeError('RAM loading failed at '+label+'; see '+str(session/(label+'.log')))
        return r.stdout.decode(errors='replace')
    prepare_dfu(session, pwned=pwned, progress=progress, run=run)
    run([tools()/'irecovery','-i',hex(identity['ecid']),'-f',session/'iBEC.img3'],'ibec-upload')
    time.sleep(2)
    if recheck_recovery(session)['mode']!='Recovery':raise RuntimeError('RAM iBEC did not enter recovery')
    for name,command in [('Ramdisk.img3','ramdisk'),('DeviceTree.img3','devicetree'),('Kernelcache.img3','bootx')]:
        run([tools()/'irecovery','-i',hex(identity['ecid']),'-f',session/name],command+'-upload')
        run([tools()/'irecovery','-i',hex(identity['ecid']),'-c',command],command)
    state.update(stage='ram-boot-requested',ram_boot_requested=True);checkpoint(session/'rescue-run.json',state)
    return identity


def prepare_dfu(session, *, pwned=False, progress=print, run=None):
    session=Path(session).resolve()
    identity=json.loads((session/'device.json').read_text())['identity']
    if run is None:
        def run(argv,label,timeout=45):
            progress(label)
            result=subprocess.run(list(map(str,argv)),cwd=session,capture_output=True,timeout=timeout)
            (session/(label+'.log')).write_bytes(result.stdout+result.stderr)
            if result.returncode:raise RuntimeError('DFU preparation failed at '+label)
            return result.stdout.decode(errors='replace')
    if recheck_recovery(session)['mode']!='DFU':raise ValueError('The selected device must be in DFU')
    unique_usb_target(identity['ecid'])
    selected_profile=profile(identity['product'])
    if pwned:
        progress('Checking software-entered pwned iBSS')
    elif selected_profile.get('external_pwndfu'):
        progress('Checking the external A5 pwnDFU marker')
        query=run([tools()/'irecovery','-i',hex(identity['ecid']),'-q'],'a5-pwndfu-ready')
        if 'PWND: [checkm8]' not in query and 'PWND:[checkm8]' not in query:
            raise RuntimeError('A5 requires PWND:[checkm8] from A5Mate before the host can send iBSS')
        # Match Legacy iOS Kit's device_send_unpacked_ibss path for A5.  The
        # raw RSA-patched 8.4.1 iBSS is sent only after the external exploit
        # marker and remains a retryable, pre-erase transition.
        run([tools()/'primepwn',session/'pwnediBSS'],'a5-ibss-upload',60)
    elif platform.system()=='Darwin' and platform.machine()=='arm64':
        # The native arm64 ipwnder can exit without leaving A6/A6X in the
        # required pwned-iBSS state. The qualified Apple Silicon sequence is
        # the Rosetta exploit followed by gaster's USB reset.
        run(['arch','-x86_64',KIT/'bin/macos/ipwnder','-pv'],'pwn',60)
        run(['arch','-x86_64',KIT/'bin/macos/gaster','reset'],'pwn-reset',60)
    else:
        # Reuse the kit's A6/A6X selection, USB setup, and pwned-iBSS loader.
        run(['bash',KIT/'restore.sh','--pwn','--device='+identity['product'],
             '--ecid='+str(identity['ecid']),'--no-version-check','--no-internet-check','--no-color'],
            'kit-pwn',180)
    time.sleep(2)
    recheck_recovery(session)
    query=run([tools()/'irecovery','-i',hex(identity['ecid']),'-q'],'ibss-ready')
    ready=('SRTG: N/A' in query and
           (selected_profile['soc']=='a5' or 'IBFL: 0x1b' in query))
    if not ready:
        raise RuntimeError('The Kit did not return the required pwned iBSS state')


def connect(session, timeout=120):
    session=Path(session)
    record=json.loads((session/'device.json').read_text())
    prefix=json.loads((session/'ssh-prefix.json').read_text())
    maintenance=record.get('rescue_maintenance','/olsn0w-maintenance')
    ram=Rescue(prefix,record['identity'],maintenance)
    deadline=time.monotonic()+timeout
    while True:
        try:
            ram.guard()
            return ram
        except (RuntimeError,subprocess.TimeoutExpired) as error:
            if time.monotonic()>=deadline:raise RuntimeError('RAM SSH did not become ready') from error
            time.sleep(3)
